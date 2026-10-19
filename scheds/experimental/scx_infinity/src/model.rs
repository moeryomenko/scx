// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Shared model for both ready-queue prototypes.
//!
//! The BPF core keeps one scheduler-owned queue per CPU. A head insert
//! takes a key below `KEY_MID`, a tail insert a key above it, and dispatch
//! pops the lowest head. Two implementations are modelled:
//!
//! - [`EdqModel`] orders by `(key, insertion)`, mirroring `scx_edq`.
//! - [`ListModel`] is an intrusive FIFO list: a head key pushes to the
//!   front and a tail key to the back.
//!
//! Both are driven through [`IntrusiveQueue`], so one test suite covers the
//! ordering, the 7:1 gate, exact removal, yield-to, queued reweight, peer
//! steal, a stale pop and the task lifetime. The tests run for both
//! implementations in the default test build.
//!
//! This module builds only for tests.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::policy::gate_tail;

/// Head keys count down from this value and tail keys count up from it.
pub const KEY_MID: u64 = 1 << 62;
/// One steal tier scans at most this many eligible peers.
pub const STEAL_MAX_PEERS: usize = 8;

/// Where an insert puts the new item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Position {
    Head,
    Tail,
}

/// One queued task as the queue sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Item {
    pub id: u64,
    pub key: u64,
    pub weight: u64,
    pub slice: u64,
}

/// The queue contract the two prototypes share.
pub trait IntrusiveQueue {
    /// Insert a new item. Returns false when the id is already queued.
    fn insert(&mut self, item: Item, position: Position) -> bool;
    /// Remove one exact item by id.
    fn remove(&mut self, id: u64) -> Option<Item>;
    /// Pop the head.
    fn pop(&mut self) -> Option<Item>;
    /// Id of the head item, without removing it.
    fn peek_id(&self) -> Option<u64>;
    /// Position from the head. Zero runs next.
    fn rank(&self, id: u64) -> Option<usize>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `scx_edq`: order by the scheduler key, then by insertion sequence.
#[derive(Debug, Default)]
pub struct EdqModel {
    items: Vec<Item>,
    seq: u64,
}

impl IntrusiveQueue for EdqModel {
    fn insert(&mut self, item: Item, _position: Position) -> bool {
        if self.items.iter().any(|queued| queued.id == item.id) {
            return false;
        }
        self.seq = self.seq.wrapping_add(1);
        let at = self.items.partition_point(|queued| queued.key < item.key);
        self.items.insert(at, item);
        true
    }

    fn remove(&mut self, id: u64) -> Option<Item> {
        let at = self.items.iter().position(|item| item.id == id)?;
        Some(self.items.remove(at))
    }

    fn pop(&mut self) -> Option<Item> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0))
        }
    }

    fn peek_id(&self) -> Option<u64> {
        self.items.first().map(|item| item.id)
    }

    fn rank(&self, id: u64) -> Option<usize> {
        self.items.iter().position(|item| item.id == id)
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

/// The queue-list prototype: an intrusive FIFO list ordered by insert
/// side. A head key pushes to the front, a tail key to the back.
#[derive(Debug, Default)]
pub struct ListModel {
    items: VecDeque<Item>,
}

impl IntrusiveQueue for ListModel {
    fn insert(&mut self, item: Item, position: Position) -> bool {
        if self.items.iter().any(|queued| queued.id == item.id) {
            return false;
        }
        match position {
            Position::Head => self.items.push_front(item),
            Position::Tail => self.items.push_back(item),
        }
        true
    }

    fn remove(&mut self, id: u64) -> Option<Item> {
        let at = self.items.iter().position(|item| item.id == id)?;
        self.items.remove(at)
    }

    fn pop(&mut self) -> Option<Item> {
        self.items.pop_front()
    }

    fn peek_id(&self) -> Option<u64> {
        self.items.front().map(|item| item.id)
    }

    fn rank(&self, id: u64) -> Option<usize> {
        self.items.iter().position(|item| item.id == id)
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

/// Task run state, matching `enum inf_task_state` in `intf.h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Idle,
    Queued,
    Dispatched,
    Running,
    Parked,
    Exiting,
}

#[derive(Clone, Debug)]
pub struct Task {
    pub weight: u64,
    pub slice: u64,
    pub state: TaskState,
    pub queued_cpu: Option<usize>,
    pub holdcnt: u32,
    /// CPUs on which the task may run.
    pub allowed: Vec<usize>,
    pub exiting: bool,
}

impl Task {
    fn new(weight: u64, allowed: Vec<usize>) -> Self {
        Self {
            weight,
            slice: 1,
            state: TaskState::Idle,
            queued_cpu: None,
            holdcnt: 0,
            allowed,
            exiting: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StealTier {
    Llc,
    Node,
}

#[derive(Clone, Copy, Debug)]
pub struct Pop {
    pub id: u64,
    pub weight: u64,
    pub stale: bool,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub head_inserts: u64,
    pub tail_inserts: u64,
    pub exempt_inserts: u64,
    pub steals: u64,
    pub steal_llc: u64,
    pub steal_node: u64,
    pub yield_to_moves: u64,
    pub reweight_moves: u64,
    pub stale_pops: u64,
    pub lost_state_errors: u64,
}

/// A small scheduler: one queue per CPU, the gate and key runs, the
/// per-CPU weight and depth, the steal cursors and the task table.
pub struct Model<Q> {
    pub queues: Vec<Q>,
    pub seq: Vec<u32>,
    pub head_seq: Vec<u64>,
    pub tail_seq: Vec<u64>,
    pub w_sum: Vec<i64>,
    pub depth: Vec<i64>,
    pub llc: Vec<u32>,
    pub node: Vec<u32>,
    pub online: Vec<bool>,
    pub cursor_llc: Vec<u32>,
    pub cursor_node: Vec<u32>,
    pub tasks: BTreeMap<u64, Task>,
    pub stats: Stats,
}

impl<Q: IntrusiveQueue + Default> Model<Q> {
    pub fn new(ncpu: usize) -> Self {
        Self {
            queues: (0..ncpu).map(|_| Q::default()).collect(),
            seq: vec![0; ncpu],
            head_seq: vec![KEY_MID; ncpu],
            tail_seq: vec![KEY_MID; ncpu],
            w_sum: vec![0; ncpu],
            depth: vec![0; ncpu],
            llc: vec![0; ncpu],
            node: vec![0; ncpu],
            online: vec![true; ncpu],
            cursor_llc: vec![0; ncpu],
            cursor_node: vec![0; ncpu],
            tasks: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    pub fn set_topo(&mut self, cpu: usize, llc: u32, node: u32) {
        self.llc[cpu] = llc;
        self.node[cpu] = node;
    }

    pub fn add_task(&mut self, id: u64, weight: u64, allowed: Vec<usize>) {
        self.tasks.insert(id, Task::new(weight, allowed));
    }

    fn head_key(&mut self, cpu: usize) -> u64 {
        self.head_seq[cpu] = self.head_seq[cpu].wrapping_sub(1);
        self.head_seq[cpu]
    }

    fn tail_key(&mut self, cpu: usize) -> u64 {
        let key = self.tail_seq[cpu];
        self.tail_seq[cpu] = self.tail_seq[cpu].wrapping_add(1);
        key
    }

    /// Replica of the enqueue decision in `inf_enqueue_common()`.
    pub fn enqueue(
        &mut self,
        id: u64,
        cpu: usize,
        wake: bool,
        head_flag: bool,
        reenq: bool,
        last: bool,
        preempt: bool,
    ) -> Position {
        let slice = self.tasks.get(&id).map(|task| task.slice).unwrap_or(1);
        let expired = slice == 0 && !wake && !head_flag;
        let mut gated = false;

        let position = if head_flag {
            Position::Head
        } else if expired || reenq || last || preempt {
            Position::Tail
        } else {
            gated = true;
            let seq = self.seq[cpu];
            self.seq[cpu] = seq.wrapping_add(1);
            if gate_tail(seq) {
                Position::Tail
            } else {
                Position::Head
            }
        };

        let weight = self.tasks.get(&id).map(|task| task.weight).unwrap_or(100);
        self.push(cpu, id, weight, slice, position, gated);
        position
    }

    fn push(
        &mut self,
        cpu: usize,
        id: u64,
        weight: u64,
        slice: u64,
        position: Position,
        gated: bool,
    ) {
        let key = match position {
            Position::Head => self.head_key(cpu),
            Position::Tail => self.tail_key(cpu),
        };
        let item = Item {
            id,
            key,
            weight,
            slice,
        };
        if !self.queues[cpu].insert(item, position) {
            self.stats.lost_state_errors += 1;
            return;
        }
        self.w_sum[cpu] += weight as i64;
        self.depth[cpu] += 1;
        if let Some(task) = self.tasks.get_mut(&id) {
            task.state = TaskState::Queued;
            task.queued_cpu = Some(cpu);
        }
        if gated {
            match position {
                Position::Head => self.stats.head_inserts += 1,
                Position::Tail => self.stats.tail_inserts += 1,
            }
        } else {
            self.stats.exempt_inserts += 1;
        }
    }

    /// Pop the head. A node whose task left the task table is stale.
    pub fn pop(&mut self, cpu: usize, hold: bool) -> Option<Pop> {
        let item = self.queues[cpu].pop()?;
        self.w_sum[cpu] -= item.weight as i64;
        self.depth[cpu] -= 1;

        let stale = !self.tasks.contains_key(&item.id);
        if stale {
            self.stats.stale_pops += 1;
        } else if let Some(task) = self.tasks.get_mut(&item.id) {
            task.state = TaskState::Dispatched;
            task.queued_cpu = None;
            if hold {
                task.holdcnt += 1;
            }
        }

        Some(Pop {
            id: item.id,
            weight: item.weight,
            stale,
        })
    }

    /// Remove one exact item from a queue and release its charge.
    pub fn remove(&mut self, cpu: usize, id: u64) -> Option<Item> {
        let item = self.queues[cpu].remove(id)?;
        self.w_sum[cpu] -= item.weight as i64;
        self.depth[cpu] -= 1;
        if let Some(task) = self.tasks.get_mut(&id) {
            task.queued_cpu = None;
            if task.state == TaskState::Queued {
                task.state = TaskState::Idle;
            }
        }
        Some(item)
    }

    pub fn rank(&self, cpu: usize, id: u64) -> Option<usize> {
        self.queues[cpu].rank(id)
    }

    pub fn drain(&mut self, cpu: usize) -> Vec<u64> {
        let mut order = Vec::new();
        while let Some(pop) = self.pop(cpu, false) {
            order.push(pop.id);
        }
        order
    }

    /// Two-argument yield: the donor forfeits its slice and a runnable
    /// queued target moves to the newest head key. The gate does not move.
    pub fn yield_to(&mut self, from: u64, to: u64) -> bool {
        if let Some(task) = self.tasks.get_mut(&from) {
            task.slice = 0;
        }
        if from == to {
            return false;
        }
        let Some(cpu) = self.tasks.get(&to).and_then(|task| task.queued_cpu) else {
            return false;
        };
        match self.tasks.get(&to) {
            Some(task) if task.state == TaskState::Queued && !task.exiting => {}
            _ => return false,
        }

        let item = self.remove(cpu, to).expect("a queued target is removable");
        let key = self.head_key(cpu);
        let moved = Item {
            id: to,
            key,
            weight: item.weight,
            slice: item.slice,
        };
        self.queues[cpu].insert(moved, Position::Head);
        self.w_sum[cpu] += item.weight as i64;
        self.depth[cpu] += 1;
        if let Some(task) = self.tasks.get_mut(&to) {
            task.state = TaskState::Queued;
            task.queued_cpu = Some(cpu);
        }
        self.stats.yield_to_moves += 1;
        true
    }

    /// Queued reweight: leave the queue and re-enter through the gate.
    pub fn reweight(&mut self, id: u64, weight: u64) -> bool {
        let Some(cpu) = self.tasks.get(&id).and_then(|task| task.queued_cpu) else {
            if let Some(task) = self.tasks.get_mut(&id) {
                task.weight = weight;
            }
            return false;
        };
        let Some(item) = self.remove(cpu, id) else {
            return false;
        };
        if let Some(task) = self.tasks.get_mut(&id) {
            task.weight = weight;
        }

        let seq = self.seq[cpu];
        self.seq[cpu] = seq.wrapping_add(1);
        let position = if gate_tail(seq) {
            Position::Tail
        } else {
            Position::Head
        };
        self.push(cpu, id, weight, item.slice, position, true);
        self.stats.reweight_moves += 1;
        true
    }

    /// One steal tier: at most eight eligible peers from the rotating
    /// cursor. A head that the destination cannot run is skipped.
    pub fn steal(&mut self, dst: usize, tier: StealTier) -> Option<u64> {
        let ncpu = self.queues.len() as u32;
        let start = match tier {
            StealTier::Llc => self.cursor_llc[dst] % ncpu,
            StealTier::Node => self.cursor_node[dst] % ncpu,
        };
        let mut next = start;
        let mut examined = 0usize;

        for step in 0..ncpu {
            if examined >= STEAL_MAX_PEERS {
                break;
            }
            let peer = (start + step) % ncpu;
            if peer as usize == dst || !self.online[peer as usize] {
                continue;
            }
            let eligible = match tier {
                StealTier::Llc => self.llc[peer as usize] == self.llc[dst],
                StealTier::Node => {
                    self.node[peer as usize] == self.node[dst]
                        && self.llc[peer as usize] != self.llc[dst]
                }
            };
            if !eligible {
                continue;
            }
            examined += 1;
            next = (peer + 1) % ncpu;

            let Some(id) = self.queues[peer as usize].peek_id() else {
                continue;
            };
            let allowed = self
                .tasks
                .get(&id)
                .map(|task| task.allowed.contains(&dst))
                .unwrap_or(false);
            if !allowed {
                /* Do not look deeper in this peer queue. */
                continue;
            }

            let Some(item) = self.queues[peer as usize].pop() else {
                continue;
            };
            self.w_sum[peer as usize] -= item.weight as i64;
            self.depth[peer as usize] -= 1;
            self.w_sum[dst] += item.weight as i64;
            if let Some(task) = self.tasks.get_mut(&id) {
                task.state = TaskState::Dispatched;
                task.queued_cpu = None;
            }
            self.stats.steals += 1;
            match tier {
                StealTier::Llc => self.stats.steal_llc += 1,
                StealTier::Node => self.stats.steal_node += 1,
            }
            match tier {
                StealTier::Llc => self.cursor_llc[dst] = next,
                StealTier::Node => self.cursor_node[dst] = next,
            }
            return Some(id);
        }

        match tier {
            StealTier::Llc => self.cursor_llc[dst] = next,
            StealTier::Node => self.cursor_node[dst] = next,
        }
        None
    }

    /// End a task and report whether its context can be freed now.
    pub fn exit_task(&mut self, id: u64) -> bool {
        if let Some(task) = self.tasks.get_mut(&id) {
            task.exiting = true;
            task.state = TaskState::Exiting;
        }
        if let Some(cpu) = self.tasks.get(&id).and_then(|task| task.queued_cpu) {
            self.remove(cpu, id);
        }
        self.tasks
            .get(&id)
            .map(|task| task.holdcnt == 0)
            .unwrap_or(true)
    }

    /// Drop one hold; returns true when an exiting task is now free.
    pub fn drop_hold(&mut self, id: u64) -> bool {
        if let Some(task) = self.tasks.get_mut(&id) {
            if task.holdcnt > 0 {
                task.holdcnt -= 1;
            }
            task.exiting && task.holdcnt == 0
        } else {
            true
        }
    }

    /// Remove the task from the table: the context is freed.
    pub fn release(&mut self, id: u64) {
        self.tasks.remove(&id);
    }

    /// Simulate a task that exited behind a queued node.
    pub fn abandon(&mut self, id: u64) {
        self.tasks.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_cpu<Q: IntrusiveQueue + Default>() -> Model<Q> {
        Model::new(1)
    }

    fn ordering<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        for id in 1..=7 {
            model.add_task(id, 100, vec![0]);
            assert_eq!(
                model.enqueue(id, 0, true, false, false, false, false),
                Position::Head
            );
        }
        /* The most recent head insert runs first. */
        assert_eq!(model.rank(0, 7), Some(0));
        assert_eq!(model.rank(0, 1), Some(6));

        model.add_task(8, 100, vec![0]);
        assert_eq!(
            model.enqueue(8, 0, false, false, false, false, false),
            Position::Tail
        );
        assert_eq!(model.rank(0, 8), Some(7));
        assert_eq!(model.drain(0), vec![7, 6, 5, 4, 3, 2, 1, 8]);
        assert_eq!(model.w_sum[0], 0);
    }

    fn gate_ratio<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        for id in 0..8_000 {
            model.add_task(id, 100, vec![0]);
            model.enqueue(id, 0, false, false, false, false, false);
        }
        assert_eq!(model.stats.head_inserts, 7_000);
        assert_eq!(model.stats.tail_inserts, 1_000);
        assert_eq!(model.seq[0], 8_000);
    }

    fn exact_removal<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        for id in 1..=4 {
            model.add_task(id, 100, vec![0]);
            model.enqueue(id, 0, true, false, false, false, false);
        }
        assert_eq!(model.rank(0, 2), Some(2));
        let removed = model.remove(0, 2).expect("queued");
        assert_eq!(removed.id, 2);
        assert_eq!(model.rank(0, 2), None);
        assert_eq!(model.w_sum[0], 300);
        assert_eq!(model.drain(0), vec![4, 3, 1]);
        assert_eq!(model.w_sum[0], 0);
    }

    fn yield_to<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        for id in 1..=4 {
            model.add_task(id, 100, vec![0]);
            model.enqueue(id, 0, true, false, false, false, false);
        }
        let seq = model.seq[0];
        assert_eq!(model.rank(0, 1), Some(3));

        assert!(model.yield_to(4, 1));
        assert_eq!(model.rank(0, 1), Some(0));
        /* The gate did not advance and the weight is unchanged. */
        assert_eq!(model.seq[0], seq);
        assert_eq!(model.w_sum[0], 400);
        assert_eq!(model.stats.yield_to_moves, 1);

        /* An unqueued target is refused. */
        model.add_task(9, 100, vec![0]);
        assert!(!model.yield_to(1, 9));
        /* A running or exiting target is refused. */
        model.tasks.get_mut(&2).unwrap().state = TaskState::Running;
        assert!(!model.yield_to(1, 2));
        model.tasks.get_mut(&2).unwrap().state = TaskState::Queued;
        model.tasks.get_mut(&2).unwrap().exiting = true;
        assert!(!model.yield_to(1, 2));
    }

    fn reweight<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        for id in 1..=3 {
            model.add_task(id, 100, vec![0]);
            model.enqueue(id, 0, true, false, false, false, false);
        }
        let seq = model.seq[0];

        /* One gate slot, and a head slot at seq 3. */
        assert!(model.reweight(1, 400));
        assert_eq!(model.seq[0], seq + 1);
        assert_eq!(model.stats.reweight_moves, 1);
        assert_eq!(model.rank(0, 1), Some(0));
        assert_eq!(model.w_sum[0], 600);

        /* At seq 7 the reinsert takes the tail slot. */
        let mut model = one_cpu::<Q>();
        for id in 1..=7 {
            model.add_task(id, 100, vec![0]);
            model.enqueue(id, 0, true, false, false, false, false);
        }
        assert_eq!(model.seq[0], 7);
        assert!(model.reweight(1, 400));
        assert_eq!(model.seq[0], 8);
        assert_eq!(model.rank(0, 1), Some(6));
        assert_eq!(model.w_sum[0], 1_000);
    }

    fn peer_steal<Q: IntrusiveQueue + Default>() {
        let mut model: Model<Q> = Model::new(6);
        /* Node 0: CPUs 0,1 in LLC 0 and CPUs 2,3 in LLC 1.
         * Node 1: CPUs 4,5 in LLC 2. */
        for (cpu, (llc, node)) in [(0, 0), (0, 0), (1, 0), (1, 0), (2, 1), (2, 1)]
            .into_iter()
            .enumerate()
        {
            model.set_topo(cpu, llc, node);
        }

        model.add_task(10, 100, vec![0]);
        model.enqueue(10, 2, true, false, false, false, false);
        model.add_task(11, 100, vec![0]);
        model.enqueue(11, 1, true, false, false, false, false);

        /* Same LLC wins over the same-node peer. */
        assert_eq!(model.steal(0, StealTier::Llc), Some(11));
        assert_eq!(model.stats.steal_llc, 1);
        assert_eq!(model.steal(0, StealTier::Llc), None);
        /* The node tier excludes the local LLC and finds CPU 2. */
        assert_eq!(model.steal(0, StealTier::Node), Some(10));
        assert_eq!(model.stats.steal_node, 1);
        assert_eq!(model.w_sum[0], 200);

        /* An affinity-limited head is skipped, not bypassed. */
        let mut model: Model<Q> = Model::new(2);
        model.set_topo(1, 0, 0);
        model.add_task(20, 100, vec![1]);
        model.enqueue(20, 1, true, false, false, false, false);
        assert_eq!(model.steal(0, StealTier::Llc), None);

        /* At most eight peers are examined; the cursor rotates. */
        let mut model: Model<Q> = Model::new(12);
        for cpu in 0..12 {
            model.set_topo(cpu, 0, 0);
        }
        model.add_task(30, 100, vec![0]);
        model.enqueue(30, 9, true, false, false, false, false);
        assert_eq!(model.steal(0, StealTier::Llc), None);
        assert_eq!(model.cursor_llc[0], 9);
        assert_eq!(model.steal(0, StealTier::Llc), Some(30));
    }

    fn stale_pop<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        model.add_task(1, 100, vec![0]);
        model.enqueue(1, 0, true, false, false, false, false);
        model.add_task(2, 100, vec![0]);
        model.enqueue(2, 0, true, false, false, false, false);

        /* The task behind the node exits and its context is gone. */
        model.abandon(2);
        let first = model.pop(0, true).expect("stale node");
        assert!(first.stale);
        assert_eq!(first.id, 2);
        assert_eq!(model.stats.stale_pops, 1);
        assert_eq!(model.w_sum[0], 100);

        /* The remaining task is not lost. */
        let second = model.pop(0, true).expect("live node");
        assert!(!second.stale);
        assert_eq!(second.id, 1);
        assert!(model.queues[0].is_empty());
    }

    fn task_lifetime<Q: IntrusiveQueue + Default>() {
        let mut model = one_cpu::<Q>();
        model.add_task(1, 100, vec![0]);
        model.enqueue(1, 0, true, false, false, false, false);

        let pop = model.pop(0, true).expect("queued");
        assert_eq!(pop.id, 1);
        assert_eq!(model.tasks[&1].holdcnt, 1);

        /* Exit cannot free a context that a pop still holds. */
        assert!(!model.exit_task(1));
        assert_eq!(model.tasks[&1].state, TaskState::Exiting);
        assert!(model.drop_hold(1));
        model.release(1);
        assert!(!model.tasks.contains_key(&1));
    }

    macro_rules! both_queues {
        ($name:ident, $body:ident) => {
            #[test]
            fn $name() {
                $body::<EdqModel>();
                $body::<ListModel>();
            }
        };
    }

    both_queues!(both_queues_keep_bounded_lifo_order, ordering);
    both_queues!(both_queues_keep_the_seven_to_one_gate, gate_ratio);
    both_queues!(both_queues_remove_an_exact_node, exact_removal);
    both_queues!(both_queues_move_a_yield_to_target, yield_to);
    both_queues!(both_queues_reinsert_a_reweight, reweight);
    both_queues!(both_queues_steal_from_peers, peer_steal);
    both_queues!(both_queues_drop_a_stale_pop, stale_pop);
    both_queues!(both_queues_hold_a_task_across_exit, task_lifetime);
}

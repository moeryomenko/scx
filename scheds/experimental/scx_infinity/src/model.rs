// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Pure queue model for the tests.
//!
//! The BPF core keeps one vtime-ordered DSQ per CPU. A head insert takes a
//! key below `INF_KEY_MID`, a tail insert a key above it, and the core pops
//! the lowest key. `VecDeque` reproduces the same order: head inserts go to
//! the front, tail inserts to the back, and dispatch pops the front. This
//! module checks queue progress, weight accounting and slice expiry without
//! a kernel. It builds only for tests.
#![allow(dead_code)]

use std::collections::VecDeque;

use crate::policy::gate_tail;

/// Where an enqueue puts the task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    Head,
    Tail,
}

/// Replica of the enqueue decision in `inf_enqueue_common()`.
///
/// The order is the same as the BPF core: a core head hint wins, an expiry
/// or a requeue rotates to the tail, and every other arrival, including a
/// wakeup, passes the 7:1 gate.
pub fn classify_enqueue(
    slice: u64,
    wake: bool,
    head_flag: bool,
    reenq: bool,
    last: bool,
    preempt: bool,
    seq: u32,
) -> Insert {
    let expired = slice == 0 && !wake && !head_flag;

    if head_flag {
        Insert::Head
    } else if expired || reenq || last || preempt {
        Insert::Tail
    } else if gate_tail(seq) {
        Insert::Tail
    } else {
        Insert::Head
    }
}

#[derive(Clone, Copy, Debug)]
struct Item {
    id: u64,
    weight: u64,
}

/// A single per-CPU queue with the weight counters of `struct inf_cpu_ctx`.
#[derive(Debug, Default)]
pub struct QueueModel {
    items: VecDeque<Item>,
    pub head_inserts: u64,
    pub tail_inserts: u64,
    pub exempt_inserts: u64,
    pub expiries: u64,
    /// Signed so a test can detect an accounting underflow.
    pub w_sum: i64,
    pub seq: u32,
}

impl QueueModel {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, id: u64, weight: u64, insert: Insert, exempt: bool) {
        let item = Item { id, weight };

        match insert {
            Insert::Head => self.items.push_front(item),
            Insert::Tail => self.items.push_back(item),
        }
        self.w_sum += weight as i64;
        if exempt {
            self.exempt_inserts += 1;
        } else if insert == Insert::Head {
            self.head_inserts += 1;
        } else {
            self.tail_inserts += 1;
        }
    }

    /// A gated arrival. The sequence advances only on this path, as in the
    /// BPF core.
    pub fn enqueue_regular(&mut self, id: u64, weight: u64) -> Insert {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let insert = classify_enqueue(1, false, false, false, false, false, seq);
        self.push(id, weight, insert, false);
        insert
    }

    /// A wakeup. It is not exempt: it advances the gate sequence and can
    /// take either the head or the tail slot. A zero slice does not turn a
    /// wakeup into an expiry.
    pub fn enqueue_wakeup(&mut self, id: u64, weight: u64) -> Insert {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let insert = classify_enqueue(0, true, false, false, false, false, seq);
        self.push(id, weight, insert, false);
        insert
    }

    /// An expiry, a requeue or a yield hand-back, which is exempt and takes
    /// the tail.
    pub fn enqueue_expired(&mut self, id: u64, weight: u64) {
        self.expiries += 1;
        self.push(id, weight, Insert::Tail, true);
    }

    /// Remove a queued task and reinsert it at the tail, as slice expiry
    /// does through `ops.enqueue()` with a zero slice.
    pub fn rotate_to_tail(&mut self, id: u64) -> bool {
        let Some(index) = self.items.iter().position(|item| item.id == id) else {
            return false;
        };
        let item = self.items.remove(index).unwrap();
        self.w_sum -= item.weight as i64;
        self.expiries += 1;
        self.push(id, item.weight, Insert::Tail, true);
        true
    }

    /// Replace the weight of a queued task, as `ops.set_weight()` does.
    pub fn set_weight(&mut self, id: u64, weight: u64) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return false;
        };
        self.w_sum += weight as i64 - item.weight as i64;
        item.weight = weight;
        true
    }

    /// Pop the queue head, as `ops.dispatch()` does.
    pub fn pop(&mut self) -> Option<(u64, u64)> {
        let item = self.items.pop_front()?;
        self.w_sum -= item.weight as i64;
        Some((item.id, item.weight))
    }

    /// Position from the head. Zero is the next task to run.
    pub fn rank(&self, id: u64) -> Option<usize> {
        self.items.iter().position(|item| item.id == id)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn drain(&mut self) -> Vec<u64> {
        let mut order = Vec::with_capacity(self.items.len());
        while let Some((id, _)) = self.pop() {
            order.push(id);
        }
        order
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::policy;

    #[test]
    fn normal_enqueues_keep_the_seven_to_one_ratio() {
        let mut queue = QueueModel::new();

        for id in 0..8_000 {
            queue.enqueue_regular(id, 100);
        }

        assert_eq!(queue.head_inserts, 7_000);
        assert_eq!(queue.tail_inserts, 1_000);
        assert_eq!(queue.head_inserts / queue.tail_inserts, 7);
    }

    #[test]
    fn a_queued_task_moves_ahead_only_on_head_inserts() {
        let mut queue = QueueModel::new();
        queue.enqueue_regular(0, 100);
        let start = queue.rank(0).unwrap();

        let mut head_inserts = 0u64;
        for id in 1..=800 {
            if queue.enqueue_regular(id, 100) == Insert::Head {
                head_inserts += 1;
            }
        }

        assert_eq!(queue.rank(0), Some(start + head_inserts as usize));
        assert_eq!(queue.head_inserts - 1, head_inserts);

        queue.pop().unwrap();
        assert_eq!(queue.rank(0), Some(start + head_inserts as usize - 1));
    }

    #[test]
    fn a_stopped_queue_drains_every_task_exactly_once() {
        let mut queue = QueueModel::new();
        let mut expected = BTreeSet::new();

        for id in 0..256 {
            let weight = 100 + u64::from((id % 7) as u32);
            if id % 3 == 0 {
                queue.enqueue_wakeup(id, weight);
            } else {
                queue.enqueue_regular(id, weight);
            }
            expected.insert(id);
        }

        let order = queue.drain();
        let actual: BTreeSet<u64> = order.iter().copied().collect();

        assert_eq!(actual, expected);
        assert_eq!(order.len(), expected.len());
        assert!(queue.is_empty());
        assert_eq!(queue.w_sum, 0);
    }

    #[test]
    fn tail_insertions_drain_in_fifo_order() {
        let mut queue = QueueModel::new();

        for id in 0..5 {
            queue.enqueue_expired(id, 100);
        }

        assert_eq!(queue.drain(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn slice_expiry_rotates_a_task_to_the_tail() {
        let mut queue = QueueModel::new();
        queue.enqueue_wakeup(1, 100);
        queue.enqueue_wakeup(2, 100);
        assert_eq!(queue.rank(1), Some(1));

        assert!(queue.rotate_to_tail(1));
        assert_eq!(queue.expiries, 1);
        assert_eq!(queue.rank(1), Some(1));
        assert_eq!(queue.drain(), vec![2, 1]);
    }

    #[test]
    fn a_lone_task_is_dispatched_again_after_each_quantum() {
        let mut queue = QueueModel::new();
        queue.enqueue_wakeup(7, 100);

        for _ in 0..3 {
            assert_eq!(queue.pop(), Some((7, 100)));
            assert!(queue.is_empty());
            queue.enqueue_expired(7, 100);
            assert_eq!(queue.len(), 1);
        }

        assert_eq!(queue.w_sum, 100);
    }

    #[test]
    fn a_wakeup_that_the_gate_places_on_the_head_is_not_exempt() {
        let mut queue = QueueModel::new();

        assert_eq!(queue.enqueue_wakeup(1, 100), Insert::Head);
        assert_eq!(queue.head_inserts, 1);
        assert_eq!(queue.tail_inserts, 0);
        assert_eq!(queue.exempt_inserts, 0);
        assert_eq!(queue.seq, 1);
        assert_eq!(queue.rank(1), Some(0));
    }

    #[test]
    fn a_wakeup_that_the_gate_places_on_the_tail_runs_last() {
        let mut queue = QueueModel::new();

        for id in 0..7 {
            assert_eq!(queue.enqueue_regular(id, 100), Insert::Head);
        }
        assert_eq!(queue.enqueue_wakeup(7, 100), Insert::Tail);

        assert_eq!(queue.head_inserts, 7);
        assert_eq!(queue.tail_inserts, 1);
        assert_eq!(queue.exempt_inserts, 0);
        assert_eq!(queue.rank(7), Some(7));
        assert_eq!(queue.pop(), Some((6, 100)));
    }

    #[test]
    fn only_the_head_hint_and_expiry_bypass_the_gate() {
        assert_eq!(
            classify_enqueue(0, true, false, false, false, false, 0),
            Insert::Head
        );
        assert_eq!(
            classify_enqueue(0, false, false, false, false, false, 0),
            Insert::Tail
        );
        assert_eq!(
            classify_enqueue(0, false, true, false, false, false, 7),
            Insert::Head
        );
    }

    #[test]
    fn weight_sum_tracks_join_leave_and_reweight() {
        let mut queue = QueueModel::new();

        queue.enqueue_regular(1, 100);
        queue.enqueue_regular(2, 200);
        assert_eq!(queue.w_sum, 300);

        assert!(queue.set_weight(1, 400));
        assert_eq!(queue.w_sum, 600);

        assert_eq!(queue.pop(), Some((2, 200)));
        assert_eq!(queue.w_sum, 400);

        assert_eq!(queue.pop(), Some((1, 400)));
        assert_eq!(queue.w_sum, 0);
        assert!(queue.pop().is_none());
        assert_eq!(queue.w_sum, 0);
    }

    #[test]
    fn repeated_expiry_does_not_double_count_the_weight() {
        let mut queue = QueueModel::new();
        queue.enqueue_wakeup(9, 50);

        for _ in 0..16 {
            assert!(queue.rotate_to_tail(9));
            assert_eq!(queue.len(), 1);
            assert_eq!(queue.w_sum, 50);
        }
    }

    #[test]
    fn the_queue_weight_is_the_quantum_normalizer() {
        let mut queue = QueueModel::new();
        queue.enqueue_regular(1, 100);
        queue.enqueue_regular(2, 100);

        let half = policy::quantum_ns(policy::QUANTUM_DEFAULT_NS, 100, queue.w_sum as u64);
        assert_eq!(half, policy::QUANTUM_DEFAULT_NS / 2);

        queue.enqueue_regular(3, 200);
        let third = policy::quantum_ns(policy::QUANTUM_DEFAULT_NS, 100, queue.w_sum as u64);
        assert_eq!(third, policy::QUANTUM_DEFAULT_NS / 4);

        queue.pop().unwrap();
        queue.set_weight(3, 100);
        assert_eq!(queue.w_sum, 200);
    }
}

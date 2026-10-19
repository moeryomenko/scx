// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Pure model of the shared cgroup weight accounting.
//!
//! Mirrors `lib/cgroup_weight.bpf.c` and the hooks in
//! `src/bpf/main.bpf.c`. The BPF program is the implementation; this model
//! pins the lifecycle and the folded weights that the hooks must produce, so
//! a regression fails in `cargo test` before it reaches a kernel.
#![allow(dead_code)]

use std::collections::BTreeMap;

/// Fixed-point bits of the folded shares/load product.
pub const WEIGHT_SHIFT: u32 = 10;
/// Fixed-point one for [`WEIGHT_SHIFT`].
pub const WEIGHT_ONE: u64 = 1 << WEIGHT_SHIFT;
/// `SCHED_IDLE` weight of a task under a `cpu.idle` cgroup.
pub const IDLE_WEIGHT: u64 = 3;
/// Weight cap mirrored by the BPF core.
pub const WEIGHT_CAP: u64 = 1 << 32;
/// Product cap that keeps the BPF multiplication inside 64 bits.
const PRODUCT_CAP: u64 = 1 << 20;

/// Per-(cgroup, CPU) accounting state.
#[derive(Clone, Copy, Debug, Default)]
pub struct Group {
    pub shares: u64,
    pub idle: bool,
    pub load: u64,
    pub nr: u64,
    pub contrib: u64,
}

/// Result of folding one task's cgroup path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fold {
    pub weight: u64,
    pub scale: u64,
    pub idle: bool,
}

/// A one-CPU mirror of the shared library.
#[derive(Default)]
pub struct Tree {
    groups: BTreeMap<u64, Group>,
    parents: BTreeMap<u64, u64>,
    epoch: u64,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_group(&mut self, id: u64, parent: Option<u64>, shares: u64) {
        self.groups.insert(
            id,
            Group {
                shares: shares.max(1),
                ..Group::default()
            },
        );
        if let Some(parent) = parent {
            self.parents.insert(id, parent);
        }
        self.epoch += 1;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn group(&self, id: u64) -> Option<&Group> {
        self.groups.get(&id)
    }

    /// `cpu.weight` changed. The new shares move the group's contribution to
    /// its parent immediately, before any task refolds.
    pub fn set_weight(&mut self, id: u64, shares: u64) {
        if let Some(g) = self.groups.get_mut(&id) {
            g.shares = shares.max(1);
        }
        self.contrib_sync(id);
        self.epoch += 1;
    }

    /// `cpu.idle` changed. The shares and the contribution do not move; only
    /// the members' effective weight changes, at their next fold.
    pub fn set_idle(&mut self, id: u64, idle: bool) {
        if let Some(g) = self.groups.get_mut(&id) {
            g.idle = idle;
        }
        self.epoch += 1;
    }

    /// Fold the path from the task's own group up to the root. `path` is in
    /// that order, which is the order `scw_fold()` walks.
    pub fn fold(&self, path: &[u64], base: u64, joining: bool) -> Fold {
        let base = base.max(1);
        let mut product = WEIGHT_ONE;
        let mut add = if joining { base } else { 0 };
        let mut idle = false;

        for id in path {
            let Some(g) = self.groups.get(id) else {
                continue;
            };
            if g.idle {
                idle = true;
            }
            let shares = g.shares.max(1);
            /* An empty level uses its shares, so it does not scale. */
            let total = g.load + add;
            let total = if total == 0 { shares } else { total };
            product = product.min(PRODUCT_CAP);
            product = product * shares / total;
            add = if joining && g.contrib == 0 { shares } else { 0 };
        }

        let scale = product.max(1);
        let mut weight = if idle {
            IDLE_WEIGHT
        } else {
            (base * scale + WEIGHT_ONE / 2) >> WEIGHT_SHIFT
        };
        weight = weight.clamp(1, WEIGHT_CAP);

        Fold {
            weight,
            scale,
            idle,
        }
    }

    /// First enqueue of a runnable period: count the task in its own group
    /// and in every present ancestor.
    pub fn join(&mut self, path: &[u64], base: u64) {
        let base = base.max(1);
        for id in path {
            if let Some(g) = self.groups.get_mut(id) {
                g.nr += 1;
            }
        }
        if let Some(leaf) = path.first() {
            if let Some(g) = self.groups.get_mut(leaf) {
                g.load += base;
            }
            self.contrib_sync(*leaf);
        }
    }

    /// The runnable period ended: reverse the join, count first, then load.
    pub fn leave(&mut self, path: &[u64], base: u64) {
        let base = base.max(1);
        for id in path {
            if let Some(g) = self.groups.get_mut(id) {
                g.nr = g.nr.saturating_sub(1);
            }
        }
        if let Some(leaf) = path.first() {
            if let Some(g) = self.groups.get_mut(leaf) {
                g.load = g.load.saturating_sub(base);
            }
            self.contrib_sync(*leaf);
        }
    }

    /// A nice-weight change moves only the task's own contribution.
    pub fn reweight(&mut self, path: &[u64], old: u64, new: u64) {
        if old == new {
            return;
        }
        if let Some(leaf) = path.first() {
            if let Some(g) = self.groups.get_mut(leaf) {
                let load = g.load as i64 + new as i64 - old as i64;
                g.load = load.max(0) as u64;
            }
            self.contrib_sync(*leaf);
        }
    }

    /// Bring each group's contribution in line with its count, then move the
    /// delta into its parent's load.
    fn contrib_sync(&mut self, id: u64) {
        let mut cur = Some(id);
        while let Some(cgid) = cur {
            let Some(g) = self.groups.get(&cgid).copied() else {
                break;
            };
            let target = if g.nr > 0 { g.shares } else { 0 };
            if target != g.contrib {
                if let Some(g) = self.groups.get_mut(&cgid) {
                    g.contrib = target;
                }
                if let Some(parent) = self.parents.get(&cgid).copied() {
                    if let Some(p) = self.groups.get_mut(&parent) {
                        let load = p.load as i64 + target as i64 - g.contrib as i64;
                        p.load = load.max(0) as u64;
                    }
                }
            }
            cur = self.parents.get(&cgid).copied();
        }
    }
}

/// The dequeue flag classes this kernel delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dequeue {
    /// `SCX_DEQ_SLEEP`.
    Sleep,
    /// `SCX_DEQ_SCHED_CHANGE`.
    SchedChange,
    /// `SCX_DEQ_CORE_SCHED_EXEC`.
    CoreSchedExec,
    /// A custody transfer with no flag, delivered with `deq_flags == 0`.
    Custody,
}

impl Dequeue {
    /// Only a sleep or a property change ends the runnable period.
    pub fn ends_runnable(self) -> bool {
        matches!(self, Dequeue::Sleep | Dequeue::SchedChange)
    }
}

/// A task's folded state across its runnable period.
#[derive(Clone, Debug)]
pub struct Task {
    pub path: Vec<u64>,
    pub base: u64,
    pub weight: u64,
    pub idle: bool,
    pub epoch: u64,
    pub joined: bool,
}

impl Task {
    pub fn new(path: Vec<u64>, base: u64) -> Self {
        Self {
            path,
            base,
            weight: base,
            idle: false,
            epoch: 0,
            joined: false,
        }
    }

    fn refold(&mut self, tree: &Tree, joining: bool) {
        let epoch = tree.epoch();
        let fold = tree.fold(&self.path, self.base, joining);
        self.weight = fold.weight;
        self.idle = fold.idle;
        self.epoch = epoch;
    }

    /// `ops.enqueue()`: join on the first enqueue, refold a joined task
    /// whose stored epoch is stale.
    pub fn enqueue(&mut self, tree: &mut Tree) {
        if !self.joined {
            self.refold(tree, true);
            tree.join(&self.path, self.base);
            self.joined = true;
        } else if self.epoch != tree.epoch() {
            self.refold(tree, false);
        }
    }

    /// `ops.dispatch()`: refold a stale task before its slice is computed.
    pub fn dispatch(&mut self, tree: &Tree) {
        if self.joined && self.epoch != tree.epoch() {
            self.refold(tree, false);
        }
    }

    /// `ops.dequeue()`.
    pub fn dequeue(&mut self, tree: &mut Tree, kind: Dequeue) {
        if kind.ends_runnable() && self.joined {
            tree.leave(&self.path, self.base);
            self.joined = false;
        }
    }

    /// `ops.exit_task()`: a leave happens once even if a dequeue already
    /// ended the runnable period.
    pub fn exit(&mut self, tree: &mut Tree) {
        if self.joined {
            tree.leave(&self.path, self.base);
            self.joined = false;
        }
    }

    /// `ops.set_weight()` with a nice-weight change.
    pub fn set_base(&mut self, tree: &mut Tree, base: u64) {
        let old = self.base;
        self.base = base;
        if self.joined {
            tree.reweight(&self.path, old, base);
            if self.epoch != tree.epoch() {
                self.refold(tree, false);
            } else {
                let fold = tree.fold(&self.path, base, false);
                self.weight = fold.weight;
                self.idle = fold.idle;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_flat_groups() -> Tree {
        let mut tree = Tree::new();
        /* Kernel scale: cpu.weight 100 maps to shares 1024, 200 to 2048. */
        tree.add_group(1, None, 1024);
        tree.add_group(2, None, 2048);
        tree
    }

    #[test]
    fn a_live_weight_change_refolds_at_the_next_enqueue_or_dispatch() {
        let mut tree = two_flat_groups();
        let mut a = Task::new(vec![1], 1024);
        let mut b = Task::new(vec![2], 1024);
        a.enqueue(&mut tree);
        b.enqueue(&mut tree);
        assert_eq!(b.weight, 2048);

        /* Start equal, then raise group 2 to 2048 at run time. */
        tree.set_weight(2, 1024);
        assert_eq!(b.weight, 2048, "a running task keeps its slice weight");

        b.dispatch(&tree);
        assert_eq!(b.weight, 1024, "the next dispatch folds the new shares");

        tree.set_weight(2, 2048);
        b.enqueue(&mut tree);
        assert_eq!(b.weight, 2048, "the next enqueue folds the new shares");
    }

    #[test]
    fn a_live_idle_change_toggles_the_effective_weight() {
        let mut tree = two_flat_groups();
        let mut b = Task::new(vec![2], 1024);
        b.enqueue(&mut tree);
        assert_eq!(b.weight, 2048);

        tree.set_idle(2, true);
        assert_eq!(b.weight, 2048, "no fold happens before the next hook");
        b.dispatch(&tree);
        assert_eq!(b.weight, IDLE_WEIGHT);

        tree.set_idle(2, false);
        b.dispatch(&tree);
        assert_eq!(b.weight, 2048, "idle off returns to the cpu.weight share");
    }

    #[test]
    fn a_parent_contribution_follows_a_child_weight_change() {
        let mut tree = Tree::new();
        tree.add_group(1, None, 2048); /* parent */
        tree.add_group(2, Some(1), 1024); /* child */
        let mut task = Task::new(vec![2, 1], 1024);
        task.enqueue(&mut tree);

        assert_eq!(tree.group(2).unwrap().contrib, 1024);
        assert_eq!(tree.group(1).unwrap().load, 1024);

        /* The child's shares double, so its contribution must double. */
        tree.set_weight(2, 2048);
        assert_eq!(tree.group(2).unwrap().contrib, 2048);
        assert_eq!(tree.group(1).unwrap().load, 2048);

        task.dispatch(&tree);
        assert_eq!(task.weight, 2048);
    }

    #[test]
    fn an_empty_level_does_not_scale_the_task() {
        let mut tree = Tree::new();
        tree.add_group(1, None, 1024);
        let fold = tree.fold(&[1], 100, false);
        assert_eq!(fold.weight, 100);
        assert_eq!(fold.scale, WEIGHT_ONE);
    }

    #[test]
    fn a_base_weight_change_keeps_the_group_load_in_step() {
        let mut tree = Tree::new();
        tree.add_group(1, None, 1024);
        let mut task = Task::new(vec![1], 1024);
        task.enqueue(&mut tree);
        assert_eq!(tree.group(1).unwrap().load, 1024);

        task.set_base(&mut tree, 512);
        assert_eq!(tree.group(1).unwrap().load, 512);
        /* The group share, not the raw base, is the contention weight. */
        assert_eq!(task.weight, 1024);
    }
}

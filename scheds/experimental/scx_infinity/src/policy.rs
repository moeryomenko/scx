// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Arithmetic shared with the BPF core.
//!
//! The BPF program in `src/bpf/main.bpf.c` mirrors these formulas. Keeping
//! them here lets `cargo test` cover the boundary cases without a kernel.
#![allow(dead_code)]

/// Infinity base quantum, 1 ms.
pub const QUANTUM_DEFAULT_NS: u64 = 1_000_000;
/// Lowest accepted quantum, 100 us.
pub const QUANTUM_MIN_NS: u64 = 100_000;
/// Highest accepted quantum, 4 ms.
pub const QUANTUM_MAX_NS: u64 = 4_000_000;

/// Default preemption margin, 100 us.
pub const PREEMPT_MARGIN_DEFAULT_NS: u64 = 100_000;
/// Highest accepted preemption margin, 1 ms.
pub const PREEMPT_MARGIN_MAX_NS: u64 = 1_000_000;

/// Slice floor for a task far below the queue weight, 100 us.
pub const QUANTUM_FLOOR_NS: u64 = 100_000;

/// One tail insert in every eight regular enqueues.
pub const GATE_MASK: u32 = 7;
/// Weight cap mirrored by the BPF core.
pub const WEIGHT_CAP: u64 = 1 << 32;

/// Convert a microsecond startup setting to nanoseconds and enforce the
/// supported range.
pub fn quantum_us_to_ns(us: u64) -> Result<u64, String> {
    let ns = us
        .checked_mul(1000)
        .ok_or_else(|| format!("quantum {us} us overflows nanoseconds"))?;

    if !(QUANTUM_MIN_NS..=QUANTUM_MAX_NS).contains(&ns) {
        return Err(format!(
            "quantum must be between {} us and {} us",
            QUANTUM_MIN_NS / 1000,
            QUANTUM_MAX_NS / 1000
        ));
    }
    Ok(ns)
}

/// Weighted quantum:
///
/// ```text
/// q = max(base * weight / total, floor)
/// ```
///
/// `total` includes the task itself. A zero weight is the lightest task
/// and a zero total means the task is alone. Weights cap at `WEIGHT_CAP`,
/// which keeps the BPF product inside 64 bits.
///
/// A task whose weight is below one tenth of the queue weight gets at
/// least `QUANTUM_FLOOR_NS` (100 us), so a very light task cannot build a
/// sub-microsecond slice and a reschedule storm. The floor never exceeds
/// the base quantum.
pub fn quantum_ns(base: u64, weight: u64, total: u64) -> u64 {
    let weight = weight.clamp(1, WEIGHT_CAP);
    let total = total.max(weight);

    if base == 0 {
        return 1;
    }
    let mut q = (u128::from(base) * u128::from(weight) / u128::from(total))
        .min(u128::from(u64::MAX)) as u64;
    if weight.saturating_mul(10) < total {
        q = q.max(QUANTUM_FLOOR_NS.min(base));
    }
    q.max(1)
}

/// True when a regular enqueue takes the tail slot instead of the head.
///
/// The kernel sequence wraps at `u32::MAX`, so that value is a tail slot
/// as well. Any other eighth value is a tail slot.
pub fn gate_tail(seq: u32) -> bool {
    seq == u32::MAX || (seq & GATE_MASK) == GATE_MASK
}

/// Fixed-point scale of the folded cgroup hierarchy.
pub const CGROUP_WEIGHT_SHIFT: u32 = 10;
/// Fixed-point one for [`CGROUP_WEIGHT_SHIFT`].
pub const CGROUP_WEIGHT_ONE: u64 = 1 << CGROUP_WEIGHT_SHIFT;
/// SCHED_IDLE weight of a task under a `cpu.idle` cgroup.
pub const CGROUP_WEIGHT_IDLE: u64 = 3;

/// Fold one `shares / load` level into a fixed-point product.
///
/// Mirrors the BPF `scw_fold()` step. `levels` runs from the task's own
/// group up to the root, and each entry is the group's `cpu.weight` as
/// `shares` and its load on the CPU as `load`.
pub fn hierarchy_scale(levels: &[(u64, u64)]) -> u64 {
    let mut product = u128::from(CGROUP_WEIGHT_ONE);

    for &(shares, load) in levels {
        let shares = shares.max(1);
        /* Mirrors the BPF library: an empty groupload uses its shares,
         * so the level does not scale the task. */
        let load = if load == 0 { shares } else { load };
        /* Mirrors the BPF cap that keeps the product inside 64 bits. */
        product = product.min(1u128 << 20);
        product = product * u128::from(shares) / u128::from(load);
    }

    (product as u64).max(1)
}

/// Effective weight from the kernel task weight and the folded hierarchy.
///
/// A cgroup in `cpu.idle` mode at any level uses the SCHED_IDLE weight of 3
/// instead of the folded share.
pub fn effective_weight(base: u32, levels: &[(u64, u64)], idle: bool) -> u64 {
    if idle {
        return CGROUP_WEIGHT_IDLE;
    }
    let base = if base == 0 { 1 } else { u64::from(base) };
    let scale = hierarchy_scale(levels);
    ((base * scale + CGROUP_WEIGHT_ONE / 2) >> CGROUP_WEIGHT_SHIFT).max(1)
}

/// A fresh wakeup preempts only when the enqueue took a head slot and the
/// victim still retains more than the configured preemption margin.
///
/// The newcomer weight is not part of the decision, because the reference
/// Infinity 7.2.6-7 policy preempts on head arrival alone. A lighter
/// wakeup can therefore preempt a heavier victim.
pub fn should_preempt(head_slot: bool, victim_slice: u64, preempt_margin_ns: u64) -> bool {
    head_slot && victim_slice > preempt_margin_ns
}

/// Why a task left the BPF scheduler's custody. Mirrors the flags that
/// `ops.dequeue()` and `ops.quiescent()` receive from the core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeqReason {
    /// The core ran a task that was still queued. The task stays runnable.
    CoreSchedExec,
    /// The task is no longer runnable.
    Sleep,
    /// The task left for a property change or a class change.
    SchedChange,
    /// Any other custody transfer or dispatch pop.
    Other,
}

/// True when the reason ends a runnable period, so the group load drops.
///
/// Only a sleep or a property change ends the period. A core-scheduled
/// execution and a plain dispatch pop both leave a runnable task.
pub fn dequeue_ends_runnable(reason: DeqReason) -> bool {
    matches!(reason, DeqReason::Sleep | DeqReason::SchedChange)
}

/// One cgroup's account on one CPU. Mirrors the join, leave and fold of
/// `lib/cgroup_weight.bpf.c` so the transition matrix can be tested
/// without a kernel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GroupAccount {
    /// `cpu.weight` (shares) of the group.
    pub shares: u64,
    /// Sum of the joined member weights, including a running member.
    pub load: u64,
    /// Number of joined tasks in the group or below it.
    pub nr: u64,
    /// True while a task of this group is counted on this CPU.
    pub joined: bool,
}

impl GroupAccount {
    pub fn new(shares: u64) -> Self {
        Self {
            shares: shares.max(1),
            ..Default::default()
        }
    }

    /// Count a first enqueue of a runnable period. A repeat is a no-op.
    pub fn join(&mut self, base: u64) {
        if self.joined {
            return;
        }
        self.nr += 1;
        self.load += base;
        self.joined = true;
    }

    /// Drop a task at the end of a runnable period. A repeat is a no-op.
    pub fn leave(&mut self, base: u64) {
        if !self.joined {
            return;
        }
        self.nr = self.nr.saturating_sub(1);
        self.load = self.load.saturating_sub(base);
        self.joined = false;
    }

    /// Apply a dequeue or quiescent reason. Returns true when the load
    /// dropped.
    pub fn on_dequeue(&mut self, reason: DeqReason, base: u64) -> bool {
        if !dequeue_ends_runnable(reason) || !self.joined {
            return false;
        }
        self.leave(base);
        true
    }

    /// A cgroup move: leave this group and join @to.
    pub fn on_move(&mut self, base: u64, to: &mut GroupAccount) {
        self.leave(base);
        to.join(base);
    }

    /// A live `cpu.weight` change. A running task refolds at its next
    /// enqueue or dispatch, so the new share is visible immediately here.
    pub fn set_shares(&mut self, shares: u64) {
        self.shares = shares.max(1);
    }

    /// Effective weight of a member of this group on this CPU.
    pub fn effective_weight(&self, base: u64, idle: bool) -> u64 {
        effective_weight(base as u32, &[(self.shares.max(1), self.load)], idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_defaults_match_the_bpf_header() {
        assert_eq!(
            QUANTUM_DEFAULT_NS,
            crate::bpf_intf::INF_QUANTUM_DEFAULT_NS as u64
        );
        assert_eq!(QUANTUM_MIN_NS, crate::bpf_intf::INF_QUANTUM_MIN_NS as u64);
        assert_eq!(QUANTUM_MAX_NS, crate::bpf_intf::INF_QUANTUM_MAX_NS as u64);
        assert_eq!(GATE_MASK, crate::bpf_intf::INF_GATE_MASK);
        assert_eq!(WEIGHT_CAP, crate::bpf_intf::INF_WEIGHT_CAP as u64);
        assert_eq!(
            QUANTUM_FLOOR_NS,
            crate::bpf_intf::INF_QUANTUM_FLOOR_NS as u64
        );
        assert_eq!(
            PREEMPT_MARGIN_DEFAULT_NS,
            crate::bpf_intf::INF_PREEMPT_MARGIN_DEFAULT_NS as u64
        );
        assert_eq!(
            PREEMPT_MARGIN_MAX_NS,
            crate::bpf_intf::INF_PREEMPT_MARGIN_MAX_NS as u64
        );
    }

    #[test]
    fn startup_quantum_accepts_the_range_and_rejects_outside() {
        assert_eq!(quantum_us_to_ns(100).unwrap(), QUANTUM_MIN_NS);
        assert_eq!(quantum_us_to_ns(1000).unwrap(), QUANTUM_DEFAULT_NS);
        assert_eq!(quantum_us_to_ns(4000).unwrap(), QUANTUM_MAX_NS);
        assert!(quantum_us_to_ns(99).is_err());
        assert!(quantum_us_to_ns(4001).is_err());
        assert!(quantum_us_to_ns(u64::MAX).is_err());
    }

    #[test]
    fn quantum_is_the_base_for_a_zero_weight_and_a_zero_total() {
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 0, 0), QUANTUM_DEFAULT_NS);
        /* A zero weight becomes one, far below one tenth of the total. */
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 0, 1000), QUANTUM_FLOOR_NS);
    }

    #[test]
    fn quantum_splits_a_pair_of_equal_tasks_in_half() {
        assert_eq!(
            quantum_ns(QUANTUM_DEFAULT_NS, 100, 200),
            QUANTUM_DEFAULT_NS / 2
        );
        assert_eq!(
            quantum_ns(QUANTUM_DEFAULT_NS, 200, 300),
            QUANTUM_DEFAULT_NS * 2 / 3
        );
    }

    #[test]
    fn quantum_floor_holds_a_tiny_weight_at_one_hundred_microseconds() {
        assert_eq!(
            quantum_ns(QUANTUM_DEFAULT_NS, 1, u64::MAX),
            QUANTUM_FLOOR_NS
        );
        assert_eq!(
            quantum_ns(QUANTUM_DEFAULT_NS, 1, QUANTUM_DEFAULT_NS as u64),
            QUANTUM_FLOOR_NS
        );
    }

    #[test]
    fn quantum_floor_does_not_apply_at_one_tenth_of_the_queue_weight() {
        /* 100 / 1000 is exactly one tenth, so the proportional slice
         * stands. One unit below it takes the floor, one above keeps the
         * proportional slice. */
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 100, 1_000), QUANTUM_FLOOR_NS);
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 99, 1_000), QUANTUM_FLOOR_NS);
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 101, 1_000), 101_000);
    }

    #[test]
    fn quantum_saturates_instead_of_overflowing() {
        assert_eq!(quantum_ns(u64::MAX, u64::MAX, 1), u64::MAX);
        assert_eq!(quantum_ns(1, u64::MAX, u64::MAX), 1);
        assert_eq!(
            quantum_ns(QUANTUM_MAX_NS, WEIGHT_CAP, WEIGHT_CAP),
            QUANTUM_MAX_NS
        );
    }

    #[test]
    fn gate_takes_one_tail_in_every_eight_regular_enqueues() {
        let tails: Vec<u32> = (0..32).filter(|seq| gate_tail(*seq)).collect();
        assert_eq!(tails, vec![7, 15, 23, 31]);
        assert!(gate_tail(u32::MAX));

        let count = (0..8000).filter(|seq| gate_tail(*seq)).count();
        assert_eq!(count, 1000);
    }

    #[test]
    fn effective_weight_follows_the_cgroup_ratio() {
        /* Two equal members: one at shares 100, one at shares 200. */
        let a = effective_weight(1024, &[(100, 300)], false);
        let b = effective_weight(1024, &[(200, 300)], false);
        assert_eq!(a, 341);
        assert_eq!(b, 682);
        assert_eq!(a * 2, b);
    }

    #[test]
    fn nested_groups_multiply_their_shares() {
        /* 100/100 at the leaf and 200/100 at the parent: 2x in total. */
        let nested = effective_weight(1024, &[(100, 100), (200, 100)], false);
        let flat = effective_weight(1024, &[(200, 100)], false);
        assert_eq!(nested, flat);
        assert_eq!(nested, 2048);
    }

    #[test]
    fn an_empty_group_contributes_nothing_to_its_parent() {
        /* A child that is not in the parent's load does not scale it. */
        assert_eq!(hierarchy_scale(&[(100, 100)]), CGROUP_WEIGHT_ONE);
        assert_eq!(effective_weight(100, &[(100, 100)], false), 100);
    }

    #[test]
    fn rounding_is_stable_across_a_three_way_split() {
        let levels = [(100, 300)];
        let weights: Vec<u64> = (0..3)
            .map(|base| effective_weight(base * 100 + 100, &levels, false))
            .collect();
        assert_eq!(weights, vec![33, 67, 100]);
    }

    #[test]
    fn idle_cgroup_uses_the_sched_idle_weight() {
        assert_eq!(effective_weight(10000, &[(100, 100)], true), 3);
        assert_eq!(effective_weight(1, &[(10000, 3)], true), 3);
    }

    #[test]
    fn idle_at_any_level_overrides_every_weight_share() {
        /* Kernel cfs_rq_is_idle() applies at every level, so an idle
         * ancestor wins over a heavy leaf share. */
        let levels = [(10000, 1), (1, 10000), (5000, 5000)];
        assert_eq!(effective_weight(10000, &levels, true), CGROUP_WEIGHT_IDLE);
    }

    #[test]
    fn hierarchy_scale_is_the_product_of_the_levels() {
        /* 1/2 at the leaf and 1/4 at the parent give 1/8. */
        assert_eq!(hierarchy_scale(&[(100, 200), (100, 400)]), 128);
        assert_eq!(
            effective_weight(1024, &[(100, 200), (100, 400)], false),
            128
        );
    }

    #[test]
    fn a_zero_load_does_not_divide_by_zero() {
        assert_eq!(hierarchy_scale(&[(100, 0)]), CGROUP_WEIGHT_ONE);
        assert_eq!(effective_weight(1024, &[(100, 0)], false), 1024);
    }

    #[test]
    fn preemption_needs_a_head_slot_and_a_live_victim_slice() {
        let margin = PREEMPT_MARGIN_DEFAULT_NS;
        assert!(should_preempt(true, margin + 1, margin));
        /* The victim must strictly exceed the margin. */
        assert!(!should_preempt(true, margin, margin));
        assert!(!should_preempt(true, margin - 1, margin));
        assert!(should_preempt(true, 1, 0));
        /* A wakeup that the gate placed on the tail never preempts. */
        assert!(!should_preempt(false, QUANTUM_DEFAULT_NS, margin));
    }

    #[test]
    fn the_preemption_decision_ignores_the_newcomer_weight() {
        /* The reference Infinity 7.2.6-7 policy preempts on head arrival
         * alone, so a lighter wakeup preempts a heavier victim. The
         * helper has no weight input and one head-slot value decides the
         * outcome for every victim slice above the margin. This test pins
         * that the removed weight comparison has no path back into the
         * decision. */
        let margin = PREEMPT_MARGIN_DEFAULT_NS;

        for victim_slice in [margin + 1, QUANTUM_DEFAULT_NS, QUANTUM_MAX_NS] {
            assert!(should_preempt(true, victim_slice, margin));
        }
    }

    #[test]
    fn the_dequeue_matrix_keeps_a_running_task_and_drops_a_sleeper() {
        assert!(!dequeue_ends_runnable(DeqReason::CoreSchedExec));
        assert!(!dequeue_ends_runnable(DeqReason::Other));
        assert!(dequeue_ends_runnable(DeqReason::Sleep));
        assert!(dequeue_ends_runnable(DeqReason::SchedChange));
    }

    #[test]
    fn a_running_task_keeps_its_group_load() {
        let mut a = GroupAccount::new(100);

        a.join(100);
        assert_eq!(a.load, 100);
        assert_eq!(a.nr, 1);

        /* The core runs a still-queued task: the period continues. */
        assert!(!a.on_dequeue(DeqReason::CoreSchedExec, 100));
        /* A plain dispatch pop also continues the period. */
        assert!(!a.on_dequeue(DeqReason::Other, 100));

        assert_eq!(a.load, 100);
        assert_eq!(a.effective_weight(100, false), 100);
        assert_eq!(a.effective_weight(200, false), 200);
    }

    #[test]
    fn a_sleeper_drops_the_load_once_across_dequeue_and_quiescent() {
        let mut a = GroupAccount::new(100);

        a.join(100);
        assert!(a.on_dequeue(DeqReason::Sleep, 100));
        assert_eq!(a.load, 0);
        assert_eq!(a.nr, 0);

        /* A task the scheduler dispatched is seen by quiescent, not by
         * dequeue; the second drop is a no-op either way. */
        assert!(!a.on_dequeue(DeqReason::Sleep, 100));
        assert_eq!(a.load, 0);
    }

    #[test]
    fn a_property_change_drops_the_load_and_the_next_enqueue_rejoins() {
        let mut a = GroupAccount::new(100);

        a.join(100);
        assert!(a.on_dequeue(DeqReason::SchedChange, 100));
        assert_eq!(a.load, 0);

        a.join(100);
        assert_eq!(a.load, 100);
        assert_eq!(a.effective_weight(100, false), 100);
    }

    #[test]
    fn a_cgroup_move_transfers_the_load_between_groups() {
        let mut from = GroupAccount::new(100);
        let mut to = GroupAccount::new(200);

        from.join(100);
        assert_eq!(from.load, 100);
        assert_eq!(to.load, 0);

        from.on_move(100, &mut to);
        assert_eq!(from.load, 0);
        assert_eq!(from.nr, 0);
        assert_eq!(to.load, 100);
        assert_eq!(to.nr, 1);
        /* The moved task now folds against the destination shares. */
        assert_eq!(to.effective_weight(100, false), 200);
    }

    #[test]
    fn a_live_share_change_moves_the_effective_weight() {
        let mut a = GroupAccount::new(100);

        a.join(100);
        assert_eq!(a.effective_weight(100, false), 100);

        /* The share change is seen at the next fold. */
        a.set_shares(200);
        assert_eq!(a.effective_weight(100, false), 200);
        assert_eq!(a.effective_weight(50, false), 100);
    }

    #[test]
    fn two_pinned_groups_hold_the_weight_ratio() {
        let mut a = GroupAccount::new(100);
        let mut b = GroupAccount::new(200);

        a.join(100);
        b.join(200);

        let wa = a.effective_weight(100, false);
        let wb = b.effective_weight(200, false);
        assert_eq!(wa, 100);
        assert_eq!(wb, 200);
        assert_eq!(wb, 2 * wa);
    }

    #[test]
    fn an_idle_group_keeps_the_idle_weight_across_a_live_change() {
        let mut a = GroupAccount::new(100);

        a.join(100);
        assert_eq!(a.effective_weight(100, true), CGROUP_WEIGHT_IDLE);

        a.set_shares(2000);
        assert_eq!(a.effective_weight(100, true), CGROUP_WEIGHT_IDLE);
        assert_eq!(a.effective_weight(10000, true), CGROUP_WEIGHT_IDLE);
    }

    #[test]
    fn the_group_load_never_goes_negative() {
        let mut a = GroupAccount::new(100);

        /* A leave without a join is a no-op, not an underflow. */
        a.leave(100);
        assert_eq!(a.load, 0);
        assert_eq!(a.nr, 0);

        a.join(100);
        a.leave(100);
        a.leave(100);
        assert_eq!(a.load, 0);
        assert_eq!(a.nr, 0);
    }
}

// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Policy helpers shared with the BPF core.
//!
//! Revision 4 takes the service slot from the kernel tick, so this module
//! carries no quantum, no slice floor and no folded cgroup weight. One
//! `ops.tick` call is one service slot (specification sections 2.5 and 6.3).
//! The live policy is in `src/bpf/main.bpf.c`. Keeping the pure helpers here
//! lets `cargo test` cover them without a kernel.
#![allow(dead_code)]

/// Default preemption margin, 100 us.
pub const PREEMPT_MARGIN_DEFAULT_NS: u64 = 100_000;
/// Highest accepted preemption margin, 1 ms.
pub const PREEMPT_MARGIN_MAX_NS: u64 = 1_000_000;

/// One tail insert in every eight regular enqueues.
pub const GATE_MASK: u32 = 7;

/// True when a regular enqueue takes the tail slot instead of the head.
///
/// The kernel sequence wraps at `u32::MAX`, so that value is a tail slot
/// as well. Any other eighth value is a tail slot.
pub fn gate_tail(seq: u32) -> bool {
    seq == u32::MAX || (seq & GATE_MASK) == GATE_MASK
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn margin_and_gate_defaults_match_the_bpf_header() {
        assert_eq!(GATE_MASK, crate::bpf_intf::INF_GATE_MASK);
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
    fn gate_takes_one_tail_in_every_eight_regular_enqueues() {
        let tails: Vec<u32> = (0..32).filter(|seq| gate_tail(*seq)).collect();
        assert_eq!(tails, vec![7, 15, 23, 31]);
        assert!(gate_tail(u32::MAX));

        let count = (0..8000).filter(|seq| gate_tail(*seq)).count();
        assert_eq!(count, 1000);
    }

    #[test]
    fn the_dequeue_matrix_keeps_a_running_task_and_drops_a_sleeper() {
        assert!(!dequeue_ends_runnable(DeqReason::CoreSchedExec));
        assert!(!dequeue_ends_runnable(DeqReason::Other));
        assert!(dequeue_ends_runnable(DeqReason::Sleep));
        assert!(dequeue_ends_runnable(DeqReason::SchedChange));
    }
}

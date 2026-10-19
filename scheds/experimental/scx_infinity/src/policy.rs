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
/// Lowest accepted startup quantum, 100 us.
pub const QUANTUM_MIN_NS: u64 = 100_000;
/// Highest accepted startup quantum, 4 ms.
pub const QUANTUM_MAX_NS: u64 = 4_000_000;

/// One tail insert in every eight regular enqueues.
pub const GATE_MASK: u32 = 7;
/// The preemption reserve is one eighth of the configured quantum.
pub const PREEMPT_DIV: u64 = 8;
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
/// q = max(base * weight / total, 1)
/// ```
///
/// `total` includes the task itself. A zero weight is the lightest task
/// and a zero total means the task is alone. Weights cap at `WEIGHT_CAP`,
/// which keeps the BPF product inside 64 bits.
pub fn quantum_ns(base: u64, weight: u64, total: u64) -> u64 {
    let weight = weight.clamp(1, WEIGHT_CAP);
    let total = total.max(weight);

    if base == 0 {
        return 1;
    }
    let q = (u128::from(base) * u128::from(weight) / u128::from(total)).min(u128::from(u64::MAX));
    (q as u64).max(1)
}

/// True when a regular enqueue takes the tail slot instead of the head.
///
/// The kernel sequence wraps at `u32::MAX`, so that value is a tail slot
/// as well. Any other eighth value is a tail slot.
pub fn gate_tail(seq: u32) -> bool {
    seq == u32::MAX || (seq & GATE_MASK) == GATE_MASK
}

/// Effective weight from the kernel task weight and the cgroup share.
///
/// `group_weight` is the cgroup `cpu.weight` in the kernel range 1..10000.
/// A zero input means the default share of 100. A cgroup in `cpu.idle`
/// mode uses the SCHED_IDLE weight of 3 instead.
pub fn effective_weight(base: u32, group_weight: u32, idle: bool) -> u64 {
    if idle {
        return 3;
    }
    let base = if base == 0 { 1 } else { u64::from(base) };
    let group = if group_weight == 0 {
        100
    } else {
        u64::from(group_weight)
    };
    ((base * group + 50) / 100).max(1)
}

/// The victim must retain at least this much slice before a preemption.
pub fn preempt_reserve_ns(base: u64) -> u64 {
    (base / PREEMPT_DIV).max(1)
}

/// A fresh wakeup preempts only when it is heavier than the running task
/// and the victim still retains the preemption reserve.
pub fn should_preempt(
    newcomer_weight: u64,
    victim_weight: u64,
    victim_slice: u64,
    base: u64,
) -> bool {
    newcomer_weight > victim_weight && victim_slice >= preempt_reserve_ns(base)
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
    fn quantum_is_one_for_a_zero_weight_and_a_zero_total() {
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 0, 0), QUANTUM_DEFAULT_NS);
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 0, 1000), 1000);
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
    fn quantum_never_rounds_to_zero() {
        assert_eq!(quantum_ns(QUANTUM_DEFAULT_NS, 1, u64::MAX), 1);
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
        let a = effective_weight(100, 100, false);
        let b = effective_weight(100, 200, false);
        assert_eq!(a, 100);
        assert_eq!(b, 200);
        assert_eq!(a * 2, b);
    }

    #[test]
    fn idle_cgroup_uses_the_sched_idle_weight() {
        assert_eq!(effective_weight(10000, 10000, true), 3);
    }

    #[test]
    fn preemption_needs_a_heavier_newcomer_and_a_live_victim() {
        let base = QUANTUM_DEFAULT_NS;
        assert!(should_preempt(200, 100, preempt_reserve_ns(base), base));
        assert!(!should_preempt(100, 200, base, base));
        assert!(!should_preempt(
            200,
            100,
            preempt_reserve_ns(base) - 1,
            base
        ));
    }
}

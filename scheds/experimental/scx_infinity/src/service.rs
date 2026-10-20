// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Pure model of the revision-4 service policy.
//!
//! `src/bpf/main.bpf.c` mirrors these rules. Keeping them in Rust lets
//! `cargo test` cover the arithmetic, the frontier, the band, the gate, the
//! reservation and the event table without a kernel. Section numbers refer
//! to `.agent/tasks/spec/spec.md` revision 4.
//!
//! The module has three layers:
//!
//! - Service arithmetic: the Q16 charge, the wrap-safe comparison, the
//!   half-range guard, the interval split and the epoch boundary.
//! - Queue primitives: the parent queue with its monotone frontier and its
//!   7:1 gate, the band scan and the frozen event table.
//! - [`Simulator`]: a deterministic hierarchy that drives dispatch, tick,
//!   yield, sleep, reweight, move and steal across several levels.

#![allow(dead_code)]

/// One service slot, the dispatch slice and the band width, 1 ms.
/// Section 2.5.
pub const INF_SLOT_NS: u64 = 1_000_000;
/// The delta bound of one settlement, 4 ms. Section 2.2.
pub const INF_SETTLE_MAX_NS: u64 = 4_000_000;
/// Q16 fixed point.
pub const INF_Q16_SHIFT: u32 = 16;
/// One nanosecond at weight 1 in Q16 service units: 100 * 2^16.
pub const INF_SERVICE_SCALE: u64 = 100 << INF_Q16_SHIFT;
/// The band width in Q16 service units, one slot. Section 2.5.
pub const INF_BAND_Q16: u64 = INF_SLOT_NS << INF_Q16_SHIFT;
/// The largest charge one settlement can add, in Q16 service units.
pub const INF_SETTLE_MAX_Q16: u64 = INF_SETTLE_MAX_NS * INF_SERVICE_SCALE;
/// The widest service gap the band plus one settlement allows between
/// dispatchable siblings.
pub const INF_MAX_GAP_Q16: u64 = INF_BAND_Q16 + INF_SETTLE_MAX_Q16;
/// A band scan inspects at most 32 entities. Section 2.5.
pub const INF_BAND_SCAN_MAX: usize = 32;
/// One tail insertion in every eight normal insertions. Section 2.4.
pub const INF_GATE_MASK: u32 = 7;
/// Entity weight bounds. Section 2.1.
pub const INF_WEIGHT_MIN: u32 = 1;
pub const INF_WEIGHT_MAX: u32 = 10_000;
/// The weight of a `SCHED_IDLE` task and of a `cpu.idle` group.
pub const INF_WEIGHT_IDLE: u32 = 3;
/// Half of the `u64` range. A gap at or above it has no order.
pub const INF_HALF_RANGE: u64 = 1 << 63;
/// Group entities per CPU. Section 3.8.
pub const INF_GROUPS_PER_CPU: usize = 128;
/// Task entities in the pool. Section 3.8.
pub const INF_TASKS_MAX: usize = 65_536;

fn clamp_weight(weight: u32) -> u32 {
    weight.clamp(INF_WEIGHT_MIN, INF_WEIGHT_MAX)
}

/// One charge in Q16 service units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Charge {
    /// The service added by this charge.
    pub delta_q16: u64,
    /// The value after the charge, wrapped.
    pub v_q16: u64,
    /// The retained division remainder, below the weight.
    pub rem: u64,
}

/// Add `runtime_ns` of service at `weight`, with a retained remainder.
///
/// ```text
/// V += (runtime_ns * 100 * 2^16 + rem) / weight
/// rem = (runtime_ns * 100 * 2^16 + rem) % weight
/// ```
pub fn charge(v_q16: u64, rem: u64, runtime_ns: u64, weight: u32) -> Charge {
    let weight = u128::from(clamp_weight(weight));
    let rem = u128::from(rem) % weight;
    let scaled = u128::from(runtime_ns) * u128::from(INF_SERVICE_SCALE) + rem;
    let delta_q16 = (scaled / weight).min(u128::from(u64::MAX)) as u64;

    Charge {
        delta_q16,
        v_q16: v_q16.wrapping_add(delta_q16),
        rem: (scaled % weight) as u64,
    }
}

/// Wrap-safe "a is older than b". Valid only inside the half range.
pub fn service_less(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// The greater of two service values under the wrap-safe order.
pub fn service_max(a: u64, b: u64) -> u64 {
    if service_less(a, b) { b } else { a }
}

/// The distance between two service values, measured the short way.
pub fn service_distance(a: u64, b: u64) -> u64 {
    let distance = a.wrapping_sub(b);
    if distance < INF_HALF_RANGE {
        distance
    } else {
        distance.wrapping_neg()
    }
}

/// True when the two values are closer than half the `u64` range, so the
/// wrap-safe comparison orders them.
pub fn within_half_range(a: u64, b: u64) -> bool {
    service_distance(a, b) < INF_HALF_RANGE
}

/// The inclusive upper edge of the band a queue with minimum `vmin` scans.
pub fn band_cutoff(vmin: u64) -> u64 {
    vmin.wrapping_add(INF_BAND_Q16)
}

/// True when `v` is inside the service band of a queue with minimum `vmin`.
pub fn in_band(v: u64, vmin: u64) -> bool {
    !service_less(band_cutoff(vmin), v)
}

/// True when `v` cannot be a dispatchable sibling of a queue whose
/// minimum is `vmin`: it is behind the frontier or more than a band plus
/// one settlement ahead of it. Counted as `half_range_faults`.
pub fn half_range_fault(v: u64, vmin: u64) -> bool {
    v.wrapping_sub(vmin) > INF_MAX_GAP_Q16
}

/// Split `[start_ns, end_ns)` at every boundary strictly inside it.
///
/// The result is sorted, deduplicated and contiguous. A boundary outside
/// the interval, or on an edge, is ignored. An empty or inverted interval
/// yields no piece. Summing the pieces and charging them in order gives
/// the same value and remainder as one charge of the whole interval,
/// because the remainder is retained.
pub fn split_interval(start_ns: u64, end_ns: u64, boundaries_ns: &[u64]) -> Vec<(u64, u64)> {
    if end_ns <= start_ns {
        return Vec::new();
    }

    let mut cuts: Vec<u64> = boundaries_ns
        .iter()
        .copied()
        .filter(|cut| *cut > start_ns && *cut < end_ns)
        .collect();
    cuts.sort_unstable();
    cuts.dedup();

    let mut pieces = Vec::with_capacity(cuts.len() + 1);
    let mut previous = start_ns;
    for cut in cuts {
        pieces.push((previous, cut));
        previous = cut;
    }
    pieces.push((previous, end_ns));
    pieces
}

/// The service state of one entity: past service, residue, latched weight
/// and the epoch of that weight. Section 2.2 and section 2.7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Service {
    v_q16: u64,
    rem: u64,
    weight: u32,
    epoch: u64,
}

impl Service {
    pub fn new(v_q16: u64, weight: u32, epoch: u64) -> Self {
        Self {
            v_q16,
            rem: 0,
            weight: clamp_weight(weight),
            epoch,
        }
    }

    pub fn v_q16(&self) -> u64 {
        self.v_q16
    }

    pub fn rem(&self) -> u64 {
        self.rem
    }

    pub fn weight(&self) -> u32 {
        self.weight
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Charge one interval at the latched weight.
    pub fn charge(&mut self, runtime_ns: u64) -> u64 {
        let charged = charge(self.v_q16, self.rem, runtime_ns, self.weight);
        self.v_q16 = charged.v_q16;
        self.rem = charged.rem;
        charged.delta_q16
    }

    /// Latch a new weight and drop the residue it was charged with.
    /// Returns the flushed remainder.
    pub fn latch(&mut self, weight: u32, epoch: u64) -> u64 {
        let flushed = self.rem;
        self.rem = 0;
        self.weight = clamp_weight(weight);
        self.epoch = epoch;
        flushed
    }

    /// Settle one slot at the latched weight, then observe a new epoch.
    ///
    /// A running entity settles with its old weight and applies a new one
    /// only after the settle. An epoch bump with no weight change keeps
    /// the remainder: it is a reweight of another entity, not of this one.
    pub fn settle_epoch(&mut self, runtime_ns: u64, epoch: u64, weight: u32) -> u64 {
        let delta = self.charge(runtime_ns);

        if epoch != self.epoch {
            if weight == self.weight {
                self.epoch = epoch;
            } else {
                self.latch(weight, epoch);
            }
        }
        delta
    }

    /// Raise the value to the parent frontier before it becomes visible.
    pub fn clamp_to(&mut self, frontier_q16: u64) -> u64 {
        self.v_q16 = service_max(self.v_q16, frontier_q16);
        self.v_q16
    }

    /// Reinitialize at a destination coordinate. The source value and the
    /// residue are not carried. Returns the dropped source value.
    pub fn relocate(&mut self, frontier_q16: u64) -> u64 {
        let dropped = self.v_q16;
        self.v_q16 = frontier_q16;
        self.rem = 0;
        dropped
    }
}

/// How an entity enters a parent queue. Section 2.4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertClass {
    /// Not an insertion: the entity keeps its record.
    None,
    /// A normal insertion, resolved by the gate to a head or a tail.
    Normal,
    /// `SCX_ENQ_HEAD` and an eligible yield-to: head, no gate step.
    HeadExempt,
    /// A tail path requeue: tail, no gate step.
    Tail,
}

/// The class an entity actually carries inside a queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedClass {
    None,
    Head,
    Tail,
}

/// Whether an event replaces the insertion record or keeps it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAction {
    Kept,
    Replaced,
}

/// The frozen event table of section 2.4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum PolicyEvent {
    RunnableAdmission = 0,
    RunnableAdmissionHeadExempt = 1,
    PostSlotAncestorRequeue = 2,
    LeafExpiry = 3,
    ExplicitYield = 4,
    PartialPreemption = 5,
    QuotaRelease = 6,
    Reweight = 7,
    CgroupMove = 8,
    CommittedSteal = 9,
    FailedSteal = 10,
    EligibleYieldTo = 11,
}

impl PolicyEvent {
    pub const COUNT: usize = 12;
}

/// One row of the frozen event table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRule {
    pub event: PolicyEvent,
    pub key: KeyAction,
    pub class: InsertClass,
    pub advances_gate: bool,
}

/// The frozen event table. The leaf and every ancestor on the path
/// re-enter their own parent queue, so the class applies at every level.
pub const EVENT_TABLE: [EventRule; PolicyEvent::COUNT] = [
    EventRule {
        event: PolicyEvent::RunnableAdmission,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::RunnableAdmissionHeadExempt,
        key: KeyAction::Replaced,
        class: InsertClass::HeadExempt,
        advances_gate: false,
    },
    EventRule {
        event: PolicyEvent::PostSlotAncestorRequeue,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::LeafExpiry,
        key: KeyAction::Replaced,
        class: InsertClass::Tail,
        advances_gate: false,
    },
    EventRule {
        event: PolicyEvent::ExplicitYield,
        key: KeyAction::Replaced,
        class: InsertClass::Tail,
        advances_gate: false,
    },
    EventRule {
        event: PolicyEvent::PartialPreemption,
        key: KeyAction::Replaced,
        class: InsertClass::Tail,
        advances_gate: false,
    },
    EventRule {
        event: PolicyEvent::QuotaRelease,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::Reweight,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::CgroupMove,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::CommittedSteal,
        key: KeyAction::Replaced,
        class: InsertClass::Normal,
        advances_gate: true,
    },
    EventRule {
        event: PolicyEvent::FailedSteal,
        key: KeyAction::Kept,
        class: InsertClass::None,
        advances_gate: false,
    },
    EventRule {
        event: PolicyEvent::EligibleYieldTo,
        key: KeyAction::Replaced,
        class: InsertClass::HeadExempt,
        advances_gate: false,
    },
];

pub fn event_rule(event: PolicyEvent) -> EventRule {
    EVENT_TABLE[event as usize]
}

/// Resolve one insertion through the per-parent 7:1 gate.
///
/// A normal insertion takes `seq = gate_seq` and advances the counter. If
/// `seq & 7 == 7` it is a tail insertion, otherwise a head insertion.
/// Head-exempt and tail insertions do not advance the counter.
pub fn gate_insert(gate_seq: &mut u32, class: InsertClass) -> ResolvedClass {
    match class {
        InsertClass::None => ResolvedClass::None,
        InsertClass::HeadExempt => ResolvedClass::Head,
        InsertClass::Tail => ResolvedClass::Tail,
        InsertClass::Normal => {
            let seq = *gate_seq;
            *gate_seq = seq.wrapping_add(1);
            if seq & INF_GATE_MASK == INF_GATE_MASK {
                ResolvedClass::Tail
            } else {
                ResolvedClass::Head
            }
        }
    }
}

/// One entity inside its parent queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueEntry {
    pub id: u32,
    pub v_q16: u64,
    pub class: ResolvedClass,
    pub tie: u64,
}

/// A read-only band scan result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    /// The position in the scanned slice.
    pub index: usize,
    /// True when the band was wider than the scan cap and the queue head
    /// was used.
    pub truncated: bool,
    /// The number of entities inspected.
    pub scanned: usize,
    /// The selected entity's service value.
    pub v_q16: u64,
}

/// A band scan plus its diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scan {
    pub selection: Selection,
    pub faults: u32,
    pub truncated: u32,
}

/// Read-only selection over a parent queue in queue order. Section 2.5.
///
/// The band is `V <= Vmin + INF_BAND_Q16`. Inside it the scan tracks the
/// newest head at the lowest head service and the oldest tail at the
/// lowest tail service. The lower service wins, and the head wins at
/// equal service. A band wider than [`INF_BAND_SCAN_MAX`] falls back to
/// the queue head, which always has `Vmin`.
pub fn scan(entries: &[QueueEntry]) -> Option<Scan> {
    let head = entries.first()?;
    let vmin = head.v_q16;
    let mut faults = 0u32;
    for entry in entries {
        if half_range_fault(entry.v_q16, vmin) {
            faults += 1;
        }
    }

    let cutoff = band_cutoff(vmin);
    let eligible = entries
        .iter()
        .position(|entry| service_less(cutoff, entry.v_q16))
        .unwrap_or(entries.len());

    if eligible > INF_BAND_SCAN_MAX {
        return Some(Scan {
            selection: Selection {
                index: 0,
                truncated: true,
                scanned: INF_BAND_SCAN_MAX,
                v_q16: head.v_q16,
            },
            faults,
            truncated: 1,
        });
    }

    let mut best_head: Option<usize> = None;
    let mut best_tail: Option<usize> = None;

    for (index, entry) in entries[..eligible].iter().enumerate() {
        match entry.class {
            ResolvedClass::Head => {
                best_head = Some(match best_head {
                    None => index,
                    Some(current) => {
                        let candidate = &entries[current];
                        if service_less(entry.v_q16, candidate.v_q16)
                            || (entry.v_q16 == candidate.v_q16 && entry.tie > candidate.tie)
                        {
                            index
                        } else {
                            current
                        }
                    }
                });
            }
            ResolvedClass::Tail => {
                best_tail = Some(match best_tail {
                    None => index,
                    Some(current) => {
                        let candidate = &entries[current];
                        if service_less(entry.v_q16, candidate.v_q16)
                            || (entry.v_q16 == candidate.v_q16 && entry.tie < candidate.tie)
                        {
                            index
                        } else {
                            current
                        }
                    }
                });
            }
            ResolvedClass::None => {}
        }
    }

    let index = match (best_head, best_tail) {
        (None, None) => 0,
        (Some(head), None) => head,
        (None, Some(tail)) => tail,
        (Some(head), Some(tail)) => {
            let head_v = entries[head].v_q16;
            let tail_v = entries[tail].v_q16;
            if head_v == tail_v || service_less(head_v, tail_v) {
                head
            } else {
                tail
            }
        }
    };

    Some(Scan {
        selection: Selection {
            index,
            truncated: false,
            scanned: eligible,
            v_q16: entries[index].v_q16,
        },
        faults,
        truncated: 0,
    })
}

/// Read-only selection.
pub fn select(entries: &[QueueEntry]) -> Option<Selection> {
    scan(entries).map(|scan| scan.selection)
}

/// Read-only selection that records the band cap and half-range counters.
pub fn select_counted(entries: &[QueueEntry], counters: &mut Counters) -> Option<Selection> {
    let result = scan(entries)?;

    counters.half_range_faults = counters
        .half_range_faults
        .saturating_add(u64::from(result.faults));
    counters.band_scan_truncated = counters
        .band_scan_truncated
        .saturating_add(u64::from(result.truncated));
    Some(result.selection)
}

/// Diagnostics that are not policy state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub settle_clamps: u64,
    pub remote_slots: u64,
    pub half_range_faults: u64,
    pub band_scan_truncated: u64,
    pub entity_overflow: u64,
    pub state_repairs: u64,
    pub steals: u64,
    pub steal_refusals: u64,
    pub steal_failures: u64,
    pub exempt_inserts: u64,
    pub yield_charges: u64,
}

/// One per-parent child queue: ordered by service, with a monotone
/// frontier and the 7:1 gate. Section 2.3 and section 2.4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentQueue {
    entries: Vec<QueueEntry>,
    frontier_q16: u64,
    gate_seq: u32,
    next_tie: u64,
}

impl ParentQueue {
    pub fn new(frontier_q16: u64) -> Self {
        Self {
            entries: Vec::new(),
            frontier_q16,
            gate_seq: 0,
            next_tie: 0,
        }
    }

    pub fn frontier(&self) -> u64 {
        self.frontier_q16
    }

    pub fn gate_seq(&self) -> u32 {
        self.gate_seq
    }

    pub fn next_tie(&self) -> u64 {
        self.next_tie
    }

    pub fn entries(&self) -> &[QueueEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: u32) -> Option<&QueueEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// The minimum service over dispatchable siblings.
    pub fn vmin(&self) -> Option<u64> {
        self.entries.first().map(|entry| entry.v_q16)
    }

    /// Advance the frontier to `Vmin`. It never decreases.
    pub fn observe_vmin(&mut self) -> Option<u64> {
        let vmin = self.vmin()?;
        self.frontier_q16 = service_max(self.frontier_q16, vmin);
        Some(self.frontier_q16)
    }

    /// Raise an activation or a quota release to the frontier.
    pub fn clamp(&self, v_q16: u64) -> u64 {
        service_max(v_q16, self.frontier_q16)
    }

    /// Read-only band scan. Changes no key, gate, service or frontier.
    pub fn peek(&self) -> Option<Selection> {
        select(&self.entries)
    }

    /// Insert one entity through the gate and return its resolved class.
    pub fn insert(&mut self, id: u32, v_q16: u64, class: InsertClass) -> ResolvedClass {
        let resolved = gate_insert(&mut self.gate_seq, class);

        if resolved == ResolvedClass::None {
            return resolved;
        }

        let entry = QueueEntry {
            id,
            v_q16,
            class: resolved,
            tie: self.next_tie,
        };
        self.next_tie = self.next_tie.wrapping_add(1);
        self.insert_ordered(entry);
        resolved
    }

    /// Restore an exact record. A failed steal changes no gate and no tie.
    pub fn insert_kept(&mut self, entry: QueueEntry) {
        self.insert_ordered(entry);
    }

    /// Remove an entity exactly and return its record.
    pub fn remove(&mut self, id: u32) -> Option<QueueEntry> {
        let position = self.entries.iter().position(|entry| entry.id == id)?;
        Some(self.entries.remove(position))
    }

    fn insert_ordered(&mut self, entry: QueueEntry) {
        let position = self.position_for(&entry);
        self.entries.insert(position, entry);
    }

    fn position_for(&self, entry: &QueueEntry) -> usize {
        self.entries
            .iter()
            .position(|queued| {
                if queued.v_q16 == entry.v_q16 {
                    entry.tie < queued.tie
                } else {
                    service_less(entry.v_q16, queued.v_q16)
                }
            })
            .unwrap_or(self.entries.len())
    }
}

/// One dispatch's reservation. Section 2.6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    cpu: u32,
    start_now: u64,
    slot_ns: u64,
    open: bool,
}

/// What one settlement charges to the two ledgers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Settlement {
    /// The actual-runtime ledger. The only input to `cpu.max`.
    pub actual_ns: u64,
    /// The policy-service ledger. Charged to `V` at every level.
    pub policy_ns: u64,
    /// True when the tick arrived on another CPU under `NOHZ_FULL`.
    pub remote: bool,
    /// True when the runtime was clamped to the delta bound.
    pub clamped: bool,
}

impl Settlement {
    /// The policy charge the actual-runtime ledger does not see.
    pub fn extra_ns(&self) -> u64 {
        self.policy_ns.saturating_sub(self.actual_ns)
    }
}

impl Reservation {
    pub fn new(cpu: u32, start_now: u64, slot_ns: u64) -> Self {
        Self {
            cpu,
            start_now,
            slot_ns,
            open: true,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Settle at a tick. A local tick measures, a remote tick counts one
    /// slot because the clocks are not comparable across CPUs.
    pub fn settle_at(
        &mut self,
        callback_cpu: u32,
        now: u64,
        counters: &mut Counters,
    ) -> Settlement {
        if !self.open {
            return Settlement::default();
        }
        self.open = false;

        if callback_cpu != self.cpu {
            counters.remote_slots = counters.remote_slots.saturating_add(1);
            return Settlement {
                actual_ns: self.slot_ns,
                policy_ns: self.slot_ns,
                remote: true,
                clamped: false,
            };
        }

        self.measure(now, counters)
    }

    /// Settle at a remote tick without a local clock reading.
    pub fn settle_remote(&mut self, counters: &mut Counters) -> Settlement {
        if !self.open {
            return Settlement::default();
        }
        self.open = false;
        counters.remote_slots = counters.remote_slots.saturating_add(1);
        Settlement {
            actual_ns: self.slot_ns,
            policy_ns: self.slot_ns,
            remote: true,
            clamped: false,
        }
    }

    /// Settle an explicit yield. The actual ledger sees the runtime, the
    /// policy ledger sees `max(actual, reserved_slot)`.
    pub fn settle_yield(&mut self, now: u64, counters: &mut Counters) -> Settlement {
        if !self.open {
            return Settlement::default();
        }
        self.open = false;
        counters.yield_charges = counters.yield_charges.saturating_add(1);

        let mut settlement = self.measure(now, counters);
        settlement.policy_ns = settlement.policy_ns.max(self.slot_ns);
        settlement
    }

    fn measure(&self, now: u64, counters: &mut Counters) -> Settlement {
        let runtime_ns = now.saturating_sub(self.start_now);
        let clamped = runtime_ns > INF_SETTLE_MAX_NS;
        let actual_ns = runtime_ns.min(INF_SETTLE_MAX_NS);

        if clamped {
            counters.settle_clamps = counters.settle_clamps.saturating_add(1);
        }

        Settlement {
            actual_ns,
            policy_ns: actual_ns,
            remote: false,
            clamped,
        }
    }
}

/// Where a new group entity is accounted. Section 3.8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityPlacement {
    /// A free slot exists.
    Free(u16),
    /// The pool is full. The task joins this resident ancestor.
    Ancestor(u16),
    /// The pool is full and no ancestor is resident. Join slot 0.
    Root,
}

/// Place a new group entity. `used` slots are taken and slot 0 is the
/// root. `ancestry` is nearest-first, with a resident flag per entry.
pub fn place_group(
    used: usize,
    ancestry: &[(u16, bool)],
    counters: &mut Counters,
) -> EntityPlacement {
    if used < INF_GROUPS_PER_CPU {
        return EntityPlacement::Free(used as u16);
    }

    counters.entity_overflow = counters.entity_overflow.saturating_add(1);
    match ancestry.iter().find(|(_, resident)| *resident) {
        Some((slot, _)) => EntityPlacement::Ancestor(*slot),
        None => EntityPlacement::Root,
    }
}

/// The task pool is full. `ops.init_task()` returns `-ENOMEM`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskPoolFull;

/// The index of a new task entity, or the pool error at the bound.
pub fn alloc_task(nr_live: usize) -> Result<usize, TaskPoolFull> {
    if nr_live >= INF_TASKS_MAX {
        Err(TaskPoolFull)
    } else {
        Ok(nr_live)
    }
}

/// The outcome of one transactional steal. Section 4.3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Steal {
    pub committed: bool,
    /// The source record, restored on a failure.
    pub saved: Option<QueueEntry>,
    /// The destination record after a commit.
    pub destination: Option<QueueEntry>,
}

/// Move one queued task from a source parent to a destination parent.
///
/// The record is removed exactly and restored on refusal, so the source
/// keeps its class and tie. No gate advances before the destination
/// insert commits.
pub fn try_steal(
    id: u32,
    source: &mut ParentQueue,
    destination: &mut ParentQueue,
    destination_accepts: bool,
    counters: &mut Counters,
) -> Steal {
    let saved = match source.remove(id) {
        Some(entry) => entry,
        None => {
            counters.steal_refusals = counters.steal_refusals.saturating_add(1);
            return Steal {
                committed: false,
                saved: None,
                destination: None,
            };
        }
    };

    if !destination_accepts {
        source.insert_kept(saved);
        counters.steal_failures = counters.steal_failures.saturating_add(1);
        return Steal {
            committed: false,
            saved: Some(saved),
            destination: None,
        };
    }

    let frontier = destination.frontier();
    destination.insert(id, frontier, InsertClass::Normal);
    counters.steals = counters.steals.saturating_add(1);

    Steal {
        committed: true,
        saved: Some(saved),
        destination: destination.get(id).copied(),
    }
}

/// A deterministic model of one CPU's entity tree.
///
/// The root entity is slot 0. A group entity is inserted into its parent
/// only while it has a runnable descendant. A task path is removed at
/// dispatch and re-enters through the event table at the end of the slot.
pub struct Simulator {
    nodes: Vec<SimNode>,
    counters: Counters,
    epoch: u64,
    slot_ns: u64,
    clock_ns: u64,
    settled_ns: u64,
    running: Option<Vec<usize>>,
    reservation: Option<Reservation>,
}

struct SimNode {
    parent: Option<usize>,
    group: bool,
    queued: bool,
    weight: u32,
    service: Service,
    children: Option<ParentQueue>,
}

/// A comparable view of the whole tree, for state-change tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub services: Vec<Service>,
    pub queued: Vec<bool>,
    pub weights: Vec<u32>,
    pub queues: Vec<Option<QueueView>>,
    pub counters: Counters,
    pub running: Option<Vec<usize>>,
    pub reservation_open: bool,
    pub settled_ns: u64,
}

/// A comparable view of one parent queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueView {
    pub frontier_q16: u64,
    pub gate_seq: u32,
    pub next_tie: u64,
    pub entries: Vec<QueueEntry>,
}

impl Simulator {
    pub fn new() -> Self {
        Self {
            nodes: vec![SimNode {
                parent: None,
                group: true,
                queued: false,
                weight: INF_WEIGHT_MIN,
                service: Service::new(0, INF_WEIGHT_MIN, 0),
                children: Some(ParentQueue::new(0)),
            }],
            counters: Counters::default(),
            epoch: 0,
            slot_ns: INF_SLOT_NS,
            clock_ns: 0,
            settled_ns: 0,
            running: None,
            reservation: None,
        }
    }

    pub fn nr_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn settled_ns(&self) -> u64 {
        self.settled_ns
    }

    pub fn reservation_open(&self) -> bool {
        self.reservation.is_some()
    }

    pub fn service(&self, id: usize) -> &Service {
        &self.nodes[id].service
    }

    pub fn frontier(&self, group: usize) -> u64 {
        self.nodes[group]
            .children
            .as_ref()
            .expect("a group entity")
            .frontier()
    }

    pub fn gate_seq(&self, group: usize) -> u32 {
        self.nodes[group]
            .children
            .as_ref()
            .expect("a group entity")
            .gate_seq()
    }

    pub fn is_queued(&self, id: usize) -> bool {
        self.nodes[id].queued
    }

    /// The queue record of an entity, when it is queued.
    pub fn queue_entry(&self, group: usize, id: usize) -> Option<QueueEntry> {
        self.nodes[group]
            .children
            .as_ref()
            .and_then(|queue| queue.get(id as u32))
            .copied()
    }

    /// Create a dormant group. It enters its parent when it gets work.
    pub fn add_group(&mut self, parent: usize, weight: u32) -> usize {
        let id = self.nodes.len();
        let weight = clamp_weight(weight);
        self.nodes.push(SimNode {
            parent: Some(parent),
            group: true,
            queued: false,
            weight,
            service: Service::new(0, weight, self.epoch),
            children: Some(ParentQueue::new(0)),
        });
        id
    }

    /// Create a runnable task and admit it and its ancestors.
    pub fn add_task(&mut self, parent: usize, weight: u32) -> usize {
        let id = self.nodes.len();
        let weight = clamp_weight(weight);
        self.nodes.push(SimNode {
            parent: Some(parent),
            group: false,
            queued: false,
            weight,
            service: Service::new(0, weight, self.epoch),
            children: None,
        });
        self.admit_event(id, PolicyEvent::RunnableAdmission);
        self.admit_ancestors(parent);
        id
    }

    /// Read-only descent. Returns the path from the root child to a leaf
    /// task and changes nothing.
    pub fn peek(&self) -> Option<Vec<usize>> {
        self.descend().map(|(path, _, _)| path)
    }

    /// A dispatch that the destination refuses. Changes no state.
    pub fn try_dispatch(&mut self, accept: bool) -> Option<Vec<usize>> {
        if accept { self.dispatch() } else { self.peek() }
    }

    /// Select one leaf, advance the frontier at every level, remove the
    /// path and open the reservation.
    pub fn dispatch(&mut self) -> Option<Vec<usize>> {
        let (path, faults, truncated) = self.descend()?;
        self.counters.half_range_faults = self
            .counters
            .half_range_faults
            .saturating_add(u64::from(faults));
        self.counters.band_scan_truncated = self
            .counters
            .band_scan_truncated
            .saturating_add(u64::from(truncated));

        let mut parent = 0usize;
        for &id in &path {
            let queue = self.nodes[parent]
                .children
                .as_mut()
                .expect("a group entity");
            queue.observe_vmin();
            queue.remove(id as u32)?;
            self.nodes[id].queued = false;
            parent = id;
        }

        self.running = Some(path.clone());
        self.reservation = Some(Reservation::new(0, self.clock_ns, self.slot_ns));
        Some(path)
    }

    /// End the current slot at the tick: settle, charge every level with
    /// the policy runtime and requeue the path through the normal gate.
    pub fn tick(&mut self, runtime_ns: u64) -> Option<Settlement> {
        let path = self.running.take()?;
        self.clock_ns = self.clock_ns.saturating_add(runtime_ns);
        let settlement = self.close(Close::Tick)?;

        for &id in path.iter().rev() {
            if id != 0 {
                self.charge_node(id, settlement.policy_ns);
            }
        }
        for &id in path.iter().rev() {
            if id != 0 {
                self.admit_event(id, PolicyEvent::PostSlotAncestorRequeue);
            }
        }
        Some(settlement)
    }

    /// End the slot at an explicit yield. The donor pays the reserved
    /// slot to the policy ledger and re-enters at the tail.
    pub fn yield_now(&mut self, runtime_ns: u64) -> Option<Settlement> {
        let path = self.running.take()?;
        self.clock_ns = self.clock_ns.saturating_add(runtime_ns);
        let settlement = self.close(Close::Yield)?;

        for &id in path.iter().rev() {
            if id != 0 {
                self.charge_node(id, settlement.policy_ns);
            }
        }
        for &id in path.iter().rev() {
            if id != 0 {
                self.admit_event(id, PolicyEvent::ExplicitYield);
            }
        }
        Some(settlement)
    }

    /// Stop a runnable task. Its dormant ancestors leave their queues and
    /// keep their history.
    pub fn sleep(&mut self, id: usize) -> bool {
        if self.is_running(id) || !self.unqueue(id) {
            return false;
        }
        self.dormant_ancestors(id);
        true
    }

    /// Apply a live weight change. A queued entity keeps its `V` and
    /// re-enters through the normal gate. A running entity settles the
    /// slot at the old weight first.
    pub fn reweight(&mut self, id: usize, weight: u32) -> bool {
        if !(INF_WEIGHT_MIN..=INF_WEIGHT_MAX).contains(&weight) {
            return false;
        }

        self.epoch = self.epoch.wrapping_add(1);
        let epoch = self.epoch;
        self.nodes[id].weight = weight;

        if self.nodes[id].queued {
            self.unqueue(id);
            self.nodes[id].service.latch(weight, epoch);
            let v_q16 = self.nodes[id].service.v_q16();
            let parent = self.nodes[id].parent.expect("a queued node has a parent");
            self.nodes[parent]
                .children
                .as_mut()
                .expect("a group entity")
                .insert(id as u32, v_q16, InsertClass::Normal);
            self.nodes[id].queued = true;
            return true;
        }

        if !self.is_running(id) {
            self.nodes[id].service.latch(weight, epoch);
        }
        true
    }

    /// Move a task to another parent. The source value is not carried.
    pub fn move_task(&mut self, id: usize, destination: usize) -> bool {
        if self.nodes[id].group
            || !self.nodes[destination].group
            || self.is_running(id)
            || self.nodes[id].parent == Some(destination)
            || !self.unqueue(id)
        {
            return false;
        }

        self.dormant_ancestors(id);
        let frontier = self.frontier(destination);
        self.nodes[id].service.relocate(frontier);
        self.nodes[id].parent = Some(destination);
        self.admit_event(id, PolicyEvent::CgroupMove);
        self.admit_ancestors(destination);
        true
    }

    /// Steal a queued task into another parent. A refused steal leaves the
    /// source record and both gates unchanged.
    pub fn steal(&mut self, id: usize, destination: usize, destination_accepts: bool) -> bool {
        if self.nodes[id].group || !self.nodes[destination].group || self.is_running(id) {
            return false;
        }
        let source = match self.nodes[id].parent {
            Some(source) => source,
            None => return false,
        };
        if source == destination {
            return false;
        }

        let mut source_queue = self.nodes[source].children.take().expect("a group entity");
        let mut destination_queue = self.nodes[destination]
            .children
            .take()
            .expect("a group entity");
        let outcome = try_steal(
            id as u32,
            &mut source_queue,
            &mut destination_queue,
            destination_accepts,
            &mut self.counters,
        );
        self.nodes[source].children = Some(source_queue);
        self.nodes[destination].children = Some(destination_queue);

        if !outcome.committed {
            return false;
        }

        let v_q16 = self.nodes[destination]
            .children
            .as_ref()
            .and_then(|queue| queue.get(id as u32))
            .map(|entry| entry.v_q16)
            .expect("the steal committed");
        self.nodes[id].service.relocate(v_q16);
        self.nodes[id].parent = Some(destination);
        self.admit_ancestors(destination);
        true
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            services: self.nodes.iter().map(|node| node.service).collect(),
            queued: self.nodes.iter().map(|node| node.queued).collect(),
            weights: self.nodes.iter().map(|node| node.weight).collect(),
            queues: self
                .nodes
                .iter()
                .map(|node| node.children.as_ref().map(QueueView::of))
                .collect(),
            counters: self.counters,
            running: self.running.clone(),
            reservation_open: self.reservation.is_some(),
            settled_ns: self.settled_ns,
        }
    }

    fn descend(&self) -> Option<(Vec<usize>, u32, u32)> {
        let mut path = Vec::new();
        let mut group = 0usize;
        let mut faults = 0u32;
        let mut truncated = 0u32;

        loop {
            let queue = self.nodes[group].children.as_ref()?;
            let scanned = scan(queue.entries())?;
            faults = faults.saturating_add(scanned.faults);
            truncated = truncated.saturating_add(scanned.truncated);
            let id = queue.entries()[scanned.selection.index].id as usize;
            path.push(id);
            if self.nodes[id].group {
                group = id;
            } else {
                return Some((path, faults, truncated));
            }
        }
    }

    fn charge_node(&mut self, id: usize, runtime_ns: u64) {
        let epoch = self.epoch;
        let weight = self.nodes[id].weight;
        self.nodes[id]
            .service
            .settle_epoch(runtime_ns, epoch, weight);
    }

    fn admit_event(&mut self, id: usize, event: PolicyEvent) -> ResolvedClass {
        let rule = event_rule(event);

        if rule.key == KeyAction::Kept {
            return ResolvedClass::None;
        }
        self.admit(id, rule.class)
    }

    fn admit(&mut self, id: usize, class: InsertClass) -> ResolvedClass {
        let parent = match self.nodes[id].parent {
            Some(parent) => parent,
            None => return ResolvedClass::None,
        };

        if class == InsertClass::HeadExempt {
            self.counters.exempt_inserts = self.counters.exempt_inserts.saturating_add(1);
        }

        let frontier = self.nodes[parent]
            .children
            .as_ref()
            .expect("a group entity")
            .frontier();
        let v_q16 = self.nodes[id].service.clamp_to(frontier);
        let resolved = self.nodes[parent]
            .children
            .as_mut()
            .expect("a group entity")
            .insert(id as u32, v_q16, class);
        self.nodes[id].queued = resolved != ResolvedClass::None;
        resolved
    }

    fn admit_ancestors(&mut self, from: usize) {
        let mut group = Some(from);

        while let Some(id) = group {
            if id == 0 {
                break;
            }
            if !self.nodes[id].queued {
                self.admit_event(id, PolicyEvent::RunnableAdmission);
            }
            group = self.nodes[id].parent;
        }
    }

    fn unqueue(&mut self, id: usize) -> bool {
        let parent = match self.nodes[id].parent {
            Some(parent) => parent,
            None => return false,
        };
        let removed = self.nodes[parent]
            .children
            .as_mut()
            .expect("a group entity")
            .remove(id as u32)
            .is_some();

        if removed {
            self.nodes[id].queued = false;
        }
        removed
    }

    fn dormant_ancestors(&mut self, from: usize) {
        let mut group = self.nodes[from].parent;

        while let Some(id) = group {
            if id == 0 {
                break;
            }
            let empty = self.nodes[id]
                .children
                .as_ref()
                .expect("a group entity")
                .is_empty();
            if !empty {
                break;
            }
            if self.nodes[id].queued {
                self.unqueue(id);
            }
            group = self.nodes[id].parent;
        }
    }

    fn is_running(&self, id: usize) -> bool {
        self.running.as_ref().is_some_and(|path| path.contains(&id))
    }

    fn close(&mut self, how: Close) -> Option<Settlement> {
        let mut reservation = self.reservation.take()?;
        let settlement = match how {
            Close::Tick => reservation.settle_at(0, self.clock_ns, &mut self.counters),
            Close::Yield => reservation.settle_yield(self.clock_ns, &mut self.counters),
        };
        self.settled_ns = self.settled_ns.saturating_add(settlement.actual_ns);
        Some(settlement)
    }
}

enum Close {
    Tick,
    Yield,
}

impl QueueView {
    fn of(queue: &ParentQueue) -> Self {
        Self {
            frontier_q16: queue.frontier(),
            gate_seq: queue.gate_seq(),
            next_tie: queue.next_tie(),
            entries: queue.entries().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic linear congruential generator. The 10,000-pair check
    /// needs varied inputs, not a random source.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    fn entry(id: u32, v_q16: u64, class: ResolvedClass, tie: u64) -> QueueEntry {
        QueueEntry {
            id,
            v_q16,
            class,
            tie,
        }
    }

    #[test]
    fn q16_charge_keeps_the_remainder_below_the_weight() {
        for weight in [1u32, 3, 100, 1000, 10000] {
            let charged = charge(0, 0, INF_SLOT_NS, weight);
            let reference =
                u128::from(INF_SLOT_NS) * u128::from(INF_SERVICE_SCALE) / u128::from(weight);
            assert_eq!(u128::from(charged.delta_q16), reference);
            assert!(charged.rem < u64::from(weight));

            let small = charge(0, 0, 29, weight);
            assert!(small.rem < u64::from(weight));
        }

        /* A weight that does not divide the scale retains a remainder. */
        assert_eq!(charge(0, 0, 29, 3).rem, 2);
    }

    #[test]
    fn ten_thousand_charges_match_the_u128_reference() {
        let mut rng = Lcg::new(0x5eed);
        let mut v_q16 = 0u64;
        let mut rem = 0u64;
        let mut weight = 100u32;

        for _ in 0..10_000 {
            let runtime_ns = rng.next() % (INF_SETTLE_MAX_NS + 1);
            let next_weight = 1 + (rng.next() % u64::from(INF_WEIGHT_MAX)) as u32;

            /* A weight change flushes the residue under the old weight,
             * so the reference never divides a residue by a new weight. */
            if next_weight != weight {
                weight = next_weight;
                rem = 0;
            }

            let reference = (u128::from(runtime_ns) * u128::from(INF_SERVICE_SCALE)
                + u128::from(rem))
                / u128::from(weight);
            let charged = charge(v_q16, rem, runtime_ns, weight);

            assert_eq!(u128::from(charged.delta_q16), reference);
            assert_eq!(charged.v_q16, v_q16.wrapping_add(reference as u64));
            assert_eq!(
                u128::from(charged.rem),
                reference_rem(runtime_ns, rem, weight)
            );
            v_q16 = charged.v_q16;
            rem = charged.rem;
        }
    }

    fn reference_rem(runtime_ns: u64, rem: u64, weight: u32) -> u128 {
        (u128::from(runtime_ns) * u128::from(INF_SERVICE_SCALE) + u128::from(rem))
            % u128::from(weight)
    }

    #[test]
    fn a_long_charge_wraps_without_losing_order() {
        /* At weight 1 the value advances 100 * 2^16 per nanosecond and
         * wraps after about 47 minutes. */
        let mut service = Service::new(u64::MAX - 1_000, 1, 0);
        let delta = service.charge(1_000);

        assert_eq!(delta, 1_000 * INF_SERVICE_SCALE);
        assert!(service.v_q16() < 1_000 * INF_SERVICE_SCALE);
        assert!(service_less(u64::MAX - 1_000, service.v_q16()));
        assert!(!service_less(service.v_q16(), u64::MAX - 1_000));
        assert!(within_half_range(u64::MAX - 1_000, service.v_q16()));
    }

    #[test]
    fn the_half_range_guard_rejects_a_gap_at_two_to_the_63() {
        assert!(within_half_range(10, 10 + INF_HALF_RANGE - 1));
        /* Exactly half the range apart has no order. One unit further is
         * half the range apart in the other direction and is ordered. */
        assert!(!within_half_range(10, 10 + INF_HALF_RANGE));
        assert!(within_half_range(10, 10 + INF_HALF_RANGE + 1));
        /* Across the wrap the distance stays small. */
        assert!(within_half_range(u64::MAX - 3, 2));
    }

    #[test]
    fn a_value_outside_the_band_and_delta_bounds_is_a_half_range_fault() {
        let vmin = 1 << 40;

        assert!(!half_range_fault(vmin, vmin));
        assert!(!half_range_fault(vmin + INF_BAND_Q16, vmin));
        assert!(!half_range_fault(vmin + INF_MAX_GAP_Q16, vmin));
        assert!(half_range_fault(vmin + INF_MAX_GAP_Q16 + 1, vmin));
        assert!(half_range_fault(vmin - 1, vmin));

        let entries = vec![
            entry(1, vmin, ResolvedClass::Head, 1),
            entry(2, vmin + INF_BAND_Q16, ResolvedClass::Head, 2),
            entry(3, vmin + INF_MAX_GAP_Q16 + 1, ResolvedClass::Head, 3),
        ];
        let mut counters = Counters::default();
        select_counted(&entries, &mut counters);
        assert_eq!(counters.half_range_faults, 1);
    }

    #[test]
    fn a_settlement_is_bounded_by_the_delta_limit() {
        let mut counters = Counters::default();
        let mut reservation = Reservation::new(0, 1_000, INF_SLOT_NS);
        let settlement = reservation.settle_at(0, 1_000 + INF_SETTLE_MAX_NS + 1, &mut counters);

        assert_eq!(settlement.actual_ns, INF_SETTLE_MAX_NS);
        assert_eq!(settlement.policy_ns, INF_SETTLE_MAX_NS);
        assert!(settlement.clamped);
        assert_eq!(counters.settle_clamps, 1);

        /* A settle is idempotent: a second one charges nothing. */
        let again = reservation.settle_at(0, 9_999_999, &mut counters);
        assert_eq!(again, Settlement::default());
        assert_eq!(counters.settle_clamps, 1);
    }

    #[test]
    fn a_remote_tick_charges_the_slot_and_counts_remote_slots() {
        let mut counters = Counters::default();
        let mut reservation = Reservation::new(2, 1_000, INF_SLOT_NS);
        let settlement = reservation.settle_at(3, 0, &mut counters);

        assert!(settlement.remote);
        assert_eq!(settlement.actual_ns, INF_SLOT_NS);
        assert_eq!(settlement.policy_ns, INF_SLOT_NS);
        assert_eq!(counters.remote_slots, 1);
        assert!(!reservation.is_open());
    }

    #[test]
    fn an_explicit_yield_charges_the_reserved_slot_to_the_policy_ledger() {
        let mut counters = Counters::default();
        let mut reservation = Reservation::new(0, 10_000, INF_SLOT_NS);
        let settlement = reservation.settle_yield(10_000 + 29_000, &mut counters);

        assert_eq!(settlement.actual_ns, 29_000);
        assert_eq!(settlement.policy_ns, INF_SLOT_NS);
        assert_eq!(settlement.extra_ns(), INF_SLOT_NS - 29_000);
        assert_eq!(counters.yield_charges, 1);

        /* A yield after the slot keeps the actual runtime. */
        let mut reservation = Reservation::new(0, 0, INF_SLOT_NS);
        let settlement = reservation.settle_yield(2 * INF_SLOT_NS, &mut counters);
        assert_eq!(settlement.policy_ns, 2 * INF_SLOT_NS);

        /* A second settle charges nothing. */
        assert_eq!(
            reservation.settle_yield(9 * INF_SLOT_NS, &mut counters),
            Settlement::default()
        );
    }

    #[test]
    fn a_weight_change_mid_interval_flushes_the_remainder() {
        let mut service = Service::new(0, 3, 1);
        let first = service.charge(29);
        assert!(service.rem() > 0);
        let rem_before = service.rem();

        /* The new weight arrives during the slot: the slot settles at the
         * old weight, then the residue is dropped and the epoch latches. */
        let delta = service.settle_epoch(29_000, 2, 300);
        let reference =
            (u128::from(29_000u64) * u128::from(INF_SERVICE_SCALE) + u128::from(rem_before)) / 3;

        assert_eq!(u128::from(delta), reference);
        assert_eq!(service.v_q16(), first + delta);
        assert_eq!(service.rem(), 0);
        assert_eq!(service.epoch(), 2);
        assert_eq!(service.weight(), 300);

        /* The next charge uses the latched weight. */
        let next = service.charge(INF_SLOT_NS);
        assert_eq!(
            u128::from(next),
            u128::from(INF_SLOT_NS) * u128::from(INF_SERVICE_SCALE) / 300
        );
    }

    #[test]
    fn an_epoch_bump_without_a_weight_change_keeps_the_remainder() {
        let mut service = Service::new(0, 3, 1);
        service.charge(29);
        let rem_before = service.rem();
        assert!(rem_before > 0);

        service.settle_epoch(0, 2, 3);

        assert_eq!(service.epoch(), 2);
        assert_eq!(service.weight(), 3);
        assert_eq!(service.rem(), rem_before);
    }

    #[test]
    fn an_arbitrary_interval_split_covers_the_interval_once() {
        let pieces = split_interval(
            1_000,
            10_000,
            &[5_000, 2_000, 5_000, 0, 20_000, 10_000, 1_000],
        );

        assert_eq!(
            pieces,
            vec![(1_000, 2_000), (2_000, 5_000), (5_000, 10_000)]
        );
        assert!(split_interval(10, 10, &[5]).is_empty());
        assert!(split_interval(20, 10, &[15]).is_empty());

        /* Charging the pieces in order equals one charge of the whole
         * interval, because the remainder is retained. */
        let mut piecewise = Service::new(0, 3, 0);
        for (from, to) in &pieces {
            piecewise.charge(to - from);
        }
        let mut whole = Service::new(0, 3, 0);
        whole.charge(9_000);
        assert_eq!(piecewise.v_q16(), whole.v_q16());
        assert_eq!(piecewise.rem(), whole.rem());
    }

    #[test]
    fn the_band_is_exactly_one_slot_above_the_minimum() {
        let vmin = 5 << 40;

        assert_eq!(band_cutoff(vmin), vmin + INF_BAND_Q16);
        assert!(in_band(vmin, vmin));
        assert!(in_band(vmin + INF_BAND_Q16, vmin));
        assert!(!in_band(vmin + INF_BAND_Q16 + 1, vmin));
    }

    #[test]
    fn the_gate_makes_one_tail_insert_in_every_eight_normal_insertions() {
        let mut gate_seq = 0u32;
        let mut tails = 0;

        for _ in 0..8 {
            match gate_insert(&mut gate_seq, InsertClass::Normal) {
                ResolvedClass::Tail => tails += 1,
                ResolvedClass::Head => {}
                ResolvedClass::None => panic!("a normal insert never resolves to none"),
            }
        }
        assert_eq!(tails, 1);
        assert_eq!(gate_seq, 8);

        /* Head-exempt and tail inserts do not advance the gate. */
        let before = gate_seq;
        assert_eq!(
            gate_insert(&mut gate_seq, InsertClass::HeadExempt),
            ResolvedClass::Head
        );
        assert_eq!(
            gate_insert(&mut gate_seq, InsertClass::Tail),
            ResolvedClass::Tail
        );
        assert_eq!(
            gate_insert(&mut gate_seq, InsertClass::None),
            ResolvedClass::None
        );
        assert_eq!(gate_seq, before);

        /* 10,000 normal insertions hold the exact 7:1 ratio. */
        let mut gate_seq = 0u32;
        let mut tails = 0;
        for _ in 0..10_000 {
            if gate_insert(&mut gate_seq, InsertClass::Normal) == ResolvedClass::Tail {
                tails += 1;
            }
        }
        assert_eq!(tails, 1_250);
    }

    #[test]
    fn the_frozen_event_table_has_one_row_per_event() {
        assert_eq!(EVENT_TABLE.len(), PolicyEvent::COUNT);
        let expected = [
            (
                PolicyEvent::RunnableAdmission,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::RunnableAdmissionHeadExempt,
                KeyAction::Replaced,
                InsertClass::HeadExempt,
                false,
            ),
            (
                PolicyEvent::PostSlotAncestorRequeue,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::LeafExpiry,
                KeyAction::Replaced,
                InsertClass::Tail,
                false,
            ),
            (
                PolicyEvent::ExplicitYield,
                KeyAction::Replaced,
                InsertClass::Tail,
                false,
            ),
            (
                PolicyEvent::PartialPreemption,
                KeyAction::Replaced,
                InsertClass::Tail,
                false,
            ),
            (
                PolicyEvent::QuotaRelease,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::Reweight,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::CgroupMove,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::CommittedSteal,
                KeyAction::Replaced,
                InsertClass::Normal,
                true,
            ),
            (
                PolicyEvent::FailedSteal,
                KeyAction::Kept,
                InsertClass::None,
                false,
            ),
            (
                PolicyEvent::EligibleYieldTo,
                KeyAction::Replaced,
                InsertClass::HeadExempt,
                false,
            ),
        ];

        for (index, (event, key, class, advances_gate)) in expected.into_iter().enumerate() {
            let rule = event_rule(event);

            assert_eq!(rule.event, event);
            assert_eq!(rule.key, key, "key of {event:?}");
            assert_eq!(rule.class, class, "class of {event:?}");
            assert_eq!(rule.advances_gate, advances_gate, "gate of {event:?}");
            assert_eq!(EVENT_TABLE[index].event, event);
        }
    }

    #[test]
    fn the_newest_head_at_the_lowest_service_wins() {
        let queue = vec![
            entry(1, 100, ResolvedClass::Head, 1),
            entry(2, 100, ResolvedClass::Head, 2),
            entry(3, 100, ResolvedClass::Tail, 1),
        ];

        let selection = select(&queue).expect("a candidate");
        assert_eq!(queue[selection.index].id, 2);
        assert!(!selection.truncated);
        assert_eq!(selection.scanned, 3);
    }

    #[test]
    fn a_tail_at_lower_service_beats_a_newer_head() {
        let queue = vec![
            entry(1, 100, ResolvedClass::Tail, 1),
            entry(2, 200, ResolvedClass::Head, 2),
        ];

        let selection = select(&queue).expect("a candidate");
        assert_eq!(queue[selection.index].id, 1);
    }

    #[test]
    fn a_head_beats_a_tail_at_equal_service_and_the_oldest_tail_wins() {
        let mixed = vec![
            entry(1, 100, ResolvedClass::Tail, 1),
            entry(2, 100, ResolvedClass::Head, 2),
        ];
        assert_eq!(mixed[select(&mixed).expect("a candidate").index].id, 2);

        let tails = vec![
            entry(1, 100, ResolvedClass::Tail, 9),
            entry(2, 100, ResolvedClass::Tail, 3),
        ];
        assert_eq!(tails[select(&tails).expect("a candidate").index].id, 2);
    }

    #[test]
    fn a_candidate_above_the_cutoff_loses_even_when_it_is_a_head() {
        let queue = vec![
            entry(1, 0, ResolvedClass::Tail, 1),
            entry(2, INF_BAND_Q16 + 1, ResolvedClass::Head, 2),
        ];

        let selection = select(&queue).expect("a candidate");
        assert_eq!(queue[selection.index].id, 1);
        assert_eq!(selection.scanned, 1);
    }

    #[test]
    fn the_band_scan_stops_at_32_and_falls_back_to_the_queue_head() {
        let wide: Vec<QueueEntry> = (0..33)
            .map(|index| entry(index, 100, ResolvedClass::Head, u64::from(index)))
            .collect();
        let mut counters = Counters::default();
        let selection = select_counted(&wide, &mut counters).expect("a candidate");

        assert!(selection.truncated);
        assert_eq!(selection.scanned, INF_BAND_SCAN_MAX);
        assert_eq!(selection.index, 0);
        assert_eq!(counters.band_scan_truncated, 1);

        let exact: Vec<QueueEntry> = (0..32)
            .map(|index| entry(index, 100, ResolvedClass::Head, u64::from(index)))
            .collect();
        let mut counters = Counters::default();
        let selection = select_counted(&exact, &mut counters).expect("a candidate");

        assert!(!selection.truncated);
        assert_eq!(selection.scanned, 32);
        assert_eq!(counters.band_scan_truncated, 0);
    }

    #[test]
    fn vmin_covers_only_dispatchable_siblings() {
        let mut queue = ParentQueue::new(0);
        queue.insert(1, 10, InsertClass::Normal);
        queue.insert(2, 20, InsertClass::Normal);

        assert_eq!(queue.vmin(), Some(10));
        /* A dormant or parked entity is not in the parent queue, so it
         * cannot pin Vmin. */
        queue.remove(1);
        assert_eq!(queue.vmin(), Some(20));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn the_frontier_advances_to_vmin_and_never_decreases() {
        let mut queue = ParentQueue::new(0);
        queue.insert(1, 100, InsertClass::Normal);
        queue.insert(2, 300, InsertClass::Normal);

        queue.observe_vmin();
        assert_eq!(queue.frontier(), 100);

        queue.remove(1);
        queue.observe_vmin();
        assert_eq!(queue.frontier(), 300);

        /* A lower activation is clamped before it becomes visible. */
        assert_eq!(queue.clamp(50), 300);
        /* A drained queue does not lower the frontier. */
        queue.remove(2);
        assert_eq!(queue.vmin(), None);
        queue.observe_vmin();
        assert_eq!(queue.frontier(), 300);
    }

    #[test]
    fn a_new_entity_in_an_empty_parent_starts_at_the_retained_frontier() {
        let mut queue = ParentQueue::new(0);
        queue.insert(1, 100, InsertClass::Normal);
        queue.observe_vmin();
        queue.remove(1);

        assert_eq!(queue.vmin(), None);
        assert_eq!(queue.clamp(0), 100);
    }

    #[test]
    fn pool_exhaustion_falls_back_to_the_nearest_resident_ancestor() {
        let mut counters = Counters::default();

        /* Slot 0 is the root entity, so the pool starts at one used slot. */
        assert_eq!(place_group(1, &[], &mut counters), EntityPlacement::Free(1));
        assert_eq!(
            place_group(INF_GROUPS_PER_CPU - 1, &[], &mut counters),
            EntityPlacement::Free((INF_GROUPS_PER_CPU - 1) as u16)
        );
        assert_eq!(counters.entity_overflow, 0);

        assert_eq!(
            place_group(INF_GROUPS_PER_CPU, &[(9, true)], &mut counters),
            EntityPlacement::Ancestor(9)
        );
        assert_eq!(
            place_group(INF_GROUPS_PER_CPU, &[(9, false), (4, true)], &mut counters),
            EntityPlacement::Ancestor(4)
        );
        assert_eq!(
            place_group(INF_GROUPS_PER_CPU, &[(9, false)], &mut counters),
            EntityPlacement::Root
        );
        assert_eq!(counters.entity_overflow, 3);

        assert_eq!(alloc_task(INF_TASKS_MAX - 1), Ok(INF_TASKS_MAX - 1));
        assert_eq!(alloc_task(INF_TASKS_MAX), Err(TaskPoolFull));
    }

    #[test]
    fn a_failed_steal_restores_the_source_record_and_advances_no_gate() {
        let mut source = ParentQueue::new(0);
        source.insert(7, 5_000, InsertClass::Normal);
        let record = source.get(7).copied().expect("the task is queued");
        let source_gate = source.gate_seq();

        let mut destination = ParentQueue::new(1 << 30);
        let destination_gate = destination.gate_seq();
        let mut counters = Counters::default();

        let steal = try_steal(7, &mut source, &mut destination, false, &mut counters);
        assert!(!steal.committed);
        assert_eq!(source.get(7), Some(&record));
        assert_eq!(source.gate_seq(), source_gate);
        assert_eq!(destination.gate_seq(), destination_gate);
        assert!(destination.is_empty());
        assert_eq!(counters.steal_failures, 1);
        assert_eq!(counters.steals, 0);

        /* A committed steal inserts once at the destination frontier and
         * advances the destination gate exactly once. */
        let frontier = destination.frontier();
        let steal = try_steal(7, &mut source, &mut destination, true, &mut counters);
        assert!(steal.committed);
        assert!(source.is_empty());
        assert_eq!(destination.gate_seq(), destination_gate.wrapping_add(1));
        assert_eq!(
            destination.get(7).map(|queued| queued.v_q16),
            Some(frontier)
        );
        assert_eq!(counters.steals, 1);

        /* A steal of a task that is not in the source queue is refused. */
        let steal = try_steal(7, &mut source, &mut destination, true, &mut counters);
        assert!(!steal.committed);
        assert_eq!(counters.steal_refusals, 1);
    }

    #[test]
    fn repeated_peeks_and_a_refused_dispatch_change_nothing() {
        let mut sim = Simulator::new();
        let group = sim.add_group(0, 100);
        sim.add_task(group, 100);
        sim.add_task(group, 100);

        let before = sim.snapshot();
        for _ in 0..3 {
            assert_eq!(sim.peek(), sim.peek());
        }
        assert_eq!(sim.snapshot(), before);

        let peeked = sim.peek();
        assert_eq!(sim.try_dispatch(false), peeked);
        assert_eq!(sim.snapshot(), before);

        assert!(sim.dispatch().is_some());
        assert_ne!(sim.snapshot(), before);
    }

    #[test]
    fn the_simulator_shares_one_cpu_across_three_levels() {
        let mut sim = Simulator::new();
        let group = sim.add_group(0, 100);
        let subgroup = sim.add_group(group, 100);
        let light = sim.add_task(subgroup, 100);
        let heavy = sim.add_task(subgroup, 300);
        let direct = sim.add_task(0, 200);

        let slots = 2_400;
        let mut counts = vec![0usize; sim.nr_nodes()];
        for _ in 0..slots {
            let path = sim.dispatch().expect("a runnable task");
            counts[*path.last().expect("a leaf")] += 1;
            sim.tick(INF_SLOT_NS).expect("a closed slot");
        }

        /* group:direct is 100:200 at the root and light:heavy is 100:300
         * inside the nested group, so light 1/12, heavy 3/12, direct 8/12. */
        assert!(near(counts[light], slots / 12, slots / 40), "{counts:?}");
        assert!(near(counts[heavy], slots / 4, slots / 20), "{counts:?}");
        assert!(
            near(counts[direct], slots * 2 / 3, slots / 20),
            "{counts:?}"
        );
        assert_eq!(counts[group], 0);
        assert_eq!(counts[subgroup], 0);
        assert_eq!(sim.settled_ns(), slots as u64 * INF_SLOT_NS);
    }

    #[test]
    fn the_running_path_leaves_every_queue_and_reenters_through_the_normal_gate() {
        let mut sim = Simulator::new();
        let group = sim.add_group(0, 100);
        let task = sim.add_task(group, 100);

        let path = sim.dispatch().expect("a runnable task");
        assert_eq!(path, vec![group, task]);
        assert!(!sim.is_queued(task));
        assert!(!sim.is_queued(group));

        let root_gate = sim.gate_seq(0);
        let leaf_gate = sim.gate_seq(group);
        sim.tick(INF_SLOT_NS).expect("a closed slot");

        assert!(sim.is_queued(task));
        assert!(sim.is_queued(group));
        assert_eq!(sim.gate_seq(0), root_gate.wrapping_add(1));
        assert_eq!(sim.gate_seq(group), leaf_gate.wrapping_add(1));
    }

    #[test]
    fn a_yield_requeues_at_the_tail_and_a_stop_after_it_charges_nothing() {
        let mut sim = Simulator::new();
        let task = sim.add_task(0, 100);

        sim.dispatch().expect("a runnable task");
        let settlement = sim.yield_now(29_000).expect("a closed slot");

        assert_eq!(settlement.actual_ns, 29_000);
        assert_eq!(settlement.policy_ns, INF_SLOT_NS);
        assert_eq!(sim.settled_ns(), 29_000);
        assert!(sim.is_queued(task));
        /* The donor pays the reserved slot even though it stopped early. */
        assert_eq!(
            sim.service(task).v_q16(),
            charge(0, 0, INF_SLOT_NS, 100).delta_q16
        );
        assert!(!sim.reservation_open());

        let service_before = *sim.service(task);
        assert!(sim.sleep(task));
        assert!(!sim.is_queued(task));
        assert_eq!(*sim.service(task), service_before);
        assert_eq!(sim.settled_ns(), 29_000);
        assert_eq!(sim.counters().yield_charges, 1);
    }

    #[test]
    fn a_cgroup_move_starts_at_the_destination_frontier_without_carrying_v() {
        let mut sim = Simulator::new();
        let source = sim.add_group(0, 100);
        let task = sim.add_task(source, 100);

        for _ in 0..4 {
            sim.dispatch().expect("a runnable task");
            sim.tick(INF_SLOT_NS).expect("a closed slot");
        }
        let source_v = sim.service(task).v_q16();
        let source_history = sim.service(source).v_q16();
        let settled = sim.settled_ns();
        assert_ne!(source_v, 0);
        assert_ne!(source_history, 0);

        let destination = sim.add_group(0, 100);
        assert_eq!(sim.frontier(destination), 0);
        assert!(sim.move_task(task, destination));

        /* The source value is not carried. The task starts at the
         * destination frontier with no residue. */
        assert_eq!(sim.service(task).v_q16(), 0);
        assert_eq!(sim.service(task).rem(), 0);
        assert_ne!(sim.service(task).v_q16(), source_v);
        /* The source keeps its history and the move charges nothing. */
        assert_eq!(sim.service(source).v_q16(), source_history);
        assert_eq!(sim.frontier(destination), 0);
        assert_eq!(sim.settled_ns(), settled);
        assert!(sim.is_queued(task));
        assert!(!sim.is_queued(source));
        assert!(sim.is_queued(destination));

        /* The moved task runs from the new parent on the next slot. */
        let path = sim.dispatch().expect("a runnable task");
        assert_eq!(path, vec![destination, task]);
        sim.tick(INF_SLOT_NS).expect("a closed slot");
        assert_eq!(sim.settled_ns(), settled + INF_SLOT_NS);
    }

    #[test]
    fn a_queued_reweight_keeps_v_and_takes_one_normal_gate_step() {
        let mut sim = Simulator::new();
        let group = sim.add_group(0, 100);
        let task = sim.add_task(group, 100);
        let v_q16 = sim.service(task).v_q16();
        let gate = sim.gate_seq(group);

        assert!(sim.reweight(task, 300));
        assert_eq!(sim.service(task).weight(), 300);
        assert_eq!(sim.service(task).v_q16(), v_q16);
        assert_eq!(sim.service(task).rem(), 0);
        assert_eq!(sim.gate_seq(group), gate.wrapping_add(1));
        assert!(sim.is_queued(task));
    }

    #[test]
    fn a_dormant_group_keeps_its_history_for_the_next_activation() {
        let mut sim = Simulator::new();
        let group = sim.add_group(0, 100);
        let task = sim.add_task(group, 100);

        for _ in 0..2 {
            sim.dispatch().expect("a runnable task");
            sim.tick(INF_SLOT_NS).expect("a closed slot");
        }
        let frontier = sim.frontier(group);
        let history = sim.service(group).v_q16();
        assert!(frontier > 0);

        assert!(sim.sleep(task));
        assert!(!sim.is_queued(group));
        assert_eq!(sim.service(group).v_q16(), history);
        assert_eq!(sim.frontier(group), frontier);

        /* Re-activation clamps to the retained frontier. */
        let revived = sim.add_task(group, 100);
        assert!(sim.is_queued(revived));
        assert_eq!(sim.service(revived).v_q16(), frontier);
    }

    #[test]
    fn a_steal_moves_a_task_between_parents_and_a_failure_restores_it() {
        let mut sim = Simulator::new();
        let source = sim.add_group(0, 100);
        let destination = sim.add_group(0, 100);
        let moved = sim.add_task(source, 100);
        sim.add_task(source, 100);

        for _ in 0..2 {
            sim.dispatch().expect("a runnable task");
            sim.tick(INF_SLOT_NS).expect("a closed slot");
        }
        let record = sim.queue_entry(source, moved).expect("the task is queued");
        let source_gate = sim.gate_seq(source);
        let destination_gate = sim.gate_seq(destination);
        let settled = sim.settled_ns();

        /* A refused steal restores the exact source record and gate. */
        assert!(!sim.steal(moved, destination, false));
        assert_eq!(sim.queue_entry(source, moved), Some(record));
        assert_eq!(sim.gate_seq(source), source_gate);
        assert_eq!(sim.gate_seq(destination), destination_gate);
        assert_eq!(sim.settled_ns(), settled);
        assert_eq!(sim.counters().steal_failures, 1);

        /* A committed steal inserts once at the destination frontier. */
        let destination_frontier = sim.frontier(destination);
        assert!(sim.steal(moved, destination, true));
        assert!(sim.queue_entry(source, moved).is_none());
        assert_eq!(
            sim.queue_entry(destination, moved).map(|entry| entry.v_q16),
            Some(destination_frontier)
        );
        assert_eq!(sim.service(moved).v_q16(), destination_frontier);
        assert_eq!(sim.service(moved).rem(), 0);
        assert_eq!(sim.gate_seq(destination), destination_gate.wrapping_add(1));
        assert_eq!(sim.settled_ns(), settled);
        assert_eq!(sim.counters().steals, 1);
    }

    fn near(actual: usize, expected: usize, tolerance: usize) -> bool {
        actual.abs_diff(expected) <= tolerance
    }
}

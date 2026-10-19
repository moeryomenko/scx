// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Pure model of the locality-first placement order.
//!
//! `src/bpf/main.bpf.c` implements the same order over a scheduler-local
//! topology map. The model keeps the ranking and mask filtering testable
//! without a kernel. The class values are shared through `intf.h`.
#![allow(dead_code)]

use clap::ValueEnum;

/// Default queue depth at which a CPU is considered crowded.
pub const SPILL_THRESHOLD_DEFAULT: u32 = 4;
/// Lowest accepted spill threshold.
pub const SPILL_THRESHOLD_MIN: u32 = 1;
/// Highest accepted spill threshold.
pub const SPILL_THRESHOLD_MAX: u32 = 64;

/// Placement preference. `Auto` walks the full locality order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum PlacementMode {
    #[default]
    Auto,
    Llc,
    Numa,
    Machine,
}

impl PlacementMode {
    /// Value written to the BPF `placement_mode` rodata field.
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Auto => 0,
            Self::Llc => 1,
            Self::Numa => 2,
            Self::Machine => 3,
        }
    }
}

/// Best to worst placement class.
pub const CLASS_IDLE_CORE_LLC: u32 = 0;
pub const CLASS_IDLE_CORE_NODE: u32 = 1;
pub const CLASS_IDLE_CORE_REMOTE: u32 = 2;
pub const CLASS_IDLE_THREAD_LLC: u32 = 3;
pub const CLASS_IDLE_THREAD_NODE: u32 = 4;
pub const CLASS_IDLE_THREAD_REMOTE: u32 = 5;
pub const CLASS_CAPACITY: u32 = 6;

/// One CPU row, matching the seeded BPF `inf_cpu_topo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuTopo {
    pub cpu: usize,
    pub node: usize,
    pub llc: usize,
    pub core: usize,
    pub sibling: Option<usize>,
    pub primary: bool,
    pub capacity: u32,
    pub online: bool,
}

/// One node distance row. `node_distances[node][peer]` is the distance.
#[derive(Clone, Debug, Default)]
pub struct TopologyView {
    pub cpus: Vec<CpuTopo>,
    pub node_distances: Vec<Vec<u32>>,
}

/// Inputs of one placement decision.
#[derive(Clone, Debug, Default)]
pub struct PlacementRequest {
    pub prev_cpu: usize,
    pub this_cpu: usize,
    /// `true` for a CPU in the task affinity and cpuset mask.
    pub allowed: Vec<bool>,
    /// `true` when the CPU is idle.
    pub idle: Vec<bool>,
    /// `true` when every thread of the CPU's physical core is idle.
    pub idle_core: Vec<bool>,
    /// Advisory per-CPU queue depth.
    pub depth: Vec<u32>,
    /// The task cannot migrate.
    pub pinned: bool,
}

#[derive(Clone, Copy, Debug)]
struct Score {
    class: u32,
    distance: u32,
    capacity: u32,
    depth: u32,
    cpu: usize,
}

fn allowed_cpu<'a>(
    view: &'a TopologyView,
    req: &PlacementRequest,
    cpu: usize,
) -> Option<&'a CpuTopo> {
    let topo = view.cpus.get(cpu)?;
    if !topo.online || !req.allowed.get(cpu).copied().unwrap_or(false) {
        return None;
    }
    Some(topo)
}

fn first_allowed(view: &TopologyView, req: &PlacementRequest, primary_only: bool) -> Option<usize> {
    view.cpus
        .iter()
        .filter(|topo| allowed_cpu(view, req, topo.cpu).is_some())
        .find(|topo| !primary_only || topo.primary)
        .map(|topo| topo.cpu)
}

/// The waker CPU when allowed, else the previous CPU, else any allowed CPU.
fn local_cpu(view: &TopologyView, req: &PlacementRequest) -> Option<usize> {
    for cpu in [req.this_cpu, req.prev_cpu] {
        if allowed_cpu(view, req, cpu).is_some() {
            return Some(cpu);
        }
    }
    first_allowed(view, req, false)
}

fn node_distance(view: &TopologyView, from: usize, to: usize) -> u32 {
    view.node_distances
        .get(from)
        .and_then(|row| row.get(to))
        .copied()
        .unwrap_or(u32::MAX)
}

fn classify(
    topo: &CpuTopo,
    local: &CpuTopo,
    mode: PlacementMode,
    core_idle: bool,
    thread_idle: bool,
) -> Option<u32> {
    if mode == PlacementMode::Machine {
        return Some(CLASS_CAPACITY);
    }
    if mode == PlacementMode::Llc && topo.llc != local.llc {
        return None;
    }
    if mode == PlacementMode::Numa && topo.node != local.node {
        return None;
    }

    if core_idle {
        if topo.llc == local.llc {
            Some(CLASS_IDLE_CORE_LLC)
        } else if topo.node == local.node {
            Some(CLASS_IDLE_CORE_NODE)
        } else {
            Some(CLASS_IDLE_CORE_REMOTE)
        }
    } else if thread_idle {
        if topo.llc == local.llc {
            Some(CLASS_IDLE_THREAD_LLC)
        } else if topo.node == local.node {
            Some(CLASS_IDLE_THREAD_NODE)
        } else {
            Some(CLASS_IDLE_THREAD_REMOTE)
        }
    } else {
        Some(CLASS_CAPACITY)
    }
}

fn score_better(a: &Score, b: &Score) -> bool {
    (
        a.class,
        a.distance,
        std::cmp::Reverse(a.capacity),
        a.depth,
        a.cpu,
    ) < (
        b.class,
        b.distance,
        std::cmp::Reverse(b.capacity),
        b.depth,
        b.cpu,
    )
}

fn capacity_better(a: &Score, b: &Score, spill: u32) -> bool {
    let a_fits = a.depth < spill;
    let b_fits = b.depth < spill;

    if a_fits != b_fits {
        return a_fits;
    }
    if a.capacity != b.capacity {
        return a.capacity > b.capacity;
    }
    if a.depth != b.depth {
        return a.depth < b.depth;
    }
    a.cpu < b.cpu
}

/// Pick a CPU for one wakeup.
///
/// The order is previous CPU when idle, then an idle physical core in the
/// local LLC, the local node and a remote node, then an idle SMT thread in
/// the same three scopes, then capacity ranking. A pinned task keeps its
/// previous CPU or any CPU in its mask. With `smt` off, an SMT sibling of a
/// busy core is never returned while a primary thread is available.
pub fn pick(
    view: &TopologyView,
    req: &PlacementRequest,
    mode: PlacementMode,
    smt: bool,
    spill_threshold: u32,
) -> Option<usize> {
    let local = local_cpu(view, req)?;
    let local_topo = allowed_cpu(view, req, local)?;

    if req.pinned || req.allowed.iter().filter(|allowed| **allowed).count() == 1 {
        return allowed_cpu(view, req, req.prev_cpu)
            .map(|topo| topo.cpu)
            .or(Some(local));
    }

    if let Some(topo) = allowed_cpu(view, req, req.prev_cpu)
        && (smt || topo.primary)
        && req.idle.get(topo.cpu).copied().unwrap_or(false)
    {
        return Some(topo.cpu);
    }

    let spill = spill_threshold.clamp(SPILL_THRESHOLD_MIN, SPILL_THRESHOLD_MAX);
    let mut best: Option<Score> = None;
    let mut capacity: Option<Score> = None;

    for topo in &view.cpus {
        if allowed_cpu(view, req, topo.cpu).is_none() {
            continue;
        }
        if !smt && !topo.primary {
            continue;
        }

        let core_idle = req.idle_core.get(topo.cpu).copied().unwrap_or(false);
        let thread_idle = req.idle.get(topo.cpu).copied().unwrap_or(false);
        let Some(class) = classify(topo, local_topo, mode, core_idle, thread_idle) else {
            continue;
        };

        let distance = if class == CLASS_IDLE_CORE_REMOTE || class == CLASS_IDLE_THREAD_REMOTE {
            node_distance(view, local_topo.node, topo.node)
        } else {
            0
        };
        let score = Score {
            class,
            distance,
            capacity: topo.capacity,
            depth: req.depth.get(topo.cpu).copied().unwrap_or(0),
            cpu: topo.cpu,
        };

        if class == CLASS_CAPACITY {
            if capacity.is_none_or(|current| capacity_better(&score, &current, spill)) {
                capacity = Some(score);
            }
        } else if best.is_none_or(|current| score_better(&score, &current)) {
            best = Some(score);
        }
    }

    if let Some(score) = best {
        return Some(score.cpu);
    }
    if let Some(score) = capacity {
        return Some(score.cpu);
    }

    first_allowed(view, req, !smt).or(Some(local))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(
        id: usize,
        node: usize,
        llc: usize,
        core: usize,
        sibling: Option<usize>,
        capacity: u32,
    ) -> CpuTopo {
        CpuTopo {
            cpu: id,
            node,
            llc,
            core,
            sibling,
            primary: sibling.is_none_or(|peer| id < peer),
            capacity,
            online: true,
        }
    }

    /// 16 CPUs, two nodes, four LLCs, two threads per core.
    ///
    /// node 0: llc 0 (cores 0, 1), llc 1 (cores 2, 3)
    /// node 1: llc 2 (cores 4, 5)
    /// node 2: llc 3 (cores 6, 7)
    fn view() -> TopologyView {
        let mut cpus = Vec::new();
        for (base, node, llc) in [(0usize, 0usize, 0usize), (4, 0, 1), (8, 1, 2), (12, 2, 3)] {
            for core in 0..2 {
                let first = base + core * 2;
                cpus.push(cpu(first, node, llc, llc * 2 + core, Some(first + 1), 100));
                cpus.push(cpu(first + 1, node, llc, llc * 2 + core, Some(first), 100));
            }
        }
        TopologyView {
            cpus,
            node_distances: vec![vec![10, 20, 30], vec![20, 10, 25], vec![30, 25, 10]],
        }
    }

    fn request(n: usize, prev_cpu: usize, this_cpu: usize) -> PlacementRequest {
        PlacementRequest {
            prev_cpu,
            this_cpu,
            allowed: vec![true; n],
            idle: vec![false; n],
            idle_core: vec![false; n],
            depth: vec![0; n],
            pinned: false,
        }
    }

    #[test]
    fn classes_and_modes_match_the_bpf_header() {
        assert_eq!(
            CLASS_IDLE_CORE_LLC,
            crate::bpf_intf::INF_CLASS_IDLE_CORE_LLC
        );
        assert_eq!(
            CLASS_IDLE_CORE_NODE,
            crate::bpf_intf::INF_CLASS_IDLE_CORE_NODE
        );
        assert_eq!(
            CLASS_IDLE_CORE_REMOTE,
            crate::bpf_intf::INF_CLASS_IDLE_CORE_REMOTE
        );
        assert_eq!(
            CLASS_IDLE_THREAD_LLC,
            crate::bpf_intf::INF_CLASS_IDLE_THREAD_LLC
        );
        assert_eq!(
            CLASS_IDLE_THREAD_NODE,
            crate::bpf_intf::INF_CLASS_IDLE_THREAD_NODE
        );
        assert_eq!(
            CLASS_IDLE_THREAD_REMOTE,
            crate::bpf_intf::INF_CLASS_IDLE_THREAD_REMOTE
        );
        assert_eq!(CLASS_CAPACITY, crate::bpf_intf::INF_CLASS_CAPACITY);
        assert_eq!(
            PlacementMode::Auto.as_u32(),
            crate::bpf_intf::INF_PLACEMENT_AUTO
        );
        assert_eq!(
            PlacementMode::Llc.as_u32(),
            crate::bpf_intf::INF_PLACEMENT_LLC
        );
        assert_eq!(
            PlacementMode::Numa.as_u32(),
            crate::bpf_intf::INF_PLACEMENT_NUMA
        );
        assert_eq!(
            PlacementMode::Machine.as_u32(),
            crate::bpf_intf::INF_PLACEMENT_MACHINE
        );
    }

    #[test]
    fn previous_idle_cpu_wins() {
        let view = view();
        let mut req = request(view.cpus.len(), 2, 0);
        req.idle[0] = true;
        req.idle[2] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(2));
    }

    #[test]
    fn local_llc_idle_core_wins_over_the_node() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle_core[6] = true;
        req.idle_core[8] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(6));
    }

    #[test]
    fn nearest_remote_node_wins() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle_core[8] = true;
        req.idle_core[12] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(8));
    }

    #[test]
    fn idle_core_wins_over_an_idle_smt_sibling() {
        let view = view();
        let mut req = request(view.cpus.len(), 0, 0);
        /* CPU 1 is the sibling of busy CPU 0. CPU 2 is a full idle core. */
        req.idle[1] = true;
        req.idle[2] = true;
        req.idle_core[2] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(2));
    }

    #[test]
    fn capacity_ranking_picks_the_faster_cpu() {
        let mut view = view();
        view.cpus[2].capacity = 200;
        view.cpus[3].capacity = 300;
        let req = request(view.cpus.len(), 1, 0);

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(3));
    }

    #[test]
    fn spill_threshold_prefers_a_cpu_below_the_threshold() {
        let mut view = view();
        view.cpus[2].capacity = 400;
        view.cpus[3].capacity = 300;
        let mut req = request(view.cpus.len(), 1, 0);
        req.depth[2] = 4;
        req.depth[3] = 1;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(3));
        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 5), Some(2));
    }

    #[test]
    fn pinned_task_stays_in_its_mask() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.allowed = vec![false; view.cpus.len()];
        req.allowed[7] = true;
        req.pinned = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(7));
    }

    #[test]
    fn affinity_filter_drives_the_local_domain() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.allowed = vec![false; view.cpus.len()];
        req.allowed[6] = true;
        req.idle_core[6] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(6));
    }

    #[test]
    fn smt_off_never_returns_a_sibling_of_a_busy_core() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        /* Only the sibling of busy CPU 0 is idle. */
        req.idle[1] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), Some(1));

        let picked = pick(&view, &req, PlacementMode::Auto, false, 4).unwrap();
        assert!(view.cpus[picked].primary);
        assert_ne!(picked, 1);
    }

    #[test]
    fn offline_cpus_are_skipped() {
        let mut view = view();
        view.cpus[1].online = false;
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle[1] = true;

        let picked = pick(&view, &req, PlacementMode::Auto, true, 4).unwrap();
        assert_ne!(picked, 1);
    }

    #[test]
    fn llc_mode_stays_in_the_local_llc() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle_core[6] = true;

        let picked = pick(&view, &req, PlacementMode::Llc, true, 4).unwrap();
        assert_eq!(view.cpus[picked].llc, 0);
    }

    #[test]
    fn numa_mode_does_not_leave_the_local_node() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle_core[8] = true;

        let picked = pick(&view, &req, PlacementMode::Numa, true, 4).unwrap();
        assert_eq!(view.cpus[picked].node, 0);
    }

    #[test]
    fn machine_mode_ignores_locality_and_idle_state() {
        let mut view = view();
        view.cpus[2].capacity = 500;
        let mut req = request(view.cpus.len(), 1, 0);
        req.idle_core[8] = true;

        assert_eq!(pick(&view, &req, PlacementMode::Machine, true, 4), Some(2));
    }

    #[test]
    fn an_empty_mask_returns_nothing() {
        let view = view();
        let mut req = request(view.cpus.len(), 1, 0);
        req.allowed = vec![false; view.cpus.len()];

        assert_eq!(pick(&view, &req, PlacementMode::Auto, true, 4), None);
    }
}

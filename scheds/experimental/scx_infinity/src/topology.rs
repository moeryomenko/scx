// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Seed the scheduler-local BPF topology from `scx_utils::Topology`.
//!
//! The map is scheduler-local on purpose. It carries the node, LLC, core,
//! SMT sibling and capacity data the placement order needs, and the shared
//! utilities stay free of placement policy.

use std::mem::size_of_val;

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use log::info;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;

use crate::BpfSkel;
use crate::bpf_intf;

/// Distance used for a node pair the loader does not know.
const NODE_DISTANCE_FAR: u32 = 1000;

fn update_cpu(skel: &mut BpfSkel<'_>, cpu: u32, entry: &bpf_intf::inf_cpu_topo) -> Result<()> {
    let key = cpu.to_ne_bytes();
    /* SAFETY: the entry is a plain C-layout value and its length is exact. */
    let value =
        unsafe { std::slice::from_raw_parts(entry as *const _ as *const u8, size_of_val(entry)) };
    skel.maps
        .topo_stor
        .update(&key, value, MapFlags::ANY)
        .with_context(|| format!("failed to seed placement topology for CPU {cpu}"))
}

fn update_node(skel: &mut BpfSkel<'_>, node: u32, entry: &bpf_intf::inf_node_topo) -> Result<()> {
    let key = node.to_ne_bytes();
    /* SAFETY: the entry is a plain C-layout value and its length is exact. */
    let value =
        unsafe { std::slice::from_raw_parts(entry as *const _ as *const u8, size_of_val(entry)) };
    skel.maps
        .node_topo_stor
        .update(&key, value, MapFlags::ANY)
        .with_context(|| format!("failed to seed NUMA distance row for node {node}"))
}

/// Write one CPU row per possible CPU id and one distance row per node.
///
/// A CPU outside the online span is written with `online == 0`, so the BPF
/// scan never selects it. A CPU with no known topology entry is treated the
/// same way.
pub fn seed(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<()> {
    let siblings = topo.sibling_cpus();
    let mut primary = vec![false; *NR_CPU_IDS];
    for core in topo.all_cores.values() {
        if let Some((&first, _)) = core.cpus.iter().next()
            && let Some(slot) = primary.get_mut(first)
        {
            *slot = true;
        }
    }

    let mut online = 0usize;
    for cpu in 0..*NR_CPU_IDS {
        /* SAFETY: generated C-layout struct; all-zero is the offline row. */
        let mut entry: bpf_intf::inf_cpu_topo = unsafe { std::mem::zeroed() };
        entry.sibling_cpu = bpf_intf::INF_NO_CPU;

        if topo.span.test_cpu(cpu)
            && let Some(cpu_topo) = topo.all_cpus.get(&cpu)
        {
            entry.node_id = u32::try_from(cpu_topo.node_id).unwrap_or(0);
            entry.llc_id = u32::try_from(cpu_topo.llc_id).unwrap_or(0);
            entry.core_id = u32::try_from(cpu_topo.core_id).unwrap_or(0);

            let sibling = siblings.get(cpu).copied().unwrap_or(-1);
            if sibling >= 0 {
                entry.sibling_cpu = sibling as u32;
            }

            let capacity = cpu_topo
                .kernel_cpu_capacity
                .unwrap_or(cpu_topo.cpu_capacity);
            entry.capacity = u32::try_from(capacity).unwrap_or(u32::MAX);
            entry.core_primary = u32::from(primary.get(cpu).copied().unwrap_or(true));
            entry.online = 1;
            online += 1;
        }

        update_cpu(skel, cpu as u32, &entry)?;
    }

    let mut nodes = 0usize;
    for node in topo.nodes.values() {
        let node_id = u32::try_from(node.id).context("node id does not fit in u32")?;
        if node_id >= bpf_intf::INF_MAX_NODES {
            continue;
        }

        /* SAFETY: generated C-layout struct; zero is a valid base value. */
        let mut entry: bpf_intf::inf_node_topo = unsafe { std::mem::zeroed() };
        entry.distance.fill(NODE_DISTANCE_FAR);
        for (target, distance) in node.distance.iter().enumerate() {
            if let Some(slot) = entry.distance.get_mut(target) {
                *slot = u32::try_from(*distance).unwrap_or(NODE_DISTANCE_FAR);
            }
        }

        update_node(skel, node_id, &entry)?;
        nodes += 1;
    }

    info!(
        "Placement topology: {online} online CPUs, {nodes} nodes, {} LLCs",
        topo.all_llcs.len()
    );
    Ok(())
}

// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
#[cfg(test)]
mod cgroup;
mod config;
#[cfg(test)]
mod model;
mod placement;
mod policy;
mod reload;
mod service;
mod topology;

use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use config::LiveConfig;
use config::Overrides;
use libbpf_rs::MapCore;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use log::error;
use log::info;
use placement::PlacementMode;
use scx_arena::ArenaLib;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::{CgroupBwSupport, resize_cgroup_bw, setup_cgroup_bw};

const SCHEDULER_NAME: &str = "scx_infinity";
const STATS_INTERVAL: Duration = Duration::from_millis(100);
/// cgroup v2 caps nesting at 32 levels.
const CGROUP_TREE_HEIGHT_MAX: u32 = 32;

/// scx_infinity: experimental sched_ext scheduler.
///
/// A bounded-LIFO scheduler with a hierarchical service order. The queue
/// takes seven head inserts and one tail insert per eight gated enqueues.
/// Wakeups pass the same gate, `SCX_ENQ_HEAD` is the only head-exempt
/// hint, and expiry, requeue, forced progress and yield enter at the
/// tail. One `ops.tick` call is one service slot, so the slot comes from
/// the measured kernel tick and is not a setting.
///
/// The TOML file at $XDG_CONFIG_HOME/scx_infinity/config.toml (or
/// $HOME/.config/scx_infinity/config.toml) holds the placement
/// preferences. A command-line value overrides the file. The file is
/// reloaded on SIGHUP; an invalid file is rejected as a whole and the
/// active settings stay live.
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Configuration file. Overrides the default XDG path.
    #[clap(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Removed in revision 4. Declared only to reject it with a clear
    /// migration message instead of a generic unknown-argument error.
    #[clap(long, value_name = "N", hide = true)]
    quantum_us: Option<u64>,

    /// Placement preference: auto, llc, numa or machine.
    #[clap(long, value_enum)]
    placement: Option<PlacementMode>,

    /// Do not place new work on an SMT sibling of a busy core.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_smt: bool,

    /// Queue depth at which a CPU is considered crowded, 1 to 64.
    #[clap(long, value_name = "N")]
    spill_threshold: Option<u32>,

    /// Minimum remaining slice of a preemption victim, in microseconds.
    #[clap(long, value_name = "N")]
    preempt_margin_us: Option<u64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Do not enforce cpu.max. cpu.weight and cpu.idle stay on.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_cpu_max: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Diagnostic: record queue transitions and dump the queue and task
    /// snapshots when the scheduler exits. The trace is off by default.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    trace: bool,

    /// Diagnostic: refuse this many local DSQ inserts to exercise the
    /// requeue fallback. Requires --trace for the transition records.
    #[clap(long, value_name = "N", hide = true)]
    test_dsq_refuse: Option<u64>,

    /// Diagnostic: refuse this many handoff operations of KIND, where KIND
    /// is dsq, dest-insert, source-remove, steal or hold. Each refusal is
    /// counted by faults_injected. Without the option no handoff is
    /// refused.
    #[clap(long, value_name = "KIND:COUNT", hide = true)]
    test_handoff_fail: Option<String>,
}

/// The handoff kinds of `--test-handoff-fail`, in the same order as the
/// `INF_HO_*` constants of the BPF interface.
const HANDOFF_FAULT_KINDS: [&str; 5] = ["dsq", "dest-insert", "source-remove", "steal", "hold"];

/// Parse `KIND:COUNT` into the kind index of the BPF interface and the
/// number of refusals to arm.
fn parse_handoff_fault(spec: &str) -> Result<(u32, u64)> {
    let (kind, count) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("--test-handoff-fail expects KIND:COUNT, got '{spec}'"))?;
    let index = HANDOFF_FAULT_KINDS
        .iter()
        .position(|name| *name == kind)
        .ok_or_else(|| {
            anyhow!(
                "--test-handoff-fail: unknown handoff kind '{kind}', expected one of {}",
                HANDOFF_FAULT_KINDS.join(", ")
            )
        })?;
    let count: u64 = count
        .parse()
        .with_context(|| format!("--test-handoff-fail: '{count}' is not a count of refusals"))?;
    if count == 0 {
        bail!("--test-handoff-fail: the count of refusals must be at least one");
    }
    /* Kind 0 is INF_HO_NONE, so the first injectable kind is 1. */
    Ok(((index + 1) as u32, count))
}

impl Opts {
    /// The command-line values that override the configuration file.
    fn overrides(&self) -> Overrides {
        Overrides {
            placement: self.placement,
            no_smt: self.no_smt,
            preempt_margin_us: self.preempt_margin_us,
            spill_threshold: self.spill_threshold,
        }
    }
}

fn describe(config: &LiveConfig) -> String {
    format!(
        "placement={:?} smt={} preempt_margin_ns={} spill_threshold={} stats_interval_ms={}",
        config.placement,
        config.smt,
        config.preempt_margin_ns,
        config.spill_threshold,
        config.stats_interval_ms,
    )
}

/// Publish one configuration with a single map update.
///
/// The BPF side reads the entry with one lookup per decision, so a reader
/// sees either the whole old value or the whole new one. The map is never
/// resized.
fn write_config(skel: &mut BpfSkel<'_>, config: &LiveConfig, generation: u32) -> Result<()> {
    let value = config.to_bpf(generation);
    /* SAFETY: the value is a plain C-layout struct and its length is exact. */
    let bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!(value) as *const u8,
            std::mem::size_of::<bpf_intf::inf_cfg>(),
        )
    };
    let key = 0u32.to_ne_bytes();

    skel.maps
        .cfg_stor
        .update(&key, bytes, libbpf_rs::MapFlags::ANY)
        .context("failed to publish the live configuration")
}

/// Read one fixed-size map value into a plain C-layout struct.
fn read_map_value<T: Copy, M: MapCore>(map: &M, key: &[u8]) -> Option<T> {
    let bytes = map.lookup(key, libbpf_rs::MapFlags::ANY).ok().flatten()?;
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    /* SAFETY: the length is checked and T is a plain C-layout struct. */
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

/// Name of one callback of the per-task transition trace, from `intf.h`.
fn callback_name(cb: i32) -> &'static str {
    match cb as u32 {
        bpf_intf::INF_CB_NONE => "none",
        bpf_intf::INF_CB_SELECT_CPU => "select_cpu",
        bpf_intf::INF_CB_ENQUEUE => "enqueue",
        bpf_intf::INF_CB_RUNNING => "running",
        bpf_intf::INF_CB_TICK => "tick",
        bpf_intf::INF_CB_STOPPING => "stopping",
        bpf_intf::INF_CB_DEQUEUE => "dequeue",
        bpf_intf::INF_CB_QUIESCENT => "quiescent",
        bpf_intf::INF_CB_DISPATCH => "dispatch",
        bpf_intf::INF_CB_YIELD => "yield",
        bpf_intf::INF_CB_SET_WEIGHT => "set_weight",
        bpf_intf::INF_CB_CGROUP_MOVE => "cgroup_move",
        bpf_intf::INF_CB_EXIT_TASK => "exit_task",
        bpf_intf::INF_TT_ENQ_RET => "enqueue_ret",
        bpf_intf::INF_TT_DISP_RET => "dispatch_ret",
        bpf_intf::INF_TT_TICK_CHECK => "tick_check",
        bpf_intf::INF_TT_DISP_CHECK => "dispatch_check",
        bpf_intf::INF_TT_ENQ_CHECK => "enqueue_check",
        _ => "unknown",
    }
}

/// Name of one trace operation, from `intf.h`.
fn trace_op_name(op: u32) -> &'static str {
    match op {
        bpf_intf::INF_TR_ENQ_PARK => "enq_park",
        bpf_intf::INF_TR_ENQ_STALE => "enq_stale",
        bpf_intf::INF_TR_ENQ_INSERT_FAIL => "enq_insert_fail",
        bpf_intf::INF_TR_INSERT => "insert",
        bpf_intf::INF_TR_DEQ_QUEUED => "deq_queued",
        bpf_intf::INF_TR_DEQ_PENDING => "deq_pending",
        bpf_intf::INF_TR_DEQ_REMOVE_FAIL => "deq_remove_fail",
        bpf_intf::INF_TR_DEQ_END => "deq_end",
        bpf_intf::INF_TR_POP => "pop",
        bpf_intf::INF_TR_POP_STALE => "pop_stale",
        bpf_intf::INF_TR_POP_AFFINITY => "pop_affinity",
        bpf_intf::INF_TR_POP_PENDING => "pop_pending",
        bpf_intf::INF_TR_DSQ_OK => "dsq_ok",
        bpf_intf::INF_TR_DSQ_REFUSED => "dsq_refused",
        bpf_intf::INF_TR_REQUEUE => "requeue",
        bpf_intf::INF_TR_REQUEUE_FAIL => "requeue_fail",
        bpf_intf::INF_TR_STEAL => "steal",
        bpf_intf::INF_TR_STEAL_SKIP => "steal_skip",
        bpf_intf::INF_TR_REMOVE => "remove",
        bpf_intf::INF_TR_REMOVE_FAIL => "remove_fail",
        bpf_intf::INF_TR_YIELD_TO => "yield_to",
        bpf_intf::INF_TR_REWEIGHT => "reweight",
        bpf_intf::INF_TR_EXIT => "exit",
        bpf_intf::INF_TR_SET_WEIGHT => "set_weight",
        bpf_intf::INF_TR_DISPATCH_EMPTY => "dispatch_empty",
        bpf_intf::INF_TR_EXIT_PASS => "exit_pass",
        bpf_intf::INF_TR_ENQ_ENTER => "enq_enter",
        bpf_intf::INF_TR_QUIESCENT => "quiescent",
        bpf_intf::INF_TR_Q_LEAVE => "q_leave",
        bpf_intf::INF_TR_STOPPING => "stopping",
        bpf_intf::INF_TR_RUN_START => "run_start",
        bpf_intf::INF_TR_PATH_LOST => "path_lost",
        _ => "unknown",
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    config_path: Option<PathBuf>,
    overrides: Overrides,
    live: LiveConfig,
    generation: u32,
    trace: bool,
    /* The next frozen per-task trace the loader prints. */
    frozen_printed: std::sync::atomic::AtomicU32,
    /* Kept alive for as long as the scheduler uses the arena. */
    _arenalib: ArenaLib,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        live: LiveConfig,
        config_path: Option<PathBuf>,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        let topo = Topology::new().context("failed to read the host topology")?;
        let smt_enabled = live.smt && topo.smt_enabled;
        info!(
            "Placement: {:?}, SMT {}, spill threshold {}",
            live.placement,
            if smt_enabled { "on" } else { "off" },
            live.spill_threshold
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, infinity_ops, None)?;

        skel.struct_ops.infinity_ops_mut().exit_dump_len = opts.exit_dump_len;

        /*
         * Probe cpu.max support before load. The probe also clears the
         * callback on a kernel without ops.cgroup_set_bandwidth(), so the
         * scheduler still loads with cpu.weight and cpu.idle only.
         */
        let bw_support = setup_cgroup_bw(skel.open_object_mut(), "infinity_cgroup_set_bandwidth")?;
        let cpu_bw = !opts.no_cpu_max && bw_support != CgroupBwSupport::Unsupported;
        if opts.no_cpu_max {
            info!("cpu.max disabled by --no-cpu-max");
        }

        if cpu_bw {
            let nr_llcs = topo.all_llcs.len();
            resize_cgroup_bw(
                skel.open_object_mut(),
                bpf_intf::INF_MAX_CGROUPS,
                CGROUP_TREE_HEIGHT_MAX,
                nr_llcs,
            )?;
        }

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata is missing")?;
        rodata.nr_cpu_ids = (*NR_CPU_IDS)
            .try_into()
            .context("CPU count does not fit in u32")?;
        rodata.enable_cpu_bw = cpu_bw;
        rodata.enable_trace = opts.trace;
        rodata.inject_dsq_refusal = opts.test_dsq_refuse.is_some();
        /*
         * The handoff refusals are parsed before the load, so an invalid
         * KIND:COUNT fails before the scheduler attaches.
         */
        let handoff_fault = match opts.test_handoff_fail.as_deref() {
            Some(spec) => Some(parse_handoff_fault(spec)?),
            None => None,
        };
        rodata.inject_handoff_fault = handoff_fault.is_some();
        if opts.trace {
            info!("Diagnostic trace enabled");
        }
        if cpu_bw {
            /*
             * Match the map sizes set above and keep the built-in idle
             * tracking, which this scheduler uses for placement.
             */
            rodata.nr_cgrp_max = bpf_intf::INF_MAX_CGROUPS;
            rodata.tree_height_max = CGROUP_TREE_HEIGHT_MAX;
            rodata.bw_kick_builtin_idle = true;
        }

        let mut skel = scx_ops_load!(skel, infinity_ops, uei)?;

        /*
         * The task context lives in the BPF arena; the bandwidth library
         * parks throttled tasks on an arena queue that embeds it. The
         * arena must be set up before the scheduler attaches.
         */
        let task_size = std::mem::size_of::<bpf_intf::inf_task_ctx_layout>();
        let arenalib = ArenaLib::setup(skel.object_mut(), task_size, 0, *NR_CPU_IDS)
            .context("failed to initialize the BPF arena")?;

        topology::seed(&mut skel, &topo)?;
        write_config(&mut skel, &live, 1)?;
        let struct_ops = Some(scx_ops_attach!(skel, infinity_ops)?);

        /*
         * Arm the controlled-refusal counter after attach. The flag is a
         * rodata boolean, so a run without the option never reads the map.
         */
        if let Some(count) = opts.test_dsq_refuse {
            let value = bpf_intf::inf_test_ctl { dsq_refuse: count };
            /* SAFETY: the value is a plain C-layout struct and its length is exact. */
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(value) as *const u8,
                    std::mem::size_of::<bpf_intf::inf_test_ctl>(),
                )
            };
            skel.maps
                .test_stor
                .update(&0u32.to_ne_bytes(), bytes, libbpf_rs::MapFlags::ANY)
                .context("failed to arm the DSQ refusal injection")?;
            info!("Controlled DSQ refusal armed for {count} inserts");
        }

        /*
         * Arm one handoff refusal. The array is indexed by the INF_HO_*
         * kind, so the loader and the BPF side share the order of
         * HANDOFF_FAULT_KINDS.
         */
        if let Some((kind, count)) = handoff_fault {
            let mut value: bpf_intf::inf_fault_ctl = unsafe { std::mem::zeroed() };
            value.handoff_fail[(kind as usize) & 7] = count;
            /* SAFETY: the value is a plain C-layout struct and its length is exact. */
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(value) as *const u8,
                    std::mem::size_of::<bpf_intf::inf_fault_ctl>(),
                )
            };
            skel.maps
                .fault_stor
                .update(&0u32.to_ne_bytes(), bytes, libbpf_rs::MapFlags::ANY)
                .context("failed to arm the handoff refusal injection")?;
            info!(
                "Handoff refusal armed: {} x {count}",
                HANDOFF_FAULT_KINDS[(kind as usize) - 1]
            );
        }

        info!("Infinity configuration: {}", describe(&live));

        Ok(Self {
            skel,
            struct_ops,
            config_path,
            overrides: opts.overrides(),
            live,
            generation: 1,
            trace: opts.trace,
            frozen_printed: std::sync::atomic::AtomicU32::new(0),
            _arenalib: arenalib,
        })
    }

    /// Read the arena task-context counters. The map entry is written by
    /// `ops.init_task()` and `ops.exit_task()` on the BPF side.
    fn task_pool(&self) -> Option<bpf_intf::inf_task_pool> {
        read_map_value::<bpf_intf::inf_task_pool, _>(
            &self.skel.maps.task_pool_stor,
            &0u32.to_ne_bytes(),
        )
    }

    /// Print the lifetime of the arena task contexts.
    ///
    /// A context that is allocated and never freed keeps its arena pages
    /// for the rest of the run, so the pool eventually refuses an
    /// allocation and a fork fails with `scx_alloc failed`. The live value
    /// must return to zero when the workload drains; a peak far above the
    /// live count is the signature of a leak.
    fn log_task_pool(&self, when: &str) {
        let Some(pool) = self.task_pool() else {
            error!("tasks[{when}]: the task-context counter entry is missing");
            return;
        };

        info!(
            "tasks[{when}]: live={} peak={} inits={} reinits={} frees={} alloc_fail={} pool_full={} detach_fail={} no_ctx={}",
            pool.live,
            pool.peak,
            pool.inits,
            pool.reinits,
            pool.frees,
            pool.alloc_fail,
            pool.pool_full,
            pool.detach_fail,
            pool.no_ctx
        );
    }

    /// Print the diagnostic trace, the per-CPU queue snapshot and the task
    /// snapshot written by the BPF exit hook. A run without `--trace` prints
    /// nothing.
    fn dump_diagnostics(&self) {
        if !self.trace {
            return;
        }

        const TRACE_PRINT_MAX: u64 = 16384;
        let key = 0u32.to_ne_bytes();
        let Some(ctl) =
            read_map_value::<bpf_intf::inf_trace_ctl, _>(&self.skel.maps.trace_ctl_stor, &key)
        else {
            error!("diagnostics: the trace control entry is missing");
            return;
        };

        let cap = u64::from(ctl.cap);
        let kept = ctl.next.min(cap);
        let start = ctl.next.saturating_sub(TRACE_PRINT_MAX);
        info!(
            "diagnostics: enabled={} cap={} transitions={} ringed={} kept={} overwritten={} task_overflow={} printed={}",
            ctl.enabled,
            cap,
            ctl.total,
            ctl.next,
            kept,
            ctl.overwritten,
            ctl.task_overflow,
            ctl.next.saturating_sub(start)
        );
        if cap == 0 {
            error!(
                "diagnostics: the ring control entry carries no cap, so the ring was not armed by ops.init() and no record can be read"
            );
        }

        for cpu in 0..*NR_CPU_IDS {
            let key = (cpu as u32).to_ne_bytes();
            let Some(qs) =
                read_map_value::<bpf_intf::inf_queue_snap, _>(&self.skel.maps.qsnap_stor, &key)
            else {
                continue;
            };
            let mut calls = String::new();
            if let Ok(Some(row)) = self
                .skel
                .maps
                .cpu_ctx_stor
                .lookup(&key, libbpf_rs::MapFlags::ANY)
                && row.len() >= std::mem::size_of::<bpf_intf::inf_cpu_ctx>()
            {
                /* SAFETY: the map value is inf_cpu_ctx and the length is checked. */
                let cctx = unsafe {
                    std::ptr::read_unaligned(row.as_ptr() as *const bpf_intf::inf_cpu_ctx)
                };
                calls = format!(
                    " calls: disp={}/{} enq={} run={} stop={} qui={} deq={} tick={} last_disp_ns={}",
                    cctx.disp_calls,
                    cctx.disp_empty,
                    cctx.enq_calls,
                    cctx.run_calls,
                    cctx.stop_calls,
                    cctx.q_calls,
                    cctx.deq_calls,
                    cctx.tick_calls,
                    cctx.last_disp_ns
                );
            }
            info!(
                "infq: cpu={} depth={} w_sum={} head_pid={} head_state={} head_cpu={} head_gcpu={} head_hold={} head_slice={} head_weight={} head_key={} head_kflags=0x{:x} head_ops_state={} head_runnable_cpu={} local_nr={}{}",
                qs.cpu,
                qs.depth,
                qs.w_sum,
                qs.head_pid,
                qs.head_state,
                qs.head_cpu,
                qs.head_group_cpu,
                qs.head_hold,
                qs.head_slice,
                qs.head_weight,
                qs.head_key,
                qs.head_kflags,
                qs.head_ops_state,
                qs.head_runnable_cpu,
                qs.local_nr,
                calls
            );
        }

        let mut tasks = 0u32;
        for k in self.skel.maps.tsnap_stor.keys() {
            let Some(ts) =
                read_map_value::<bpf_intf::inf_task_snap, _>(&self.skel.maps.tsnap_stor, &k)
            else {
                continue;
            };
            tasks += 1;
            info!(
                "inftask: pid={} state={} queued_cpu={} group_cpu={} hold={} slice={} weight={} joined={} moving={} reweight_pending={} dequeue_pending={} exit_pending={} last_op={} src={} dst={} result={} ts={} prev_op={} prev_state={} prev_src={} prev_dst={} prev_result={} prev_ts={} node_owner={} leaf_idx={} leaf_cpu={} leaf_state={} leaf_count={} chain_broken={} path_depth={}",
                ts.pid,
                ts.state,
                ts.queued_cpu,
                ts.group_cpu,
                ts.hold,
                ts.slice,
                ts.weight,
                ts.joined,
                ts.moving,
                ts.reweight_pending,
                ts.dequeue_pending,
                ts.exit_pending,
                trace_op_name(ts.last_op),
                ts.last_src,
                ts.last_dst,
                ts.last_result,
                ts.ts,
                trace_op_name(ts.prev_op),
                ts.prev_state,
                ts.prev_src,
                ts.prev_dst,
                ts.prev_result,
                ts.prev_ts,
                ts.node_owner,
                ts.leaf_idx,
                ts.leaf_cpu,
                ts.leaf_state,
                ts.leaf_count,
                ts.chain_broken,
                ts.path_depth
            );

            let count = usize::min(ts.hist_count as usize, ts.hist.len());
            let mut hist = String::new();
            for slot in &ts.hist[..count] {
                if !hist.is_empty() {
                    hist.push(';');
                }
                hist.push_str(&format!(
                    "{},{},{},{},{}",
                    trace_op_name(slot.op),
                    slot.src,
                    slot.dst,
                    slot.result,
                    slot.state
                ));
            }
            info!("infhist: pid={} count={} {}", ts.pid, count, hist);
        }
        info!("diagnostics: task snapshots printed={tasks}");

        for seq in start..ctl.next {
            let slot = (seq % cap.max(1)) as u32;
            let Some(rec) = read_map_value::<bpf_intf::inf_trace_rec, _>(
                &self.skel.maps.trace_stor,
                &slot.to_ne_bytes(),
            ) else {
                continue;
            };
            info!(
                "inftr: seq={} op={} pid={} src={} dst={} state={} hold={} group_cpu={} slice={} result={} ts={}",
                rec.seq,
                trace_op_name(rec.op),
                rec.pid,
                rec.src_cpu,
                rec.dst_cpu,
                rec.state,
                rec.hold,
                rec.group_cpu,
                rec.slice,
                rec.result,
                rec.ts
            );
        }

        self.dump_task_traces();
    }

    /// Print one frozen trace: the detection line and every record the ring
    /// kept, oldest first.
    fn log_frozen_value(&self, slot: u32, fz: &bpf_intf::inf_tt_val) {
        info!(
            "infttfrozen: slot={} pid={} detected_cb={} records={}",
            slot,
            fz.pid,
            callback_name(fz.detected_cb as i32),
            fz.next
        );
        for rec in fz.rec.iter() {
            if rec.ts == 0 {
                break;
            }
            info!(
                "inftt: pid={} cb={} ts={} enq_flags=0x{:x} deq_flags=0x{:x} scx_flags=0x{:x} ops_state=0x{:x} dsq=0x{:x} task_cpu={} holding_cpu={} queued_cpu={} path_cpu={} ent_state={} node_owner={} chain_broken={} depth={} local_nr={} rq_nr={} ho_pending={} last_dsq_ret={}",
                rec.pid,
                callback_name(rec.cb),
                rec.ts,
                rec.enq_flags,
                rec.deq_flags,
                rec.scx_flags,
                rec.ops_state,
                rec.dsq,
                rec.task_cpu,
                rec.holding_cpu,
                rec.queued_cpu,
                rec.path_cpu,
                rec.ent_state,
                rec.node_owner,
                rec.chain_broken,
                rec.tree_depth,
                rec.local_nr,
                rec.rq_nr,
                rec.ho_pending,
                rec.last_dsq_ret
            );
        }
    }

    /// Print and publish every frozen trace that this run has not printed yet.
    ///
    /// The freeze happens in the BPF custody check, which sees the violation
    /// before the watchdog does. The loader prints the trace as soon as the
    /// frozen table names it, so the record survives even when the watchdog
    /// aborts the scheduler, and it writes one CANARY line to dmesg with the
    /// pid so the kernel log names the stranded task as well.
    fn log_new_frozen(&self) {
        let key = 0u32.to_ne_bytes();
        let Some(ctl) = read_map_value::<bpf_intf::inf_tt_ctl, _>(&self.skel.maps.ttctl_stor, &key)
        else {
            return;
        };
        let present = u32::try_from(ctl.frozen.min(u64::from(bpf_intf::INF_TT_FROZEN_MAX)))
            .unwrap_or(bpf_intf::INF_TT_FROZEN_MAX);
        let mut slot = self.frozen_printed.load(Ordering::Relaxed);
        while slot < present {
            let Some(fz) = read_map_value::<bpf_intf::inf_tt_val, _>(
                &self.skel.maps.ttfrozen_stor,
                &slot.to_ne_bytes(),
            ) else {
                break;
            };
            if fz.frozen_seq == 0 || fz.pid <= 0 {
                break;
            }
            self.log_frozen_value(slot, &fz);
            let canary = format!(
                "scx_infinity: CANARY stranded pid={} cb={} slot={}",
                fz.pid,
                callback_name(fz.detected_cb as i32),
                slot
            );
            if let Err(err) = std::fs::write("/dev/kmsg", format!("{canary}\n")) {
                error!("CANARY: cannot write to /dev/kmsg: {err}");
            } else {
                info!("{canary}");
            }
            slot += 1;
        }
        self.frozen_printed.store(slot, Ordering::Relaxed);
    }

    /// Print the per-task trace control entry and every frozen trace.
    fn dump_task_traces(&self) {
        let key = 0u32.to_ne_bytes();
        let Some(ctl) = read_map_value::<bpf_intf::inf_tt_ctl, _>(&self.skel.maps.ttctl_stor, &key)
        else {
            error!("diagnostics: the per-task trace control entry is missing");
            return;
        };

        info!(
            "inftt: enabled={} cap={} created={} checks={} scans={} stranded={} frozen={} canaries={} overwritten={}",
            ctl.enabled,
            ctl.cap,
            ctl.created,
            ctl.checks,
            ctl.scans,
            ctl.stranded,
            ctl.frozen,
            ctl.canaries,
            ctl.overwritten
        );

        self.log_new_frozen();
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /// Reload the configuration file and publish it when it is valid.
    ///
    /// The command-line overrides are applied again, so they persist
    /// across a reload. A rejected file logs the error and leaves the
    /// active configuration in place.
    fn reload_config(&mut self) {
        let path = self.config_path.clone();
        let overrides = self.overrides;
        let generation = self.generation.wrapping_add(1);
        let skel = &mut self.skel;

        match reload::reload(path.as_deref(), &overrides, |config| {
            write_config(skel, config, generation)
        }) {
            Ok(config) => {
                self.live = config;
                self.generation = generation;
                info!(
                    "Configuration reloaded (generation {}): {}",
                    generation,
                    describe(&self.live)
                );
            }
            Err(err) => {
                error!("Configuration reload failed, keeping the active settings: {err:#}");
            }
        }
    }

    fn log_stats(&self) {
        let mut head = 0u64;
        let mut tail = 0u64;
        let mut exempt = 0u64;
        let mut expiries = 0u64;
        let mut preemptions = 0u64;
        let mut yields = 0u64;
        let mut cgrp_throttled = 0u64;
        let mut cgrp_reenqueued = 0u64;
        let mut cgrp_eff_weight = 0u64;
        let mut cgrp_eff_min = 0u64;
        let mut cgrp_eff_max = 0u64;
        let mut cgrp_eff_samples = 0u64;
        let mut cgrp_scale = 0u64;
        let mut cgrp_refolds = 0u64;
        let mut deq_core_sched_exec = 0u64;
        let mut deq_sleep = 0u64;
        let mut deq_sched_change = 0u64;
        let mut deq_keep = 0u64;
        let mut q_sleep = 0u64;
        let mut q_sched_change = 0u64;
        let mut q_keep = 0u64;
        let mut cgrp_cpu_moves = 0u64;
        let mut steals = 0u64;
        let mut steal_llc = 0u64;
        let mut steal_node = 0u64;
        let mut yield_to_moves = 0u64;
        let mut reweight_moves = 0u64;
        let mut stale_pops = 0u64;
        let mut lost_state_errors = 0u64;
        let mut requeues = 0u64;
        let mut weight_changes = 0u64;
        let mut reweight_queued = 0u64;
        let mut weight_queued_cpu = 0u64;
        let mut exit_passes = 0u64;
        let mut enq_no_ctx = 0u64;
        let mut enq_no_cctx = 0u64;
        let mut stale_requeues = 0u64;
        let mut stale_skips = 0u64;
        let mut disp_pop = 0u64;
        let mut disp_renew = 0u64;
        let mut disp_total = 0u64;
        let mut disp_q = 0u64;
        let mut link_lost = 0u64;
        let mut count_lost = 0u64;
        let mut admit_unlinked = 0u64;
        let mut disp_empty_lost = 0u64;
        let mut run_unowned = 0u64;
        let mut stop_unowned = 0u64;
        let mut q_unowned = 0u64;
        let mut slot_end_stop = 0u64;
        let mut stop_slice_refused = 0u64;
        let mut disp_renew_unowned = 0u64;
        let mut runnable_unlinked = 0u64;
        let mut ticks = 0u64;
        let mut handoffs = 0u64;
        let mut handoff_max_ns = 0u64;
        let mut handoff_overdue = 0u64;
        let mut handoff_orphans = 0u64;
        let mut handoff_duplicates = 0u64;
        let mut faults_injected = 0u64;
        let mut core_rescues = 0u64;
        let mut core_missing_seen = 0u64;
        let mut dsq_refusals = 0u64;
        let mut entity_own = 0u64;
        let mut entity_ancestor = 0u64;
        let mut handoff_inflight = 0u64;

        let key = 0u32.to_ne_bytes();
        if let Ok(Some(rows)) = self
            .skel
            .maps
            .stats_stor
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            for row in rows {
                if row.len() < std::mem::size_of::<bpf_intf::inf_stats>() {
                    continue;
                }
                /* SAFETY: the map value is inf_stats and the length is checked. */
                let stats =
                    unsafe { std::ptr::read_unaligned(row.as_ptr() as *const bpf_intf::inf_stats) };
                head += stats.head_inserts;
                tail += stats.tail_inserts;
                exempt += stats.exempt_inserts;
                expiries += stats.expiries;
                preemptions += stats.preemptions;
                yields += stats.yields;
                cgrp_throttled += stats.cgrp_throttled;
                cgrp_reenqueued += stats.cgrp_reenqueued;
                cgrp_eff_weight = cgrp_eff_weight.max(stats.cgrp_eff_weight);
                if stats.cgrp_eff_min != 0 {
                    cgrp_eff_min = if cgrp_eff_min == 0 {
                        stats.cgrp_eff_min
                    } else {
                        cgrp_eff_min.min(stats.cgrp_eff_min)
                    };
                }
                cgrp_eff_max = cgrp_eff_max.max(stats.cgrp_eff_max);
                cgrp_eff_samples += stats.cgrp_eff_samples;
                cgrp_scale = cgrp_scale.max(stats.cgrp_scale);
                cgrp_refolds += stats.cgrp_refolds;
                deq_core_sched_exec += stats.deq_core_sched_exec;
                deq_sleep += stats.deq_sleep;
                deq_sched_change += stats.deq_sched_change;
                deq_keep += stats.deq_keep;
                q_sleep += stats.q_sleep;
                q_sched_change += stats.q_sched_change;
                q_keep += stats.q_keep;
                cgrp_cpu_moves += stats.cgrp_cpu_moves;
                steals += stats.steals;
                steal_llc += stats.steal_llc;
                steal_node += stats.steal_node;
                yield_to_moves += stats.yield_to_moves;
                reweight_moves += stats.reweight_moves;
                stale_pops += stats.stale_pops;
                lost_state_errors += stats.lost_state_errors;
                requeues += stats.requeues;
                weight_changes += stats.weight_changes;
                reweight_queued += stats.reweight_queued;
                weight_queued_cpu += stats.weight_queued_cpu;
                exit_passes += stats.exit_passes;
                enq_no_ctx += stats.enq_no_ctx;
                enq_no_cctx += stats.enq_no_cctx;
                stale_requeues += stats.stale_requeues;
                stale_skips += stats.stale_skips;
                disp_pop += stats.disp_pop;
                disp_renew += stats.disp_renew;
                disp_total += stats.disp_total;
                disp_q += stats.disp_q;
                link_lost += stats.link_lost;
                count_lost += stats.count_lost;
                admit_unlinked += stats.admit_unlinked;
                disp_empty_lost += stats.disp_empty_lost;
                run_unowned += stats.run_unowned;
                stop_unowned += stats.stop_unowned;
                q_unowned += stats.q_unowned;
                slot_end_stop += stats.slot_end_stop;
                stop_slice_refused += stats.stop_slice_refused;
                disp_renew_unowned += stats.disp_renew_unowned;
                runnable_unlinked += stats.runnable_unlinked;
                ticks += stats.tick_slots;
                handoffs += stats.handoffs;
                handoff_max_ns = handoff_max_ns.max(stats.handoff_max_ns);
                handoff_overdue += stats.handoff_overdue;
                handoff_orphans += stats.handoff_orphans;
                handoff_duplicates += stats.handoff_duplicates;
                faults_injected += stats.faults_injected;
                core_rescues += stats.core_rescues;
                core_missing_seen += stats.core_missing_seen;
                dsq_refusals += stats.dsq_refusals;
                entity_own += stats.entity_own;
                entity_ancestor += stats.entity_ancestor;
            }
        }

        let mut w_joins = 0u64;
        let mut w_leaves = 0u64;
        let mut w_reweights = 0u64;
        let mut w_moves = 0u64;
        let mut w_refolds = 0u64;
        let mut w_load_underflows = 0u64;
        let mut w_nr_underflows = 0u64;
        let mut w_epoch = 0u64;
        let mut w_init_idle = 0u64;
        let mut w_idle_on = 0u64;
        let mut w_idle_off = 0u64;
        if let Ok(Some(rows)) = self
            .skel
            .maps
            .scw_stats_stor
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            for row in rows {
                if row.len() < std::mem::size_of::<bpf_intf::inf_cgroup_weight_stats>() {
                    continue;
                }
                /* SAFETY: the map value is inf_cgroup_weight_stats and the length is checked. */
                let stats = unsafe {
                    std::ptr::read_unaligned(
                        row.as_ptr() as *const bpf_intf::inf_cgroup_weight_stats
                    )
                };
                w_joins += stats.joins;
                w_leaves += stats.leaves;
                w_reweights += stats.reweights;
                w_moves += stats.moves;
                w_refolds += stats.refolds;
                w_load_underflows += stats.load_underflows;
                w_nr_underflows += stats.nr_underflows;
                w_epoch = w_epoch.max(stats.epoch);
                w_init_idle += stats.init_idle;
                w_idle_on += stats.idle_on;
                w_idle_off += stats.idle_off;
            }
        }

        let mut depth = 0i64;
        for cpu in 0..*NR_CPU_IDS {
            let key = (cpu as u32).to_ne_bytes();
            if let Ok(Some(row)) = self
                .skel
                .maps
                .cpu_ctx_stor
                .lookup(&key, libbpf_rs::MapFlags::ANY)
                && row.len() >= std::mem::size_of::<bpf_intf::inf_cpu_ctx>()
            {
                /* SAFETY: the map value is inf_cpu_ctx and the length is checked. */
                let cctx = unsafe {
                    std::ptr::read_unaligned(row.as_ptr() as *const bpf_intf::inf_cpu_ctx)
                };
                depth += cctx.depth;
                handoff_inflight += cctx.ho_pid.iter().filter(|pid| **pid != 0).count() as u64;
            }
        }

        info!(
            "inserts: head={head} tail={tail} exempt={exempt} \
             expiries={expiries} preemptions={preemptions} yields={yields} \
             depth={depth} cgrp: throttled={cgrp_throttled} \
             reenqueued={cgrp_reenqueued} eff_weight={cgrp_eff_weight} \
             eff_min={cgrp_eff_min} eff_max={cgrp_eff_max} \
             eff_samples={cgrp_eff_samples} scale_q10={cgrp_scale} \
             refolds={cgrp_refolds} deq: sleep={deq_sleep} \
             sched_change={deq_sched_change} core_exec={deq_core_sched_exec} \
             keep={deq_keep} qui: sleep={q_sleep} \
             sched_change={q_sched_change} keep={q_keep} \
             cpu_moves={cgrp_cpu_moves} weight: joins={w_joins} leaves={w_leaves} \
             reweights={w_reweights} moves={w_moves} refolds={w_refolds} \
             underflow={w_load_underflows} nr_underflow={w_nr_underflows} \
             epoch={w_epoch} init_idle={w_init_idle} idle_on={w_idle_on} \
             idle_off={w_idle_off} queue: steals={steals} \
             llc={steal_llc} node={steal_node} yield_to={yield_to_moves} \
             reweight={reweight_moves} stale={stale_pops} \
             lost={lost_state_errors} requeues={requeues} \
             weight_changes={weight_changes} queued={reweight_queued} \
             queued_cpu={weight_queued_cpu} exit_passes={exit_passes} \
             no_ctx={enq_no_ctx} no_cctx={enq_no_cctx} \
             stale_requeues={stale_requeues} stale_skips={stale_skips} \
             disp: pop={disp_pop} renew={disp_renew} \
             total={disp_total} q={disp_q} path: link_lost={link_lost} \
             count_lost={count_lost} admit_unlinked={admit_unlinked} \
             empty_lost={disp_empty_lost} unowned: run={run_unowned} \
             stop={stop_unowned} qui={q_unowned} slot_end_stop={slot_end_stop} \
             stop_slice_refused={stop_slice_refused} \
             renew_unowned={disp_renew_unowned} runnable_unlinked={runnable_unlinked} \
             ticks={ticks} handoffs={handoffs} handoff_max_ns={handoff_max_ns} \
             handoff_overdue={handoff_overdue} handoff_orphans={handoff_orphans} \
             handoff_duplicates={handoff_duplicates} \
             faults_injected={faults_injected} core_rescues={core_rescues} \
             core_missing_seen={core_missing_seen} \
             handoff_inflight={handoff_inflight} dsq_refusals={dsq_refusals} \
             entity: own={entity_own} ancestor={entity_ancestor}"
        );

        if self.trace
            && let Some(ctl) =
                read_map_value::<bpf_intf::inf_trace_ctl, _>(&self.skel.maps.trace_ctl_stor, &key)
        {
            info!(
                "trace: transitions={} ringed={} cap={} overwritten={} task_overflow={}",
                ctl.total, ctl.next, ctl.cap, ctl.overwritten, ctl.task_overflow
            );
        }

        /* The arena task-context lifetime, once per stats interval. */
        self.log_task_pool("periodic");

        /* A frozen custody trace is printed as soon as it exists. */
        if self.trace {
            self.log_new_frozen();
        }
    }

    fn run(
        &mut self,
        shutdown: Arc<AtomicBool>,
        reload_flag: Arc<AtomicBool>,
    ) -> Result<UserExitInfo> {
        let mut last_stats = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(STATS_INTERVAL);

            if reload_flag.swap(false, Ordering::Relaxed) {
                self.reload_config();
            }

            let interval = Duration::from_millis(self.live.stats_interval_ms);
            if !interval.is_zero() && last_stats.elapsed() >= interval {
                self.log_stats();
                last_stats = Instant::now();
            }
        }

        let _ = self.struct_ops.take();
        /* The quiescent value of the pool, after the workload drained. */
        self.log_task_pool("exit");
        self.dump_diagnostics();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    /*
     * A revision-3 script may still pass the removed option. Reject it
     * before any file is read, so it is never accepted and ignored.
     */
    config::reject_removed_options(opts.quantum_us)?;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let overrides = opts.overrides();
    let config_path = config::resolve_path(opts.config.as_deref());
    match &config_path {
        Some(path) => info!("Configuration file: {}", path.display()),
        None => info!(
            "Configuration file: no usable path ({} or {}), the built-in defaults apply",
            config::CONFIG_PATH,
            config::CONFIG_PATH_FALLBACK
        ),
    }
    let live = config::load_resolved(config_path.as_deref(), &overrides)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    /*
     * ctrlc handles SIGINT only. SIGTERM needs the same graceful stop, and
     * SIGHUP must reload, so both use signal-hook.
     */
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())
        .context("Error setting SIGTERM handler")?;

    let reload_flag = reload::install_reload_flag()?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&opts, live, config_path, &mut open_object)?;
    sched.run(shutdown, reload_flag)?;
    info!("{} scheduler exited", SCHEDULER_NAME);

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_parses_exit_dump_len_and_verbose() {
        let opts =
            Opts::try_parse_from(["scx_infinity", "--exit-dump-len", "4096", "--verbose"]).unwrap();

        assert_eq!(opts.exit_dump_len, 4096);
        assert!(opts.verbose);
        assert!(!opts.version);
    }

    #[test]
    fn cli_without_an_option_leaves_no_override() {
        let opts = Opts::try_parse_from(["scx_infinity"]).unwrap();

        assert_eq!(opts.overrides(), Overrides::default());
    }

    #[test]
    fn cli_rejects_the_removed_quantum_option() {
        let opts = Opts::try_parse_from(["scx_infinity", "--quantum-us", "2000"]).unwrap();

        let error = config::reject_removed_options(opts.quantum_us).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("--quantum-us"), "{message}");
        assert!(message.contains("revision 4"), "{message}");
        assert!(message.contains("measured kernel tick"), "{message}");
    }

    #[test]
    fn cli_parses_the_handoff_fault_spec() {
        let opts =
            Opts::try_parse_from(["scx_infinity", "--test-handoff-fail", "dest-insert:4"]).unwrap();

        assert_eq!(
            parse_handoff_fault(opts.test_handoff_fail.as_deref().unwrap()).unwrap(),
            (2, 4)
        );
    }

    #[test]
    fn every_fault_kind_maps_to_its_bpf_index() {
        for (index, kind) in HANDOFF_FAULT_KINDS.iter().enumerate() {
            let spec = format!("{kind}:1");
            assert_eq!(
                parse_handoff_fault(&spec).unwrap(),
                ((index + 1) as u32, 1),
                "{kind}"
            );
        }
    }

    #[test]
    fn an_unknown_fault_kind_is_rejected() {
        let error = parse_handoff_fault("nonsense:1").unwrap_err().to_string();

        assert!(error.contains("unknown handoff kind"), "{error}");
        assert!(error.contains("dest-insert"), "{error}");
    }

    #[test]
    fn a_zero_handoff_fault_count_is_rejected() {
        let error = parse_handoff_fault("dsq:0").unwrap_err().to_string();

        assert!(error.contains("at least one"), "{error}");
    }

    #[test]
    fn the_help_hides_the_removed_quantum_option() {
        let help = Opts::command().render_help().to_string();

        assert!(!help.contains("quantum"), "{help}");
        assert!(help.contains("--preempt-margin-us"), "{help}");
    }

    #[test]
    fn cli_parses_placement_options() {
        let opts = Opts::try_parse_from([
            "scx_infinity",
            "--placement",
            "numa",
            "--no-smt",
            "--spill-threshold",
            "8",
            "--preempt-margin-us",
            "250",
        ])
        .unwrap();
        let overrides = opts.overrides();

        assert_eq!(overrides.placement, Some(PlacementMode::Numa));
        assert!(overrides.no_smt);
        assert_eq!(overrides.spill_threshold, Some(8));
        assert_eq!(overrides.preempt_margin_us, Some(250));
    }

    #[test]
    fn cli_parses_the_diagnostic_flags() {
        let opts =
            Opts::try_parse_from(["scx_infinity", "--trace", "--test-dsq-refuse", "4"]).unwrap();

        assert!(opts.trace);
        assert_eq!(opts.test_dsq_refuse, Some(4));

        let default = Opts::try_parse_from(["scx_infinity"]).unwrap();
        assert!(!default.trace);
        assert_eq!(default.test_dsq_refuse, None);
    }

    #[test]
    fn cli_parses_a_config_path() {
        let opts =
            Opts::try_parse_from(["scx_infinity", "--config", "/etc/infinity.toml"]).unwrap();

        assert_eq!(opts.config, Some(PathBuf::from("/etc/infinity.toml")));
        assert_eq!(
            config::resolve_path(opts.config.as_deref()),
            Some(PathBuf::from("/etc/infinity.toml"))
        );
    }

    #[test]
    fn cli_rejects_a_bad_placement() {
        assert!(Opts::try_parse_from(["scx_infinity", "--placement", "bad"]).is_err());
    }

    #[test]
    fn cli_parses_no_cpu_max() {
        let opts = Opts::try_parse_from(["scx_infinity", "--no-cpu-max"]).unwrap();

        assert!(opts.no_cpu_max);

        let default = Opts::try_parse_from(["scx_infinity"]).unwrap();
        assert!(!default.no_cpu_max);
    }
}

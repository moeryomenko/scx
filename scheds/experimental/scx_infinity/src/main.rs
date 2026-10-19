// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod config;
#[cfg(test)]
mod model;
mod placement;
mod policy;
mod reload;
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
/// A bounded-LIFO scheduler with a weighted quantum. The queue takes
/// seven head inserts and one tail insert per eight gated enqueues.
/// Wakeups pass the same gate, `SCX_ENQ_HEAD` is the only head-exempt
/// hint, and expiry, requeue, forced progress and yield enter at the
/// tail.
///
/// The TOML file at $XDG_CONFIG_HOME/scx_infinity/config.toml (or
/// $HOME/.config/scx_infinity/config.toml) holds the base quantum and the
/// placement preferences. A command-line value overrides the file. The
/// file is reloaded on SIGHUP; an invalid file is rejected as a whole and
/// the active settings stay live.
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Configuration file. Overrides the default XDG path.
    #[clap(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Infinity base quantum in microseconds, 100 to 4000.
    #[clap(long, value_name = "N")]
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
}

impl Opts {
    /// The command-line values that override the configuration file.
    fn overrides(&self) -> Overrides {
        Overrides {
            quantum_us: self.quantum_us,
            placement: self.placement,
            no_smt: self.no_smt,
            preempt_margin_us: self.preempt_margin_us,
            spill_threshold: self.spill_threshold,
        }
    }
}

fn describe(config: &LiveConfig) -> String {
    format!(
        "quantum_ns={} placement={:?} smt={} preempt_margin_ns={} spill_threshold={} stats_interval_ms={}",
        config.quantum_ns,
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

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    config_path: Option<PathBuf>,
    overrides: Overrides,
    live: LiveConfig,
    generation: u32,
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

        info!("Infinity configuration: {}", describe(&live));

        Ok(Self {
            skel,
            struct_ops,
            config_path,
            overrides: opts.overrides(),
            live,
            generation: 1,
            _arenalib: arenalib,
        })
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
        let mut cgrp_scale = 0u64;

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
                cgrp_scale = cgrp_scale.max(stats.cgrp_scale);
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
            }
        }

        info!(
            "inserts: head={head} tail={tail} exempt={exempt} \
             expiries={expiries} preemptions={preemptions} yields={yields} \
             depth={depth} cgrp: throttled={cgrp_throttled} \
             reenqueued={cgrp_reenqueued} eff_weight={cgrp_eff_weight} \
             scale_q10={cgrp_scale}"
        );
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
    fn cli_parses_quantum_us_into_an_override() {
        let opts = Opts::try_parse_from(["scx_infinity", "--quantum-us", "2000"]).unwrap();
        let overrides = opts.overrides();

        assert_eq!(overrides.quantum_us, Some(2000));
        assert_eq!(
            policy::quantum_us_to_ns(overrides.quantum_us.unwrap()).unwrap(),
            2_000_000
        );
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

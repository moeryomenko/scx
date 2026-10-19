// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod policy;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore;
use log::info;
use scx_utils::NR_CPU_IDS;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const SCHEDULER_NAME: &str = "scx_infinity";
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// scx_infinity: experimental sched_ext scheduler.
///
/// A bounded-LIFO scheduler with a weighted quantum. The queue takes
/// seven head inserts and one tail insert per eight regular enqueues,
/// fresh wakeups enter at the head, and expiry, requeue, forced progress
/// and yield enter at the tail.
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Infinity base quantum in microseconds.
    #[clap(long, default_value_t = policy::QUANTUM_DEFAULT_NS / 1000)]
    quantum_us: u64,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, infinity_ops, None)?;

        skel.struct_ops.infinity_ops_mut().exit_dump_len = opts.exit_dump_len;

        let quantum_ns = policy::quantum_us_to_ns(opts.quantum_us).map_err(anyhow::Error::msg)?;
        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata is missing")?;
        rodata.quantum_ns = quantum_ns;
        rodata.nr_cpu_ids = (*NR_CPU_IDS)
            .try_into()
            .context("CPU count does not fit in u32")?;
        info!("Infinity quantum: {quantum_ns} ns");

        let mut skel = scx_ops_load!(skel, infinity_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, infinity_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn log_stats(&self) {
        let mut head = 0u64;
        let mut tail = 0u64;
        let mut exempt = 0u64;
        let mut expiries = 0u64;
        let mut preemptions = 0u64;
        let mut yields = 0u64;

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
             depth={depth}"
        );
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut last_stats = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_millis(100));
            if last_stats.elapsed() >= STATS_INTERVAL {
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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    sched.run(shutdown)?;
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
        assert_eq!(opts.quantum_us, policy::QUANTUM_DEFAULT_NS / 1000);
        assert!(opts.verbose);
        assert!(!opts.version);
    }

    #[test]
    fn cli_parses_quantum_us() {
        let opts = Opts::try_parse_from(["scx_infinity", "--quantum-us", "2000"]).unwrap();

        assert_eq!(opts.quantum_us, 2000);
        assert_eq!(
            policy::quantum_us_to_ns(opts.quantum_us).unwrap(),
            2_000_000
        );
    }
}

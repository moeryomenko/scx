// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use log::info;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const SCHEDULER_NAME: &str = "scx_infinity";

/// scx_infinity: experimental sched_ext scheduler.
///
/// This build is a global FIFO skeleton. It exists to carry the loader and
/// the teardown path for the Infinity policy, which is not implemented here.
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

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

        let mut skel = scx_ops_load!(skel, infinity_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, infinity_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_millis(100));
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
        assert!(opts.verbose);
        assert!(!opts.version);
    }
}

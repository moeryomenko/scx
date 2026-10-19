// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! TOML configuration and CLI precedence.
//!
//! The file lives at `$XDG_CONFIG_HOME/scx_infinity/config.toml`, or at
//! `$HOME/.config/scx_infinity/config.toml` when `XDG_CONFIG_HOME` is
//! unset, empty or not absolute. `--config` overrides the path.
//!
//! A file is parsed and validated as a whole before any value reaches the
//! scheduler. A missing file means "use built-in defaults". Command-line
//! values are applied after every file load, so an override also applies to
//! a SIGHUP reload.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::bpf_intf;
use crate::placement::PlacementMode;
use crate::placement::SPILL_THRESHOLD_DEFAULT;
use crate::placement::SPILL_THRESHOLD_MAX;
use crate::placement::SPILL_THRESHOLD_MIN;
use crate::policy;

/// Directory under the XDG configuration root.
pub const CONFIG_DIR: &str = "scx_infinity";
/// File name below `CONFIG_DIR`.
pub const CONFIG_FILE: &str = "config.toml";
/// Exact primary path, spelled out for the README and diagnostics.
pub const CONFIG_PATH: &str = "$XDG_CONFIG_HOME/scx_infinity/config.toml";
/// Exact fallback path when `XDG_CONFIG_HOME` is unusable.
pub const CONFIG_PATH_FALLBACK: &str = "$HOME/.config/scx_infinity/config.toml";

/// Live settings. A missing file or a missing key keeps the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveConfig {
    pub quantum_ns: u64,
    pub placement: PlacementMode,
    pub smt: bool,
    pub preempt_margin_ns: u64,
    pub spill_threshold: u32,
    pub stats_interval_ms: u64,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            quantum_ns: policy::QUANTUM_DEFAULT_NS,
            placement: PlacementMode::Auto,
            smt: true,
            preempt_margin_ns: policy::PREEMPT_MARGIN_DEFAULT_NS,
            spill_threshold: SPILL_THRESHOLD_DEFAULT,
            stats_interval_ms: u64::from(bpf_intf::INF_STATS_INTERVAL_DEFAULT_MS),
        }
    }
}

impl LiveConfig {
    /// Convert to the single BPF `cfg_stor` value.
    pub fn to_bpf(self, generation: u32) -> bpf_intf::inf_cfg {
        bpf_intf::inf_cfg {
            quantum_ns: self.quantum_ns,
            preempt_margin_ns: self.preempt_margin_ns,
            placement_mode: self.placement.as_u32(),
            smt_enabled: u32::from(self.smt),
            spill_threshold: self.spill_threshold,
            generation,
        }
    }
}

/// On-disk schema. Unknown keys are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default = "default_quantum_ns")]
    pub quantum_ns: u64,
    #[serde(default)]
    pub placement: PlacementMode,
    #[serde(default = "default_smt")]
    pub smt: bool,
    #[serde(default = "default_preempt_margin_ns")]
    pub preempt_margin_ns: u64,
    #[serde(default = "default_spill_threshold")]
    pub spill_threshold: u32,
    #[serde(default = "default_stats_interval_ms")]
    pub stats_interval_ms: u64,
}

impl Default for FileConfig {
    fn default() -> Self {
        let live = LiveConfig::default();
        Self {
            quantum_ns: live.quantum_ns,
            placement: live.placement,
            smt: live.smt,
            preempt_margin_ns: live.preempt_margin_ns,
            spill_threshold: live.spill_threshold,
            stats_interval_ms: live.stats_interval_ms,
        }
    }
}

fn default_quantum_ns() -> u64 {
    policy::QUANTUM_DEFAULT_NS
}

fn default_smt() -> bool {
    true
}

fn default_preempt_margin_ns() -> u64 {
    policy::PREEMPT_MARGIN_DEFAULT_NS
}

fn default_spill_threshold() -> u32 {
    SPILL_THRESHOLD_DEFAULT
}

fn default_stats_interval_ms() -> u64 {
    u64::from(bpf_intf::INF_STATS_INTERVAL_DEFAULT_MS)
}

/// Values given on the command line. Each one wins over the file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    pub quantum_us: Option<u64>,
    pub placement: Option<PlacementMode>,
    pub no_smt: bool,
    pub preempt_margin_us: Option<u64>,
    pub spill_threshold: Option<u32>,
}

impl Overrides {
    fn apply(&self, cfg: &mut LiveConfig) -> Result<()> {
        if let Some(us) = self.quantum_us {
            cfg.quantum_ns = policy::quantum_us_to_ns(us).map_err(anyhow::Error::msg)?;
        }
        if let Some(placement) = self.placement {
            cfg.placement = placement;
        }
        if self.no_smt {
            cfg.smt = false;
        }
        if let Some(us) = self.preempt_margin_us {
            cfg.preempt_margin_ns = us
                .checked_mul(1_000)
                .context("preempt margin overflows nanoseconds")?;
        }
        if let Some(spill_threshold) = self.spill_threshold {
            cfg.spill_threshold = spill_threshold;
        }
        Ok(())
    }
}

/// The XDG configuration path.
///
/// `XDG_CONFIG_HOME` is used only when it is set, non-empty and absolute.
/// Otherwise the path falls back to `$HOME/.config`.
pub fn config_path(xdg_config_home: Option<&str>, home: Option<&str>) -> Result<PathBuf> {
    if let Some(xdg) = xdg_config_home {
        let base = PathBuf::from(xdg);
        if !xdg.is_empty() && base.is_absolute() {
            return Ok(base.join(CONFIG_DIR).join(CONFIG_FILE));
        }
    }

    let home = home.context("HOME is not set and XDG_CONFIG_HOME is unusable")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join(CONFIG_DIR)
        .join(CONFIG_FILE))
}

fn default_config_path() -> Option<PathBuf> {
    config_path(
        env::var("XDG_CONFIG_HOME").ok().as_deref(),
        env::var("HOME").ok().as_deref(),
    )
    .ok()
}

/// Resolve `--config` or the default XDG path. `None` means the process
/// has no usable configuration path, so the built-in defaults apply.
pub fn resolve_path(explicit: Option<&Path>) -> Option<PathBuf> {
    explicit.map(Path::to_path_buf).or_else(default_config_path)
}

/// Parse and validate a TOML file. A missing file is the default schema.
pub fn load_file(path: &Path) -> Result<FileConfig> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(FileConfig::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read configuration {}", path.display()));
        }
    };

    let cfg: FileConfig = toml::from_str(&text)
        .with_context(|| format!("failed to parse configuration {}", path.display()))?;
    validate_file(&cfg)?;
    Ok(cfg)
}

/// Validate every field and report all errors in one message.
pub fn validate_file(cfg: &FileConfig) -> Result<()> {
    let mut errors = Vec::new();

    if !(policy::QUANTUM_MIN_NS..=policy::QUANTUM_MAX_NS).contains(&cfg.quantum_ns) {
        errors.push(format!(
            "quantum_ns must be between {} and {}, got {}",
            policy::QUANTUM_MIN_NS,
            policy::QUANTUM_MAX_NS,
            cfg.quantum_ns
        ));
    }

    if cfg.preempt_margin_ns > policy::PREEMPT_MARGIN_MAX_NS {
        errors.push(format!(
            "preempt_margin_ns must be between 0 and {}, got {}",
            policy::PREEMPT_MARGIN_MAX_NS,
            cfg.preempt_margin_ns
        ));
    }

    if !(SPILL_THRESHOLD_MIN..=SPILL_THRESHOLD_MAX).contains(&cfg.spill_threshold) {
        errors.push(format!(
            "spill_threshold must be between {} and {}, got {}",
            SPILL_THRESHOLD_MIN, SPILL_THRESHOLD_MAX, cfg.spill_threshold
        ));
    }

    if errors.is_empty() {
        return Ok(());
    }

    let mut message = String::from("invalid configuration:");
    for error in errors {
        message.push_str("\n  - ");
        message.push_str(&error);
    }
    bail!(message)
}

/// Build the live configuration from the file and the CLI overrides.
///
/// The file is validated before any override is applied, and the merged
/// result is validated again. Nothing is returned unless the whole result
/// is valid, so a caller can publish it with one update.
pub fn load_resolved(path: Option<&Path>, overrides: &Overrides) -> Result<LiveConfig> {
    let file = match path {
        Some(path) => load_file(path)?,
        None => FileConfig::default(),
    };
    let mut cfg = LiveConfig {
        quantum_ns: file.quantum_ns,
        placement: file.placement,
        smt: file.smt,
        preempt_margin_ns: file.preempt_margin_ns,
        spill_threshold: file.spill_threshold,
        stats_interval_ms: file.stats_interval_ms,
    };

    overrides.apply(&mut cfg)?;
    validate_live(&cfg)?;
    Ok(cfg)
}

fn validate_live(cfg: &LiveConfig) -> Result<()> {
    let file = FileConfig {
        quantum_ns: cfg.quantum_ns,
        placement: cfg.placement,
        smt: cfg.smt,
        preempt_margin_ns: cfg.preempt_margin_ns,
        spill_threshold: cfg.spill_threshold,
        stats_interval_ms: cfg.stats_interval_ms,
    };
    validate_file(&file)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "scx_infinity_config_{}_{}.toml",
                std::process::id(),
                id
            ));
            fs::write(&path, contents).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn defaults_match_the_schema() {
        let cfg = FileConfig::default();

        assert_eq!(cfg.quantum_ns, policy::QUANTUM_DEFAULT_NS);
        assert_eq!(cfg.placement, PlacementMode::Auto);
        assert!(cfg.smt);
        assert_eq!(cfg.preempt_margin_ns, policy::PREEMPT_MARGIN_DEFAULT_NS);
        assert_eq!(cfg.spill_threshold, SPILL_THRESHOLD_DEFAULT);
        assert_eq!(
            cfg.stats_interval_ms,
            u64::from(bpf_intf::INF_STATS_INTERVAL_DEFAULT_MS)
        );
    }

    #[test]
    fn a_valid_file_is_loaded_with_every_field() {
        let file = TempFile::new(
            r#"
quantum_ns = 2000000
placement = "numa"
smt = false
preempt_margin_ns = 250000
spill_threshold = 8
stats_interval_ms = 500
"#,
        );

        let cfg = load_resolved(Some(file.path()), &Overrides::default()).unwrap();

        assert_eq!(cfg.quantum_ns, 2_000_000);
        assert_eq!(cfg.placement, PlacementMode::Numa);
        assert!(!cfg.smt);
        assert_eq!(cfg.preempt_margin_ns, 250_000);
        assert_eq!(cfg.spill_threshold, 8);
        assert_eq!(cfg.stats_interval_ms, 500);
    }

    #[test]
    fn a_missing_file_uses_the_defaults() {
        let path =
            env::temp_dir().join(format!("scx_infinity_missing_{}.toml", std::process::id()));

        let cfg = load_resolved(Some(&path), &Overrides::default()).unwrap();

        assert_eq!(cfg, LiveConfig::default());
    }

    #[test]
    fn cli_values_win_over_the_file() {
        let file = TempFile::new(
            r#"
quantum_ns = 1000000
placement = "llc"
smt = true
spill_threshold = 4
"#,
        );
        let overrides = Overrides {
            quantum_us: Some(3_000),
            placement: Some(PlacementMode::Machine),
            no_smt: true,
            spill_threshold: Some(16),
            ..Overrides::default()
        };

        let cfg = load_resolved(Some(file.path()), &overrides).unwrap();

        assert_eq!(cfg.quantum_ns, 3_000_000);
        assert_eq!(cfg.placement, PlacementMode::Machine);
        assert!(!cfg.smt);
        assert_eq!(cfg.spill_threshold, 16);
    }

    #[test]
    fn an_invalid_file_is_rejected() {
        let file = TempFile::new(
            r#"
quantum_ns = 1000000
placement = "realtime"
"#,
        );

        let error = load_resolved(Some(file.path()), &Overrides::default()).unwrap_err();

        assert!(error.to_string().contains("failed to parse configuration"));
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let file = TempFile::new(
            r#"
quantum_ns = 1000000
queue_order = "fifo"
"#,
        );

        let error = load_resolved(Some(file.path()), &Overrides::default()).unwrap_err();

        assert!(error.to_string().contains("failed to parse configuration"));
    }

    #[test]
    fn an_out_of_range_quantum_is_rejected() {
        for quantum_ns in [policy::QUANTUM_MIN_NS - 1, policy::QUANTUM_MAX_NS + 1] {
            let file = TempFile::new(&format!("quantum_ns = {quantum_ns}\n"));

            let error = load_resolved(Some(file.path()), &Overrides::default()).unwrap_err();

            assert!(error.to_string().contains("quantum_ns must be between"));
        }
    }

    #[test]
    fn an_out_of_range_cli_quantum_is_rejected() {
        let overrides = Overrides {
            quantum_us: Some(policy::QUANTUM_MAX_NS / 1000 + 1),
            ..Overrides::default()
        };

        let error = load_resolved(None, &overrides).unwrap_err();

        assert!(error.to_string().contains("quantum must be between"));
    }

    #[test]
    fn numeric_boundaries_are_accepted_or_rejected_by_one_step() {
        let minimum = TempFile::new(&format!(
            "quantum_ns = {}\npreempt_margin_ns = 0\nspill_threshold = 1\n",
            policy::QUANTUM_MIN_NS
        ));
        let cfg = load_resolved(Some(minimum.path()), &Overrides::default()).unwrap();
        assert_eq!(cfg.quantum_ns, policy::QUANTUM_MIN_NS);
        assert_eq!(cfg.preempt_margin_ns, 0);
        assert_eq!(cfg.spill_threshold, 1);

        let maximum = TempFile::new(&format!(
            "quantum_ns = {}\npreempt_margin_ns = {}\nspill_threshold = {}\n",
            policy::QUANTUM_MAX_NS,
            policy::PREEMPT_MARGIN_MAX_NS,
            SPILL_THRESHOLD_MAX
        ));
        let cfg = load_resolved(Some(maximum.path()), &Overrides::default()).unwrap();
        assert_eq!(cfg.quantum_ns, policy::QUANTUM_MAX_NS);
        assert_eq!(cfg.preempt_margin_ns, policy::PREEMPT_MARGIN_MAX_NS);
        assert_eq!(cfg.spill_threshold, SPILL_THRESHOLD_MAX);

        let over = TempFile::new(&format!(
            "quantum_ns = {}\npreempt_margin_ns = {}\nspill_threshold = {}\n",
            policy::QUANTUM_MAX_NS + 1,
            policy::PREEMPT_MARGIN_MAX_NS + 1,
            SPILL_THRESHOLD_MAX + 1
        ));
        let error = load_resolved(Some(over.path()), &Overrides::default()).unwrap_err();
        assert!(error.to_string().contains("quantum_ns"));
        assert!(error.to_string().contains("preempt_margin_ns"));
        assert!(error.to_string().contains("spill_threshold"));
    }

    #[test]
    fn all_errors_are_reported_together() {
        let file = TempFile::new(&format!(
            "quantum_ns = {}\npreempt_margin_ns = {}\nspill_threshold = 0\n",
            policy::QUANTUM_MAX_NS + 1,
            policy::PREEMPT_MARGIN_MAX_NS + 1
        ));

        let error = load_resolved(Some(file.path()), &Overrides::default()).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("quantum_ns"));
        assert!(message.contains("preempt_margin_ns"));
        assert!(message.contains("spill_threshold"));
    }

    #[test]
    fn the_xdg_path_is_used_only_when_it_is_absolute() {
        assert_eq!(
            config_path(Some("/tmp/xdg"), Some("/home/user")).unwrap(),
            PathBuf::from("/tmp/xdg/scx_infinity/config.toml")
        );
        assert_eq!(
            config_path(Some("relative"), Some("/home/user")).unwrap(),
            PathBuf::from("/home/user/.config/scx_infinity/config.toml")
        );
        assert_eq!(
            config_path(Some(""), Some("/home/user")).unwrap(),
            PathBuf::from("/home/user/.config/scx_infinity/config.toml")
        );
        assert_eq!(
            config_path(None, Some("/home/user")).unwrap(),
            PathBuf::from("/home/user/.config/scx_infinity/config.toml")
        );
        assert_eq!(
            CONFIG_PATH_FALLBACK,
            "$HOME/.config/scx_infinity/config.toml"
        );
        assert_eq!(CONFIG_PATH, "$XDG_CONFIG_HOME/scx_infinity/config.toml");
    }

    #[test]
    fn the_bpf_value_carries_the_generation() {
        let cfg = LiveConfig {
            quantum_ns: 1_500_000,
            placement: PlacementMode::Llc,
            smt: false,
            preempt_margin_ns: 200_000,
            spill_threshold: 6,
            stats_interval_ms: 0,
        };

        let value = cfg.to_bpf(7);

        assert_eq!(value.quantum_ns, 1_500_000);
        assert_eq!(value.preempt_margin_ns, 200_000);
        assert_eq!(value.placement_mode, bpf_intf::INF_PLACEMENT_LLC);
        assert_eq!(value.smt_enabled, 0);
        assert_eq!(value.spill_threshold, 6);
        assert_eq!(value.generation, 7);
        assert_eq!(std::mem::size_of::<bpf_intf::inf_cfg>(), 32);
    }
}

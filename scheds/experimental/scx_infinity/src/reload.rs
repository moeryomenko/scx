// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! SIGHUP reload support.
//!
//! A reload reads the same path, validates the whole result, and only then
//! publishes one configuration value. A parse or validation error leaves
//! the active configuration in place. The service slot is not part of the
//! reload: it comes from the kernel tick, so a file that still sets a
//! quantum is rejected as a whole.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Context;
use anyhow::Result;

use crate::config;
use crate::config::LiveConfig;
use crate::config::Overrides;

/// Resolve a reload and publish it through `publish`.
///
/// `publish` is called once, after the whole result is valid. If either the
/// read, the validation, or the publish fails, the caller keeps its active
/// configuration.
pub fn reload<F>(path: Option<&Path>, overrides: &Overrides, publish: F) -> Result<LiveConfig>
where
    F: FnOnce(&LiveConfig) -> Result<()>,
{
    let cfg = config::load_resolved(path, overrides)?;
    publish(&cfg)?;
    Ok(cfg)
}

/// Install the SIGHUP handler. The flag is set on each signal and consumed
/// by the main loop.
pub fn install_reload_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGHUP, flag.clone())
        .context("failed to install the SIGHUP handler")?;
    Ok(flag)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::placement::PlacementMode;
    use crate::policy;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TempFile {
        path: std::path::PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "scx_infinity_reload_{}_{}.toml",
                std::process::id(),
                id
            ));
            fs::write(&path, contents).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents).unwrap();
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[derive(Default)]
    struct FakeMap {
        value: Option<LiveConfig>,
        updates: u32,
    }

    impl FakeMap {
        fn publish(&mut self, cfg: &LiveConfig) -> Result<()> {
            self.value = Some(*cfg);
            self.updates += 1;
            Ok(())
        }
    }

    #[test]
    fn invalid_toml_keeps_the_old_value() {
        let file = TempFile::new("preempt_margin_ns = [not a number]\n");
        let mut map = FakeMap {
            value: Some(LiveConfig::default()),
            updates: 0,
        };

        let result = reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        });

        assert!(result.is_err());
        assert_eq!(map.updates, 0);
        assert_eq!(map.value, Some(LiveConfig::default()));
    }

    #[test]
    fn a_valid_file_writes_one_value_with_all_fields() {
        let file = TempFile::new(
            r#"
placement = "numa"
smt = false
preempt_margin_ns = 250000
spill_threshold = 8
stats_interval_ms = 500
"#,
        );
        let mut map = FakeMap::default();

        reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        })
        .unwrap();

        assert_eq!(map.updates, 1);
        assert_eq!(
            map.value,
            Some(LiveConfig {
                placement: PlacementMode::Numa,
                smt: false,
                preempt_margin_ns: 250_000,
                spill_threshold: 8,
                stats_interval_ms: 500,
            })
        );
    }

    #[test]
    fn a_cli_override_survives_a_reload() {
        let file = TempFile::new("placement = \"llc\"\nspill_threshold = 4\n");
        let overrides = Overrides {
            placement: Some(PlacementMode::Machine),
            spill_threshold: Some(12),
            ..Overrides::default()
        };
        let mut map = FakeMap::default();

        reload(Some(file.path()), &overrides, |cfg| map.publish(cfg)).unwrap();

        let value = map.value.unwrap();
        assert_eq!(value.placement, PlacementMode::Machine);
        assert_eq!(value.spill_threshold, 12);
        assert_eq!(map.updates, 1);
    }

    #[test]
    fn an_invalid_field_rejects_the_whole_file() {
        let file = TempFile::new(&format!(
            "preempt_margin_ns = {}\nspill_threshold = 0\n",
            policy::PREEMPT_MARGIN_MAX_NS + 1
        ));
        let mut map = FakeMap {
            value: Some(LiveConfig::default()),
            updates: 0,
        };

        let result = reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        });

        assert!(result.is_err());
        assert_eq!(map.updates, 0);
        assert_eq!(map.value, Some(LiveConfig::default()));
    }

    #[test]
    fn a_quantum_key_is_rejected_as_a_whole() {
        let file = TempFile::new("placement = \"llc\"\n");
        let mut map = FakeMap::default();

        reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        })
        .unwrap();
        assert_eq!(map.updates, 1);
        let kept = map.value;

        file.write("quantum_ns = 2000000\nplacement = \"numa\"\n");
        let result = reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        });

        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("quantum_ns"), "{message}");
        assert!(message.contains("revision 4"), "{message}");
        assert_eq!(map.updates, 1);
        assert_eq!(map.value, kept);
        assert_eq!(map.value.unwrap().placement, PlacementMode::Llc);
    }

    #[test]
    fn a_valid_reload_followed_by_a_bad_one_keeps_the_first_value() {
        let file = TempFile::new("placement = \"numa\"\n");
        let mut map = FakeMap::default();

        reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        })
        .unwrap();
        assert_eq!(map.updates, 1);
        let kept = map.value;
        assert_eq!(kept.unwrap().placement, PlacementMode::Numa);

        file.write("spill_threshold = 0\n");
        let result = reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        });

        assert!(result.is_err());
        assert_eq!(map.updates, 1);
        assert_eq!(map.value, kept);
    }

    #[test]
    fn a_failing_publish_changes_nothing() {
        let file = TempFile::new("placement = \"numa\"\n");
        let mut map = FakeMap {
            value: Some(LiveConfig::default()),
            updates: 0,
        };

        let result = reload(Some(file.path()), &Overrides::default(), |_cfg| {
            anyhow::bail!("map update failed")
        });

        assert!(result.is_err());
        assert_eq!(map.updates, 0);
        let _ = &mut map;
    }
}

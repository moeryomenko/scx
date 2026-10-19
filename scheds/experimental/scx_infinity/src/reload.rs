// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! SIGHUP reload support.
//!
//! A reload reads the same path, validates the whole result, and only then
//! publishes one configuration value. A parse or validation error leaves
//! the active configuration in place.

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
        let file = TempFile::new("quantum_ns = [not a number]\n");
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
quantum_ns = 2000000
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
                quantum_ns: 2_000_000,
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
        let file = TempFile::new("quantum_ns = 2000000\nplacement = \"llc\"\n");
        let overrides = Overrides {
            quantum_us: Some(3_000),
            placement: Some(PlacementMode::Machine),
            ..Overrides::default()
        };
        let mut map = FakeMap::default();

        reload(Some(file.path()), &overrides, |cfg| map.publish(cfg)).unwrap();

        assert_eq!(map.value.unwrap().quantum_ns, 3_000_000);
        assert_eq!(map.value.unwrap().placement, PlacementMode::Machine);
        assert_eq!(map.updates, 1);
    }

    #[test]
    fn an_invalid_field_rejects_the_whole_file() {
        let file = TempFile::new(&format!(
            "quantum_ns = {}\nspill_threshold = 0\n",
            policy::QUANTUM_MAX_NS
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
    fn a_valid_reload_followed_by_a_bad_one_keeps_the_first_value() {
        let file = TempFile::new("quantum_ns = 2000000\n");
        let mut map = FakeMap::default();

        reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        })
        .unwrap();
        assert_eq!(map.updates, 1);
        assert_eq!(map.value.unwrap().quantum_ns, 2_000_000);

        file.write("quantum_ns = 50\n");
        let result = reload(Some(file.path()), &Overrides::default(), |cfg| {
            map.publish(cfg)
        });

        assert!(result.is_err());
        assert_eq!(map.updates, 1);
        assert_eq!(map.value.unwrap().quantum_ns, 2_000_000);
    }

    #[test]
    fn a_failing_publish_changes_nothing() {
        let file = TempFile::new("quantum_ns = 2000000\n");
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

//! Control loop configuration with preset profiles.
//!
//! Three preset configurations cover common scenarios:
//! - `demo()` — Fast decay for demonstrations
//! - `realistic()` — Production settings
//! - `stress_test()` — Aggressive thresholds for chaos engineering

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the HomeostasisMachine control loop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlLoopConfig {
    /// How often the control loop runs a SENSE→ACT cycle.
    #[serde(with = "duration_serde")]
    pub loop_interval: Duration,

    /// Half-life for signal decay (exponential by default).
    #[serde(with = "duration_serde")]
    pub signal_half_life: Duration,

    /// Proportionality ratio above which dampening is triggered.
    pub warning_threshold: f64,

    /// Critical proportionality ratio.
    pub critical_threshold: f64,

    /// Storm-level proportionality ratio.
    pub storm_threshold: f64,

    /// Hill curve: half-max concentration (K).
    pub hill_k: f64,

    /// Hill curve: cooperativity coefficient (n).
    pub hill_n: f64,

    /// Hill curve: maximum response (Rmax).
    pub hill_max_response: f64,

    /// How many recent readings to keep for trend analysis.
    pub history_window_size: usize,

    /// Minimum duration before declaring storm.
    #[serde(with = "duration_serde")]
    pub storm_min_duration: Duration,
}

impl ControlLoopConfig {
    /// Fast configuration for demos and testing.
    ///
    /// 15s half-life, 2s loop interval. System responds quickly
    /// so observers can see the full threat-response-recovery cycle.
    pub fn demo() -> Self {
        Self {
            loop_interval: Duration::from_secs(2),
            signal_half_life: Duration::from_secs(15),
            warning_threshold: 3.0,
            critical_threshold: 5.0,
            storm_threshold: 10.0,
            hill_k: 5.0,
            hill_n: 2.0,
            hill_max_response: 100.0,
            history_window_size: 50,
            storm_min_duration: Duration::from_secs(10),
        }
    }

    /// Production configuration.
    ///
    /// 5-minute half-life, 10s loop interval. Tuned for real-world
    /// infrastructure where changes propagate slowly.
    pub fn realistic() -> Self {
        Self {
            loop_interval: Duration::from_secs(10),
            signal_half_life: Duration::from_secs(300),
            warning_threshold: 3.0,
            critical_threshold: 5.0,
            storm_threshold: 10.0,
            hill_k: 5.0,
            hill_n: 2.0,
            hill_max_response: 100.0,
            history_window_size: 100,
            storm_min_duration: Duration::from_secs(60),
        }
    }

    /// Stress-test configuration.
    ///
    /// Aggressive thresholds and fast decay for chaos engineering.
    pub fn stress_test() -> Self {
        Self {
            loop_interval: Duration::from_secs(1),
            signal_half_life: Duration::from_secs(5),
            warning_threshold: 2.0,
            critical_threshold: 3.0,
            storm_threshold: 5.0,
            hill_k: 3.0,
            hill_n: 3.0,
            hill_max_response: 100.0,
            history_window_size: 200,
            storm_min_duration: Duration::from_secs(5),
        }
    }
}

impl Default for ControlLoopConfig {
    fn default() -> Self {
        Self::realistic()
    }
}

/// Serde helper for Duration as seconds (f64).
mod duration_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(duration.as_secs_f64())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = f64::deserialize(deserializer)?;
        Ok(Duration::from_secs_f64(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_config_fast_interval() {
        let cfg = ControlLoopConfig::demo();
        assert_eq!(cfg.loop_interval, Duration::from_secs(2));
        assert_eq!(cfg.signal_half_life, Duration::from_secs(15));
    }

    #[test]
    fn realistic_config_production_interval() {
        let cfg = ControlLoopConfig::realistic();
        assert_eq!(cfg.loop_interval, Duration::from_secs(10));
        assert_eq!(cfg.signal_half_life, Duration::from_secs(300));
    }

    #[test]
    fn stress_test_aggressive_thresholds() {
        let cfg = ControlLoopConfig::stress_test();
        assert!(cfg.warning_threshold < ControlLoopConfig::demo().warning_threshold);
        assert_eq!(cfg.loop_interval, Duration::from_secs(1));
    }

    #[test]
    fn default_is_realistic() {
        let d = ControlLoopConfig::default();
        let r = ControlLoopConfig::realistic();
        assert_eq!(d.loop_interval, r.loop_interval);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = ControlLoopConfig::demo();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ControlLoopConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.loop_interval, cfg.loop_interval);
        assert_eq!(back.hill_k, cfg.hill_k);
    }
}

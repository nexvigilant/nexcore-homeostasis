//! Brain subsystem integration for homeostasis configuration persistence.
//!
//! Provides typed artifact persistence for `ControlLoopConfig` so the
//! homeostasis machine can persist its tuning parameters across sessions.
//!
//! ## T1 Grounding
//!
//! - `persist_homeostasis_config` → π (persistence) + → (causality: homeostasis → brain)
//! - `restore_homeostasis_config` → ∃ (existence check) + ς (state restoration)

use crate::config::ControlLoopConfig;
use nexcore_brain::typed_artifact::TypedArtifact;
use nexcore_brain::{BrainSession, Result};

/// Artifact name for homeostasis configuration snapshots.
const ARTIFACT_NAME: &str = "homeostasis-config.json";

/// The typed artifact handle for homeostasis configuration.
fn artifact() -> TypedArtifact<ControlLoopConfig> {
    TypedArtifact::new(ARTIFACT_NAME)
}

/// Persist the current control loop configuration to a brain artifact.
///
/// Serializes the `ControlLoopConfig` to JSON and saves it as a `Custom`
/// artifact in the given brain session.
///
/// # Errors
///
/// Returns an error if serialization or artifact persistence fails.
pub fn persist_homeostasis_config(
    config: &ControlLoopConfig,
    session: &BrainSession,
) -> Result<()> {
    artifact().save(session, config)
}

/// Restore control loop configuration from a brain artifact.
///
/// Returns `Ok(None)` if no prior snapshot exists (first session).
///
/// # Errors
///
/// Returns an error if deserialization or session access fails.
pub fn restore_homeostasis_config(
    session: &BrainSession,
) -> Result<Option<ControlLoopConfig>> {
    artifact().load(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_session(dir: &std::path::Path) -> BrainSession {
        std::fs::create_dir_all(dir).unwrap();
        BrainSession {
            id: "test-session".to_string(),
            created_at: nexcore_chrono::DateTime::now(),
            project: None,
            git_commit: None,
            session_dir: dir.to_path_buf(),
        }
    }

    #[test]
    fn test_round_trip_demo_config() {
        let temp = TempDir::new().unwrap();
        let session = make_test_session(&temp.path().join("sess"));

        let config = ControlLoopConfig::demo();
        persist_homeostasis_config(&config, &session).unwrap();

        let restored = restore_homeostasis_config(&session).unwrap().unwrap();
        assert_eq!(restored.loop_interval, config.loop_interval);
        assert_eq!(restored.signal_half_life, config.signal_half_life);
        assert!((restored.warning_threshold - config.warning_threshold).abs() < f64::EPSILON);
        assert!((restored.hill_k - config.hill_k).abs() < f64::EPSILON);
        assert!((restored.hill_n - config.hill_n).abs() < f64::EPSILON);
    }

    #[test]
    fn test_restore_no_prior_state() {
        let temp = TempDir::new().unwrap();
        let session = make_test_session(&temp.path().join("sess"));

        let result = restore_homeostasis_config(&session).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_overwrite_preserves_latest() {
        let temp = TempDir::new().unwrap();
        let session = make_test_session(&temp.path().join("sess"));

        let config1 = ControlLoopConfig::demo();
        persist_homeostasis_config(&config1, &session).unwrap();

        let config2 = ControlLoopConfig::stress_test();
        persist_homeostasis_config(&config2, &session).unwrap();

        let restored = restore_homeostasis_config(&session).unwrap().unwrap();
        assert_eq!(restored.loop_interval, config2.loop_interval);
        assert!((restored.warning_threshold - config2.warning_threshold).abs() < f64::EPSILON);
    }
}

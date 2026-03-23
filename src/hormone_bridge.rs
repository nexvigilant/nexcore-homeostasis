//! # Hormone Bridge
//!
//! Inter-crate pipeline: Hormones → Homeostasis.
//!
//! Converts endocrine state (hormone levels) into homeostasis baseline
//! adjustments and behavioral modifiers that tune the control loop.
//!
//! ```text
//! Hormones::EndocrineState → Baseline adjustments (setpoint tuning)
//! Hormones::HormoneLevel → Response threshold modifiers
//! Hormones::BehavioralModifiers → Control loop parameter shifts
//! ```
//!
//! **Biological mapping**: The endocrine system regulates homeostasis
//! through hormonal signaling. Cortisol raises the stress response
//! threshold, adrenaline accelerates response rate, serotonin/dopamine
//! modulate the proportionality setpoint. This bridge converts those
//! persistent hormone levels into homeostasis machine parameters.

use nexcore_hormones::{BehavioralModifiers, EndocrineState, HormoneLevel, HormoneType};

/// Hormonal adjustment factors for the homeostasis control loop.
///
/// These factors are derived from the endocrine state and applied
/// to the homeostasis machine's baseline parameters.
///
/// **Biological mapping**: Hormonal regulation of homeostatic setpoints —
/// cortisol shifts pain thresholds, adrenaline adjusts response speed,
/// dopamine/serotonin tune the reward/risk balance.
#[derive(Debug, Clone)]
pub struct HormonalAdjustment {
    /// Multiplier for warning threshold (cortisol-driven).
    /// > 1.0 = more tolerant of stress, < 1.0 = more sensitive.
    pub warning_threshold_factor: f64,
    /// Multiplier for response rate (adrenaline-driven).
    /// > 1.0 = faster response, < 1.0 = slower response.
    pub response_rate_factor: f64,
    /// Shift for proportionality target (serotonin/dopamine balance).
    /// Positive = more aggressive response, negative = more conservative.
    pub proportionality_shift: f64,
    /// Whether the system is in crisis mode (cortisol > 0.7 + adrenaline > 0.7).
    pub crisis_mode: bool,
    /// Whether rest is recommended (melatonin high, dopamine low).
    pub rest_recommended: bool,
}

/// Convert an endocrine state into homeostasis adjustment factors.
///
/// **Biological mapping**: Neuroendocrine integration — the hypothalamus
/// reads circulating hormone levels and adjusts homeostatic setpoints
/// accordingly. High cortisol raises tolerance; high adrenaline speeds
/// response; balanced serotonin/dopamine maintains proportionality.
pub fn endocrine_to_adjustment(state: &EndocrineState) -> HormonalAdjustment {
    let cortisol = state.get(HormoneType::Cortisol).value();
    let adrenaline = state.get(HormoneType::Adrenaline).value();
    let dopamine = state.get(HormoneType::Dopamine).value();
    let serotonin = state.get(HormoneType::Serotonin).value();

    // Cortisol: high cortisol raises warning threshold (stress tolerance)
    // Range: 0.8 (low cortisol, sensitive) to 1.2 (high cortisol, tolerant)
    let warning_threshold_factor = 0.8 + cortisol * 0.4;

    // Adrenaline: high adrenaline speeds up response
    // Range: 0.5 (resting) to 1.5 (fight-or-flight)
    let response_rate_factor = 0.5 + adrenaline;

    // Serotonin/Dopamine balance: affects proportionality
    // High dopamine = more aggressive; high serotonin = more conservative
    let proportionality_shift = (dopamine - serotonin) * 0.3;

    HormonalAdjustment {
        warning_threshold_factor,
        response_rate_factor,
        proportionality_shift,
        crisis_mode: state.is_crisis_mode(),
        rest_recommended: state.should_rest(),
    }
}

/// Convert behavioral modifiers into a summary score (0.0–1.0).
///
/// Higher values indicate a more active/responsive system.
///
/// **Biological mapping**: Arousal level — the composite readiness
/// of the organism, integrating risk tolerance, exploration drive,
/// and crisis state into a single activation metric.
pub fn behavioral_arousal(modifiers: &BehavioralModifiers) -> f64 {
    let mut arousal = 0.0;
    arousal += modifiers.risk_tolerance * 0.3;
    arousal += modifiers.exploration_rate * 0.2;
    arousal += (1.0 - modifiers.validation_depth) * 0.2; // Less validation = more active
    if modifiers.crisis_mode {
        arousal += 0.3;
    }
    arousal.clamp(0.0, 1.0)
}

/// Map a single hormone level to a homeostasis threat modifier.
///
/// Returns a value from 0.0 (no influence) to 1.0 (maximum influence)
/// based on how far the hormone deviates from baseline (0.5).
///
/// **Biological mapping**: Hormonal deviation detection — the further
/// a hormone is from its resting level, the stronger its influence
/// on homeostatic regulation.
pub fn hormone_deviation(level: HormoneLevel) -> f64 {
    let baseline = 0.5;
    (level.value() - baseline).abs() * 2.0 // Scale to 0.0–1.0
}

/// Compute the throughput metric for endocrine-homeostasis coupling.
///
/// Returns the mood score from the endocrine state, representing
/// the net hormonal influence on homeostatic regulation.
///
/// **Biological mapping**: Allostatic load — the cumulative hormonal
/// burden on homeostatic systems.
pub fn endocrine_throughput(state: &EndocrineState) -> f64 {
    state.mood_score()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_state() -> EndocrineState {
        EndocrineState::default()
    }

    #[test]
    fn test_endocrine_to_adjustment_defaults() {
        let state = default_state();
        let adj = endocrine_to_adjustment(&state);

        // Default: cortisol = baseline (0.5), adrenaline = min (0.0)
        // warning_threshold_factor = 0.8 + 0.5 * 0.4 = 1.0
        assert!((adj.warning_threshold_factor - 1.0).abs() < 0.01);
        // response_rate_factor = 0.5 + 0.0 = 0.5 (adrenaline defaults to min)
        assert!((adj.response_rate_factor - 0.5).abs() < 0.01);
        // proportionality_shift ≈ 0 (dopamine ≈ serotonin, both baseline)
        assert!(adj.proportionality_shift.abs() < 0.1);
        assert!(!adj.crisis_mode);
    }

    #[test]
    fn test_endocrine_to_adjustment_high_cortisol() {
        let mut state = default_state();
        state.set(HormoneType::Cortisol, HormoneLevel::new(0.9));
        let adj = endocrine_to_adjustment(&state);

        // High cortisol → higher warning threshold (more tolerant)
        assert!(adj.warning_threshold_factor > 1.1);
    }

    #[test]
    fn test_endocrine_to_adjustment_high_adrenaline() {
        let mut state = default_state();
        state.set(HormoneType::Adrenaline, HormoneLevel::new(0.9));
        let adj = endocrine_to_adjustment(&state);

        // High adrenaline → faster response
        assert!(adj.response_rate_factor > 1.3);
    }

    #[test]
    fn test_endocrine_to_adjustment_crisis() {
        let mut state = default_state();
        state.set(HormoneType::Cortisol, HormoneLevel::new(0.9));
        state.set(HormoneType::Adrenaline, HormoneLevel::new(0.9));
        let adj = endocrine_to_adjustment(&state);

        assert!(adj.crisis_mode);
    }

    #[test]
    fn test_behavioral_arousal_default() {
        let modifiers = BehavioralModifiers {
            risk_tolerance: 0.5,
            validation_depth: 0.5,
            exploration_rate: 0.5,
            verbosity: 0.5,
            crisis_mode: false,
            partnership_mode: false,
            rest_recommended: false,
        };
        let arousal = behavioral_arousal(&modifiers);
        // 0.5*0.3 + 0.5*0.2 + 0.5*0.2 = 0.15 + 0.1 + 0.1 = 0.35
        assert!((arousal - 0.35).abs() < 0.01);
    }

    #[test]
    fn test_behavioral_arousal_crisis() {
        let modifiers = BehavioralModifiers {
            risk_tolerance: 0.8,
            validation_depth: 0.2,
            exploration_rate: 0.8,
            verbosity: 0.5,
            crisis_mode: true,
            partnership_mode: false,
            rest_recommended: false,
        };
        let arousal = behavioral_arousal(&modifiers);
        assert!(arousal > 0.7, "Crisis mode should have high arousal: got {arousal}");
    }

    #[test]
    fn test_behavioral_arousal_clamped() {
        let modifiers = BehavioralModifiers {
            risk_tolerance: 1.0,
            validation_depth: 0.0,
            exploration_rate: 1.0,
            verbosity: 1.0,
            crisis_mode: true,
            partnership_mode: true,
            rest_recommended: false,
        };
        let arousal = behavioral_arousal(&modifiers);
        assert!(arousal <= 1.0, "Arousal should be clamped to 1.0: got {arousal}");
    }

    #[test]
    fn test_hormone_deviation_at_baseline() {
        let level = HormoneLevel::new(0.5);
        let dev = hormone_deviation(level);
        assert!((dev - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hormone_deviation_high() {
        let level = HormoneLevel::new(1.0);
        let dev = hormone_deviation(level);
        assert!((dev - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hormone_deviation_low() {
        let level = HormoneLevel::new(0.0);
        let dev = hormone_deviation(level);
        assert!((dev - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_endocrine_throughput() {
        let state = default_state();
        let throughput = endocrine_throughput(&state);
        // Mood score is a bounded metric
        assert!(throughput >= 0.0);
    }
}

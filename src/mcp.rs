//! MCP tool functions for the Homeostasis Machine.
//!
//! Each function takes a typed params struct and returns a JSON value
//! representing the computed homeostasis metric.  These are pure library
//! functions — registration as MCP tools happens in `nexcore-mcp`.
//!
//! ## Covered Tools
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`homeostasis_hill_curve`] | Compute Hill-equation response for a signal level |
//! | [`homeostasis_signal_decay`] | Calculate exponential signal decay over elapsed time |
//! | [`homeostasis_proportionality_check`] | Assess response/threat proportionality |
//! | [`homeostasis_storm_evaluate`] | Run storm detection on provided metrics |
//! | [`homeostasis_baseline_status`] | Health assessment relative to a baseline value |
//! | [`homeostasis_circuit_breaker_status`] | Check whether a circuit breaker would trip |
//! | [`homeostasis_rate_limiter_check`] | Check rate-limit capacity and utilisation |
//! | [`homeostasis_amplification_check`] | Verify amplifier/attenuator balance |
//! | [`homeostasis_five_laws_audit`] | Audit a system config against the Five Laws |
//! | [`homeostasis_incident_summary`] | Summarise incident patterns from JSON input |
//! | [`homeostasis_response_budget`] | Calculate response budget usage and exhaustion |
//! | [`homeostasis_system_snapshot`] | Comprehensive system health snapshot |

use nexcore_error::{Context, Result};
use nexcore_homeostasis_primitives::hill::HillCurve;
use nexcore_homeostasis_storm::detection::StormDetector;
use serde::Deserialize;
use serde_json::{Value, json};

// =============================================================================
// Tool 1 — Hill Curve
// =============================================================================

/// Parameters for [`homeostasis_hill_curve`].
#[derive(Debug, Deserialize)]
pub struct HillCurveParams {
    /// The signal strength to evaluate.
    pub signal: f64,
    /// Maximum achievable response (Rmax). Defaults to `100.0`.
    pub max_response: Option<f64>,
    /// Signal strength at half-maximum response (K). Defaults to `50.0`.
    pub k_half: Option<f64>,
    /// Hill coefficient controlling response steepness (n). Defaults to `2.0`.
    pub hill_coefficient: Option<f64>,
}

/// Compute the Hill-equation response for a given signal level.
///
/// The Hill equation `R = Rmax × (Sⁿ / (Kⁿ + Sⁿ))` guarantees that the
/// response is always strictly less than `max_response` for any finite signal,
/// enforcing Law 3 (Response Ceilings).
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails (which should never
/// occur for well-formed `f64` values).
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{HillCurveParams, homeostasis_hill_curve};
///
/// let params = HillCurveParams {
///     signal: 50.0,
///     max_response: Some(100.0),
///     k_half: Some(50.0),
///     hill_coefficient: Some(2.0),
/// };
/// let result = homeostasis_hill_curve(params).unwrap();
/// // At K_half the response is exactly 50 % of Rmax.
/// let response = result["response"].as_f64().unwrap();
/// assert!((response - 50.0).abs() < 0.1);
/// ```
pub fn homeostasis_hill_curve(params: HillCurveParams) -> Result<Value> {
    let max_response = params.max_response.unwrap_or(100.0);
    let k_half = params.k_half.unwrap_or(50.0);
    let hill_coefficient = params.hill_coefficient.unwrap_or(2.0);

    let curve = HillCurve::new(max_response, k_half, hill_coefficient);
    let response = curve.calculate(params.signal);
    let saturated = curve.is_saturated(params.signal, 0.90);

    Ok(json!({
        "signal": params.signal,
        "response": response,
        "max_response": max_response,
        "k_half": k_half,
        "hill_coefficient": hill_coefficient,
        "saturated": saturated,
        "utilization_fraction": if max_response > 0.0 { response / max_response } else { 0.0 },
    }))
}

// =============================================================================
// Tool 2 — Signal Decay
// =============================================================================

/// Parameters for [`homeostasis_signal_decay`].
#[derive(Debug, Deserialize)]
pub struct SignalDecayParams {
    /// Signal strength at time zero.
    pub initial_strength: f64,
    /// Half-life of the signal in seconds.
    pub half_life_secs: f64,
    /// Time elapsed since the signal was created, in seconds.
    pub elapsed_secs: f64,
}

/// Calculate exponential signal decay over an elapsed time period.
///
/// Uses the formula `v(t) = v₀ × 0.5^(t / half_life)`, modelling biological
/// cytokine degradation.  This enforces Law 2 (Signal Decay): no signal
/// persists indefinitely.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{SignalDecayParams, homeostasis_signal_decay};
///
/// let params = SignalDecayParams {
///     initial_strength: 100.0,
///     half_life_secs: 60.0,
///     elapsed_secs: 60.0,
/// };
/// let result = homeostasis_signal_decay(params).unwrap();
/// // After one half-life the signal should be approximately 50.
/// let current = result["current_strength"].as_f64().unwrap();
/// assert!((current - 50.0).abs() < 0.1);
/// ```
pub fn homeostasis_signal_decay(params: SignalDecayParams) -> Result<Value> {
    let current_strength = if params.half_life_secs <= 0.0 {
        params.initial_strength
    } else {
        params.initial_strength * 0.5_f64.powf(params.elapsed_secs / params.half_life_secs)
    };

    let remaining_fraction = if params.initial_strength > 0.0 {
        current_strength / params.initial_strength
    } else {
        1.0
    };

    let is_significant = current_strength >= 0.01;

    Ok(json!({
        "initial_strength": params.initial_strength,
        "current_strength": current_strength,
        "elapsed_secs": params.elapsed_secs,
        "half_life_secs": params.half_life_secs,
        "remaining_fraction": remaining_fraction,
        "is_significant": is_significant,
    }))
}

// =============================================================================
// Tool 3 — Proportionality Check
// =============================================================================

/// Parameters for [`homeostasis_proportionality_check`].
#[derive(Debug, Deserialize)]
pub struct ProportionalityCheckParams {
    /// Current threat level.
    pub threat_level: f64,
    /// Current response level.
    pub response_level: f64,
    /// Ratio threshold for a warning (response/threat). Defaults to `3.0`.
    pub warning_threshold: Option<f64>,
    /// Ratio threshold for a critical assessment. Defaults to `5.0`.
    pub critical_threshold: Option<f64>,
}

/// Assess the proportionality of a system's response to its threat level.
///
/// Computes `ratio = response / threat` and classifies the result as
/// `"normal"`, `"warning"`, `"critical"`, or `"storm"`.  A ratio near `1.0`
/// indicates a proportional response.  This enforces Law 5 (Proportionality).
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{ProportionalityCheckParams, homeostasis_proportionality_check};
///
/// let params = ProportionalityCheckParams {
///     threat_level: 10.0,
///     response_level: 12.0,
///     warning_threshold: None,
///     critical_threshold: None,
/// };
/// let result = homeostasis_proportionality_check(params).unwrap();
/// assert_eq!(result["assessment"].as_str().unwrap(), "normal");
/// ```
pub fn homeostasis_proportionality_check(params: ProportionalityCheckParams) -> Result<Value> {
    let warning_threshold = params.warning_threshold.unwrap_or(3.0);
    let critical_threshold = params.critical_threshold.unwrap_or(5.0);
    let storm_threshold = critical_threshold * 2.0;

    let ratio = if params.threat_level < 0.01 {
        if params.response_level > 0.0 {
            params.response_level
        } else {
            1.0
        }
    } else {
        params.response_level / params.threat_level
    };

    let assessment = if ratio >= storm_threshold {
        "storm"
    } else if ratio >= critical_threshold {
        "critical"
    } else if ratio >= warning_threshold {
        "warning"
    } else {
        "normal"
    };

    let needs_dampening = ratio > warning_threshold;
    let needs_amplification = params.threat_level > 0.0 && ratio < 0.5;

    Ok(json!({
        "threat_level": params.threat_level,
        "response_level": params.response_level,
        "ratio": ratio,
        "assessment": assessment,
        "needs_dampening": needs_dampening,
        "needs_amplification": needs_amplification,
        "thresholds": {
            "warning": warning_threshold,
            "critical": critical_threshold,
            "storm": storm_threshold,
        },
    }))
}

// =============================================================================
// Tool 4 — Storm Evaluate
// =============================================================================

/// Parameters for [`homeostasis_storm_evaluate`].
#[derive(Debug, Deserialize)]
pub struct StormEvaluateParams {
    /// Threat level for the current reading.
    pub threat_level: f64,
    /// Response level for the current reading.
    pub response_level: f64,
    /// Damage level for the current reading.
    pub damage_level: f64,
    /// Number of identical readings to feed as history. Defaults to `1`.
    pub history_count: Option<usize>,
}

/// Run storm detection on provided metrics and return the [`StormSignature`].
///
/// Creates a [`StormDetector`] with default thresholds, optionally feeds
/// `history_count` identical readings to warm up the history buffer, and
/// returns the resulting signature fields as JSON.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{StormEvaluateParams, homeostasis_storm_evaluate};
///
/// let params = StormEvaluateParams {
///     threat_level: 5.0,
///     response_level: 6.0,
///     damage_level: 0.0,
///     history_count: None,
/// };
/// let result = homeostasis_storm_evaluate(params).unwrap();
/// assert!(result["risk_score"].as_f64().unwrap() < 0.3);
/// ```
pub fn homeostasis_storm_evaluate(params: StormEvaluateParams) -> Result<Value> {
    let mut detector = StormDetector::default();
    let history_count = params.history_count.unwrap_or(1).max(1);

    // Warm up the history buffer so trend and acceleration calculations work.
    for _ in 0..history_count.saturating_sub(1) {
        detector.evaluate(
            params.threat_level,
            params.response_level,
            params.damage_level,
            None,
        );
    }

    let sig = detector.evaluate(
        params.threat_level,
        params.response_level,
        params.damage_level,
        None,
    );

    Ok(json!({
        "phase": sig.phase,
        "risk_score": sig.risk_score,
        "proportionality": sig.proportionality,
        "proportionality_trend": sig.proportionality_trend,
        "response_acceleration": sig.response_acceleration,
        "threat_level": sig.threat_level,
        "response_level": sig.response_level,
        "duration_at_elevated_secs": sig.duration_at_elevated_secs,
        "time_since_detection_secs": sig.time_since_detection_secs,
        "self_damage_detected": sig.self_damage_detected,
        "self_damage_sources": sig.self_damage_sources,
    }))
}

// =============================================================================
// Tool 5 — Baseline Status
// =============================================================================

/// Parameters for [`homeostasis_baseline_status`].
#[derive(Debug, Deserialize)]
pub struct BaselineStatusParams {
    /// The current observed value.
    pub current_value: f64,
    /// The healthy baseline / set-point value. Defaults to `0.0`.
    pub baseline_value: Option<f64>,
    /// Fraction of the baseline that constitutes acceptable deviation.
    /// Defaults to `0.20` (20 %).
    pub tolerance: Option<f64>,
}

/// Assess health relative to a baseline set-point.
///
/// Computes the signed deviation and whether the system is within the
/// configured tolerance band.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{BaselineStatusParams, homeostasis_baseline_status};
///
/// let params = BaselineStatusParams {
///     current_value: 105.0,
///     baseline_value: Some(100.0),
///     tolerance: Some(0.10),
/// };
/// let result = homeostasis_baseline_status(params).unwrap();
/// // 105 is 5 % above baseline — within 10 % tolerance.
/// assert_eq!(result["within_tolerance"].as_bool().unwrap(), true);
/// ```
pub fn homeostasis_baseline_status(params: BaselineStatusParams) -> Result<Value> {
    let baseline = params.baseline_value.unwrap_or(0.0);
    let tolerance = params.tolerance.unwrap_or(0.20);

    let deviation = params.current_value - baseline;
    let deviation_fraction = if baseline.abs() > f64::EPSILON {
        deviation / baseline.abs()
    } else {
        // Baseline is zero; treat any non-zero current as 100 % deviation.
        if params.current_value.abs() > f64::EPSILON {
            1.0
        } else {
            0.0
        }
    };

    let within_tolerance = deviation_fraction.abs() <= tolerance;

    let severity = if deviation_fraction.abs() < 0.05 {
        "normal"
    } else if deviation_fraction.abs() <= tolerance {
        "elevated"
    } else if deviation_fraction.abs() <= tolerance * 3.0 {
        "warning"
    } else {
        "critical"
    };

    Ok(json!({
        "current": params.current_value,
        "baseline": baseline,
        "deviation": deviation,
        "deviation_fraction": deviation_fraction,
        "within_tolerance": within_tolerance,
        "tolerance": tolerance,
        "severity": severity,
    }))
}

// =============================================================================
// Tool 6 — Circuit Breaker Status
// =============================================================================

/// Parameters for [`homeostasis_circuit_breaker_status`].
#[derive(Debug, Deserialize)]
pub struct CircuitBreakerStatusParams {
    /// Number of consecutive failures observed.
    pub failure_count: u32,
    /// Failure count at which the breaker trips. Defaults to `5`.
    pub threshold: Option<u32>,
    /// Seconds after tripping before the breaker auto-recovers. Defaults to `30.0`.
    pub timeout_secs: Option<f64>,
}

/// Check whether a circuit breaker would trip given the current failure count.
///
/// This is a stateless projection — it does not track an actual [`CircuitBreaker`]
/// instance but computes what state a breaker with the given parameters would
/// be in.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{CircuitBreakerStatusParams, homeostasis_circuit_breaker_status};
///
/// let params = CircuitBreakerStatusParams {
///     failure_count: 6,
///     threshold: Some(5),
///     timeout_secs: Some(30.0),
/// };
/// let result = homeostasis_circuit_breaker_status(params).unwrap();
/// assert_eq!(result["state"].as_str().unwrap(), "open");
/// assert_eq!(result["tripped"].as_bool().unwrap(), true);
/// ```
pub fn homeostasis_circuit_breaker_status(params: CircuitBreakerStatusParams) -> Result<Value> {
    let threshold = params.threshold.unwrap_or(5);
    let timeout_secs = params.timeout_secs.unwrap_or(30.0);

    let tripped = params.failure_count >= threshold;
    let state = if tripped { "open" } else { "closed" };
    let remaining_until_threshold = threshold.saturating_sub(params.failure_count);
    let load_fraction = (params.failure_count as f64 / threshold as f64).min(1.0);

    Ok(json!({
        "failure_count": params.failure_count,
        "threshold": threshold,
        "timeout_secs": timeout_secs,
        "tripped": tripped,
        "state": state,
        "remaining_until_threshold": remaining_until_threshold,
        "load_fraction": load_fraction,
    }))
}

// =============================================================================
// Tool 7 — Rate Limiter Check
// =============================================================================

/// Parameters for [`homeostasis_rate_limiter_check`].
#[derive(Debug, Deserialize)]
pub struct RateLimiterCheckParams {
    /// Observed current request rate (requests per second).
    pub current_rate: f64,
    /// Maximum allowed rate. Defaults to `100.0`.
    pub max_rate: Option<f64>,
    /// Burst headroom above `max_rate` that is still permitted. Defaults to `0.0`.
    pub burst_size: Option<f64>,
}

/// Check rate-limit status and remaining capacity.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{RateLimiterCheckParams, homeostasis_rate_limiter_check};
///
/// let params = RateLimiterCheckParams {
///     current_rate: 80.0,
///     max_rate: Some(100.0),
///     burst_size: Some(10.0),
/// };
/// let result = homeostasis_rate_limiter_check(params).unwrap();
/// assert_eq!(result["allowed"].as_bool().unwrap(), true);
/// ```
pub fn homeostasis_rate_limiter_check(params: RateLimiterCheckParams) -> Result<Value> {
    let max_rate = params.max_rate.unwrap_or(100.0);
    let burst_size = params.burst_size.unwrap_or(0.0);
    let effective_limit = max_rate + burst_size;

    let allowed = params.current_rate <= effective_limit;
    let utilization = if effective_limit > 0.0 {
        (params.current_rate / effective_limit).min(1.0)
    } else {
        1.0
    };
    let remaining_capacity = (effective_limit - params.current_rate).max(0.0);
    let over_limit_by = (params.current_rate - effective_limit).max(0.0);

    Ok(json!({
        "current_rate": params.current_rate,
        "max_rate": max_rate,
        "burst_size": burst_size,
        "effective_limit": effective_limit,
        "allowed": allowed,
        "utilization": utilization,
        "remaining_capacity": remaining_capacity,
        "over_limit_by": over_limit_by,
    }))
}

// =============================================================================
// Tool 8 — Amplification Check
// =============================================================================

/// Parameters for [`homeostasis_amplification_check`].
#[derive(Debug, Deserialize)]
pub struct AmplificationCheckParams {
    /// Gain of the amplifier component.
    pub amplifier_gain: f64,
    /// Gain of the attenuator component.
    pub attenuator_gain: f64,
}

/// Verify that an amplifier/attenuator pair satisfies Law 1 (Paired Controls).
///
/// The attenuator gain must be **≥** the amplifier gain for the system to be
/// able to brake faster than it accelerates.  Returns a recommendation when
/// the balance is suboptimal.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{AmplificationCheckParams, homeostasis_amplification_check};
///
/// let params = AmplificationCheckParams {
///     amplifier_gain: 2.0,
///     attenuator_gain: 2.5,
/// };
/// let result = homeostasis_amplification_check(params).unwrap();
/// assert_eq!(result["balanced"].as_bool().unwrap(), true);
/// ```
pub fn homeostasis_amplification_check(params: AmplificationCheckParams) -> Result<Value> {
    let balanced = params.attenuator_gain >= params.amplifier_gain;
    let ratio = if params.amplifier_gain > 0.0 {
        params.attenuator_gain / params.amplifier_gain
    } else {
        f64::INFINITY
    };

    let recommendation = if params.attenuator_gain < params.amplifier_gain {
        format!(
            "VIOLATION: Attenuator gain ({:.2}) < amplifier gain ({:.2}). \
             Storm is guaranteed. Increase attenuator gain to at least {:.2}.",
            params.attenuator_gain,
            params.amplifier_gain,
            params.amplifier_gain * 1.25,
        )
    } else if (ratio - 1.0).abs() < f64::EPSILON {
        "Gains are equal. Consider making the attenuator 10-25 % stronger for safety margin."
            .to_string()
    } else if ratio < 1.25 {
        "Attenuator is marginally stronger than the amplifier. Consider 25 % headroom.".to_string()
    } else {
        "Pair is healthy. Attenuator has sufficient gain over the amplifier.".to_string()
    };

    Ok(json!({
        "amplifier_gain": params.amplifier_gain,
        "attenuator_gain": params.attenuator_gain,
        "balanced": balanced,
        "ratio": ratio,
        "recommendation": recommendation,
    }))
}

// =============================================================================
// Tool 9 — Five Laws Audit
// =============================================================================

/// Parameters for [`homeostasis_five_laws_audit`].
#[derive(Debug, Deserialize)]
pub struct FiveLawsAuditParams {
    /// Law 1: Does the system have paired amplifier/attenuator controls?
    pub has_paired_controls: bool,
    /// Law 2: Do all signals have a decay / TTL mechanism?
    pub has_signal_decay: bool,
    /// Law 3: Are there mathematical response ceilings (e.g. Hill curve)?
    pub has_response_ceiling: bool,
    /// Law 4: Does the system measure its own response (self-measurement)?
    pub has_self_measurement: bool,
    /// Law 5: Is there proportionality enforcement (goal = appropriate, not maximal)?
    pub has_proportionality: bool,
}

/// Audit a system configuration against the Five Laws of Homeostasis.
///
/// Returns a score from 0–5 (one point per satisfied law), a list of
/// violations, and targeted recommendations.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{FiveLawsAuditParams, homeostasis_five_laws_audit};
///
/// let params = FiveLawsAuditParams {
///     has_paired_controls: true,
///     has_signal_decay: true,
///     has_response_ceiling: true,
///     has_self_measurement: true,
///     has_proportionality: false,
/// };
/// let result = homeostasis_five_laws_audit(params).unwrap();
/// assert_eq!(result["score"].as_u64().unwrap(), 4);
/// assert_eq!(result["violations"].as_array().unwrap().len(), 1);
/// ```
pub fn homeostasis_five_laws_audit(params: FiveLawsAuditParams) -> Result<Value> {
    let laws = [
        (
            params.has_paired_controls,
            "Law 1: Paired Controls",
            "Every amplifier needs a paired attenuator. \
             Register pairs through PairedAmplificationSystem.",
        ),
        (
            params.has_signal_decay,
            "Law 2: Signal Decay",
            "All signals must have a half-life TTL. \
             Use DecayingSignal with an explicit half_life duration.",
        ),
        (
            params.has_response_ceiling,
            "Law 3: Response Ceiling",
            "Responses must have a mathematical ceiling. \
             Use HillCurve or ResponseCeiling to enforce Rmax.",
        ),
        (
            params.has_self_measurement,
            "Law 4: Self-Measurement",
            "The system must measure its own response level. \
             Enable SensorType::SelfMeasurement in the state tracker.",
        ),
        (
            params.has_proportionality,
            "Law 5: Proportionality",
            "The goal is appropriate response, not maximum response. \
             Implement proportionality check with configurable thresholds.",
        ),
    ];

    let mut score = 0u32;
    let mut violations: Vec<&'static str> = Vec::new();
    let mut recommendations: Vec<&'static str> = Vec::new();

    for &(satisfied, law_name, rec) in &laws {
        if satisfied {
            score += 1;
        } else {
            violations.push(law_name);
            recommendations.push(rec);
        }
    }

    let health_grade = match score {
        5 => "excellent",
        4 => "good",
        3 => "adequate",
        2 => "poor",
        1 => "critical",
        _ => "failing",
    };

    Ok(json!({
        "score": score,
        "max_score": 5,
        "health_grade": health_grade,
        "violations": violations,
        "recommendations": recommendations,
        "laws": {
            "paired_controls": params.has_paired_controls,
            "signal_decay": params.has_signal_decay,
            "response_ceiling": params.has_response_ceiling,
            "self_measurement": params.has_self_measurement,
            "proportionality": params.has_proportionality,
        },
    }))
}

// =============================================================================
// Tool 10 — Incident Summary
// =============================================================================

/// Parameters for [`homeostasis_incident_summary`].
#[derive(Debug, Deserialize)]
pub struct IncidentSummaryParams {
    /// JSON array of incident summary objects.
    ///
    /// Each object may contain:
    /// - `"severity"`: `"low"` | `"medium"` | `"high"` | `"critical"`
    /// - `"duration_secs"`: `f64`
    /// - `"tags"`: object of string-to-string entries
    pub incidents_json: String,
}

/// Summarise incident patterns from a JSON array of incident summaries.
///
/// Parses the provided JSON, then returns aggregate statistics: total count,
/// counts by severity, average duration, and detected recurring patterns.
///
/// # Errors
///
/// Returns an error if `incidents_json` is not a valid JSON array.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{IncidentSummaryParams, homeostasis_incident_summary};
///
/// let params = IncidentSummaryParams {
///     incidents_json: r#"[
///         {"severity": "high", "duration_secs": 120.0},
///         {"severity": "medium", "duration_secs": 60.0},
///         {"severity": "high", "duration_secs": 90.0}
///     ]"#.to_string(),
/// };
/// let result = homeostasis_incident_summary(params).unwrap();
/// assert_eq!(result["total"].as_u64().unwrap(), 3);
/// ```
pub fn homeostasis_incident_summary(params: IncidentSummaryParams) -> Result<Value> {
    let incidents: Vec<Value> = serde_json::from_str(&params.incidents_json)
        .context("incidents_json must be a valid JSON array")?;

    let total = incidents.len();

    let mut by_severity = std::collections::HashMap::<String, u64>::new();
    let mut duration_sum = 0.0_f64;
    let mut duration_count = 0u64;
    let mut tag_counts = std::collections::HashMap::<String, u64>::new();

    for inc in &incidents {
        // Severity tallying.
        if let Some(sev) = inc.get("severity").and_then(|v: &Value| v.as_str()) {
            *by_severity.entry(sev.to_string()).or_insert(0_u64) += 1;
        } else {
            *by_severity.entry("unknown".to_string()).or_insert(0_u64) += 1;
        }

        // Duration statistics.
        if let Some(d) = inc.get("duration_secs").and_then(|v: &Value| v.as_f64()) {
            duration_sum += d;
            duration_count += 1;
        }

        // Tag frequency analysis for recurring patterns.
        if let Some(tags) = inc.get("tags").and_then(|v: &Value| v.as_object()) {
            for (k, v) in tags {
                if let Some(val) = v.as_str() {
                    let key = format!("{k}={val}");
                    *tag_counts.entry(key).or_insert(0_u64) += 1;
                }
            }
        }
    }

    let avg_duration = if duration_count > 0 {
        duration_sum / duration_count as f64
    } else {
        0.0
    };

    // A pattern is "recurring" if it appears in > 30 % of incidents.
    let min_recurrence = ((total as f64 * 0.30).ceil() as u64).max(2);
    let recurring_patterns: Vec<String> = tag_counts
        .iter()
        .filter(|&(_, count)| *count >= min_recurrence)
        .map(|(k, _)| k.clone())
        .collect();

    Ok(json!({
        "total": total,
        "by_severity": by_severity,
        "avg_duration_secs": avg_duration,
        "total_duration_secs": duration_sum,
        "recurring_patterns": recurring_patterns,
    }))
}

// =============================================================================
// Tool 11 — Response Budget
// =============================================================================

/// Parameters for [`homeostasis_response_budget`].
#[derive(Debug, Deserialize)]
pub struct ResponseBudgetParams {
    /// Total response-level units consumed so far this hour.
    pub hourly_total: f64,
    /// Maximum budget per hour. Defaults to `200.0`.
    pub max_budget: Option<f64>,
    /// Current response rate (units per minute).
    pub current_rate: f64,
}

/// Calculate response budget usage and projected exhaustion time.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{ResponseBudgetParams, homeostasis_response_budget};
///
/// let params = ResponseBudgetParams {
///     hourly_total: 100.0,
///     max_budget: Some(200.0),
///     current_rate: 5.0,
/// };
/// let result = homeostasis_response_budget(params).unwrap();
/// let used = result["used_fraction"].as_f64().unwrap();
/// assert!((used - 0.5).abs() < 0.01);
/// ```
pub fn homeostasis_response_budget(params: ResponseBudgetParams) -> Result<Value> {
    let max_budget = params.max_budget.unwrap_or(200.0);
    let used_fraction = if max_budget > 0.0 {
        (params.hourly_total / max_budget).min(1.0)
    } else {
        1.0
    };

    let remaining = (max_budget - params.hourly_total).max(0.0);

    // Projected exhaustion in minutes: remaining / current_rate.
    let projected_exhaustion_minutes = if params.current_rate > 0.0 {
        remaining / params.current_rate
    } else {
        f64::INFINITY
    };

    let budget_status = if used_fraction >= 1.0 {
        "exhausted"
    } else if used_fraction >= 0.9 {
        "critical"
    } else if used_fraction >= 0.7 {
        "warning"
    } else {
        "healthy"
    };

    Ok(json!({
        "hourly_total": params.hourly_total,
        "max_budget": max_budget,
        "used_fraction": used_fraction,
        "remaining": remaining,
        "current_rate": params.current_rate,
        "projected_exhaustion_minutes": projected_exhaustion_minutes,
        "budget_status": budget_status,
    }))
}

// =============================================================================
// Tool 12 — System Snapshot
// =============================================================================

/// Parameters for [`homeostasis_system_snapshot`].
#[derive(Debug, Deserialize)]
pub struct SystemSnapshotParams {
    /// Current threat level.
    pub threat_level: f64,
    /// Current response level.
    pub response_level: f64,
    /// Healthy baseline value for comparison. Defaults to `0.0`.
    pub baseline_value: Option<f64>,
    /// Current damage level. Defaults to `0.0`.
    pub damage_level: Option<f64>,
}

/// Generate a comprehensive system health snapshot.
///
/// Combines proportionality assessment, storm risk evaluation, and baseline
/// deviation into a single unified JSON document.  This is the highest-level
/// diagnostic function in the module.
///
/// # Errors
///
/// Returns an error only when JSON serialisation fails.
///
/// # Example
///
/// ```
/// use nexcore_homeostasis::mcp::{SystemSnapshotParams, homeostasis_system_snapshot};
///
/// let params = SystemSnapshotParams {
///     threat_level: 10.0,
///     response_level: 11.0,
///     baseline_value: Some(10.0),
///     damage_level: Some(0.0),
/// };
/// let result = homeostasis_system_snapshot(params).unwrap();
/// assert_eq!(result["health_status"].as_str().unwrap(), "healthy");
/// ```
pub fn homeostasis_system_snapshot(params: SystemSnapshotParams) -> Result<Value> {
    let damage_level = params.damage_level.unwrap_or(0.0);
    let baseline_value = params.baseline_value.unwrap_or(0.0);

    // Proportionality.
    let prop_ratio = if params.threat_level < 0.01 {
        if params.response_level > 0.0 {
            params.response_level
        } else {
            1.0
        }
    } else {
        params.response_level / params.threat_level
    };

    let proportionality_status = if prop_ratio >= 10.0 {
        "storm"
    } else if prop_ratio >= 5.0 {
        "critical"
    } else if prop_ratio >= 3.0 {
        "warning"
    } else {
        "normal"
    };

    // Quick storm risk estimate without full history.
    let storm_risk = {
        let mut risk = 0.0_f64;
        // Factor 1: proportionality
        if prop_ratio >= 10.0 {
            risk += 0.35;
        } else if prop_ratio >= 5.0 {
            risk += 0.25;
        } else if prop_ratio >= 3.0 {
            risk += 0.15;
        }
        // Factor 2: self-damage signal
        if damage_level > 0.0 && params.response_level > 50.0 {
            risk += 0.20;
        }
        // Factor 3: absolute response level vs a generous ceiling of 200
        let response_ratio = params.response_level / 200.0;
        risk += (response_ratio * 0.20).min(0.20);
        risk.min(1.0)
    };

    // Baseline deviation.
    let baseline_deviation = params.response_level - baseline_value;
    let baseline_deviation_fraction = if baseline_value.abs() > f64::EPSILON {
        baseline_deviation / baseline_value.abs()
    } else if params.response_level.abs() > f64::EPSILON {
        1.0
    } else {
        0.0
    };

    let health_status = if storm_risk >= 0.7 {
        "storm"
    } else if storm_risk >= 0.5 {
        "critical"
    } else if storm_risk >= 0.3 {
        "warning"
    } else if prop_ratio > 3.0 {
        "elevated"
    } else {
        "healthy"
    };

    Ok(json!({
        "health_status": health_status,
        "proportionality": {
            "ratio": prop_ratio,
            "status": proportionality_status,
            "needs_dampening": prop_ratio > 3.0,
            "needs_amplification": params.threat_level > 0.0 && prop_ratio < 0.5,
        },
        "storm_risk": {
            "score": storm_risk,
            "level": if storm_risk >= 0.7 { "high" } else if storm_risk >= 0.4 { "medium" } else { "low" },
        },
        "baseline": {
            "value": baseline_value,
            "current": params.response_level,
            "deviation": baseline_deviation,
            "deviation_fraction": baseline_deviation_fraction,
        },
        "signals": {
            "threat_level": params.threat_level,
            "response_level": params.response_level,
            "damage_level": damage_level,
        },
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Tool 1: Hill Curve ────────────────────────────────────────────────────

    #[test]
    fn hill_curve_at_k_half_returns_half_max() {
        let params = HillCurveParams {
            signal: 50.0,
            max_response: Some(100.0),
            k_half: Some(50.0),
            hill_coefficient: Some(2.0),
        };
        let result = homeostasis_hill_curve(params).unwrap();
        let response = result["response"].as_f64().unwrap();
        assert!(
            (response - 50.0).abs() < 0.1,
            "response at K_half: {response}"
        );
        assert!(!result["saturated"].as_bool().unwrap());
    }

    #[test]
    fn hill_curve_zero_signal_returns_zero_response() {
        let params = HillCurveParams {
            signal: 0.0,
            max_response: Some(100.0),
            k_half: None,
            hill_coefficient: None,
        };
        let result = homeostasis_hill_curve(params).unwrap();
        assert!(result["response"].as_f64().unwrap() < f64::EPSILON);
    }

    #[test]
    fn hill_curve_defaults_are_applied() {
        let params = HillCurveParams {
            signal: 25.0,
            max_response: None,
            k_half: None,
            hill_coefficient: None,
        };
        let result = homeostasis_hill_curve(params).unwrap();
        assert_eq!(result["max_response"].as_f64().unwrap(), 100.0);
        assert_eq!(result["k_half"].as_f64().unwrap(), 50.0);
    }

    // ── Tool 2: Signal Decay ──────────────────────────────────────────────────

    #[test]
    fn signal_decay_after_one_half_life() {
        let params = SignalDecayParams {
            initial_strength: 100.0,
            half_life_secs: 60.0,
            elapsed_secs: 60.0,
        };
        let result = homeostasis_signal_decay(params).unwrap();
        let current = result["current_strength"].as_f64().unwrap();
        assert!((current - 50.0).abs() < 0.1, "expected ~50, got {current}");
    }

    #[test]
    fn signal_decay_zero_half_life_returns_initial() {
        let params = SignalDecayParams {
            initial_strength: 80.0,
            half_life_secs: 0.0,
            elapsed_secs: 300.0,
        };
        let result = homeostasis_signal_decay(params).unwrap();
        // When half_life == 0 we return initial unchanged.
        let current = result["current_strength"].as_f64().unwrap();
        assert!((current - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn signal_decay_remaining_fraction_decreases() {
        let make = |elapsed: f64| {
            homeostasis_signal_decay(SignalDecayParams {
                initial_strength: 100.0,
                half_life_secs: 60.0,
                elapsed_secs: elapsed,
            })
            .unwrap()["remaining_fraction"]
                .as_f64()
                .unwrap()
        };
        assert!(make(30.0) > make(60.0));
        assert!(make(60.0) > make(120.0));
    }

    // ── Tool 3: Proportionality Check ────────────────────────────────────────

    #[test]
    fn proportionality_normal_when_ratio_below_warning() {
        let params = ProportionalityCheckParams {
            threat_level: 10.0,
            response_level: 12.0,
            warning_threshold: None,
            critical_threshold: None,
        };
        let result = homeostasis_proportionality_check(params).unwrap();
        assert_eq!(result["assessment"].as_str().unwrap(), "normal");
        assert!(!result["needs_dampening"].as_bool().unwrap());
    }

    #[test]
    fn proportionality_storm_when_ratio_very_high() {
        let params = ProportionalityCheckParams {
            threat_level: 1.0,
            response_level: 100.0,
            warning_threshold: Some(3.0),
            critical_threshold: Some(5.0),
        };
        let result = homeostasis_proportionality_check(params).unwrap();
        // ratio = 100; storm threshold = 10
        assert_eq!(result["assessment"].as_str().unwrap(), "storm");
        assert!(result["needs_dampening"].as_bool().unwrap());
    }

    // ── Tool 4: Storm Evaluate ────────────────────────────────────────────────

    #[test]
    fn storm_evaluate_clear_for_normal_conditions() {
        let params = StormEvaluateParams {
            threat_level: 10.0,
            response_level: 11.0,
            damage_level: 0.0,
            history_count: None,
        };
        let result = homeostasis_storm_evaluate(params).unwrap();
        let risk = result["risk_score"].as_f64().unwrap();
        assert!(risk < 0.3, "expected low risk, got {risk}");
    }

    #[test]
    fn storm_evaluate_high_risk_for_massive_overresponse() {
        let params = StormEvaluateParams {
            threat_level: 1.0,
            response_level: 200.0,
            damage_level: 50.0,
            history_count: Some(30),
        };
        let result = homeostasis_storm_evaluate(params).unwrap();
        let risk = result["risk_score"].as_f64().unwrap();
        assert!(risk >= 0.25, "expected elevated risk, got {risk}");
    }

    // ── Tool 5: Baseline Status ───────────────────────────────────────────────

    #[test]
    fn baseline_status_within_tolerance() {
        let params = BaselineStatusParams {
            current_value: 105.0,
            baseline_value: Some(100.0),
            tolerance: Some(0.10),
        };
        let result = homeostasis_baseline_status(params).unwrap();
        assert!(result["within_tolerance"].as_bool().unwrap());
    }

    #[test]
    fn baseline_status_outside_tolerance() {
        let params = BaselineStatusParams {
            current_value: 150.0,
            baseline_value: Some(100.0),
            tolerance: Some(0.10),
        };
        let result = homeostasis_baseline_status(params).unwrap();
        assert!(!result["within_tolerance"].as_bool().unwrap());
    }

    #[test]
    fn baseline_status_zero_baseline_handled() {
        let params = BaselineStatusParams {
            current_value: 5.0,
            baseline_value: Some(0.0),
            tolerance: Some(0.20),
        };
        let result = homeostasis_baseline_status(params).unwrap();
        // Any non-zero value above a zero baseline is 100 % deviation.
        let frac = result["deviation_fraction"].as_f64().unwrap();
        assert!((frac - 1.0).abs() < f64::EPSILON);
    }

    // ── Tool 6: Circuit Breaker Status ───────────────────────────────────────

    #[test]
    fn circuit_breaker_trips_at_threshold() {
        let params = CircuitBreakerStatusParams {
            failure_count: 5,
            threshold: Some(5),
            timeout_secs: None,
        };
        let result = homeostasis_circuit_breaker_status(params).unwrap();
        assert!(result["tripped"].as_bool().unwrap());
        assert_eq!(result["state"].as_str().unwrap(), "open");
    }

    #[test]
    fn circuit_breaker_closed_below_threshold() {
        let params = CircuitBreakerStatusParams {
            failure_count: 3,
            threshold: Some(5),
            timeout_secs: Some(30.0),
        };
        let result = homeostasis_circuit_breaker_status(params).unwrap();
        assert!(!result["tripped"].as_bool().unwrap());
        assert_eq!(result["state"].as_str().unwrap(), "closed");
        assert_eq!(result["remaining_until_threshold"].as_u64().unwrap(), 2);
    }

    // ── Tool 7: Rate Limiter Check ────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_when_under_limit() {
        let params = RateLimiterCheckParams {
            current_rate: 50.0,
            max_rate: Some(100.0),
            burst_size: None,
        };
        let result = homeostasis_rate_limiter_check(params).unwrap();
        assert!(result["allowed"].as_bool().unwrap());
        let remaining = result["remaining_capacity"].as_f64().unwrap();
        assert!((remaining - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rate_limiter_rejects_when_over_limit() {
        let params = RateLimiterCheckParams {
            current_rate: 120.0,
            max_rate: Some(100.0),
            burst_size: Some(10.0),
        };
        let result = homeostasis_rate_limiter_check(params).unwrap();
        assert!(!result["allowed"].as_bool().unwrap());
        let over = result["over_limit_by"].as_f64().unwrap();
        assert!((over - 10.0).abs() < f64::EPSILON);
    }

    // ── Tool 8: Amplification Check ──────────────────────────────────────────

    #[test]
    fn amplification_check_balanced_pair() {
        let params = AmplificationCheckParams {
            amplifier_gain: 2.0,
            attenuator_gain: 2.5,
        };
        let result = homeostasis_amplification_check(params).unwrap();
        assert!(result["balanced"].as_bool().unwrap());
        let ratio = result["ratio"].as_f64().unwrap();
        assert!((ratio - 1.25).abs() < 0.01);
    }

    #[test]
    fn amplification_check_unbalanced_pair() {
        let params = AmplificationCheckParams {
            amplifier_gain: 3.0,
            attenuator_gain: 2.0,
        };
        let result = homeostasis_amplification_check(params).unwrap();
        assert!(!result["balanced"].as_bool().unwrap());
        let rec = result["recommendation"].as_str().unwrap();
        assert!(
            rec.contains("VIOLATION"),
            "expected violation message, got: {rec}"
        );
    }

    // ── Tool 9: Five Laws Audit ───────────────────────────────────────────────

    #[test]
    fn five_laws_audit_perfect_score() {
        let params = FiveLawsAuditParams {
            has_paired_controls: true,
            has_signal_decay: true,
            has_response_ceiling: true,
            has_self_measurement: true,
            has_proportionality: true,
        };
        let result = homeostasis_five_laws_audit(params).unwrap();
        assert_eq!(result["score"].as_u64().unwrap(), 5);
        assert_eq!(result["health_grade"].as_str().unwrap(), "excellent");
        assert!(result["violations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn five_laws_audit_partial_violations() {
        let params = FiveLawsAuditParams {
            has_paired_controls: false,
            has_signal_decay: true,
            has_response_ceiling: false,
            has_self_measurement: true,
            has_proportionality: true,
        };
        let result = homeostasis_five_laws_audit(params).unwrap();
        assert_eq!(result["score"].as_u64().unwrap(), 3);
        assert_eq!(result["violations"].as_array().unwrap().len(), 2);
    }

    // ── Tool 10: Incident Summary ─────────────────────────────────────────────

    #[test]
    fn incident_summary_counts_correctly() {
        let params = IncidentSummaryParams {
            incidents_json: r#"[
                {"severity": "high", "duration_secs": 120.0},
                {"severity": "medium", "duration_secs": 60.0},
                {"severity": "high", "duration_secs": 90.0}
            ]"#
            .to_string(),
        };
        let result = homeostasis_incident_summary(params).unwrap();
        assert_eq!(result["total"].as_u64().unwrap(), 3);
        let by_sev = result["by_severity"].as_object().unwrap();
        assert_eq!(by_sev["high"].as_u64().unwrap(), 2);
        assert_eq!(by_sev["medium"].as_u64().unwrap(), 1);
    }

    #[test]
    fn incident_summary_avg_duration() {
        let params = IncidentSummaryParams {
            incidents_json: r#"[
                {"severity": "low", "duration_secs": 100.0},
                {"severity": "low", "duration_secs": 200.0}
            ]"#
            .to_string(),
        };
        let result = homeostasis_incident_summary(params).unwrap();
        let avg = result["avg_duration_secs"].as_f64().unwrap();
        assert!((avg - 150.0).abs() < f64::EPSILON, "avg={avg}");
    }

    #[test]
    fn incident_summary_invalid_json_returns_error() {
        let params = IncidentSummaryParams {
            incidents_json: "not json".to_string(),
        };
        assert!(homeostasis_incident_summary(params).is_err());
    }

    // ── Tool 11: Response Budget ──────────────────────────────────────────────

    #[test]
    fn response_budget_half_used() {
        let params = ResponseBudgetParams {
            hourly_total: 100.0,
            max_budget: Some(200.0),
            current_rate: 5.0,
        };
        let result = homeostasis_response_budget(params).unwrap();
        let used = result["used_fraction"].as_f64().unwrap();
        assert!((used - 0.5).abs() < f64::EPSILON);
        assert_eq!(result["budget_status"].as_str().unwrap(), "healthy");
    }

    #[test]
    fn response_budget_exhausted() {
        let params = ResponseBudgetParams {
            hourly_total: 210.0,
            max_budget: Some(200.0),
            current_rate: 10.0,
        };
        let result = homeostasis_response_budget(params).unwrap();
        assert_eq!(result["used_fraction"].as_f64().unwrap(), 1.0);
        assert_eq!(result["budget_status"].as_str().unwrap(), "exhausted");
        assert_eq!(result["remaining"].as_f64().unwrap(), 0.0);
    }

    #[test]
    fn response_budget_zero_rate_projects_infinity() {
        let params = ResponseBudgetParams {
            hourly_total: 50.0,
            max_budget: Some(200.0),
            current_rate: 0.0,
        };
        let result = homeostasis_response_budget(params).unwrap();
        // JSON serialises f64::INFINITY as null in serde_json.
        // It should be null (infinity) or a very large number.
        assert!(result["projected_exhaustion_minutes"].is_null());
    }

    // ── Tool 12: System Snapshot ──────────────────────────────────────────────

    #[test]
    fn system_snapshot_healthy_conditions() {
        let params = SystemSnapshotParams {
            threat_level: 10.0,
            response_level: 11.0,
            baseline_value: Some(10.0),
            damage_level: Some(0.0),
        };
        let result = homeostasis_system_snapshot(params).unwrap();
        assert_eq!(result["health_status"].as_str().unwrap(), "healthy");
        let ratio = result["proportionality"]["ratio"].as_f64().unwrap();
        assert!((ratio - 1.1).abs() < 0.01);
    }

    #[test]
    fn system_snapshot_storm_conditions() {
        let params = SystemSnapshotParams {
            threat_level: 1.0,
            response_level: 200.0,
            baseline_value: None,
            damage_level: Some(80.0),
        };
        let result = homeostasis_system_snapshot(params).unwrap();
        // With massive over-response and self-damage the risk should be high.
        let risk = result["storm_risk"]["score"].as_f64().unwrap();
        assert!(risk >= 0.50, "expected high storm risk, got {risk}");
    }

    #[test]
    fn system_snapshot_needs_amplification() {
        let params = SystemSnapshotParams {
            threat_level: 100.0,
            response_level: 5.0,
            baseline_value: None,
            damage_level: None,
        };
        let result = homeostasis_system_snapshot(params).unwrap();
        assert!(
            result["proportionality"]["needs_amplification"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !result["proportionality"]["needs_dampening"]
                .as_bool()
                .unwrap()
        );
    }
}

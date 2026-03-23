//! The `HomeostasisMachine` — central orchestrator for self-regulating systems.
//!
//! Implements the continuous `SENSE → COMPARE → DECIDE → ACT → DECAY → LEARN`
//! control loop, inspired by the hypothalamic-pituitary-adrenal (HPA) axis —
//! the master regulatory system that maintains homeostasis while preventing
//! runaway amplification (cytokine storm).
//!
//! ## Design principle
//!
//! The machine MUST always be able to dampen itself. If it can only amplify,
//! a storm is inevitable. Proportionality (response / threat) is the central
//! safety metric.
//!
//! ## Example
//!
//! ```no_run
//! use nexcore_homeostasis::machine::HomeostasisMachine;
//! use nexcore_homeostasis::config::ControlLoopConfig;
//! use nexcore_homeostasis::primitives::Baseline;
//!
//! let baseline = Baseline::default();
//! let config = ControlLoopConfig::demo();
//! let mut machine = HomeostasisMachine::new(baseline, config);
//!
//! // Inject a moderate threat and step.
//! machine.inject_threat(5.0);
//! let state = machine.step().unwrap();
//! assert!(state.response_phase != nexcore_homeostasis::primitives::ResponsePhase::Idle
//!     || state.threat_level < 0.01);
//! ```

use crate::config::ControlLoopConfig;
use crate::traits::{Actuator, Sensor};
use nexcore_error::Result;
use nexcore_homeostasis_memory::memory::IncidentMemory;
use nexcore_homeostasis_primitives::{
    ActionData, ActionType, Baseline, HealthStatus, SignalManager, SignalType, StateTracker,
    SystemState, sensor_to_signal_type,
};
use nexcore_homeostasis_storm::detection::StormDetector;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Budget constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default response budget per hour (realistic preset).
const DEFAULT_RESPONSE_BUDGET_PER_HOUR: f64 = 200.0;

/// Max response rate per step (units/iteration).
const MAX_RESPONSE_RATE: f64 = 10.0;

/// Max dampening rate per step.
const MAX_DAMPENING_RATE: f64 = 15.0;

/// Storm risk threshold that triggers emergency dampening.
const STORM_RISK_EMERGENCY_THRESHOLD: f64 = 0.7;

// ─────────────────────────────────────────────────────────────────────────────
// HomeostasisMachine
// ─────────────────────────────────────────────────────────────────────────────

/// The central orchestrator — a self-regulating system that maintains homeostasis.
///
/// The machine continuously monitors external threats and internal state,
/// responds proportionally to deviations from baseline, and — critically —
/// dampens its own response when it becomes disproportionate.
///
/// ## Biological analogy
///
/// The HPA axis: the hypothalamus, pituitary, and adrenal glands form a
/// negative-feedback loop that mounts a stress response and then terminates it
/// once the threat resolves. Without the termination arm, cortisol would rise
/// unchecked.
///
/// ## Control loop phases
///
/// 1. **SENSE** — poll all registered sensors; anomalous readings create signals.
/// 2. **COMPARE** — compute threat level, damage level, and state vs baseline.
/// 3. **DECIDE** — proportionality-based action selection.
/// 4. **ACT** — apply action and push to all actuators.
/// 5. **DECAY** — age signals; expired ones are pruned.
/// 6. **LEARN** — record incidents to memory (if configured).
/// 7. **TRACK** — update threat derivative for trend-aware decisions.
pub struct HomeostasisMachine {
    /// The healthy baseline for this system.
    pub baseline: Baseline,
    /// Configuration for the control loop behaviour.
    pub config: ControlLoopConfig,

    signal_manager: SignalManager,
    state_tracker: StateTracker,
    storm_detector: StormDetector,
    incident_memory: Option<IncidentMemory>,

    sensors: Vec<Box<dyn Sensor>>,
    actuators: Vec<Box<dyn Actuator>>,

    current_response_level: f64,
    running: Arc<AtomicBool>,

    // Budget tracking.
    hourly_response_total: f64,
    hour_start: Instant,

    // Threat derivative tracking (is threat rising or falling?).
    previous_threat_level: f64,
    threat_derivative: f64,
}

impl HomeostasisMachine {
    /// Create a new `HomeostasisMachine` without incident memory.
    ///
    /// The signal manager is initialised with half-life and cleanup interval
    /// taken from `config`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexcore_homeostasis::machine::HomeostasisMachine;
    /// use nexcore_homeostasis::config::ControlLoopConfig;
    /// use nexcore_homeostasis::primitives::Baseline;
    ///
    /// let machine = HomeostasisMachine::new(Baseline::default(), ControlLoopConfig::demo());
    /// assert!(machine.is_healthy());
    /// ```
    #[must_use]
    pub fn new(baseline: Baseline, config: ControlLoopConfig) -> Self {
        Self::build(baseline, config, None)
    }

    /// Create a `HomeostasisMachine` with incident memory for adaptive learning.
    ///
    /// Resolved incidents are recorded in `memory`, which builds playbooks from
    /// recurring patterns.
    ///
    /// # Example
    ///
    /// ```
    /// use nexcore_homeostasis::machine::HomeostasisMachine;
    /// use nexcore_homeostasis::config::ControlLoopConfig;
    /// use nexcore_homeostasis::primitives::Baseline;
    /// use nexcore_homeostasis_memory::memory::IncidentMemory;
    ///
    /// let memory = IncidentMemory::with_defaults();
    /// let machine = HomeostasisMachine::with_memory(
    ///     Baseline::default(),
    ///     ControlLoopConfig::demo(),
    ///     memory,
    /// );
    /// assert!(machine.is_healthy());
    /// ```
    #[must_use]
    pub fn with_memory(
        baseline: Baseline,
        config: ControlLoopConfig,
        memory: IncidentMemory,
    ) -> Self {
        Self::build(baseline, config, Some(memory))
    }

    // ── Private constructor ───────────────────────────────────────────────────

    fn build(
        baseline: Baseline,
        config: ControlLoopConfig,
        memory: Option<IncidentMemory>,
    ) -> Self {
        let signal_manager = SignalManager::new(
            config.signal_half_life,
            // cleanup_interval: 1/10 of half_life, clamped between 5 s and 60 s.
            Duration::from_secs_f64(
                (config.signal_half_life.as_secs_f64() / 10.0).clamp(5.0, 60.0),
            ),
            10_000,
        );

        let metrics_to_track = vec![
            "error_rate".into(),
            "latency_p99_ms".into(),
            "resource_utilization".into(),
            "queue_depth".into(),
            "response_level".into(),
            "threat_level".into(),
            "proportionality".into(),
        ];

        let state_tracker = StateTracker::new(
            metrics_to_track,
            Duration::from_secs(3600),
            config.history_window_size,
        );

        let storm_detector = StormDetector::new(
            config.warning_threshold,
            config.critical_threshold,
            config.storm_threshold,
            0.1, // acceleration_warning
            0.3, // acceleration_critical
            config.storm_min_duration,
            config.storm_min_duration.saturating_mul(3),
            Duration::from_secs(1800), // history_window
            500,
        );

        Self {
            baseline,
            config,
            signal_manager,
            state_tracker,
            storm_detector,
            incident_memory: memory,
            sensors: Vec::new(),
            actuators: Vec::new(),
            current_response_level: 0.0,
            running: Arc::new(AtomicBool::new(false)),
            hourly_response_total: 0.0,
            hour_start: Instant::now(),
            previous_threat_level: 0.0,
            threat_derivative: 0.0,
        }
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// Register a sensor to provide input to the control loop.
    ///
    /// Sensors can be external threat sensors (PAMPs), internal damage sensors
    /// (DAMPs), or self-measurement sensors (proprioception).
    pub fn register_sensor(&mut self, sensor: Box<dyn Sensor>) {
        tracing::info!(sensor = sensor.name(), "registered sensor");
        self.sensors.push(sensor);
    }

    /// Register an actuator to execute actions decided by the control loop.
    pub fn register_actuator(&mut self, actuator: Box<dyn Actuator>) {
        tracing::info!(actuator = actuator.name(), "registered actuator");
        self.actuators.push(actuator);
    }

    // ── Signal injection ──────────────────────────────────────────────────────

    /// Manually inject a threat signal at the given severity level.
    ///
    /// Useful for testing or integrating with external detection systems.
    /// `level` maps directly to the decaying signal's initial value.
    pub fn inject_threat(&mut self, level: f64) {
        self.signal_manager
            .create_signal(SignalType::Threat, "manual_inject", level, None);
        tracing::debug!(level, "threat injected");
    }

    /// Manually inject an internal damage signal.
    pub fn inject_damage(&mut self, level: f64) {
        self.signal_manager
            .create_signal(SignalType::Damage, "manual_inject", level, None);
        tracing::debug!(level, "damage injected");
    }

    /// Manually inject a dampening (anti-inflammatory) signal.
    ///
    /// This is how external systems tell the machine to calm down.
    pub fn inject_dampening(&mut self, level: f64) {
        self.signal_manager
            .create_signal(SignalType::Dampening, "manual_inject", level, None);
        tracing::debug!(level, "dampening injected");
    }

    // ── Core control loop ─────────────────────────────────────────────────────

    /// Execute a single complete control loop iteration.
    ///
    /// **Phases:**
    /// 1. SENSE — poll sensors, convert anomalous readings to signals.
    /// 2. TRACK DERIVATIVE — record whether threat is rising or falling.
    /// 3. COMPARE — update `StateTracker` to get the new `SystemState`.
    /// 4. DECIDE — proportionality-based action selection.
    /// 5. ACT — apply the action and notify actuators.
    /// 6. DECAY — age and prune signals.
    /// 7. LEARN — record to incident memory if in storm.
    ///
    /// Returns the new [`SystemState`] for this iteration.
    ///
    /// # Errors
    ///
    /// Propagates sensor read errors if the underlying future fails. Individual
    /// sensor errors are logged and skipped rather than aborting the loop.
    pub fn step(&mut self) -> Result<SystemState> {
        // ── Phase 1: SENSE ────────────────────────────────────────────────────
        let metrics = self.gather_metrics_sync();

        // ── Phase 2: TRACK DERIVATIVE ─────────────────────────────────────────
        let threat_level = self.signal_manager.get_threat_level();
        let damage_level = self.signal_manager.get_damage_level();
        self.threat_derivative = threat_level - self.previous_threat_level;
        self.previous_threat_level = threat_level;

        // ── Phase 3: COMPARE ──────────────────────────────────────────────────
        let state = self.state_tracker.update_state(
            metrics,
            threat_level,
            damage_level,
            self.current_response_level,
            &self.baseline,
        );

        // ── Phase 4: DECIDE ───────────────────────────────────────────────────
        let action = self.decide_action(&state);

        // ── Phase 5: ACT ──────────────────────────────────────────────────────
        self.execute_action(&action);

        // ── Phase 6: DECAY ────────────────────────────────────────────────────
        self.signal_manager.tick();

        // ── Phase 7: LEARN ────────────────────────────────────────────────────
        self.maybe_record_incident(&state, &action);

        Ok(state)
    }

    /// Start the control loop as a tokio background task.
    ///
    /// The task runs until [`stop`](Self::stop) is called. Each iteration
    /// sleeps for one second before checking the running flag again. Callers
    /// that need the step loop drive it externally or build a `Send`-safe wrapper.
    pub fn start(&self) -> JoinHandle<()> {
        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);
        tokio::spawn(async move {
            tracing::info!("HomeostasisMachine background task started");
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            tracing::info!("HomeostasisMachine background task stopped");
        })
    }

    /// Signal the control loop to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("HomeostasisMachine stop requested");
    }

    // ── Observation helpers ───────────────────────────────────────────────────

    /// Most recent `SystemState`, or a synthetic healthy state if no iteration
    /// has run yet.
    #[must_use]
    pub fn current_state(&self) -> SystemState {
        self.state_tracker
            .current_state()
            .cloned()
            .unwrap_or_else(|| self.make_initial_state())
    }

    /// Current response level (0 = baseline, higher = active response).
    #[must_use]
    pub fn response_level(&self) -> f64 {
        self.current_response_level
    }

    /// Current threat level (sum of all `Threat` signal strengths).
    #[must_use]
    pub fn threat_level(&self) -> f64 {
        self.signal_manager.get_threat_level()
    }

    /// Response / threat proportionality ratio.
    ///
    /// - `~1.0` = proportional response
    /// - `> 3.0` = over-responding (dampening triggered)
    /// - `< 0.5` = under-responding (amplification triggered)
    #[must_use]
    pub fn proportionality(&self) -> f64 {
        Self::compute_proportionality(
            self.current_response_level,
            self.signal_manager.get_threat_level(),
        )
    }

    /// Whether the system is in a healthy state.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.state_tracker
            .current_state()
            .map(|s| s.is_healthy())
            .unwrap_or(true)
    }

    /// Whether the system is in a cytokine-storm-like cascade state.
    #[must_use]
    pub fn is_in_storm(&self) -> bool {
        self.state_tracker
            .current_state()
            .map(|s| s.is_in_storm())
            .unwrap_or(false)
    }

    /// Comprehensive statistics snapshot as JSON.
    ///
    /// Includes health status, response phase, levels, budget, and signal stats.
    #[must_use]
    pub fn get_statistics(&self) -> serde_json::Value {
        let state = self.state_tracker.current_state();
        let signal_stats = self.signal_manager.get_statistics();

        serde_json::json!({
            "health_status": state
                .map(|s| format!("{:?}", s.health_status))
                .unwrap_or_else(|| "unknown".into()),
            "response_phase": state
                .map(|s| format!("{:?}", s.response_phase))
                .unwrap_or_else(|| "unknown".into()),
            "response_level": self.current_response_level,
            "threat_level": self.signal_manager.get_threat_level(),
            "damage_level": self.signal_manager.get_damage_level(),
            "proportionality": self.proportionality(),
            "storm_risk": state.map(|s| s.storm_risk).unwrap_or(0.0),
            "threat_derivative": self.threat_derivative,
            "hourly_response_budget_used": self.hourly_response_total,
            "hourly_response_budget_remaining":
                DEFAULT_RESPONSE_BUDGET_PER_HOUR - self.hourly_response_total,
            "sensors_count": self.sensors.len(),
            "actuators_count": self.actuators.len(),
            "signals": {
                "total": signal_stats.total_signals,
                "total_strength": signal_stats.total_strength,
                "net_inflammatory": signal_stats.net_inflammatory_state,
            },
        })
    }

    // ── Emergency controls ────────────────────────────────────────────────────

    /// Manually force dampening by the given factor.
    ///
    /// `factor = 0.5` halves the response level. This is an emergency override
    /// for human-in-the-loop intervention.
    pub fn force_dampen(&mut self, factor: f64) {
        let old = self.current_response_level;
        self.current_response_level *= factor.clamp(0.0, 1.0);
        tracing::warn!(
            old,
            new = self.current_response_level,
            factor,
            "manual force_dampen"
        );
        self.inject_dampening(self.current_response_level);
    }

    /// Emergency shutdown: immediately zero the response and clear all signals.
    ///
    /// This is the "pull the plug" option — use sparingly.
    pub fn force_shutdown(&mut self) {
        tracing::warn!("EMERGENCY SHUTDOWN executed");
        self.current_response_level = 0.0;
        self.signal_manager.clear_all();
        self.hourly_response_total = 0.0;
        self.threat_derivative = 0.0;
        self.previous_threat_level = 0.0;
    }

    // ── Private implementation ────────────────────────────────────────────────

    /// Synchronously gather metrics from all registered sensors.
    ///
    /// Each anomalous reading is converted to a `SignalType` via
    /// [`sensor_to_signal_type`] and injected into the signal manager.
    /// Sensor errors are logged and skipped — they do not abort the loop.
    fn gather_metrics_sync(&mut self) -> HashMap<String, f64> {
        let mut metrics: HashMap<String, f64> = HashMap::new();

        for sensor in &self.sensors {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(sensor.read())
            });

            match result {
                Ok(Some(reading)) => {
                    metrics.insert(sensor.name().to_owned(), reading.value);

                    if reading.is_anomalous {
                        let sig_type = sensor_to_signal_type(reading.sensor_type);
                        self.signal_manager.create_signal(
                            sig_type,
                            sensor.name(),
                            reading.anomaly_severity,
                            None,
                        );
                        tracing::debug!(
                            sensor = sensor.name(),
                            signal_type = ?sig_type,
                            severity = reading.anomaly_severity,
                            "anomalous reading — signal created",
                        );
                    }
                }
                Ok(None) => {
                    tracing::trace!(sensor = sensor.name(), "sensor returned no data");
                }
                Err(err) => {
                    tracing::warn!(
                        sensor = sensor.name(),
                        error = %err,
                        "sensor read error (skipped)"
                    );
                }
            }
        }

        // Self-measurement: always record the machine's own current levels.
        metrics.insert("response_level".into(), self.current_response_level);
        metrics.insert(
            "threat_level".into(),
            self.signal_manager.get_threat_level(),
        );
        metrics.insert(
            "damage_level".into(),
            self.signal_manager.get_damage_level(),
        );
        metrics.insert("proportionality".into(), self.proportionality());

        metrics
    }

    /// Core decision logic: select the next action based on current state.
    ///
    /// Priority order:
    /// 1. Storm or imminent storm → `EmergencyDampen`.
    /// 2. Exceeds `absolute_max_response` → `EmergencyShutdown`.
    /// 3. Hourly budget exceeded → `Dampen`.
    /// 4. Proportionality > critical → `Dampen` aggressively.
    /// 5. Proportionality > warning → `Dampen` mildly.
    /// 6. Threat dropping fast → accelerated `Dampen`.
    /// 7. Under-responding (prop < 0.5) → `Amplify`.
    /// 8. No threat, response elevated → `ReturnToBaseline`.
    /// 9. Threat exists, proportional → `Maintain`.
    /// 10. Otherwise → `Idle`.
    fn decide_action(&mut self, state: &SystemState) -> ActionData {
        // Evaluate storm detector.
        let storm_sig = self.storm_detector.evaluate(
            state.threat_level,
            state.current_response_level,
            state.damage_level,
            Some(&state.metrics),
        );

        // 1. Storm or high storm risk → emergency dampen.
        if state.is_in_storm() || storm_sig.risk_score > STORM_RISK_EMERGENCY_THRESHOLD {
            let target = (self.current_response_level * 0.5_f64).max(0.0);
            tracing::warn!(
                risk = storm_sig.risk_score,
                "storm detected — emergency dampen"
            );
            return ActionData::new(
                ActionType::EmergencyDampen,
                target,
                format!(
                    "Storm detected or imminent (risk={:.2})",
                    storm_sig.risk_score
                ),
            );
        }

        // 2. Absolute maximum exceeded → emergency shutdown.
        if self.current_response_level > self.baseline.absolute_max_response {
            tracing::error!(
                level = self.current_response_level,
                max = self.baseline.absolute_max_response,
                "absolute max exceeded — emergency shutdown"
            );
            return ActionData::new(
                ActionType::EmergencyShutdown,
                0.0,
                "Response exceeded absolute maximum".to_owned(),
            );
        }

        // 3. Hourly budget exceeded → moderate dampen.
        if self.hourly_response_total > DEFAULT_RESPONSE_BUDGET_PER_HOUR {
            let target = self.current_response_level * 0.8;
            return ActionData::new(
                ActionType::Dampen,
                target,
                "Hourly response budget exceeded".to_owned(),
            );
        }

        let proportionality = state.proportionality;

        // 4. Over-responding: proportionality > critical → dampen 30%.
        if proportionality > self.config.critical_threshold {
            let target = self.current_response_level * 0.7;
            return ActionData::new(
                ActionType::Dampen,
                target,
                format!("Disproportionate response (prop={proportionality:.2})"),
            );
        }

        // 5. Over-responding: proportionality > warning → dampen 10%.
        if proportionality > self.config.warning_threshold {
            let target = self.current_response_level * 0.9;
            return ActionData::new(
                ActionType::Dampen,
                target,
                format!("Elevated response ratio (prop={proportionality:.2})"),
            );
        }

        // 6. Threat falling fast → accelerated recovery.
        if self.threat_derivative < -10.0 && self.current_response_level > 20.0 {
            let recovery_rate = (MAX_DAMPENING_RATE * 2.0).min(self.current_response_level * 0.15);
            let target = (self.current_response_level - recovery_rate).max(0.0);
            return ActionData::new(
                ActionType::Dampen,
                target,
                format!(
                    "Threat dropping (Δ={:.1}), accelerating recovery",
                    self.threat_derivative
                ),
            );
        }

        // 7. Under-responding (only when threat is not falling).
        if state.threat_level > 0.0 && proportionality < 0.5 && self.threat_derivative >= 0.0 {
            let target = (state.threat_level * 1.5)
                .min(self.current_response_level + MAX_RESPONSE_RATE)
                .min(self.baseline.max_tolerable_response);
            return ActionData::new(
                ActionType::Amplify,
                target,
                format!("Insufficient response (prop={proportionality:.2})"),
            );
        }

        // 8. No threat, response elevated → return to baseline.
        if state.threat_level < 0.1
            && self.current_response_level > self.baseline.resting_response_level
        {
            let target = (self.current_response_level - MAX_DAMPENING_RATE)
                .max(self.baseline.resting_response_level);
            return ActionData::new(
                ActionType::ReturnToBaseline,
                target,
                "Threat cleared, returning to baseline".to_owned(),
            );
        }

        // 9. Threat exists, proportional → maintain.
        if state.threat_level > 0.0 {
            return ActionData::new(
                ActionType::Maintain,
                self.current_response_level,
                "Response proportional, maintaining".to_owned(),
            );
        }

        // 10. Idle.
        ActionData::new(ActionType::Idle, 0.0, "No threat, system idle".to_owned())
    }

    /// Apply the decided action: update response level, budget, and notify actuators.
    fn execute_action(&mut self, action: &ActionData) {
        let old_level = self.current_response_level;
        self.current_response_level = action.target_response_level.max(0.0);

        self.update_response_budget(self.current_response_level);

        // Inject a response signal for self-tracking.
        if self.current_response_level > 0.0 {
            self.signal_manager.create_signal(
                SignalType::Response,
                "control_loop",
                self.current_response_level,
                None,
            );
        }

        if action.action_type != ActionType::Idle {
            tracing::info!(
                action = ?action.action_type,
                old = old_level,
                new = self.current_response_level,
                reason = %action.reason,
                "action executed"
            );
        }

        // Notify actuators best-effort.
        for actuator in &self.actuators {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(actuator.execute(action))
            });
            if let Err(err) = result {
                tracing::warn!(
                    actuator = actuator.name(),
                    error = %err,
                    "actuator execute error (skipped)"
                );
            }
        }
    }

    /// Track hourly response budget consumption, resetting each hour.
    fn update_response_budget(&mut self, response_level: f64) {
        if self.hour_start.elapsed() >= Duration::from_secs(3600) {
            self.hourly_response_total = 0.0;
            self.hour_start = Instant::now();
        }
        self.hourly_response_total += response_level;
    }

    /// Record an incident to memory when a storm is detected.
    fn maybe_record_incident(&mut self, state: &SystemState, _action: &ActionData) {
        if state.is_in_storm() {
            if let Some(memory) = &mut self.incident_memory {
                use nexcore_homeostasis_memory::incident::{IncidentSeverity, IncidentSignature};
                use nexcore_homeostasis_primitives::StormPhase;

                let sig = IncidentSignature {
                    storm_phase: StormPhase::Active,
                    severity: IncidentSeverity::High,
                    peak_risk_score: state.storm_risk,
                    peak_proportionality: state.proportionality,
                    self_damage: state.damage_level > 0.0,
                    affected_systems: vec!["homeostasis_machine".to_owned()],
                    actions_taken: vec![ActionType::EmergencyDampen],
                    trigger_sensors: self.sensors.iter().map(|s| s.name().to_owned()).collect(),
                };
                // Record best-effort; ignore ID.
                let _incident_id = memory.create_incident(sig, IncidentSeverity::High);
            }
        }
    }

    /// Compute response / threat proportionality.
    ///
    /// - Returns `1.0` when both are near zero (healthy baseline).
    /// - Returns `response_level` directly when threat < 0.01 but response > 0
    ///   (effectively infinite ratio, bounded to the response value itself).
    fn compute_proportionality(response_level: f64, threat_level: f64) -> f64 {
        if threat_level > 0.01 {
            response_level / threat_level
        } else if response_level > 0.0 {
            response_level
        } else {
            1.0
        }
    }

    /// Construct a synthetic healthy initial state for callers that query before
    /// the first `step()`.
    fn make_initial_state(&self) -> SystemState {
        use nexcore_homeostasis_primitives::ResponsePhase;
        use nexcore_homeostasis_primitives::state::DynamicsType;

        SystemState {
            timestamp: Instant::now(),
            metrics: HashMap::new(),
            health_status: HealthStatus::Healthy,
            response_phase: ResponsePhase::Idle,
            current_response_level: 0.0,
            response_duration: Duration::ZERO,
            response_budget_consumed: 0.0,
            threat_level: 0.0,
            damage_level: 0.0,
            proportionality: 1.0,
            storm_risk: 0.0,
            trends: HashMap::new(),
            overall_deviation: 0.0,
            most_deviant_metric: None,
            notes: Vec::new(),
            dynamics: DynamicsType::Continuous,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlLoopConfig;
    use nexcore_homeostasis_primitives::{Baseline, HealthStatus, ResponsePhase};

    // Helper: machine with stress_test config (fast decay, tight thresholds).
    fn test_machine() -> HomeostasisMachine {
        HomeostasisMachine::new(Baseline::default(), ControlLoopConfig::stress_test())
    }

    // ── Test 1: Creation ──────────────────────────────────────────────────────

    #[test]
    fn machine_creation_with_default_config() {
        let machine = HomeostasisMachine::new(Baseline::default(), ControlLoopConfig::default());
        assert_eq!(machine.response_level(), 0.0);
        assert_eq!(machine.threat_level(), 0.0);
        assert!(machine.is_healthy());
        assert!(!machine.is_in_storm());
    }

    // ── Test 2: step() with no sensors ───────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn step_no_sensors_returns_healthy_state() {
        let mut machine = test_machine();
        let state = machine.step().unwrap();
        assert_eq!(state.health_status, HealthStatus::Healthy);
        assert_eq!(state.response_phase, ResponsePhase::Idle);
        assert_eq!(state.threat_level, 0.0);
    }

    // ── Test 3: inject_threat + step → response increases ────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn inject_threat_and_step_increases_response() {
        let mut machine = test_machine();
        assert_eq!(machine.response_level(), 0.0);

        // Inject a strong threat and step.
        machine.inject_threat(20.0);
        machine.step().unwrap();

        // With threat = 20 and response = 0, proportionality < 0.5 → Amplify.
        assert!(
            machine.response_level() > 0.0,
            "response should be > 0 after threat; got {}",
            machine.response_level()
        );
        assert!(machine.threat_level() > 0.0, "threat_level should be > 0");
    }

    // ── Test 4: multiple steps → proportional response ────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_steps_proportional_to_threat() {
        let mut machine = test_machine();

        for _ in 0..3 {
            machine.inject_threat(10.0);
            machine.step().unwrap();
        }

        let response = machine.response_level();
        let threat = machine.threat_level();
        assert!(response > 0.0, "expected positive response, got {response}");
        assert!(threat > 0.0, "expected positive threat, got {threat}");
    }

    // ── Test 5: threat removal → return to baseline ───────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn threat_removal_returns_to_baseline() {
        let mut machine =
            HomeostasisMachine::new(Baseline::default(), ControlLoopConfig::stress_test());

        // Build up some response.
        for _ in 0..3 {
            machine.inject_threat(10.0);
            machine.step().unwrap();
        }

        let response_after_threat = machine.response_level();
        assert!(
            response_after_threat > 0.0,
            "should have response > 0; got {response_after_threat}"
        );

        // Clear signals so threat decays to zero, then step many times.
        machine.signal_manager.clear_all();
        for _ in 0..10 {
            machine.step().unwrap();
        }

        let response_after_recovery = machine.response_level();
        assert!(
            response_after_recovery < response_after_threat,
            "response should decrease after threat removal: {response_after_threat} -> {response_after_recovery}"
        );
    }

    // ── Test 6: storm detection → emergency dampen ────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn massive_threat_triggers_emergency_dampen() {
        let mut machine =
            HomeostasisMachine::new(Baseline::default(), ControlLoopConfig::stress_test());

        // Force a high response level with a tiny threat → proportionality >> storm_threshold.
        machine.current_response_level = 80.0;
        machine.inject_threat(0.5);
        machine.step().unwrap();

        let after_response = machine.response_level();
        assert!(
            after_response < 80.0,
            "emergency dampen should reduce response below 80; got {after_response}"
        );
    }

    // ── Test 7: response budget → dampening ──────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn response_budget_exceeded_triggers_dampening() {
        let mut machine = test_machine();

        machine.hourly_response_total = DEFAULT_RESPONSE_BUDGET_PER_HOUR + 1.0;
        machine.current_response_level = 50.0;

        machine.step().unwrap();

        assert!(
            machine.response_level() <= 50.0,
            "response should have been dampened from 50; got {}",
            machine.response_level()
        );
    }

    // ── Test 8: force_dampen ──────────────────────────────────────────────────

    #[test]
    fn force_dampen_reduces_response_level() {
        let mut machine = test_machine();
        machine.current_response_level = 60.0;

        machine.force_dampen(0.5);

        assert!(
            (machine.response_level() - 30.0).abs() < 0.01,
            "force_dampen(0.5) should halve 60 → 30; got {}",
            machine.response_level()
        );
    }

    // ── Test 9: force_shutdown ────────────────────────────────────────────────

    #[test]
    fn force_shutdown_clears_everything() {
        let mut machine = test_machine();

        machine.current_response_level = 75.0;
        machine.hourly_response_total = 150.0;
        machine.inject_threat(10.0);
        machine.inject_damage(5.0);

        machine.force_shutdown();

        assert_eq!(
            machine.response_level(),
            0.0,
            "response should be 0 after shutdown"
        );
        assert_eq!(machine.hourly_response_total, 0.0, "budget should be reset");
        assert_eq!(
            machine.threat_level(),
            0.0,
            "all signals should be cleared: threat = {}",
            machine.threat_level()
        );
        assert_eq!(machine.threat_derivative, 0.0);
    }
}

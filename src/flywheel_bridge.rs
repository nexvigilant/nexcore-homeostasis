// Copyright (c) 2026 NexVigilant LLC. All Rights Reserved.
// Intellectual Property of Matthew Alexander Campion, PharmD

//! Flywheel bridge — homeostasis machine emits lifecycle events into the flywheel bus.
//!
//! ## T1 Grounding
//!
//! | Function | Primitives |
//! |---|---|
//! | `emit_cycle_complete` | → (causality) + ν (frequency: iteration) + σ (sequence) |
//! | `emit_baseline_shift` | μ (mapping: old → new) + ς (state change) |
//! | `emit_threshold_drift` | ∂ (boundary drift) + N (quantity: delta) |

use nexcore_flywheel::{EventKind, FlywheelBus, FlywheelEvent, node::FlywheelTier};

/// Emit a `CycleComplete` event from the homeostasis machine into the flywheel bus.
///
/// Called at the end of each homeostasis regulation cycle. The `iteration` counter
/// identifies which cycle just completed.
pub fn emit_cycle_complete(bus: &FlywheelBus, iteration: u64) {
    bus.emit(FlywheelEvent::broadcast(
        FlywheelTier::Live,
        EventKind::CycleComplete { iteration },
    ));
}

/// Emit a `BaselineShift` event when a homeostasis baseline measurement changes.
///
/// Called when a monitored metric's setpoint shifts from `old` to `new`.
/// The `metric` string identifies which measurement shifted (e.g. `"threat_level"`).
pub fn emit_baseline_shift(bus: &FlywheelBus, metric: &str, old: f64, new: f64) {
    bus.emit(FlywheelEvent::broadcast(
        FlywheelTier::Live,
        EventKind::BaselineShift {
            metric: metric.to_owned(),
            old,
            new,
        },
    ));
}

/// Emit a `ThresholdDrift` event when a homeostasis control parameter drifts.
///
/// Called when a regulation threshold shifts by `delta` (positive = loosened,
/// negative = tightened). The `parameter` string names the drifting threshold.
pub fn emit_threshold_drift(bus: &FlywheelBus, parameter: &str, delta: f64) {
    bus.emit(FlywheelEvent::broadcast(
        FlywheelTier::Live,
        EventKind::ThresholdDrift {
            parameter: parameter.to_owned(),
            delta,
        },
    ));
}

/// Consume pending flywheel events relevant to the homeostasis node.
///
/// Drains `CycleComplete`, `BaselineShift`, `ThresholdDrift`, and
/// `AdaptationReady` events from the Live tier. Homeostasis reacts to its
/// own cycle completions (feedback), baseline/threshold drift from other
/// nodes, and immunity adaptation signals that may shift setpoints.
pub fn consume_homeostasis_events(bus: &FlywheelBus) -> Vec<FlywheelEvent> {
    let events = bus.consume(FlywheelTier::Live);
    events
        .into_iter()
        .filter(|e| {
            matches!(
                &e.kind,
                EventKind::CycleComplete { .. }
                    | EventKind::BaselineShift { .. }
                    | EventKind::ThresholdDrift { .. }
                    | EventKind::AdaptationReady { .. }
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consume_homeostasis_events_filters() {
        let bus = FlywheelBus::new();

        // Relevant: cycle complete
        emit_cycle_complete(&bus, 10);
        // Relevant: adaptation from immunity
        bus.emit(FlywheelEvent::broadcast(
            FlywheelTier::Live,
            EventKind::AdaptationReady {
                category: "unwrap".to_owned(),
            },
        ));
        // Irrelevant: trust update
        bus.emit(FlywheelEvent::broadcast(
            FlywheelTier::Live,
            EventKind::TrustUpdate {
                score: 0.9,
                level: "high".to_owned(),
            },
        ));

        let consumed = consume_homeostasis_events(&bus);
        assert_eq!(
            consumed.len(),
            2,
            "should consume cycle + adaptation, not trust"
        );
    }

    #[test]
    fn test_consume_includes_threshold_drift() {
        let bus = FlywheelBus::new();
        emit_threshold_drift(&bus, "retry_ceiling", -0.05);

        let consumed = consume_homeostasis_events(&bus);
        assert_eq!(consumed.len(), 1, "threshold drift feeds homeostasis");
    }

    /// Emit a `CycleComplete` event and verify it is consumed with the correct iteration.
    #[test]
    fn test_emit_cycle_complete() {
        let bus = FlywheelBus::new();
        emit_cycle_complete(&bus, 42);

        let events = bus.consume(FlywheelTier::Staging);
        assert_eq!(events.len(), 1, "expected exactly one event");
        match &events[0].kind {
            EventKind::CycleComplete { iteration } => {
                assert_eq!(*iteration, 42);
            }
            other => panic!("unexpected event kind: {other:?}"),
        }
    }

    /// Emit a `BaselineShift` event and verify metric, old, and new values survive the bus.
    #[test]
    fn test_emit_baseline_shift() {
        let bus = FlywheelBus::new();
        emit_baseline_shift(&bus, "cortisol_setpoint", 0.6, 0.4);

        let events = bus.consume(FlywheelTier::Draft);
        assert_eq!(events.len(), 1, "expected exactly one event");
        match &events[0].kind {
            EventKind::BaselineShift { metric, old, new } => {
                assert_eq!(metric, "cortisol_setpoint");
                assert!((old - 0.6).abs() < f64::EPSILON);
                assert!((new - 0.4).abs() < f64::EPSILON);
            }
            other => panic!("unexpected event kind: {other:?}"),
        }
    }

    /// Emit a `ThresholdDrift` event and verify parameter and delta survive the bus.
    #[test]
    fn test_emit_threshold_drift() {
        let bus = FlywheelBus::new();
        emit_threshold_drift(&bus, "retry_ceiling", -0.05);

        let events = bus.consume(FlywheelTier::Live);
        assert_eq!(events.len(), 1, "expected exactly one event");
        match &events[0].kind {
            EventKind::ThresholdDrift { parameter, delta } => {
                assert_eq!(parameter, "retry_ceiling");
                assert!((delta - (-0.05)).abs() < f64::EPSILON);
            }
            other => panic!("unexpected event kind: {other:?}"),
        }
    }
}

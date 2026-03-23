//! Sensor and Actuator traits — the dependency inversion contracts.
//!
//! The control loop depends on these traits, not concrete implementations.
//! Users provide sensors that read metrics and actuators that execute actions.

use nexcore_error::Result;
use nexcore_homeostasis_primitives::{
    ActionData, ActionResult, ActionType, SensorReading, SensorType,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A sensor that produces readings.
pub trait Sensor: Send + Sync {
    /// Human-readable name of this sensor.
    fn name(&self) -> &str;

    /// Sensor category.
    fn sensor_type(&self) -> SensorType;

    /// Take a reading. Returns `None` if the sensor has no data.
    fn read(&self) -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send + '_>>;
}

/// An actuator that executes actions.
pub trait Actuator: Send + Sync {
    /// Human-readable name of this actuator.
    fn name(&self) -> &str;

    /// Execute an action and return the result.
    fn execute(
        &self,
        action: &ActionData,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult>> + Send + '_>>;
}

// =============================================================================
// CallbackSensor
// =============================================================================

/// A sensor that wraps an async closure.
///
/// # Example
///
/// ```no_run
/// use nexcore_homeostasis::traits::CallbackSensor;
/// use nexcore_homeostasis::primitives::{SensorReading, SensorType};
///
/// let sensor = CallbackSensor::new("cpu", SensorType::SelfMeasurement, || {
///     Box::pin(async {
///         Ok(Some(SensorReading::normal(0.42, "cpu", SensorType::SelfMeasurement)))
///     })
/// });
/// assert_eq!(sensor.name(), "cpu");
/// ```
pub struct CallbackSensor<F>
where
    F: Fn() -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send>> + Send + Sync,
{
    name: String,
    sensor_type: SensorType,
    callback: F,
}

impl<F> CallbackSensor<F>
where
    F: Fn() -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send>> + Send + Sync,
{
    /// Create a new `CallbackSensor`.
    pub fn new(name: impl Into<String>, sensor_type: SensorType, callback: F) -> Self {
        Self {
            name: name.into(),
            sensor_type,
            callback,
        }
    }
}

impl<F> Sensor for CallbackSensor<F>
where
    F: Fn() -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send>> + Send + Sync,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn sensor_type(&self) -> SensorType {
        self.sensor_type
    }

    fn read(&self) -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send + '_>> {
        (self.callback)()
    }
}

// =============================================================================
// LoggingActuator
// =============================================================================

/// An actuator that logs actions to tracing instead of executing them.
///
/// Useful as a no-op placeholder during development and testing.
pub struct LoggingActuator {
    name: String,
}

impl LoggingActuator {
    /// Create a new `LoggingActuator` with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Actuator for LoggingActuator {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(
        &self,
        action: &ActionData,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult>> + Send + '_>> {
        let action_type = action.action_type;
        let target = action.target_response_level;
        let name = self.name.clone();
        Box::pin(async move {
            tracing::info!(
                actuator = %name,
                action = ?action_type,
                target = target,
                "LoggingActuator: would execute action"
            );
            Ok(ActionResult::success(action_type, Some(target), 0.0))
        })
    }
}

// =============================================================================
// SimulatedThreatSource
// =============================================================================

/// Internal state for [`SimulatedThreatSource`].
struct SimulatedThreatInner {
    attacking: bool,
    intensity: f64,
}

/// A test-only sensor that simulates an external threat.
///
/// Can be controlled programmatically to start and stop attacks,
/// making it useful for integration tests and demos.
pub struct SimulatedThreatSource {
    name: String,
    inner: Arc<RwLock<SimulatedThreatInner>>,
}

impl SimulatedThreatSource {
    /// Create a new idle `SimulatedThreatSource`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Arc::new(RwLock::new(SimulatedThreatInner {
                attacking: false,
                intensity: 0.0,
            })),
        }
    }

    /// Begin an attack at the given intensity (0–10 scale).
    pub async fn start_attack(&self, intensity: f64) {
        let mut inner = self.inner.write().await;
        inner.attacking = true;
        inner.intensity = intensity;
    }

    /// End the attack and return intensity to zero.
    pub async fn stop_attack(&self) {
        let mut inner = self.inner.write().await;
        inner.attacking = false;
        inner.intensity = 0.0;
    }

    /// Return `true` if an attack is currently active.
    pub async fn is_attacking(&self) -> bool {
        self.inner.read().await.attacking
    }
}

impl Sensor for SimulatedThreatSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn sensor_type(&self) -> SensorType {
        SensorType::ExternalThreat
    }

    fn read(&self) -> Pin<Box<dyn Future<Output = Result<Option<SensorReading>>> + Send + '_>> {
        let inner = Arc::clone(&self.inner);
        let name = self.name.clone();
        Box::pin(async move {
            let state = inner.read().await;
            if state.attacking {
                Ok(Some(SensorReading::anomalous(
                    state.intensity,
                    name,
                    SensorType::ExternalThreat,
                    (state.intensity / 10.0).min(1.0),
                    0.95,
                )))
            } else {
                Ok(Some(SensorReading::normal(
                    0.0,
                    name,
                    SensorType::ExternalThreat,
                )))
            }
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn callback_sensor_produces_reading() {
        let sensor = CallbackSensor::new("test", SensorType::Environmental, || {
            Box::pin(async {
                Ok(Some(SensorReading::normal(
                    42.0,
                    "test",
                    SensorType::Environmental,
                )))
            })
        });
        assert_eq!(sensor.name(), "test");
        assert_eq!(sensor.sensor_type(), SensorType::Environmental);
        let reading = sensor.read().await.unwrap().unwrap();
        assert_eq!(reading.value, 42.0);
    }

    #[tokio::test]
    async fn logging_actuator_succeeds() {
        let actuator = LoggingActuator::new("test-log");
        let action = ActionData::new(ActionType::Dampen, 50.0, "test reason");
        let result = actuator.execute(&action).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn simulated_threat_starts_and_stops() {
        let source = SimulatedThreatSource::new("threat");
        assert!(!source.is_attacking().await);

        let reading = source.read().await.unwrap().unwrap();
        assert!(!reading.is_anomalous);

        source.start_attack(7.5).await;
        assert!(source.is_attacking().await);
        let reading = source.read().await.unwrap().unwrap();
        assert!(reading.is_anomalous);
        assert_eq!(reading.value, 7.5);

        source.stop_attack().await;
        assert!(!source.is_attacking().await);
        let reading = source.read().await.unwrap().unwrap();
        assert!(!reading.is_anomalous);
    }

    #[tokio::test]
    async fn simulated_threat_severity_clamped_to_one() {
        let source = SimulatedThreatSource::new("extreme");
        // intensity = 15.0 → severity = 15.0/10.0 = 1.5 → clamped to 1.0
        source.start_attack(15.0).await;
        let reading = source.read().await.unwrap().unwrap();
        assert!(reading.is_anomalous);
        assert_eq!(reading.anomaly_severity, 1.0);
    }

    #[tokio::test]
    async fn callback_sensor_can_return_none() {
        let sensor = CallbackSensor::new("absent", SensorType::Custom, || {
            Box::pin(async { Ok(None) })
        });
        let result = sensor.read().await.unwrap();
        assert!(result.is_none());
    }
}

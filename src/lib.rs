//! # Homeostasis Machine
//!
//! Self-regulating system framework inspired by biological homeostasis.
//! Prevents runaway amplification failures like retry storms, auto-scaling
//! runaway, and cascading alerts through five design laws.
//!
//! ## Five Laws
//!
//! 1. **Paired Controls** — Every amplifier needs a paired attenuator.
//! 2. **Signal Decay** — All signals have half-life TTL.
//! 3. **Response Ceilings** — Hill curve math guarantees bounded response.
//! 4. **Self-Measurement** — System measures its own response.
//! 5. **Proportionality** — Goal is appropriate response, not maximum.

#![warn(missing_docs)]
pub mod config;
pub mod flywheel_bridge;
pub mod machine;
pub mod mcp;
pub mod traits;

// Re-export sub-crates for convenience.
pub use nexcore_homeostasis_memory as memory;
pub use nexcore_homeostasis_primitives as primitives;
pub use nexcore_homeostasis_storm as storm;

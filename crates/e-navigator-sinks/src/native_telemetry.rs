use std::fmt;
use std::sync::{Arc, Mutex};

use crate::prometheus::PrometheusMetricLine;

#[doc(hidden)]
pub trait NativeTelemetrySource: Send + Sync {
    fn prometheus_lines(&self) -> Vec<PrometheusMetricLine>;
}

/// Process-local registry for bounded collector self-observability.
///
/// Sources are registered at construction time and sampled only when the
/// Prometheus endpoint is scraped. This keeps exporter health independent of
/// the signal queue and avoids a feedback loop through a failing OTLP worker.
#[derive(Clone, Default)]
pub struct NativeTelemetryRegistry {
    sources: Arc<Mutex<Vec<Arc<dyn NativeTelemetrySource>>>>,
}

impl fmt::Debug for NativeTelemetryRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTelemetryRegistry")
            .field(
                "source_count",
                &self.sources.lock().map_or(0, |sources| sources.len()),
            )
            .finish()
    }
}

impl NativeTelemetryRegistry {
    #[doc(hidden)]
    pub fn register_source(&self, source: Arc<dyn NativeTelemetrySource>) {
        if let Ok(mut sources) = self.sources.lock() {
            sources.push(source);
        }
    }

    pub(crate) fn prometheus_lines(&self) -> Vec<PrometheusMetricLine> {
        self.sources.lock().map_or_else(
            |_| Vec::new(),
            |sources| {
                sources
                    .iter()
                    .flat_map(|source| source.prometheus_lines())
                    .collect()
            },
        )
    }
}

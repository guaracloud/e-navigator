use e_navigator_core::CoreResult;
use e_navigator_signals::{
    CgroupResourceContext, MetricAggregationWindow, ProcessResourceContext, ResourceCounterMetric,
    SignalEnvelope,
};

use super::{
    context::{metric_attributes, resource_context},
    generator::ResourceMetricsGenerator,
    state::{CounterDelta, CounterState, StateKey, evict_first},
};

impl ResourceMetricsGenerator {
    pub(super) fn counter_delta(
        &self,
        key: StateKey,
        value: u64,
        timestamp_unix_nanos: u64,
    ) -> CoreResult<Option<CounterDelta>> {
        let gauge_len = self.gauge_len()?;
        let mut counters = self.counters()?;
        if let Some(previous) = counters.get_mut(&key) {
            if value == previous.value {
                previous.timestamp_unix_nanos = timestamp_unix_nanos;
                return Ok(None);
            }
            let delta = value.saturating_sub(previous.value);
            let window = MetricAggregationWindow {
                start_unix_nanos: previous.timestamp_unix_nanos,
                end_unix_nanos: timestamp_unix_nanos,
            };
            *previous = CounterState {
                value,
                timestamp_unix_nanos,
            };
            return Ok((delta > 0).then_some(CounterDelta {
                value: delta,
                window,
            }));
        }
        if counters.len().saturating_add(gauge_len) >= self.max_keys {
            evict_first(&mut counters);
            if counters.len().saturating_add(gauge_len) >= self.max_keys {
                return Ok(None);
            }
        }
        counters.insert(
            key,
            CounterState {
                value,
                timestamp_unix_nanos,
            },
        );
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn counter_metric<'a, const N: usize>(
    signal: &SignalEnvelope,
    name: &str,
    unit: &str,
    value: u64,
    window: MetricAggregationWindow,
    process: Option<ProcessResourceContext>,
    cgroup: Option<CgroupResourceContext>,
    attributes: [(&'a str, &'a str); N],
) -> SignalEnvelope {
    SignalEnvelope::resource_counter_metric(
        "generator.resource_metrics",
        signal.host.clone(),
        ResourceCounterMetric {
            metric_name: name.to_string(),
            unit: unit.to_string(),
            value,
            window,
            resource: resource_context(signal, process.as_ref(), cgroup.as_ref()),
            process,
            cgroup,
            attributes: metric_attributes(attributes),
        },
    )
}

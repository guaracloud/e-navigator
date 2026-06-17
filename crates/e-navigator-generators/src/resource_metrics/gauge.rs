use e_navigator_core::CoreResult;
use e_navigator_signals::{
    CgroupResourceContext, MetricAggregationWindow, ProcessResourceContext, ResourceGaugeMetric,
    SignalEnvelope,
};

use super::{
    context::{metric_attributes, resource_context},
    generator::ResourceMetricsGenerator,
    state::{StateKey, evict_first},
};

impl ResourceMetricsGenerator {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn update_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key, signal, name, unit, value, window, None, None, attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn update_process_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        process: ProcessResourceContext,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key,
            signal,
            name,
            unit,
            value,
            window,
            Some(process),
            None,
            attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn update_cgroup_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        cgroup: CgroupResourceContext,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key,
            signal,
            name,
            unit,
            value,
            window,
            None,
            Some(cgroup),
            attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn update_metric_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        process: Option<ProcessResourceContext>,
        cgroup: Option<CgroupResourceContext>,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        let counter_len = self.counter_len()?;
        let mut gauges = self.gauges()?;
        if let Some(previous) = gauges.get_mut(&key) {
            if *previous == value {
                return Ok(None);
            }
            *previous = value;
        } else {
            if gauges.len().saturating_add(counter_len) >= self.max_keys {
                evict_first(&mut gauges);
                if gauges.len().saturating_add(counter_len) >= self.max_keys {
                    return Ok(None);
                }
            }
            gauges.insert(key, value);
        }
        Ok(Some(gauge_metric(
            signal, name, unit, value, window, process, cgroup, attributes,
        )))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn gauge_metric<'a, const N: usize>(
    signal: &SignalEnvelope,
    name: &str,
    unit: &str,
    value: i64,
    window: MetricAggregationWindow,
    process: Option<ProcessResourceContext>,
    cgroup: Option<CgroupResourceContext>,
    attributes: [(&'a str, &'a str); N],
) -> SignalEnvelope {
    SignalEnvelope::resource_gauge_metric(
        "generator.resource_metrics",
        signal.host.clone(),
        ResourceGaugeMetric {
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

pub(super) fn saturating_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

//! Runtime selection and reading for eBPF event transports.

use e_navigator_core::EbpfEventTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum EventTransportKind {
    RingBuffer,
    PerfBuffer,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl EventTransportKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RingBuffer => "ring_buffer",
            Self::PerfBuffer => "perf_buffer",
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn select_with_probe(
    requested: EbpfEventTransport,
    probe: impl FnOnce() -> Result<bool, String>,
) -> Result<EventTransportKind, String> {
    if requested == EbpfEventTransport::PerfBuffer {
        return Ok(EventTransportKind::PerfBuffer);
    }

    match probe() {
        Ok(true) => Ok(EventTransportKind::RingBuffer),
        Ok(false) if requested == EbpfEventTransport::Auto => Ok(EventTransportKind::PerfBuffer),
        Ok(false) => Err("the kernel does not support BPF ring-buffer maps".to_string()),
        Err(err) => Err(format!("BPF ring-buffer capability probe failed: {err}")),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{EventTransportKind, select_with_probe};
    use crate::ebpf_maps::SourceMapProfile;
    use crate::reader_shutdown::ReaderShutdown;
    use crate::source_telemetry::SourceTelemetry;
    use aya::{
        Ebpf, EbpfLoader, include_bytes_aligned,
        maps::{MapData, MapType, PerCpuArray, RingBuf, perf::PerfEventArray},
        sys::is_map_supported,
        util::online_cpus,
    };
    use e_navigator_core::{CoreError, CoreResult, EbpfConfig, EbpfEventTransport};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use tokio::task::JoinHandle;
    use tracing::{info, warn};

    const TRANSPORT_LOSS_POLL_INTERVAL: Duration = Duration::from_secs(1);
    static RING_BUFFER_SUPPORT: OnceLock<Result<bool, String>> = OnceLock::new();

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct ResolvedEventTransport {
        pub(crate) kind: EventTransportKind,
        pub(crate) ring_buffer_bytes: u32,
    }

    pub(crate) enum EventMap {
        Ring(RingBuf<MapData>),
        Perf(PerfEventArray<MapData>),
    }

    impl core::fmt::Debug for EventMap {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_tuple("EventMap")
                .field(&self.kind().as_str())
                .finish()
        }
    }

    impl EventMap {
        fn kind(&self) -> EventTransportKind {
            match self {
                Self::Ring(_) => EventTransportKind::RingBuffer,
                Self::Perf(_) => EventTransportKind::PerfBuffer,
            }
        }
    }

    pub(crate) fn load_ebpf(
        config: &EbpfConfig,
        profile: SourceMapProfile,
        module: &'static str,
    ) -> CoreResult<(Ebpf, ResolvedEventTransport)> {
        load_ebpf_with(config, profile, module, |_| {})
    }

    pub(crate) fn load_ebpf_with(
        config: &EbpfConfig,
        profile: SourceMapProfile,
        module: &'static str,
        configure: impl FnOnce(&mut EbpfLoader<'_>),
    ) -> CoreResult<(Ebpf, ResolvedEventTransport)> {
        let transport = resolve_event_transport(config, module)?;
        let mut loader = EbpfLoader::new();
        configure(&mut loader);
        crate::ebpf_maps::constrain_unrelated_maps(&mut loader, profile);
        crate::ebpf_maps::configure_event_transport_maps(
            &mut loader,
            profile,
            transport.kind,
            transport.ring_buffer_bytes,
        );

        let bytes = match transport.kind {
            EventTransportKind::RingBuffer => {
                include_bytes_aligned!(concat!(env!("OUT_DIR"), "/e-navigator-ebpf-programs-ring"))
            }
            EventTransportKind::PerfBuffer => {
                include_bytes_aligned!(concat!(env!("OUT_DIR"), "/e-navigator-ebpf-programs-perf"))
            }
        };
        let mut ebpf = loader
            .load(bytes)
            .map_err(|err| module_error(module, err))?;
        // Every Aya source loads through this boundary. Seed the static
        // capture posture before returning the object so no caller can attach
        // a global hook while the map still has its zero (disabled) value.
        crate::capture_filter::seed_capture_filter_control(&mut ebpf, module)?;

        info!(
            source = module,
            event_transport = transport.kind.as_str(),
            ring_buffer_bytes = transport.ring_buffer_bytes,
            "selected eBPF event transport"
        );
        Ok((ebpf, transport))
    }

    fn resolve_event_transport(
        config: &EbpfConfig,
        module: &'static str,
    ) -> CoreResult<ResolvedEventTransport> {
        let kind = select_with_probe(config.event_transport, kernel_supports_ring_buffer).map_err(
            |message| CoreError::ModuleFailed {
                module: module.to_string(),
                message,
            },
        )?;
        if kind == EventTransportKind::RingBuffer {
            let page_size = rustix::param::page_size();
            if !(config.ring_buffer_bytes as usize).is_multiple_of(page_size) {
                return Err(CoreError::ModuleFailed {
                    module: module.to_string(),
                    message: format!(
                        "ebpf.ring_buffer_bytes ({}) must be a multiple of the kernel page size ({page_size})",
                        config.ring_buffer_bytes
                    ),
                });
            }
        }
        if kind == EventTransportKind::PerfBuffer
            && config.event_transport == EbpfEventTransport::Auto
        {
            warn!(
                source = module,
                "BPF ring-buffer maps are unsupported; using the perf-event fallback"
            );
        }
        Ok(ResolvedEventTransport {
            kind,
            ring_buffer_bytes: config.ring_buffer_bytes,
        })
    }

    fn kernel_supports_ring_buffer() -> Result<bool, String> {
        RING_BUFFER_SUPPORT
            .get_or_init(|| is_map_supported(MapType::RingBuf).map_err(|err| err.to_string()))
            .clone()
    }

    pub(crate) fn take_event_map(
        ebpf: &mut Ebpf,
        name: &'static str,
        transport: ResolvedEventTransport,
        module: &'static str,
    ) -> CoreResult<EventMap> {
        let map = ebpf.take_map(name).ok_or_else(|| CoreError::ModuleFailed {
            module: module.to_string(),
            message: format!("missing {name} map"),
        })?;
        match transport.kind {
            EventTransportKind::RingBuffer => RingBuf::try_from(map)
                .map(EventMap::Ring)
                .map_err(|err| module_error(module, err)),
            EventTransportKind::PerfBuffer => PerfEventArray::try_from(map)
                .map(EventMap::Perf)
                .map_err(|err| module_error(module, err)),
        }
    }

    pub(crate) fn spawn_event_readers<MakeHandler, Handler>(
        event_map: EventMap,
        module: &'static str,
        stream: &'static str,
        perf_page_count: usize,
        shutdown: ReaderShutdown,
        telemetry: Arc<SourceTelemetry>,
        make_handler: MakeHandler,
    ) -> CoreResult<Vec<JoinHandle<()>>>
    where
        MakeHandler: Fn() -> Handler,
        Handler: FnMut(&[u8]) -> bool + Send + 'static,
    {
        match event_map {
            EventMap::Ring(mut ring) => {
                let mut handler = make_handler();
                let handle = tokio::task::spawn_blocking(move || {
                    while !shutdown.is_stopped() {
                        if crate::perf_reader::wait_for_ring_events(&ring, module) != Some(true) {
                            continue;
                        }
                        while let Some(item) = ring.next() {
                            if !handler(&item) {
                                return;
                            }
                            telemetry.maybe_log_summary();
                        }
                    }
                });
                Ok(vec![handle])
            }
            EventMap::Perf(mut array) => {
                let cpus = online_cpus().map_err(|(_, err)| module_error(module, err))?;
                let mut handles = Vec::with_capacity(cpus.len());
                for cpu_id in cpus {
                    let mut buffer = array
                        .open(cpu_id, Some(perf_page_count))
                        .map_err(|err| module_error(module, err))?;
                    let reader_shutdown = shutdown.clone();
                    let telemetry = telemetry.clone();
                    let mut handler = make_handler();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let mut closed = false;
                        while !reader_shutdown.is_stopped() {
                            if crate::perf_reader::wait_for_events(&buffer, module, cpu_id)
                                != Some(true)
                            {
                                continue;
                            }
                            buffer.for_each(|event| {
                                if closed {
                                    return;
                                }
                                match event {
                                    aya::maps::perf::PerfEvent::Sample { head, tail } => {
                                        let bytes =
                                            crate::perf_sample::perf_sample_bytes(head, tail);
                                        closed = !handler(bytes.as_ref());
                                    }
                                    aya::maps::perf::PerfEvent::Lost { count } => {
                                        telemetry.record_lost_perf_events(count);
                                        warn!(source = module, stream, count, "lost perf events");
                                    }
                                }
                                telemetry.maybe_log_summary();
                            });
                            if closed {
                                return;
                            }
                        }
                    }));
                }
                Ok(handles)
            }
        }
    }

    pub(crate) fn spawn_transport_loss_reader(
        ebpf: &mut Ebpf,
        profile: SourceMapProfile,
        transport: ResolvedEventTransport,
        module: &'static str,
        shutdown: ReaderShutdown,
        telemetry: Arc<SourceTelemetry>,
    ) -> CoreResult<Option<JoinHandle<()>>> {
        if transport.kind != EventTransportKind::RingBuffer {
            return Ok(None);
        }

        let counters =
            PerCpuArray::try_from(ebpf.take_map("EVENT_TRANSPORT_LOSSES").ok_or_else(|| {
                CoreError::ModuleFailed {
                    module: module.to_string(),
                    message: "missing EVENT_TRANSPORT_LOSSES map".to_string(),
                }
            })?)
            .map_err(|err| module_error(module, err))?;
        Ok(Some(tokio::task::spawn_blocking(move || {
            let mut previous = 0_u64;
            loop {
                if shutdown.is_stopped() {
                    record_ring_loss_delta(&counters, profile, module, &telemetry, &mut previous);
                    return;
                }
                std::thread::sleep(TRANSPORT_LOSS_POLL_INTERVAL);
                record_ring_loss_delta(&counters, profile, module, &telemetry, &mut previous);
            }
        })))
    }

    fn record_ring_loss_delta(
        counters: &PerCpuArray<MapData, u64>,
        profile: SourceMapProfile,
        module: &'static str,
        telemetry: &SourceTelemetry,
        previous: &mut u64,
    ) {
        match read_ring_loss_total(counters, profile) {
            Ok(current) => {
                let delta = current.wrapping_sub(*previous);
                *previous = current;
                if delta != 0 {
                    telemetry.record_ring_buffer_reservation_failures(delta);
                    telemetry.maybe_log_summary();
                    warn!(
                        source = module,
                        count = delta,
                        "lost ring-buffer events after producer reservation failures"
                    );
                }
            }
            Err(err) => warn!(
                source = module,
                error = %err,
                "failed to read ring-buffer loss counters"
            ),
        }
    }

    fn read_ring_loss_total(
        counters: &PerCpuArray<MapData, u64>,
        profile: SourceMapProfile,
    ) -> Result<u64, aya::maps::MapError> {
        let mut total = 0_u64;
        for index in profile.transport_loss_indices() {
            let per_cpu = counters.get(index, 0)?;
            total = per_cpu
                .iter()
                .fold(total, |sum, value| sum.wrapping_add(*value));
        }
        Ok(total)
    }

    fn module_error(module: &'static str, err: impl core::fmt::Display) -> CoreError {
        CoreError::ModuleFailed {
            module: module.to_string(),
            message: err.to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use platform::{
    EventMap, load_ebpf, load_ebpf_with, spawn_event_readers, spawn_transport_loss_reader,
    take_event_map,
};

#[cfg(feature = "fuzzing")]
pub fn bench_ring_sample_handoff(sample: &[u8]) -> usize {
    sample.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_selection_prefers_ring_and_falls_back_only_when_unsupported() {
        assert_eq!(
            select_with_probe(EbpfEventTransport::Auto, || Ok(true)),
            Ok(EventTransportKind::RingBuffer)
        );
        assert_eq!(
            select_with_probe(EbpfEventTransport::Auto, || Ok(false)),
            Ok(EventTransportKind::PerfBuffer)
        );
        assert_eq!(
            select_with_probe(EbpfEventTransport::Auto, || Err(
                "permission denied".to_string()
            )),
            Err("BPF ring-buffer capability probe failed: permission denied".to_string())
        );
    }

    #[test]
    fn explicit_transport_modes_are_strict() {
        assert_eq!(
            select_with_probe(EbpfEventTransport::PerfBuffer, || {
                panic!("forced perf transport must not probe ring support")
            }),
            Ok(EventTransportKind::PerfBuffer)
        );
        assert_eq!(
            select_with_probe(EbpfEventTransport::RingBuffer, || Ok(false)),
            Err("the kernel does not support BPF ring-buffer maps".to_string())
        );
    }
}

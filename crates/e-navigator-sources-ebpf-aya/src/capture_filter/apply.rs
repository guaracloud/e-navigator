//! Per-source application of the shared capture-filter desired state.
//!
//! Each eBPF source owns its own copy of the filter maps (it loads its own
//! program object), so each keeps a [`FilterMapMirror`] and applies the minimal
//! diff from the shared controller. The control word is static config, written
//! once; the membership map converges on every published change.

use std::sync::Arc;
use std::time::Duration;

use aya::Ebpf;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, Map, MapData, PerCpuArray};
use e_navigator_core::capture_filter::{DesiredFilterMap, FilterMapMirror};
use e_navigator_core::{CoreError, CoreResult};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::{CaptureFilterController, shared};

/// Loss-recovery and shutdown-check cadence. Desired-map publications wake
/// every source applier immediately through the shared controller condvar.
const APPLY_TICK: Duration = Duration::from_secs(1);
const ACCOUNTING_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Seed the fail-open/fail-closed control word before any source program is
/// attached. Sources with high-frequency global hooks must call this before
/// attachment so the short setup window cannot observe unrelated workloads.
pub(crate) fn seed_capture_filter_control(ebpf: &mut Ebpf, module: &'static str) -> CoreResult<()> {
    let Some(controller) = shared() else {
        return Ok(());
    };
    let map = ebpf
        .map_mut("CAPTURE_FILTER_CONTROL")
        .ok_or_else(|| CoreError::ModuleFailed {
            module: module.to_string(),
            message: "missing CAPTURE_FILTER_CONTROL map".to_string(),
        })?;
    let mut control: AyaArray<&mut MapData, u32> =
        AyaArray::try_from(map).map_err(|err| module_error(module, err))?;
    control
        .set(0, controller.control_word(), 0)
        .map_err(|err| module_error(module, err))
}

/// If the capture filter is active, take this source's filter maps out of its
/// eBPF object, seed the control word, and spawn the applier task. Returns the
/// task handle so the source can join it on shutdown. Returns `None` (leaving
/// the maps in place, control word `0` = disabled) when the filter is
/// inactive.
pub(crate) fn attach_capture_filter(
    ebpf: &mut Ebpf,
    module: &'static str,
    is_stopped: impl Fn() -> bool + Send + 'static,
) -> CoreResult<Option<JoinHandle<()>>> {
    let Some(controller) = shared() else {
        return Ok(None);
    };

    let mut control: AyaArray<MapData, u32> =
        AyaArray::try_from(take_map(ebpf, module, "CAPTURE_FILTER_CONTROL")?)
            .map_err(|err| module_error(module, err))?;
    control
        .set(0, controller.control_word(), 0)
        .map_err(|err| module_error(module, err))?;

    let filter: AyaHashMap<MapData, u64, u8> =
        AyaHashMap::try_from(take_map(ebpf, module, "CGROUP_CAPTURE_FILTER")?)
            .map_err(|err| module_error(module, err))?;
    let dropped: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(take_map(ebpf, module, "CAPTURE_FILTER_DROPPED")?)
            .map_err(|err| module_error(module, err))?;

    let handle = tokio::task::spawn_blocking(move || {
        run_applier(module, controller, filter, dropped, is_stopped);
    });
    Ok(Some(handle))
}

fn take_map(ebpf: &mut Ebpf, module: &'static str, name: &'static str) -> CoreResult<Map> {
    ebpf.take_map(name).ok_or_else(|| CoreError::ModuleFailed {
        module: module.to_string(),
        message: format!("missing {name} map"),
    })
}

fn module_error(module: &'static str, err: impl ToString) -> CoreError {
    CoreError::ModuleFailed {
        module: module.to_string(),
        message: err.to_string(),
    }
}

fn run_applier(
    module: &'static str,
    controller: Arc<CaptureFilterController>,
    mut filter: AyaHashMap<MapData, u64, u8>,
    dropped: PerCpuArray<MapData, u64>,
    is_stopped: impl Fn() -> bool,
) {
    let mut mirror = FilterMapMirror::new();
    let mut last_generation: Option<u64> = None;
    let mut last_accounting = std::time::Instant::now();

    while !is_stopped() {
        let (generation, desired, bootstrap_started_at) =
            controller.wait_for_change(last_generation, APPLY_TICK);
        if is_stopped() {
            break;
        }

        if last_generation != Some(generation) {
            last_generation = Some(generation);
            let failures = apply_diff(module, &mut filter, &mut mirror, &desired);
            controller.record_map_apply(bootstrap_started_at, failures);
        }

        if last_accounting.elapsed() >= ACCOUNTING_LOG_INTERVAL {
            last_accounting = std::time::Instant::now();
            log_accounting(module, &desired, &dropped, mirror.len());
        }
    }
}

fn apply_diff(
    module: &'static str,
    filter: &mut AyaHashMap<MapData, u64, u8>,
    mirror: &mut FilterMapMirror,
    desired: &DesiredFilterMap,
) -> u64 {
    let diff = mirror.plan(desired);
    let mut failures = 0u64;
    for (cgroup_id, byte) in diff.upserts {
        match filter.insert(cgroup_id, byte, 0) {
            Ok(()) => mirror.record_upsert(cgroup_id, byte),
            Err(err) => {
                failures = failures.saturating_add(1);
                warn!(
                    target: "e_navigator_sources_ebpf_aya::capture_filter",
                    source = module,
                    cgroup_id,
                    error = %err,
                    "capture filter map insert failed"
                );
            }
        }
    }
    for cgroup_id in diff.removals {
        match filter.remove(&cgroup_id) {
            Ok(()) => mirror.record_removal(cgroup_id),
            Err(err) => {
                failures = failures.saturating_add(1);
                warn!(
                    target: "e_navigator_sources_ebpf_aya::capture_filter",
                    source = module,
                    cgroup_id,
                    error = %err,
                    "capture filter map remove failed"
                );
            }
        }
    }
    failures
}

/// Never silent: report how many cgroups are allowed/denied and how many events
/// the filter has suppressed since the source started.
fn log_accounting(
    module: &'static str,
    desired: &DesiredFilterMap,
    dropped: &PerCpuArray<MapData, u64>,
    live_entries: usize,
) {
    let dropped_total = read_dropped(dropped);
    info!(
        target: "e_navigator_sources_ebpf_aya::capture_filter",
        source = module,
        allowed = desired.allowed_count(),
        denied = desired.denied_count(),
        live_entries,
        dropped_total,
        "capture filter accounting"
    );
}

fn read_dropped(dropped: &PerCpuArray<MapData, u64>) -> u64 {
    match dropped.get(&0, 0) {
        Ok(per_cpu) => per_cpu
            .iter()
            .fold(0u64, |sum, value| sum.saturating_add(*value)),
        Err(_) => 0,
    }
}

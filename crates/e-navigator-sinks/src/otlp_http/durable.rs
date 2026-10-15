//! Disk admission and HTTP delivery run concurrently within each family worker.
use super::*;
use crate::durable_spool::Spool;
use std::io;
use tokio::sync::Notify;

pub(super) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

async fn storage<R: Send + 'static>(
    spool: &Arc<StdMutex<Spool>>,
    operation: impl FnOnce(&mut Spool) -> io::Result<R> + Send + 'static,
    telemetry: &Arc<AtomicExportWorkerTelemetry>,
) -> io::Result<R> {
    let spool = spool.clone();
    let telemetry = telemetry.clone();
    tokio::task::spawn_blocking(move || {
        let mut spool = spool
            .lock()
            .map_err(|_| io::Error::other("spool lock failed"))?;
        let expired = spool.expired;
        let result = operation(&mut spool);
        telemetry.spool_bytes.store(spool.bytes, Ordering::Relaxed);
        telemetry
            .spool_entries
            .store(spool.len() as u64, Ordering::Relaxed);
        telemetry
            .spool_expired
            .fetch_add(spool.expired.saturating_sub(expired), Ordering::Relaxed);
        if result.is_err() {
            telemetry.spool_errors.fetch_add(1, Ordering::Relaxed);
        }
        result
    })
    .await
    .map_err(|_| io::Error::other("spool task failed"))?
}

pub(super) async fn run<T: Send + Sync + 'static>(
    mut receiver: mpsc::Receiver<ExportCommand<T>>,
    mut exporter: HttpProtobufExporter<T>,
    telemetry: Arc<AtomicExportWorkerTelemetry>,
    tuning: ExportWorkerTuning,
    spool: Spool,
) {
    telemetry
        .spool_recovered
        .store(spool.len() as u64, Ordering::Relaxed);
    telemetry.spool_bytes.store(spool.bytes, Ordering::Relaxed);
    telemetry
        .spool_entries
        .store(spool.len() as u64, Ordering::Relaxed);
    let spool = Arc::new(StdMutex::new(spool));
    let notify = Notify::new();
    let stopping = Notify::new();
    let healthy = AtomicBool::new(true);
    let finished = AtomicBool::new(false);
    let encode = exporter.encoder();
    let append = async {
        while let Some(command) = receiver.recv().await {
            let ExportCommand::Record(record, receipt) = command else {
                receiver.close();
                continue;
            };
            let accepted = if !healthy.load(Ordering::Acquire) {
                false
            } else {
                match encode(std::slice::from_ref(&record)) {
                    Ok(body) => storage(
                        &spool,
                        move |spool| spool.append(&body, 1, now_millis()),
                        &telemetry,
                    )
                    .await
                    .is_ok(),
                    Err(_) => false,
                }
            };
            if accepted {
                telemetry.spool_accepted.fetch_add(1, Ordering::Relaxed);
                notify.notify_one();
            } else {
                telemetry.spool_rejected.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(receipt) = receipt {
                receipt.complete(accepted);
            }
        }
        finished.store(true, Ordering::Release);
        notify.notify_one();
        stopping.notify_one();
    };
    let deliver = async {
        loop {
            let entry = match storage(&spool, |spool| spool.front(now_millis()), &telemetry).await {
                Ok(Some(entry)) => entry,
                Ok(None) => {
                    if finished.load(Ordering::Acquire) {
                        return;
                    }
                    tokio::select! { () = notify.notified() => {}, () = tokio::time::sleep(tuning.flush_interval) => {} }
                    continue;
                }
                Err(_) => {
                    // Keep damaged/unreadable data for operator recovery and fail new admission.
                    healthy.store(false, Ordering::Release);
                    return;
                }
            };
            let before = exporter.counters();
            let result = match exporter.compress_body(entry.body).await {
                Ok(body) => exporter.send_encoded(body, entry.count).await,
                Err(err) => Err(err),
            };
            observe_export_counters(&telemetry, before, exporter.counters());
            let terminal =
                result.is_ok() || matches!(result, Err(crate::ExporterError::PermanentStatus(_)));
            if terminal {
                if result.is_err() {
                    telemetry
                        .dropped_export_failure
                        .fetch_add(entry.count, Ordering::Relaxed);
                }
                if storage(&spool, move |spool| spool.ack(entry.id), &telemetry)
                    .await
                    .is_err()
                {
                    // An uncertain ack may replay on restart. Stop delivery and new admission.
                    healthy.store(false, Ordering::Release);
                    return;
                }
            } else {
                telemetry.failed_batches.fetch_add(1, Ordering::Relaxed);
                telemetry.circuit_opened.fetch_add(1, Ordering::Relaxed);
                // Retain accepted requests through outages and shutdown, bounded by age/bytes.
                if finished.load(Ordering::Acquire) {
                    return;
                }
                tokio::select! { () = tokio::time::sleep(tuning.circuit_breaker_cooldown) => {}, () = stopping.notified() => { return; } }
            }
        }
    };
    tokio::join!(append, deliver);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ack_directory_sync_failure_stops_delivery_and_rejects_new_admission() {
        let fixture = crate::durable_spool::tests::Fixture::new();
        let collector = super::super::tests::FakeCollector::spawn(vec![200]).await;
        let config = super::super::tests::log_config(collector.url());
        let mut spool = Spool::open(&fixture.0, 1024, 4, 1000).expect("spool");
        spool.fail_at = 5;
        let exporter = HttpProtobufExporter::new(
            exporter_config_for(&config, &config.logs_endpoint, "logs"),
            |records: &[Vec<u8>]| Ok(records.concat()),
        )
        .expect("exporter");
        let telemetry = Arc::new(AtomicExportWorkerTelemetry::default());
        let (tx, rx) = mpsc::channel(4);
        let worker = tokio::spawn(run(
            rx,
            exporter,
            telemetry.clone(),
            ExportWorkerTuning {
                batch_size: 1,
                flush_interval: Duration::from_millis(1),
                circuit_breaker_failure_threshold: 1,
                circuit_breaker_cooldown: Duration::from_millis(1),
            },
            spool,
        ));
        let (receipt, accepted) = e_navigator_core::DurableReceipt::channel();
        tx.send(ExportCommand::Record(b"request".to_vec(), Some(receipt)))
            .await
            .expect("enqueue");
        assert!(accepted.await.expect("accepted"));
        let _ = collector.next_request().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while telemetry.spool_errors.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
            // The error counter is updated before the delivery future resumes.
            tokio::time::sleep(Duration::from_millis(10)).await;
        })
        .await
        .expect("ack failure");
        let (receipt, accepted) = e_navigator_core::DurableReceipt::channel();
        tx.send(ExportCommand::Record(
            b"new request".to_vec(),
            Some(receipt),
        ))
        .await
        .expect("enqueue");
        assert!(!accepted.await.expect("rejected after uncertain ack"));
        assert_eq!(telemetry.spool_accepted.load(Ordering::Relaxed), 1);
        assert_eq!(telemetry.spool_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(telemetry.spool_errors.load(Ordering::Relaxed), 1);
        assert!(collector.try_next_request().is_none());
        tx.send(ExportCommand::Shutdown).await.expect("shutdown");
        worker.await.expect("worker");
        assert!(
            Spool::open(&fixture.0, 1024, 4, 1000)
                .expect("safe reopen")
                .front(now_millis())
                .expect("front")
                .is_none()
        );
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::perf::{PerfEvent, PerfEventArray},
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
    use e_navigator_signals::{ExecEvent, SignalEnvelope};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{debug, warn};

    const EXECUTABLE_LEN: usize = 256;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawExecEvent {
        pid: u32,
        uid: u32,
        command: [u8; 16],
        executable: [u8; EXECUTABLE_LEN],
    }

    #[derive(Debug, Default)]
    pub struct AyaExecSource {
        host: Option<String>,
    }

    impl AyaExecSource {
        pub fn new(host: Option<String>) -> Self {
            Self { host }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaExecSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_exec", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();

            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;

            let program: &mut TracePoint = ebpf
                .program_mut("tracepoint_execve")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing tracepoint_execve program".to_string(),
                })?
                .try_into()
                .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            program.load().map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
            program
                .attach("syscalls", "sys_enter_execve")
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let mut perf_array =
                PerfEventArray::try_from(ebpf.take_map("EXEC_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_exec".to_string(),
                        message: "missing EXEC_EVENTS map".to_string(),
                    }
                })?)
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            for cpu_id in online_cpus().map_err(|(_, err)| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })? {
                let mut buffer =
                    perf_array
                        .open(cpu_id, None)
                        .map_err(|err| CoreError::ModuleFailed {
                            module: "source.aya_exec".to_string(),
                            message: err.to_string(),
                        })?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let reader_shutdown = shutdown.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    if !tail.is_empty() {
                                        warn!("dropped wrapped exec perf event sample");
                                        return;
                                    }

                                    if let Some(signal) = raw_to_signal(head, host.clone()) {
                                        if cpu_tx.blocking_send(signal).is_err() {
                                            closed = true;
                                        }
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    warn!(count, "lost exec perf events");
                                }
                            }
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }));
            }

            debug!("aya exec source attached");
            tokio::signal::ctrl_c()
                .await
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    fn raw_to_signal(bytes: &[u8], host: Option<String>) -> Option<SignalEnvelope> {
        if bytes.len() < core::mem::size_of::<RawExecEvent>() {
            return None;
        }

        let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };
        let task_comm = super::bytes_to_string(&raw.command);
        let executable = super::bytes_to_string(&raw.executable);
        let command = if executable.is_empty() {
            task_comm
        } else {
            executable.clone()
        };

        Some(SignalEnvelope::exec(
            "source.aya_exec",
            host,
            ExecEvent {
                pid: raw.pid,
                ppid: None,
                uid: Some(raw.uid),
                command,
                executable: (!executable.is_empty()).then_some(executable),
                arguments: vec![],
                cgroup_id: None,
                timestamp_unix_nanos: now_unix_nanos(),
                container: None,
                kubernetes: None,
            },
        ))
    }

    #[derive(Clone)]
    struct ReaderShutdown {
        stopped: Arc<AtomicBool>,
    }

    impl ReaderShutdown {
        fn new() -> Self {
            Self {
                stopped: Arc::new(AtomicBool::new(false)),
            }
        }

        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }

        fn is_stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }
    }

    impl Drop for ReaderShutdown {
        fn drop(&mut self) {
            self.stop();
        }
    }

    async fn join_reader_handles(handles: Vec<JoinHandle<()>>) -> CoreResult<()> {
        for handle in handles {
            handle.await.map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
        }

        Ok(())
    }

    fn bump_memlock_rlimit() {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
        if ret != 0 {
            debug!("failed to raise RLIMIT_MEMLOCK");
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaExecSource {
        host: Option<String>,
    }

    impl AyaExecSource {
        pub fn new(host: Option<String>) -> Self {
            Self { host }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaExecSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_exec", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: format!(
                    "Aya exec source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaExecSource;

#[cfg(any(target_os = "linux", test))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(any(target_os = "linux", test))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_bytes_convert_to_string() {
        let mut command = [0_u8; 16];
        command[..4].copy_from_slice(b"bash");
        assert_eq!(bytes_to_string(&command), "bash");
    }

    #[test]
    fn unix_timestamp_is_not_epoch_placeholder() {
        assert!(now_unix_nanos() > 0);
    }
}

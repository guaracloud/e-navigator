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
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawExecEvent {
        pid: u32,
        uid: u32,
        command: [u8; 16],
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

                tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    loop {
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
                });
            }

            debug!("aya exec source attached");
            tokio::signal::ctrl_c()
                .await
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })
        }
    }

    fn raw_to_signal(bytes: &[u8], host: Option<String>) -> Option<SignalEnvelope> {
        if bytes.len() < core::mem::size_of::<RawExecEvent>() {
            return None;
        }

        let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };
        let command = super::command_to_string(&raw.command);

        Some(SignalEnvelope::exec(
            "source.aya_exec",
            host,
            ExecEvent {
                pid: raw.pid,
                ppid: None,
                uid: Some(raw.uid),
                command,
                executable: None,
                arguments: vec![],
                cgroup_id: None,
                timestamp_unix_nanos: 0,
                container: None,
                kubernetes: None,
            },
        ))
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
fn command_to_string(command: &[u8; 16]) -> String {
    let end = command
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(command.len());
    String::from_utf8_lossy(&command[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_bytes_convert_to_string() {
        let mut command = [0_u8; 16];
        command[..4].copy_from_slice(b"bash");
        assert_eq!(command_to_string(&command), "bash");
    }
}

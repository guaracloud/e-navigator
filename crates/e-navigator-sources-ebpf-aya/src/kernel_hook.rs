//! Selection and capability probing for BTF-backed network I/O hooks.

use e_navigator_core::EbpfNetworkIoHook;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum NetworkIoHookKind {
    Fexit,
    Tracepoint,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl NetworkIoHookKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Fexit => "fexit",
            Self::Tracepoint => "tracepoint",
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn select_with_probe(
    requested: EbpfNetworkIoHook,
    probe: impl FnOnce() -> Result<bool, String>,
) -> Result<NetworkIoHookKind, String> {
    if requested == EbpfNetworkIoHook::Tracepoint {
        return Ok(NetworkIoHookKind::Tracepoint);
    }

    match probe() {
        Ok(true) => Ok(NetworkIoHookKind::Fexit),
        Ok(false) if requested == EbpfNetworkIoHook::Auto => Ok(NetworkIoHookKind::Tracepoint),
        Ok(false) => Err(
            "the kernel does not support both BTF-backed ksys_read and ksys_write fexit hooks"
                .to_string(),
        ),
        Err(err) => Err(format!("BPF fexit capability probe failed: {err}")),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{NetworkIoHookKind, select_with_probe};
    use aya::{Btf, programs::ProgramType, sys::is_program_supported};
    use aya_obj::btf::{BtfError, BtfKind};
    use e_navigator_core::{CoreError, CoreResult, EbpfNetworkIoHook};
    use tracing::{info, warn};

    pub(crate) struct ResolvedNetworkIoHook {
        pub(crate) kind: NetworkIoHookKind,
        pub(crate) btf: Option<Btf>,
    }

    impl core::fmt::Debug for ResolvedNetworkIoHook {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("ResolvedNetworkIoHook")
                .field("kind", &self.kind)
                .field("btf_loaded", &self.btf.is_some())
                .finish()
        }
    }

    pub(crate) fn resolve_network_io_hook(
        requested: EbpfNetworkIoHook,
    ) -> CoreResult<ResolvedNetworkIoHook> {
        if requested == EbpfNetworkIoHook::Tracepoint {
            info!(
                source = "source.aya_network",
                network_io_hook = NetworkIoHookKind::Tracepoint.as_str(),
                "selected network I/O kernel hook"
            );
            return Ok(ResolvedNetworkIoHook {
                kind: NetworkIoHookKind::Tracepoint,
                btf: None,
            });
        }

        let capability = probe_fexit_capability().map_err(module_message)?;
        let kind =
            select_with_probe(requested, || Ok(capability.is_some())).map_err(module_message)?;
        if kind == NetworkIoHookKind::Tracepoint {
            warn!(
                source = "source.aya_network",
                "BTF-backed fexit network I/O hooks are unsupported; using syscall tracepoints"
            );
        }
        info!(
            source = "source.aya_network",
            network_io_hook = kind.as_str(),
            "selected network I/O kernel hook"
        );
        Ok(ResolvedNetworkIoHook {
            kind,
            btf: capability,
        })
    }

    fn probe_fexit_capability() -> Result<Option<Btf>, String> {
        match is_program_supported(ProgramType::Tracing) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(err) => return Err(err.to_string()),
        }

        let btf = match Btf::from_sys_fs() {
            Ok(btf) => btf,
            Err(BtfError::FileError { error, .. })
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err.to_string()),
        };
        for target in ["ksys_read", "ksys_write"] {
            match btf.id_by_type_name_kind(target, BtfKind::Func) {
                Ok(_) => {}
                Err(BtfError::UnknownBtfTypeName { .. }) => return Ok(None),
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(Some(btf))
    }

    fn module_message(message: impl ToString) -> CoreError {
        CoreError::ModuleFailed {
            module: "source.aya_network".to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use platform::{ResolvedNetworkIoHook, resolve_network_io_hook};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_selection_prefers_fexit_and_falls_back_only_when_unsupported() {
        assert_eq!(
            select_with_probe(EbpfNetworkIoHook::Auto, || Ok(true)),
            Ok(NetworkIoHookKind::Fexit)
        );
        assert_eq!(
            select_with_probe(EbpfNetworkIoHook::Auto, || Ok(false)),
            Ok(NetworkIoHookKind::Tracepoint)
        );
        assert!(select_with_probe(EbpfNetworkIoHook::Auto, || Err("denied".to_string())).is_err());
    }

    #[test]
    fn explicit_network_hook_modes_are_strict() {
        assert_eq!(
            select_with_probe(EbpfNetworkIoHook::Tracepoint, || {
                panic!("forced tracepoint mode must not probe fexit")
            }),
            Ok(NetworkIoHookKind::Tracepoint)
        );
        assert!(select_with_probe(EbpfNetworkIoHook::Fexit, || Ok(false)).is_err());
        assert!(select_with_probe(EbpfNetworkIoHook::Fexit, || Err("denied".to_string())).is_err());
    }
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../e-navigator-ebpf-programs/src/main.rs");
    println!("cargo:rerun-if-changed=../e-navigator-ebpf-programs/src/dns_peer.rs");
    println!("cargo:rerun-if-env-changed=E_NAVIGATOR_BPF_TOOLCHAIN");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS")?;
    let host = std::env::var("HOST")?;
    let target = std::env::var("TARGET")?;
    let bpf_toolchain = std::env::var("E_NAVIGATOR_BPF_TOOLCHAIN")
        .unwrap_or_else(|_| "nightly-2026-07-01".to_string());

    if target_os == "linux" && host.contains("linux") {
        aya_build::build_ebpf(
            [aya_build::Package {
                name: "e-navigator-ebpf-programs",
                root_dir: "../e-navigator-ebpf-programs",
                ..Default::default()
            }],
            aya_build::Toolchain::Custom(&bpf_toolchain),
        )?;
    } else if target_os == "linux" {
        anyhow::bail!(
            "cross-compiling the Linux Aya source from host {host} to target {target} is not supported by this build script; build on Linux or set up an explicit eBPF artifact pipeline"
        );
    } else {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        std::fs::write(out_dir.join("e-navigator-ebpf-programs"), [])?;
    }

    Ok(())
}

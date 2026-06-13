fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../e-navigator-ebpf-programs/src/main.rs");

    #[cfg(target_os = "linux")]
    {
        aya_build::build_ebpf([("../e-navigator-ebpf-programs", "e-navigator-ebpf-programs")])?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        std::fs::write(out_dir.join("e-navigator-ebpf-programs"), [])?;
    }

    Ok(())
}

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use xshell::{cmd, Shell};

#[derive(Parser)]
pub enum Options {
    /// Build the eBPF program
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let opts = Options::parse();
    let sh = Shell::new()?;

    match opts {
        Options::BuildEbpf { release } => {
            let mut args = vec!["build", "-Z", "build-std=core", "--package", "sysguard-ebpf"];
            if release {
                args.push("--release");
            }
            // Cross-compile to bpfel
            args.push("--target");
            args.push("bpfel-unknown-none");
            
            // Build the kernel eBPF program using bpf-linker
            cmd!(sh, "cargo +nightly {args...}").run()?;
            
            // Copy output to a predictable location for userspace
            let out_dir = sh.current_dir().join("target").join("bpfel-unknown-none");
            let build_type = if release { "release" } else { "debug" };
            let src = out_dir.join(build_type).join("sysguard-ebpf");
            let dest_dir = sh.current_dir().join("target").join("bpf");
            let dest = dest_dir.join("sysguard-ebpf");
            
            sh.create_dir(&dest_dir)?;
            fs::copy(&src, &dest).with_context(|| {
                format!(
                    "failed to copy compiled eBPF object from {} to {}",
                    src.display(),
                    dest.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
use crate::policy::ConnectBlockPlan;
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::{
    maps::HashMap,
    programs::{CgroupAttachMode, CgroupSockAddr},
    Bpf, Pod,
};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ConnectBlockKey {
    uid: u32,
    addr: u32,
    port: u16,
    pad: u16,
}

#[cfg(target_os = "linux")]
unsafe impl Pod for ConnectBlockKey {}

#[cfg(target_os = "linux")]
pub struct EnforcementStatus {
    pub installed_rules: usize,
    pub skipped_rules: Vec<String>,
}

#[cfg(target_os = "linux")]
pub fn install_connect_enforcement(
    bpf: &mut Bpf,
    plan: &ConnectBlockPlan,
    cgroup_path: &Path,
) -> Result<EnforcementStatus> {
    if plan.enforceable.is_empty() {
        return Ok(EnforcementStatus {
            installed_rules: 0,
            skipped_rules: plan.skipped.clone(),
        });
    }

    let mut blocked_connects = HashMap::<_, ConnectBlockKey, u8>::try_from(
        bpf.map_mut("BLOCKED_CONNECT_RULES")
            .context("missing BLOCKED_CONNECT_RULES map in eBPF object")?,
    )?;

    for rule in &plan.enforceable {
        let key = ConnectBlockKey {
            uid: rule.uid.unwrap_or(0),
            addr: rule.addr.map(u32::from).unwrap_or(0),
            port: rule.port.unwrap_or(0),
            pad: 0,
        };

        blocked_connects
            .insert(key, 1, 0)
            .with_context(|| format!("failed to install connect block rule {}", rule.name))?;
    }

    let cgroup = File::open(cgroup_path)
        .with_context(|| format!("failed to open cgroup path {}", cgroup_path.display()))?;
    let program: &mut CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("missing connect4 cgroup eBPF program")?
        .try_into()?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::Single)?;

    Ok(EnforcementStatus {
        installed_rules: plan.enforceable.len(),
        skipped_rules: plan.skipped.clone(),
    })
}

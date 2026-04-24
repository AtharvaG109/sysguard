mod dedup;
mod enforce;
mod policy;

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::maps::RingBuf;
#[cfg(target_os = "linux")]
use aya::{programs::TracePoint, Bpf};
use clap::{Parser, ValueEnum};
#[cfg(target_os = "linux")]
use dedup::{DedupSummary, Deduper};
#[cfg(target_os = "linux")]
use enforce::install_connect_enforcement;
use policy::{EventRecord, PolicyDecision, PolicyFile};
#[cfg(target_os = "linux")]
use policy::RuleAction;
#[cfg(target_os = "macos")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysguard_common::EventKind;
#[cfg(target_os = "linux")]
use sysguard_common::{SysguardEvent, AF_INET};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "linux")]
use tokio::time::timeout;
#[cfg(target_os = "macos")]
use tokio::time::sleep;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// Path to policy yaml file
    #[arg(short, long, default_value = "policy.yaml")]
    policy: PathBuf,

    /// Print the full raw event stream instead of suppressing noisy defaults.
    #[arg(long)]
    verbose: bool,

    /// Only show events for a specific uid.
    #[arg(long)]
    uid: Option<u32>,

    /// Output format for emitted events.
    #[arg(long, value_enum, default_value_t = OutputMode::Plain)]
    output: OutputMode,

    /// Suppress duplicate events seen within this many milliseconds.
    #[arg(long, default_value_t = 1500)]
    dedup_window_ms: u64,

    /// Emit duplicate summaries at this interval in seconds.
    #[arg(long, default_value_t = 5)]
    summary_interval_secs: u64,

    /// Enforce connect block rules at the kernel level using a cgroup connect4 hook.
    #[arg(long)]
    enforce_connect: bool,

    /// Cgroup path used for connect enforcement.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_path: PathBuf,

    /// Print a policy summary and exit without attaching monitors.
    #[arg(long)]
    policy_summary: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputMode {
    Plain,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    let policy = PolicyFile::load(&opt.policy)?;
    if opt.policy_summary {
        println!("{}", policy.summary_line());
        return Ok(());
    }
    run(&policy, &opt).await
}

#[cfg(target_os = "linux")]
async fn run(policy: &PolicyFile, opt: &Opt) -> Result<()> {
    let bpf_data = load_bpf_object()?;
    let mut bpf = Bpf::load(&bpf_data)?;
    let connect_block_plan = policy.connect_block_plan();

    attach_tracepoint(&mut bpf, "sys_enter_execve", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(&mut bpf, "sys_enter_openat", "syscalls", "sys_enter_openat")?;
    attach_tracepoint(&mut bpf, "sys_enter_connect", "syscalls", "sys_enter_connect")?;

    if opt.enforce_connect {
        let status = install_connect_enforcement(&mut bpf, &connect_block_plan, &opt.cgroup_path)?;
        if status.installed_rules > 0 {
            println!(
                "Connect enforcement enabled on {} with {} installed rule(s).",
                opt.cgroup_path.display(),
                status.installed_rules
            );
        } else {
            println!(
                "Connect enforcement requested, but no enforceable connect block rules were found."
            );
        }

        for skipped in status.skipped_rules {
            println!("Skipped connect enforcement rule: {skipped}");
        }
    } else if !connect_block_plan.enforceable.is_empty() {
        println!(
            "Found {} enforceable connect block rule(s). They will be reported as BLOCK but not enforced unless --enforce-connect is set.",
            connect_block_plan.enforceable.len()
        );
        for skipped in connect_block_plan.skipped {
            println!("Skipped connect enforcement rule: {skipped}");
        }
    }

    let ring_buf = RingBuf::try_from(
        bpf.map_mut("EVENTS")
            .context("missing EVENTS ring buffer map in eBPF object")?,
    )?;
    let mut poll = AsyncFd::new(ring_buf)?;
    let mut deduper = Deduper::new(
        Duration::from_millis(opt.dedup_window_ms),
        Duration::from_secs(opt.summary_interval_secs),
    );

    println!("Sysguard attached. Listening for execve/openat/connect events...");
    if !opt.verbose {
        println!("Quiet mode enabled: suppressing common system noise. Use --verbose for full output.");
    }
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut shown_events = 0u64;
    let mut suppressed_events = 0u64;
    let poll_timeout = Duration::from_secs(1);

    while running.load(Ordering::SeqCst) {
        match timeout(poll_timeout, poll.readable_mut()).await {
            Ok(guard_result) => {
                let mut guard = guard_result?;
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<SysguardEvent>() {
                        let event =
                            unsafe { std::ptr::read_unaligned(item.as_ptr() as *const SysguardEvent) };
                        let mut record = linux_event_record(&event);

                        if !should_emit_linux_event(policy, &record, opt) {
                            suppressed_events += 1;
                            continue;
                        }

                        enrich_linux_event_record(&mut record);
                        let decision = policy.evaluate(&record);
                        if deduper.observe(&record, &decision) {
                            emit_event_output(opt.output, &decision, &record)?;
                            shown_events += 1;
                        } else {
                            suppressed_events += 1;
                        }
                    }
                }

                guard.clear_ready();
            }
            Err(_) => {}
        }

        for summary in deduper.flush_ready(false) {
            emit_summary_output(opt.output, &summary)?;
        }
    }

    for summary in deduper.flush_ready(true) {
        emit_summary_output(opt.output, &summary)?;
    }

    println!(
        "Sysguard stopped. shown_events={} suppressed_events={}",
        shown_events, suppressed_events
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn load_bpf_object() -> Result<Vec<u8>> {
    let object_path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpf/sysguard-ebpf"
    ));
    fs::read(&object_path).with_context(|| {
        format!(
            "failed to read eBPF object at {}. Build it first with `cargo xtask build-ebpf --release` or `./scripts/build-release.sh`",
            object_path.display()
        )
    })
}

#[cfg(target_os = "macos")]
async fn run(policy: &PolicyFile, opt: &Opt) -> Result<()> {
    println!("Sysguard macOS mode attached. Polling process launches via ps.");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut seen_pids: HashSet<u32> = snapshot_processes()?
        .into_iter()
        .map(|proc_info| proc_info.pid)
        .collect();

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(750)).await;

        let current = snapshot_processes()?;
        let current_pids: HashSet<u32> = current.iter().map(|proc_info| proc_info.pid).collect();

        for proc_info in current {
            if !seen_pids.contains(&proc_info.pid) {
                let record = EventRecord {
                    kind: EventKind::Execve,
                    pid: proc_info.pid,
                    ppid: None,
                    uid: proc_info.uid,
                    comm: proc_info.comm.clone(),
                    filename: Some(proc_info.comm),
                    daddr: None,
                    dport: None,
                    exe_path: None,
                };
                let decision = policy.evaluate(&record);
                emit_event_output(opt.output, &decision, &record)?;
            }
        }

        seen_pids = current_pids;
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn run(_policy: &PolicyFile, _opt: &Opt) -> Result<()> {
    anyhow::bail!("sysguard currently supports Linux and macOS only")
}

#[cfg(target_os = "linux")]
fn attach_tracepoint(
    bpf: &mut Bpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("missing eBPF program {program_name}"))?
        .try_into()?;
    program.load()?;
    program.attach(category, tracepoint)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_event_record(event: &SysguardEvent) -> EventRecord {
    let filename = c_string_lossy(&event.filename);
    let daddr = if event.kind == EventKind::Connect && event.socket_family == AF_INET && event.daddr != 0 {
        Some(Ipv4Addr::from(event.daddr))
    } else {
        None
    };

    EventRecord {
        kind: event.kind,
        pid: event.pid,
        ppid: None,
        uid: event.uid,
        comm: c_string_lossy(&event.comm).unwrap_or_else(|| "<unknown>".to_string()),
        filename,
        daddr,
        dport: (event.dport != 0).then_some(event.dport),
        exe_path: None,
    }
}

#[cfg(target_os = "linux")]
fn enrich_linux_event_record(record: &mut EventRecord) {
    let status_path = format!("/proc/{}/status", record.pid);
    if let Ok(status) = fs::read_to_string(status_path) {
        record.ppid = status.lines().find_map(parse_ppid_line);
    }

    let exe_path = format!("/proc/{}/exe", record.pid);
    if let Ok(path) = fs::read_link(exe_path) {
        record.exe_path = Some(path.display().to_string());
    }
}

#[cfg(target_os = "linux")]
fn parse_ppid_line(line: &str) -> Option<u32> {
    let value = line.strip_prefix("PPid:")?.trim();
    value.parse().ok()
}

fn emit_event_output(mode: OutputMode, decision: &PolicyDecision<'_>, event: &EventRecord) -> Result<()> {
    match mode {
        OutputMode::Plain => emit_plain_event(decision, event),
        OutputMode::Json => emit_json_event(decision, event)?,
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn emit_summary_output(mode: OutputMode, summary: &DedupSummary) -> Result<()> {
    match mode {
        OutputMode::Plain => emit_plain_summary(summary),
        OutputMode::Json => emit_json_summary(summary)?,
    }
    Ok(())
}

fn emit_plain_event(decision: &PolicyDecision<'_>, event: &EventRecord) {
    match decision.rule_name {
        Some(rule_name) => println!("[{}][rule={}] {}", decision.action, rule_name, event.summary()),
        None => println!("[{}][rule=<default>] {}", decision.action, event.summary()),
    }
}

#[cfg(target_os = "linux")]
fn emit_plain_summary(summary: &DedupSummary) {
    match &summary.rule_name {
        Some(rule_name) => println!(
            "[{}][rule={}][summary] {}",
            summary.action,
            rule_name,
            summary.summary_line()
        ),
        None => println!(
            "[{}][rule=<default>][summary] {}",
            summary.action,
            summary.summary_line()
        ),
    }
}

fn emit_json_event(decision: &PolicyDecision<'_>, event: &EventRecord) -> Result<()> {
    println!(
        "{{\"type\":\"event\",\"timestamp_ms\":{},\"action\":\"{}\",\"rule\":\"{}\",\"event\":{{\"event\":\"{}\",\"pid\":{},\"ppid\":{},\"uid\":{},\"comm\":{},\"file\":{},\"addr\":{},\"port\":{},\"exe\":{}}}}}",
        unix_time_ms(),
        decision.action,
        json_escape(decision.rule_name.unwrap_or("<default>")),
        policy::PolicyEventKind::from(event.kind).as_str(),
        event.pid,
        json_option_u32(event.ppid),
        event.uid,
        json_escape(&event.comm),
        json_option_str(event.filename.as_deref()),
        json_option_ip(event.daddr),
        json_option_u16(event.dport),
        json_option_str(event.exe_path.as_deref()),
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn emit_json_summary(summary: &DedupSummary) -> Result<()> {
    println!(
        "{{\"type\":\"summary\",\"timestamp_ms\":{},\"action\":\"{}\",\"rule\":\"{}\",\"event\":{{\"event\":\"{}\",\"pid\":{},\"ppid\":{},\"uid\":{},\"comm\":{},\"file\":{},\"addr\":{},\"port\":{},\"exe\":{},\"suppressed_count\":{}}}}}",
        unix_time_ms(),
        summary.action,
        json_escape(summary.rule_name.as_deref().unwrap_or("<default>")),
        summary.event.kind.as_str(),
        summary.pid,
        json_option_u32(summary.ppid),
        summary.uid,
        json_escape(&summary.event.comm),
        json_option_str(summary.event.filename.as_deref()),
        json_option_ip(summary.event.daddr),
        json_option_u16(summary.event.dport),
        json_option_str(summary.exe_path.as_deref()),
        summary.suppressed_count,
    );
    Ok(())
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn json_option_str(value: Option<&str>) -> String {
    value.map(json_escape).unwrap_or_else(|| "null".to_string())
}

fn json_option_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_option_u16(value: Option<u16>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_option_ip(value: Option<Ipv4Addr>) -> String {
    value
        .map(|value| json_escape(&value.to_string()))
        .unwrap_or_else(|| "null".to_string())
}

#[cfg(target_os = "linux")]
fn should_emit_linux_event(policy: &PolicyFile, event: &EventRecord, opt: &Opt) -> bool {
    if let Some(uid) = opt.uid {
        if event.uid != uid {
            return false;
        }
    }

    if policy.should_ignore(event) {
        return false;
    }

    if opt.verbose {
        return true;
    }

    if matches!(policy.evaluate(event).action, RuleAction::Alert | RuleAction::Block) {
        return true;
    }

    if is_noisy_process(&event.comm) {
        return false;
    }

    match event.kind {
        EventKind::Execve => event.uid >= 1000,
        EventKind::Openat => {
            if let Some(filename) = &event.filename {
                if is_noisy_path(filename) {
                    return false;
                }
            }
            event.uid >= 1000
        }
        EventKind::Connect => {
            if matches!(event.dport, Some(53)) {
                return false;
            }
            if matches!(event.daddr, Some(addr) if addr.is_loopback()) {
                return false;
            }
            event.uid >= 1000
        }
    }
}

#[cfg(target_os = "linux")]
fn is_noisy_process(comm: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "systemd",
        "vmtoolsd",
        "gnome-shell",
        "gnome-terminal-",
        "Xwayland",
        "xdg-desktop-por",
        "gsd-",
    ];
    PREFIXES.iter().any(|prefix| comm.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn is_noisy_path(path: &str) -> bool {
    const PREFIXES: &[&str] = &["/proc/", "/sys/", "/run/", "/usr/share/icons/"];
    PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn c_string_lossy(buf: &[u8]) -> Option<String> {
    let nul_idx = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let value = &buf[..nul_idx];
    if value.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(value).into_owned())
}

#[cfg(target_os = "macos")]
struct ProcInfo {
    pid: u32,
    uid: u32,
    comm: String,
}

#[cfg(target_os = "macos")]
fn snapshot_processes() -> Result<Vec<ProcInfo>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,uid=,comm="])
        .output()
        .context("failed to run ps for macOS process snapshot")?;

    if !output.status.success() {
        anyhow::bail!("ps exited with status {}", output.status);
    }

    let stdout = String::from_utf8(output.stdout).context("ps output was not valid UTF-8")?;
    let mut processes = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(pid_str) = parts.next() else {
            continue;
        };
        let Some(uid_str) = parts.next() else {
            continue;
        };
        let comm = parts.collect::<Vec<_>>().join(" ");
        if comm.is_empty() {
            continue;
        }

        let pid = match pid_str.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let uid = match uid_str.parse::<u32>() {
            Ok(uid) => uid,
            Err(_) => continue,
        };

        processes.push(ProcInfo { pid, uid, comm });
    }

    Ok(processes)
}

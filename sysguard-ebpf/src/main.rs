#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
    EbpfContext,
};
use sysguard_common::{EventKind, SysguardEvent, AF_INET};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static BLOCKED_CONNECT_RULES: HashMap<ConnectBlockKey, u8> = HashMap::with_max_entries(256, 0);

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectBlockKey {
    uid: u32,
    addr: u32,
    port: u16,
    pad: u16,
}

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16).unwrap_or(core::ptr::null()) };

    with_event(EventKind::Execve, |event| {
        if !filename_ptr.is_null() {
            unsafe {
                let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*event).filename);
            }
        }
    })
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24).unwrap_or(core::ptr::null()) };

    with_event(EventKind::Openat, |event| {
        if !filename_ptr.is_null() {
            unsafe {
                let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*event).filename);
            }
        }
    })
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let sockaddr_ptr: *const SockAddrIn = unsafe { ctx.read_at(24).unwrap_or(core::ptr::null()) };

    with_event(EventKind::Connect, |event| {
        if !sockaddr_ptr.is_null() {
            if let Ok(sockaddr) = unsafe { bpf_probe_read_user(sockaddr_ptr) } {
                unsafe {
                    (*event).socket_family = sockaddr.sin_family;
                    if sockaddr.sin_family == AF_INET {
                        (*event).dport = u16::from_be(sockaddr.sin_port);
                        (*event).daddr = u32::from_be(sockaddr.sin_addr);
                    }
                }
            }
        }
    })
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_connect4(ctx: SockAddrContext) -> Result<i32, i32> {
    let sockaddr: &bpf_sock_addr = unsafe { &*ctx.sock_addr };
    if sockaddr.user_family != AF_INET as u32 {
        return Ok(1);
    }

    let uid = ctx.uid();
    let addr = u32::from_be(sockaddr.user_ip4);
    let port = u16::from_be(sockaddr.user_port as u16);

    if is_blocked(uid, addr, port) {
        return Ok(0);
    }

    Ok(1)
}

fn is_blocked(uid: u32, addr: u32, port: u16) -> bool {
    let candidates = [
        ConnectBlockKey { uid, addr, port, pad: 0 },
        ConnectBlockKey { uid, addr, port: 0, pad: 0 },
        ConnectBlockKey { uid, addr: 0, port, pad: 0 },
        ConnectBlockKey {
            uid: 0,
            addr,
            port,
            pad: 0,
        },
        ConnectBlockKey {
            uid: 0,
            addr,
            port: 0,
            pad: 0,
        },
        ConnectBlockKey {
            uid: 0,
            addr: 0,
            port,
            pad: 0,
        },
    ];

    for candidate in candidates {
        if unsafe { BLOCKED_CONNECT_RULES.get(&candidate) }.is_some() {
            return true;
        }
    }

    false
}

fn with_event<F>(kind: EventKind, mut fill: F) -> u32
where
    F: FnMut(*mut SysguardEvent),
{
    if let Some(mut buf) = EVENTS.reserve::<SysguardEvent>(0) {
        let event = buf.as_mut_ptr();

        unsafe {
            core::ptr::write_bytes(event, 0, 1);
            (*event).kind = kind;
            (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*event).uid = bpf_get_current_uid_gid() as u32;
            (*event).comm = bpf_get_current_comm().unwrap_or([0; 16]);
            fill(event);
        }

        buf.submit(0);
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

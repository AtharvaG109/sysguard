#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_FILENAME_LEN: usize = 256;
pub const AF_INET: u16 = 2;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Execve = 1,
    Openat = 2,
    Connect = 3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysguardEvent {
    pub kind: EventKind,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub daddr: u32,
    pub dport: u16,
    pub socket_family: u16,
}

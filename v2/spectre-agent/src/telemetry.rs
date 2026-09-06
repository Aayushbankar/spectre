use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const TASK_COMM_LEN: usize = 16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Unspec = 0,
    Fork = 1,
    Exec = 2,
    Exit = 3,
    FileOpen = 4,
    NetConnect = 5,
}

impl TryFrom<u32> for EventType {
    type Error = &'static str;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(EventType::Fork),
            2 => Ok(EventType::Exec),
            3 => Ok(EventType::Exit),
            4 => Ok(EventType::FileOpen),
            5 => Ok(EventType::NetConnect),
            _ => Err("Unknown event type"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawTelemetryHeader {
    pub event_type: u32,
    pub payload_len: u32,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawForkEvent {
    pub child_pid: u32,
    pub child_tgid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawExecEvent {
    pub args_count: u32,
    pub args_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawExitEvent {
    pub exit_code: u32,
    pub signal_code: u32,
    pub duration_ns: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileOpenEvent {
    pub ret_fd: i32,
    pub flags: u32,
    pub mode: u32,
    pub path_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawNetConnectEvent {
    pub ret: i32,
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct TelemetryRecord {
    pub header: RawTelemetryHeader,
    pub payload: TelemetryPayload,
}

#[derive(Debug, Clone)]
pub enum TelemetryPayload {
    Fork(RawForkEvent),
    Exec {
        args_count: u32,
        cmdline: String,
        args: Vec<String>,
    },
    Exit(RawExitEvent),
    FileOpen {
        ret_fd: i32,
        flags: u32,
        mode: u32,
        path: String,
    },
    NetConnect {
        ret: i32,
        socket_addr: SocketAddr,
    },
}

impl RawTelemetryHeader {
    pub fn comm_str(&self) -> String {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
        String::from_utf8_lossy(&self.comm[..len]).to_string()
    }
}

pub fn parse_telemetry_event(data: &[u8]) -> Result<TelemetryRecord, &'static str> {
    let header_size = std::mem::size_of::<RawTelemetryHeader>();
    if data.len() < header_size {
        return Err("Buffer too small for telemetry header");
    }

    let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawTelemetryHeader) };
    let payload_slice = &data[header_size..];

    if payload_slice.len() < header.payload_len as usize {
        return Err("Truncated payload buffer");
    }

    let event_type = EventType::try_from(header.event_type)?;

    let payload = match event_type {
        EventType::Fork => {
            if payload_slice.len() < std::mem::size_of::<RawForkEvent>() {
                return Err("Buffer underflow for ForkEvent");
            }
            let fork = unsafe { std::ptr::read_unaligned(payload_slice.as_ptr() as *const RawForkEvent) };
            TelemetryPayload::Fork(fork)
        }
        EventType::Exec => {
            let exec_size = std::mem::size_of::<RawExecEvent>();
            if payload_slice.len() < exec_size {
                return Err("Buffer underflow for ExecEvent fixed portion");
            }
            let exec = unsafe { std::ptr::read_unaligned(payload_slice.as_ptr() as *const RawExecEvent) };
            let args_len = (exec.args_len as usize).min(payload_slice.len() - exec_size);
            let args_buf = &payload_slice[exec_size..(exec_size + args_len)];

            let args: Vec<String> = args_buf
                .split(|&b| b == 0)
                .filter(|chunk| !chunk.is_empty())
                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                .collect();

            let cmdline = if !args.is_empty() {
                args.join(" ")
            } else {
                header.comm_str()
            };

            TelemetryPayload::Exec {
                args_count: exec.args_count,
                cmdline,
                args,
            }
        }
        EventType::Exit => {
            if payload_slice.len() < std::mem::size_of::<RawExitEvent>() {
                return Err("Buffer underflow for ExitEvent");
            }
            let exit = unsafe { std::ptr::read_unaligned(payload_slice.as_ptr() as *const RawExitEvent) };
            TelemetryPayload::Exit(exit)
        }
        EventType::FileOpen => {
            let open_size = std::mem::size_of::<RawFileOpenEvent>();
            if payload_slice.len() < open_size {
                return Err("Buffer underflow for FileOpenEvent fixed portion");
            }
            let open = unsafe { std::ptr::read_unaligned(payload_slice.as_ptr() as *const RawFileOpenEvent) };
            let path_len = (open.path_len as usize).min(payload_slice.len() - open_size);
            let path_buf = &payload_slice[open_size..(open_size + path_len)];
            let clean_len = path_buf.iter().position(|&b| b == 0).unwrap_or(path_buf.len());
            let path = String::from_utf8_lossy(&path_buf[..clean_len]).to_string();

            TelemetryPayload::FileOpen {
                ret_fd: open.ret_fd,
                flags: open.flags,
                mode: open.mode,
                path,
            }
        }
        EventType::NetConnect => {
            if payload_slice.len() < std::mem::size_of::<RawNetConnectEvent>() {
                return Err("Buffer underflow for NetConnectEvent");
            }
            let net = unsafe { std::ptr::read_unaligned(payload_slice.as_ptr() as *const RawNetConnectEvent) };
            let port = u16::from_be(net.port);

            let ip = match net.family {
                2 /* AF_INET */ => {
                    let octets: [u8; 4] = net.addr[..4].try_into().map_err(|_| "Invalid IPv4 slice")?;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                10 /* AF_INET6 */ => {
                    IpAddr::V6(Ipv6Addr::from(net.addr))
                }
                _ => return Err("Unsupported address family"),
            };

            TelemetryPayload::NetConnect {
                ret: net.ret,
                socket_addr: SocketAddr::new(ip, port),
            }
        }
        EventType::Unspec => return Err("Unspecified event type received"),
    };

    Ok(TelemetryRecord { header, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_exec_event() {
        let mut buf = Vec::new();
        let hdr = RawTelemetryHeader {
            event_type: EventType::Exec as u32,
            payload_len: 8 + 19, // exec_event (8) + args (19)
            timestamp_ns: 123456789,
            pid: 42,
            tgid: 42,
            ppid: 1,
            uid: 1000,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, std::mem::size_of::<RawTelemetryHeader>())
        };
        buf.extend_from_slice(hdr_bytes);

        let exec = RawExecEvent {
            args_count: 2,
            args_len: 19,
        };
        let exec_bytes = unsafe {
            std::slice::from_raw_parts(&exec as *const _ as *const u8, std::mem::size_of::<RawExecEvent>())
        };
        buf.extend_from_slice(exec_bytes);
        buf.extend_from_slice(b"curl\0http://bad.com\0");

        let rec = parse_telemetry_event(&buf).unwrap();
        assert_eq!(rec.header.pid, 42);
        assert_eq!(rec.header.comm_str(), "curl");
        match rec.payload {
            TelemetryPayload::Exec { args_count, cmdline, args } => {
                assert_eq!(args_count, 2);
                assert_eq!(args, vec!["curl", "http://bad.com"]);
                assert_eq!(cmdline, "curl http://bad.com");
            }
            _ => panic!("Expected Exec payload"),
        }
    }

    #[test]
    fn test_deserialize_fork_event() {
        let mut buf = Vec::new();
        let hdr = RawTelemetryHeader {
            event_type: EventType::Fork as u32,
            payload_len: 8,
            timestamp_ns: 1000,
            pid: 100,
            tgid: 100,
            ppid: 1,
            uid: 0,
            comm: *b"nginx\0\0\0\0\0\0\0\0\0\0\0",
        };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, std::mem::size_of::<RawTelemetryHeader>())
        };
        buf.extend_from_slice(hdr_bytes);

        let fork = RawForkEvent {
            child_pid: 101,
            child_tgid: 101,
        };
        let fork_bytes = unsafe {
            std::slice::from_raw_parts(&fork as *const _ as *const u8, std::mem::size_of::<RawForkEvent>())
        };
        buf.extend_from_slice(fork_bytes);

        let rec = parse_telemetry_event(&buf).unwrap();
        assert_eq!(rec.header.pid, 100);
        match rec.payload {
            TelemetryPayload::Fork(f) => {
                assert_eq!(f.child_pid, 101);
            }
            _ => panic!("Expected Fork payload"),
        }
    }
}

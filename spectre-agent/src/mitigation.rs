#![allow(dead_code)]
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const MAX_STABILIZATION_PASSES: usize = 10;
const STABILIZATION_DELAY: Duration = Duration::from_millis(5);
const CGROUP_FREEZE_TIMEOUT: Duration = Duration::from_millis(500);
const PF_KTHREAD: u32 = 0x00200000;

#[cfg(target_arch = "x86_64")]
const SYS_PIDFD_OPEN: libc::c_long = 434;
#[cfg(target_arch = "x86_64")]
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

#[cfg(target_arch = "aarch64")]
const SYS_PIDFD_OPEN: libc::c_long = 434;
#[cfg(target_arch = "aarch64")]
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

#[derive(Debug)]
pub enum MitigationError {
    SafetyViolation(u32, &'static str),
    PidRecycled { expected: u64, current: u64 },
    ProcessNotFound(u32),
    CgroupError(String),
    FreezeTimeout(Duration),
    Io(io::Error),
}

impl fmt::Display for MitigationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SafetyViolation(pid, reason) => write!(f, "Safety violation: target PID {} is protected ({})", pid, reason),
            Self::PidRecycled { expected, current } => write!(f, "PID recycling detected: expected starttime {}, found {}", expected, current),
            Self::ProcessNotFound(pid) => write!(f, "Target process {} does not exist", pid),
            Self::CgroupError(msg) => write!(f, "Cgroup v2 error: {}", msg),
            Self::FreezeTimeout(d) => write!(f, "Cgroup freeze timeout after {:?}", d),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for MitigationError {}

impl From<io::Error> for MitigationError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMetadata {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub state: char,
    pub flags: u32,
    pub starttime: u64,
}

pub struct PidFd {
    fd: libc::c_int,
}

impl PidFd {
    pub fn open(pid: u32) -> Option<Self> {
        let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::pid_t, 0) as libc::c_int };
        if fd >= 0 {
            Some(PidFd { fd })
        } else {
            None
        }
    }

    pub fn send_signal(&self, sig: libc::c_int) -> io::Result<()> {
        let ret = unsafe {
            libc::syscall(
                SYS_PIDFD_SEND_SIGNAL,
                self.fd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0 as libc::c_uint,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

pub struct SafetyPolicy {
    agent_pid: u32,
    agent_ppid: u32,
    agent_ancestors: HashSet<u32>,
    protected_comms: HashSet<&'static str>,
}

impl SafetyPolicy {
    pub fn new() -> Self {
        let agent_pid = std::process::id();
        let agent_ppid = unsafe { libc::getppid() as u32 };
        let mut agent_ancestors = HashSet::new();

        let mut cur = agent_ppid;
        while cur > 1 {
            agent_ancestors.insert(cur);
            if let Ok(meta) = Self::read_proc_stat(cur) {
                cur = meta.ppid;
            } else {
                break;
            }
        }

        let mut protected_comms = HashSet::new();
        protected_comms.insert("systemd");
        protected_comms.insert("systemd-journal");
        protected_comms.insert("systemd-udevd");
        protected_comms.insert("sshd");
        protected_comms.insert("dbus-daemon");
        protected_comms.insert("auditd");
        protected_comms.insert("spectre-agent");

        SafetyPolicy {
            agent_pid,
            agent_ppid,
            agent_ancestors,
            protected_comms,
        }
    }

    pub fn read_proc_stat(pid: u32) -> Result<ProcessMetadata, MitigationError> {
        let path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&path)
            .map_err(|_| MitigationError::ProcessNotFound(pid))?;

        let open_paren = content.find('(').ok_or_else(|| {
            MitigationError::SafetyViolation(pid, "Malformed /proc/<pid>/stat (missing open paren)")
        })?;
        let close_paren = content.rfind(')').ok_or_else(|| {
            MitigationError::SafetyViolation(pid, "Malformed /proc/<pid>/stat (missing close paren)")
        })?;

        let comm = content[open_paren + 1..close_paren].to_string();
        let rest = &content[close_paren + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() < 20 {
            return Err(MitigationError::SafetyViolation(
                pid,
                "Insufficient fields in /proc/<pid>/stat",
            ));
        }

        let state = fields[0].chars().next().unwrap_or('?');
        let ppid = fields[1].parse::<u32>().unwrap_or(0);
        let flags = fields[6].parse::<u32>().unwrap_or(0);
        let starttime = fields[19].parse::<u64>().unwrap_or(0);

        Ok(ProcessMetadata {
            pid,
            ppid,
            comm,
            state,
            flags,
            starttime,
        })
    }

    pub fn validate_target(&self, pid: u32, expected_starttime: Option<u64>) -> Result<ProcessMetadata, MitigationError> {
        if pid <= 1 {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target PID 1 (init/systemd)"));
        }
        if pid == 2 {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target PID 2 (kthreadd)"));
        }
        if pid == self.agent_pid {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target agent's own PID"));
        }
        if pid == self.agent_ppid {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target agent's parent PID"));
        }
        if self.agent_ancestors.contains(&pid) {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target agent ancestor process"));
        }

        let meta = Self::read_proc_stat(pid)?;

        if meta.ppid == 2 || (meta.flags & PF_KTHREAD) != 0 {
            return Err(MitigationError::SafetyViolation(pid, "Cannot target kernel thread (PF_KTHREAD)"));
        }

        if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) {
            if cmdline.is_empty() && meta.ppid <= 2 {
                return Err(MitigationError::SafetyViolation(pid, "Target has empty cmdline and is a kernel worker"));
            }
        }

        if self.protected_comms.contains(meta.comm.as_str()) {
            return Err(MitigationError::SafetyViolation(pid, "Target binary is in critical system whitelist"));
        }

        if let Some(expected) = expected_starttime {
            if meta.starttime != expected {
                return Err(MitigationError::PidRecycled {
                    expected,
                    current: meta.starttime,
                });
            }
        }

        Ok(meta)
    }
}

pub struct ProcTreeScanner;

impl ProcTreeScanner {
    pub fn get_direct_children(pid: u32) -> HashSet<u32> {
        let mut children = HashSet::new();
        let path = format!("/proc/{}/task/{}/children", pid, pid);

        if let Ok(content) = fs::read_to_string(&path) {
            for token in content.split_whitespace() {
                if let Ok(child_pid) = token.parse::<u32>() {
                    children.insert(child_pid);
                }
            }
            return children;
        }

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(entry_pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    if let Ok(meta) = SafetyPolicy::read_proc_stat(entry_pid) {
                        if meta.ppid == pid {
                            children.insert(entry_pid);
                        }
                    }
                }
            }
        }

        children
    }
}

pub struct MitigationController {
    safety: SafetyPolicy,
}

impl MitigationController {
    pub fn new() -> Self {
        MitigationController {
            safety: SafetyPolicy::new(),
        }
    }

    fn send_signal_safe(&self, pid: u32, sig: libc::c_int) -> io::Result<()> {
        if let Some(pidfd) = PidFd::open(pid) {
            pidfd.send_signal(sig)
        } else {
            let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };
            if ret == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn terminate_process_tree(
        &self,
        target_pid: u32,
        expected_starttime: Option<u64>,
    ) -> Result<Vec<u32>, MitigationError> {
        self.safety.validate_target(target_pid, expected_starttime)?;

        let mut discovered_tree: Vec<u32> = Vec::new();
        let mut stopped_set: HashSet<u32> = HashSet::new();

        let _ = self.send_signal_safe(target_pid, libc::SIGSTOP);
        discovered_tree.push(target_pid);
        stopped_set.insert(target_pid);

        let mut pass = 0;
        loop {
            pass += 1;
            let mut new_children_found = false;
            let current_known = discovered_tree.clone();

            for pid in current_known {
                let children = ProcTreeScanner::get_direct_children(pid);
                for child in children {
                    if !stopped_set.contains(&child) {
                        if self.safety.validate_target(child, None).is_ok() {
                            let _ = self.send_signal_safe(child, libc::SIGSTOP);
                            stopped_set.insert(child);
                            discovered_tree.push(child);
                            new_children_found = true;
                        }
                    }
                }
            }

            if !new_children_found || pass >= MAX_STABILIZATION_PASSES {
                break;
            }

            thread::sleep(STABILIZATION_DELAY);
        }

        let mut terminated = Vec::new();
        for &pid in discovered_tree.iter().rev() {
            if self.safety.validate_target(pid, None).is_ok() {
                match self.send_signal_safe(pid, libc::SIGKILL) {
                    Ok(_) => {
                        terminated.push(pid);
                        let _ = self.send_signal_safe(pid, libc::SIGCONT);
                    }
                    Err(e) => {
                        log::debug!("PID {} already dead: {}", pid, e);
                    }
                }
            }
        }

        Ok(terminated)
    }

    pub fn get_cgroup_v2_path(pid: u32) -> Result<PathBuf, MitigationError> {
        let cgroup_file = format!("/proc/{}/cgroup", pid);
        let content = fs::read_to_string(&cgroup_file)
            .map_err(|e| MitigationError::CgroupError(format!("Cannot read {}: {}", cgroup_file, e)))?;

        for line in content.lines() {
            if let Some(stripped) = line.strip_prefix("0::") {
                let rel_path = stripped.trim_start_matches('/');
                let base = Path::new("/sys/fs/cgroup");
                return Ok(base.join(rel_path));
            }
        }

        Err(MitigationError::CgroupError("Process is not managed by cgroup v2".into()))
    }

    pub fn freeze_cgroup(&self, target_pid: u32) -> Result<PathBuf, MitigationError> {
        self.safety.validate_target(target_pid, None)?;

        let cgroup_dir = Self::get_cgroup_v2_path(target_pid)?;
        let canonical_cgroup = cgroup_dir.canonicalize().map_err(MitigationError::Io)?;
        let cgroup_root = Path::new("/sys/fs/cgroup").canonicalize().map_err(MitigationError::Io)?;

        if canonical_cgroup == cgroup_root {
            return Err(MitigationError::SafetyViolation(
                target_pid,
                "Cannot freeze root cgroup (/sys/fs/cgroup)",
            ));
        }

        let freeze_file = canonical_cgroup.join("cgroup.freeze");
        if !freeze_file.exists() {
            return Err(MitigationError::CgroupError(format!(
                "cgroup.freeze not found at {:?}",
                freeze_file
            )));
        }

        fs::write(&freeze_file, "1\n").map_err(MitigationError::Io)?;

        let events_file = canonical_cgroup.join("cgroup.events");
        let start = Instant::now();

        while start.elapsed() < CGROUP_FREEZE_TIMEOUT {
            if let Ok(events) = fs::read_to_string(&events_file) {
                if events.contains("frozen 1") {
                    return Ok(canonical_cgroup);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        Err(MitigationError::FreezeTimeout(CGROUP_FREEZE_TIMEOUT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_invariants_rejects_pid1_and_pid2() {
        let policy = SafetyPolicy::new();
        assert!(policy.validate_target(0, None).is_err());
        assert!(policy.validate_target(1, None).is_err());
        assert!(policy.validate_target(2, None).is_err());
    }

    #[test]
    fn test_safety_invariants_protects_self_and_ppid() {
        let policy = SafetyPolicy::new();
        let my_pid = std::process::id();
        let my_ppid = unsafe { libc::getppid() as u32 };

        assert!(policy.validate_target(my_pid, None).is_err());
        assert!(policy.validate_target(my_ppid, None).is_err());
    }
}

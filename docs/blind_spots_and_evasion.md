# Spectre Technical Audit: EDR Blind Spots, Kernel Evasion & Operational Realities

This document provides an unvarnished, technically rigorous analysis of the security architecture of Spectre (and Linux EDR/HIDS agents in general). It specifies where eBPF-based host detection succeeds, where it fails, the exact evasion techniques adversaries use to bypass tracepoint monitoring, and the engineering remedies required to harden the system.

---

## 1. Architectural Summary: Strengths vs. Fundamental Limitations

| Dimension | Spectre Capabilities | Inherent Limitations / Evasion Vectors |
| :--- | :--- | :--- |
| **Execution Telemetry** | eBPF hook at `sys_enter_execve` capturing comm, PID, PPID, UID, and packed argv up to 2048 bytes. | Bypassed by `execveat(AT_EMPTY_PATH)`, in-process shellcode, `dlopen`, and reflective ELF loaders. |
| **Lineage Tracking** | Composite-keyed `ProcessKey { pid, start_time_ns }` in `petgraph::StableDiGraph` with lazy GC. | Container PID virtualization causes host vs container PID discrepancies; lineage breaks across unmonitored namespaces. |
| **Detection Engine** | Pre-compiled Pratt AST Sigma parser with zero regex compilation overhead during event ingestion. | Relies on userspace string matching; cannot inspect kernel-internal structures or decrypt TLS payloads. |
| **Containment** | Safe tree termination using `pidfd_open` + `pidfd_send_signal`, freezing via `SIGSTOP` before `SIGKILL`. | Cannot kill processes in `TASK_UNINTERRUPTIBLE` (D-state); microsecond race in `pidfd_open` prior to fd acquisition. |
| **Visibility Interface** | Low-overhead 30 FPS Terminal UI (`ratatui` + `crossterm`) with zero web network attack surface. | TUI is a local inspection tool; requires headless logging/SIEM forwarding in distributed deployments. |

---

## 2. Kernel Evasion Techniques & EDR Blind Spots

### 2.1 Syscall Gaps: `execveat` with `AT_EMPTY_PATH`
- **Mechanism:** Linux provides multiple syscalls for process execution. In addition to `sys_enter_execve` (syscall NR 59 on x86_64), modern kernels implement `sys_enter_execveat` (syscall NR 322).
- **The Blind Spot:** An attacker opens an executable binary file descriptor (or anonymous memory fd) and executes it via:
  ```c
  syscall(__NR_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
  ```
  Because Spectre's sensor attaches strictly to `tracepoint/syscalls/sys_enter_execve`, calling `execveat` **completely bypasses the eBPF hook**. No telemetry event is generated, no Sigma rule evaluates, and the process spawns undetected.
- **Remedy:** Attach dual hooks to both `syscalls:sys_enter_execve` and `syscalls:sys_enter_execveat`, or transition to a kernel LSM hook (`lsm/bprm_creds_for_exec`) which intercepts all binary execution attempts regardless of which syscall was invoked.

### 2.2 Fileless Execution: `memfd_create` and Anonymous In-Memory Execution
- **Mechanism:** Attackers create anonymous memory files that reside purely in RAM using:
  ```c
  int fd = memfd_create("kworker_update", MFD_CLOEXEC);
  write(fd, elf_payload, payload_size);
  fexecve(fd, argv, envp);
  ```
- **The Blind Spot:** The binary has no backing file on the ext4/xfs filesystem. When inspecting `/proc/<pid>/exe`, the kernel returns `/memfd:kworker_update (deleted)`. Disk-based antivirus engines and static scanners never see a file touch disk.
- **Remedy:** Inspect the `dentry` and file backing in the eBPF program. If `bprm->file->f_path.dentry->d_name` starts with `memfd:` or matches anonymous inodes, elevate the suspicion score immediately and extract the memory buffer header (ELF header verification).

### 2.3 In-Process Execution (Zero `execve` Syscalls)
- **Mechanism:** Attackers do not create new processes. Instead, they inject into or operate within already running processes:
  1. Dynamic loading of shared libraries via `dlopen()` / `dlsym()`.
  2. Memory allocation with `mmap(PROT_READ | PROT_WRITE | PROT_EXEC)` followed by shellcode execution.
  3. Reflective ELF loading: Manually resolving ELF relocations and jumping to the entry point in userspace RAM.
- **The Blind Spot:** Spectre monitors process creation (`execve`). An adversary running an interactive meterpreter or Cobalt Strike Beacon inside a spawned Python or Node.js process executes commands in memory without issuing a single process spawn syscall.
- **Remedy:** Monitor memory protection syscalls (`sys_enter_mprotect`, `sys_enter_mmap`) for transitions to `PROT_EXEC` combined with `PROT_WRITE` (`W^X` violation), and hook socket activity (`sys_enter_connect`) to correlate network connections back to the non-spawning PID.

### 2.4 Tracepoints vs. LSM Hooks: TOCTOU & Synchronous Prevention
- **The TOCTOU Race:** Spectre reads `argv` from userspace memory inside `sensor.c` using `bpf_probe_read_user` at `sys_enter_execve`. Between the time the tracepoint fires and the kernel copies arguments into the `linux_binprm` structure, a concurrent thread in the same address space can overwrite the memory buffer (Time-of-Check to Time-of-Use). The tracepoint logs benign arguments, while the kernel executes malicious ones.
- **Passive vs. Inline Blocking:** Tracepoints are purely observational. By the time userspace receives an event from `BPF_MAP_TYPE_RINGBUF`, the malicious binary has already executed its `main()` function or ELF constructor. To prevent execution before instructions run, the agent must use kernel LSM hooks (`BPF_PROG_TYPE_LSM`) returning `-EPERM`.

---

## 3. Process Lineage, Namespaces & Container Virtualization

### 3.1 Host vs. Container PID Discrepancy
- **The Problem:** In containerized environments (Docker, containerd, Kubernetes), every container runs inside a dedicated PID namespace. Inside the container, the primary application is PID 1. However, in the host kernel root PID namespace, that process has a completely different PID (e.g., 584920).
- **Spectre Behavior:** The eBPF helper `bpf_get_current_pid_tgid()` returns the **root namespace PID**. If userspace mitigation attempts to kill "PID 1" because an alert rule reported PID 1 from container logs, terminating root PID 1 will panic the entire host Linux kernel.
- **Mitigation Architecture:** Spectre's `MitigationController` explicitly blocks signals to PID 1, PID 2, systemd, and kernel threads (`pid <= 2`). However, translating container-local PIDs to host PIDs requires querying `/proc/<pid>/status` for `NSpid` (Namespace PID list).

### 3.2 Process Hollowing and `ptrace` Injection
- **The Problem:** A process running with `CAP_SYS_PTRACE` can attach to any process running under the same UID using `PTRACE_ATTACH` and overwrite instructions using `PTRACE_POKETEXT` or `process_vm_writev`.
- **The Blind Spot:** The operating system continues to report the binary name and path of the original benign executable (e.g., `rsync` or `sshd`). Spectre's graph records the initial execution, but does not capture subsequent code modification inside the target process unless `sys_enter_ptrace` and `process_vm_writev` are instrumented.

---

## 4. Telemetry Floods and Ring Buffer DoS

### 4.1 Ring Buffer Saturation
- **The Mechanism:** Spectre allocates a 4MB kernel ring buffer (`BPF_MAP_TYPE_RINGBUF`). If an adversary realizes an eBPF sensor is present, they can launch an event flood:
  ```bash
  while true; do /bin/true; done
  ```
  A multi-threaded loop can generate 50,000 to 100,000 `execve` events per second.
- **The Impact:** If userspace cannot drain the buffer at or above this rate, `bpf_ringbuf_reserve` fails in kernel space:
  ```c
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0; // EVENT DROPPED
  ```
  Under high load, drops accumulate, creating a telemetry gap where the real malicious execution slips through unrecorded.
- **Spectre Defense:** 
  1. Ring buffer drops are tracked atomically in userspace (`stats.inc_drops()`) and displayed live in the TUI status bar.
  2. Bounded, non-blocking UI queues prevent rendering work from throttling event drainage.
  3. Kernel-side filtering (e.g., skipping ephemeral short-lived compiler runs or noise paths in eBPF) reduces ingress volume.

---

## 5. Active Response Pitfalls

### 5.1 `TASK_UNINTERRUPTIBLE` (D-State Deadlocks)
- Processes waiting on unresponsive NFS shares, dead block devices, or kernel hardware locks enter the `D` state (`TASK_UNINTERRUPTIBLE`).
- In this state, the kernel does not deliver signals, including `SIGKILL`. The mitigation will report success on `pidfd_send_signal`, but the process will remain visible in the process table until the underlying kernel I/O request completes or times out.

### 5.2 Microsecond PID Recycling Race
- **The Vulnerability:** An adversary detects that their payload was detected. They immediately exit. Concurrently, the agent detects the Sigma alert on PID 4410 and calls `syscall(__NR_pidfd_open, 4410, 0)`. If the target exits and the Linux kernel wraps around or reuses PID 4410 for an innocent daemon in that 10-microsecond window, `pidfd_open` binds to the new innocent process.
- **Remedy:** Validate the process creation timestamp from `/proc/<pid>/stat` before and after acquiring the `pidfd` descriptor. If the start time does not match `ProcessKey.start_time_ns`, abort signal transmission immediately.

### 5.3 Shared Memory & Robust Futex Deadlocks on `SIGSTOP`
- Freezing a malicious or compromised process with `SIGSTOP` before terminating child processes can freeze a thread holding a critical inter-process mutex (e.g., shared POSIX mutex or robust futex in `/dev/shm`). Any benign parent or sibling attempting to acquire that lock will freeze permanently.

---

## 6. Comparison: Spectre V2 vs. Traditional Linux EDR Agents

| Feature | Spectre V2 | Auditd / Osquery | Falco | Enterprise EDR (Falcon/SentinelOne) |
| :--- | :--- | :--- | :--- | :--- |
| **Kernel Mechanism** | eBPF Tracepoint + RingBuf | Netlink Audit Subsystem / Procfs polling | eBPF / Kernel Module (scap) | Proprietary Kernel Modules / eBPF LSM |
| **Event Overhead** | Low (O(1) RingBuf write) | Extreme (Netlink serial locks, massive syslog overhead) | Low (eBPF ring buffer) | Low to Moderate |
| **Lineage Resolution** | In-Memory Composite Graph (`StableDiGraph`) | None (flat logs, reconstructed in SIEM) | Flat events (limited ancestry) | Proprietary graph engines |
| **Inline Prevention** | Passive (kill after exec) | Passive (audit only) | Passive (audit / gRPC webhook) | Synchronous (LSM inline blocking) |
| **Rule Engine** | Pratt AST Sigma Compiler (no runtime regex compiles) | SQL queries or rule strings | Falco rule engine (Secfilter syntax) | Proprietary behavioral AI + Yara/Sigma |
| **Local Interface** | Ratatui 30 FPS Terminal UI | None (text output / daemon) | None (stdout / webhook) | Cloud Web Console |

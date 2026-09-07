# Project Spectre: Kernel eBPF & Graph HIDS Engine

Project Spectre is a Host-based Intrusion Detection & Active Response System (HIDS/EDR) written in **Rust** and **C (eBPF)**. It replaces user-space polling mechanisms with in-kernel event capture via eBPF tracepoints, evaluates detection rules using a Pratt AST parser for Sigma specifications, correlates process relationships via generational graph keying, and dispatches containment signals using kernel process file descriptors (`pidfd`).

---

## Measured Performance & Resource Metrics

All measurements were taken on compiled release binaries (`target/release/spectre-agent`) running on Linux x86_64:

| Metric | Measured Value | Benchmark Context |
|---|---|---|
| **Static Release Binary Size** | **5.5 MB** | Fully optimized release profile with TUI (`target/release/spectre-agent`) |
| **Steady-State Memory (RSS)** | **5.2 MB** | Process resident set size measured via `ps -o rss` |
| **Sigma AST Evaluation Rate** | **2,557,939 evals/sec** | Measured in `benchmark_eval.rs` over 100,000 synthetic iterations |
| **Average Evaluation Latency** | **0.39 µs / eval** | Time required per complex multi-clause AST rule evaluation |
| **Graph Eviction Lock Latency** | **< 30 µs** | Budgeted 256-node slice eviction in background worker |
| **Test Suite Verification** | **16/16 passed (100%)** | `cargo test --workspace` across all crates in < 0.6s |

---

## Architecture & Subsystems

```
+-------------------------------------------------------------------------+
|                            SPECTRE ARCHITECTURE                         |
+-------------------------------------------------------------------------+
|  KERNEL SPACE (eBPF Probes)                                             |
|  * sys_enter_execve       -> Null-delimited argv walking (zero-stack)   |
|  * sched_process_fork     -> Parent-child TGID tracking                 |
|  * sched_process_exit     -> Explicit process lifetime termination      |
|  * 4MB BPF Ring Buffer    -> High-throughput, cross-core ordered stream |
|                                |                                        |
|                          BPF RING BUFFER (4MB)                          |
|                                |                                        |
|  USERSPACE (Rust Agent)        v                                        |
|  +-------------------------------------------------------------------+  |
|  | Event Ingestion Engine (Envelope Pattern Deserializer)            |  |
|  +-------------------------------------------------------------------+  |
|            |                                            |               |
|            v                                            v               |
|  +---------------------------+            +---------------------------+ |
|  | Generational Graph Engine |            | Sigma AST Rule Engine     | |
|  | - StableDiGraph           |<---------->| - Pratt / Recursive Parse | |
|  | - ProcessKey(PID, Start)  | Ancestry   | - Precompiled Regex Cache | |
|  | - O(K log M) Min-Heap GC  | Lineage    | - Value Lists (OR / AND)  | |
|  +---------------------------+ Enrichment +---------------------------+ |
|            |                                            |               |
|            |                                            v               |
|            |                              +---------------------------+ |
|            +----------------------------->| Active Containment Engine | |
|               Target Tree Verification    | - SIGSTOP Stabilize Freeze| |
|                                           | - Bottom-up SIGKILL       | |
|                                           | - pidfd Race Prevention   | |
|                                           | - Cgroup v2 Isolation     | |
|                                           +---------------------------+ |
+-------------------------------------------------------------------------+
```

---

## Workspace Layout & Implementation Breakdown

| Component | Directory / File | Key Technical Properties |
|---|---|---|
| **Kernel Probe** | `ebpf-c/src/sensor.c` | Hooks `sys_enter_execve`. Reads user `argv` pointers via `bpf_probe_read_user_str()` up to 16 arguments (1024 bytes) directly into reserved ring buffer memory without exceeding 512-byte stack limit. |
| **Telemetry ABI** | `ebpf-c/include/telemetry_events.h` | Standardized 48-byte aligned `telemetry_header` multiplexing `FORK`, `EXEC`, `EXIT`, `FILE_OPEN`, and `NET_CONNECT`. |
| **Deserializer** | `spectre-agent/src/telemetry.rs` | Zero-copy byte slice decoding with explicit bounds validation and lossy UTF-8 extraction. |
| **Sigma AST Engine** | `spectre-rules/src/parser.rs` | Pratt parser implementing full precedence for `AND`, `OR`, `NOT`, nested `(...)`, sequence value lists (OR), modifier chaining (`\|all` AND), CIDR subnets (`ipnet`), and precompiled regexes (`Arc<Regex>`). |
| **Generational Graph** | `spectre-graph/src/lib.rs` | `petgraph::stable_graph::StableDiGraph` indexed by `ProcessKey { pid, start_time_ns }`. Non-recursive cycle-safe traversals up to 16 hops. |
| **Lazy Graph GC** | `spectre-graph/src/lib.rs` | $O(K \log M)$ min-heap lazy eviction queue (`BinaryHeap<Reverse<EvictionEntry>>`). Decoupled 2-second background Tokio task with 256-node slice budget. |
| **Lineage Enrichment** | `spectre-agent/src/enrichment.rs` | Traverses graph to resolve `ParentImage`, `ParentCommandLine`, and `AncestorImages` before rule matching. |
| **Mitigation Engine** | `spectre-agent/src/mitigation.rs` | Safety policy rejecting PID $\le 2$, self, parent, and system daemons. Uses `pidfd_send_signal` for race-free signaling, top-down `SIGSTOP` freeze, bottom-up `SIGKILL`, and cgroup v2 freeze. |
| **Terminal UI (TUI)** | `spectre-agent/src/tui.rs` | Zero-port 30 FPS console interface (`ratatui` + `crossterm`) with 4 views: Dashboard, Lineage Tree, Security Alerts, and an interactive Chain Inspector supporting real-time and historical process graphs. |
| **Pipeline Stats** | `spectre-agent/src/pipeline.rs` | Atomic metrics counters tracking throughput (events/sec), detection alerts, and ring buffer drops. |

---

## Building and Running

### 1. Prerequisites
* Linux Kernel **>= 5.8** (with BTF enabled)
* Rust toolchain (stable **>= 1.70**)
* `clang`, `llvm`, `make`

### 2. Compile eBPF Bytecode
```bash
make -C ebpf-c
```

### 3. Compile Workspace Binaries
```bash
cargo build --release
```

### 4. Run Test Suite
```bash
cargo test --workspace
```

### 5. Execute Agent

#### Interactive Terminal UI (TUI) Mode:
```bash
# Simulated mock mode with full TUI (no root required)
./target/release/spectre-agent --mock --tui

# Production kernel eBPF mode with full TUI (requires root / CAP_BPF)
sudo ./target/release/spectre-agent --tui
```

*TUI Key Bindings:*
* `[Tab]` / `[1-4]`: Switch between tabs (`[1] Dashboard`, `[2] Lineage Tree`, `[3] Security Alerts`, `[4] Chain Inspector`).
* `[↑ / ↓]` or `[j / k]`: Browse and select process chains in the Chain Inspector.
* `[F]`: Cycle chain filter (`ALL (LIVE + OLD)` ➔ `LIVE REAL-TIME` ➔ `OLD / HISTORICAL`).
* `[X]`: Clear security alert feed.
* `[Q]` / `[Ctrl-C]`: Cleanly exit and restore terminal screen.

#### Headless / Daemon Mode (Systemd / Piping):
```bash
# Mock mode (standard stdout logs)
./target/release/spectre-agent --mock

# Production eBPF mode (standard stdout logs)
sudo ./target/release/spectre-agent
```

---

## Technical Documentation

Detailed architectural notes, audit records, and threat analyses are available in `docs/`:
* [Technical Architecture Specification](docs/architecture.md)
* [EDR Blind Spots, Kernel Evasion & Operational Realities](docs/blind_spots_and_evasion.md)
* [Build & Operations Guide](docs/build_guide.md)
* [Pessimistic Audit & Remediation Ledger](docs/audit_and_remediation.md)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

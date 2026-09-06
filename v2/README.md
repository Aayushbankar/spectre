# Spectre V2: Hardened Kernel eBPF & Graph HIDS Engine

Spectre V2 is a ground-up rewrite of the Host-based Intrusion Detection & Response System in **Rust** and **eBPF**. It transforms the initial prototype into an enterprise-grade security agent capable of zero-gap kernel telemetry, AST-driven Sigma rule evaluation, generation-keyed behavioral graph correlation, and safe active containment.

---

## Architecture & Subsystems

```
+-------------------------------------------------------------------------+
|                         SPECTRE V2 ARCHITECTURE                         |
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

## 10-Round Hardening & Optimization History

| Round | Engineering Milestone | Hardened Capabilities |
|---|---|---|
| **Round 1** | **Pratt Sigma AST Engine** | Replaced naive token-splitter with a full Top-Down Operator Precedence parser supporting `AND`, `OR`, `NOT`, and arbitrary nested parentheses `(...)`. Pre-compiled regex cache. |
| **Round 2** | **Sigma Spec Compliance** | Implemented sequence value lists (default `OR`), `\|all` modifier chaining (`AND`), CIDR subnet matching (`ipnet`), and case-insensitive matching. |
| **Round 3** | **Zero-Stack `argv` eBPF Sensor** | Rewrote `sensor.c` to hook `sys_enter_execve`. Safely traverses `argv` pointers directly into reserved ringbuf memory with verifier bounds checks. |
| **Round 4** | **Multiplexed Telemetry Envelope** | Standardized 48-byte aligned `telemetry_header` multiplexing `FORK`, `EXEC`, `EXIT`, `FILE_OPEN`, and `NET_CONNECT` over a single ring buffer with zero UB. |
| **Round 5** | **Generational Graph Keys** | Eliminated PID reuse collisions by keying `petgraph::stable_graph::StableDiGraph` with `ProcessKey { pid, start_time_ns }`. Non-recursive, cycle-safe ancestry traversals. |
| **Round 6** | **Behavioral Graph Enrichment** | Wired `ProcessGraph` ancestry directly into Sigma evaluation, enabling rules matching `ParentImage`, `ParentCommandLine`, and `AncestorImages`. |
| **Round 7** | **$O(K \log M)$ Lazy Eviction & Decoupled GC** | Replaced $O(|V|+|E|)$ linear sweeps with a `BinaryHeap` min-heap eviction queue. Decoupled GC into a background worker with budgeted lock-yielding slices ($< 30\mu\text{s}$ lock hold). |
| **Round 8** | **Two-Phase Active Mitigation** | Built `MitigationController` enforcing PID 1/self safety policies, Linux `pidfd_send_signal` race protection, top-down `SIGSTOP` stabilization, and bottom-up `SIGKILL`. |
| **Round 9** | **Drop-Free Ringbuf & Pipeline Telemetry** | Sized kernel BPF ringbuf to 4MB. Added atomic pipeline throughput tracking (`PipelineStats`) measuring events per second, alerts, and drops. |
| **Round 10** | **Full Integration & Test Verification** | 14 workspace tests passing (100% pass rate). Verified mock and kernel ingestion pipelines end-to-end. |

---

## Building and Running

### Build All Crates:
```bash
cargo build --workspace
```

### Run Test Suite:
```bash
cargo test --workspace
```

### Run Spectre Agent:
* **Mock Mode (No root required, simulates attack and detection pipeline):**
  ```bash
  ./v2/target/debug/spectre-agent --mock
  ```

* **Production eBPF Mode (Requires root):**
  ```bash
  sudo ./v2/target/debug/spectre-agent
  ```

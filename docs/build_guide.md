# Spectre Build & Operations Guide

## 1. Environment & Prerequisites

Spectre compiles on Linux systems. The user-space daemon is written in Rust, and the kernel-space telemetry probe is written in C and compiled with Clang's BPF backend.

### System Requirements
* **Operating System**: Linux with kernel version **>= 5.8** (required for `BPF_MAP_TYPE_RINGBUF` support).
* **Rust Toolchain**: `rustc` and `cargo` **>= 1.70** (stable channel).
* **eBPF Toolchain**: `clang` and `llvm` (with `bpf` target support), `make`.
* **Standard Headers**: Linux UAPI and kernel headers (`linux/types.h`, etc.).

Verify prerequisites on your build host:
```bash
clang --version
cargo --version
uname -r
```

---

## 2. Directory Structure

```text
.
├── Cargo.toml               # Workspace manifest (spectre-agent, spectre-graph, spectre-rules)
├── README.md                # Technical overview and verified benchmarks
├── ebpf-c/                  # Kernel-space eBPF C implementation
│   ├── Makefile             # Clang build automation for BPF bytecode
│   ├── include/
│   │   └── telemetry_events.h  # 48-byte ABI envelope shared between C and Rust
│   ├── src/
│   │   └── sensor.c         # sys_enter_execve tracepoint & zero-stack argv walker
│   └── sensor.o             # Compiled eBPF ELF binary
├── spectre-agent/           # User-space daemon binary crate
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # CLI entrypoint, async loops, and background GC task
│       ├── telemetry.rs     # Binary envelope deserializer
│       ├── enrichment.rs    # Graph-backed ancestor and lineage resolution
│       ├── mitigation.rs    # Safety invariants, pidfd_send_signal, process tree SIGKILL
│       ├── tui.rs           # Embedded 30 FPS terminal UI & interactive Chain Inspector
│       └── pipeline.rs      # Atomic throughput and drops metrics tracker
├── spectre-graph/           # Generational process graph library
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs           # StableDiGraph, ProcessKey, full chain extraction & min-heap GC
├── spectre-rules/           # Sigma AST engine library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # Engine facade
│       ├── ast.rs           # AstNode enum definitions
│       ├── parser.rs        # Pratt Top-Down Operator Precedence parser
│       └── evaluator.rs     # Spec-compliant matcher, regex cache, CIDR evaluator
└── docs/                    # Architectural specifications and audit logs
    ├── architecture.md
    ├── build_guide.md
    ├── blind_spots_and_evasion.md
    └── audit_and_remediation.md
```

---

## 3. Compilation

### 3.1 Compile Kernel eBPF Sensor
Compile `src/sensor.c` into BPF bytecode using the provided `Makefile`:
```bash
make -C ebpf-c
```
This generates `ebpf-c/sensor.o`.

### 3.2 Compile User-Space Agent
Compile all crates in the workspace in release mode:
```bash
cargo build --release --workspace
```
The compiled binaries and libraries are located in `target/release/`. The primary daemon binary is `target/release/spectre-agent`.

---

## 4. Verification & Testing

Spectre includes automated unit tests, integration tests, and performance benchmarks.

### 4.1 Run Full Test Suite
```bash
cargo test --workspace
```
All 16 tests across the workspace should pass:
* `spectre-agent`: 4 unit tests (telemetry envelope deserialization, PID safety invariants).
* `spectre-agent`: 2 integration tests (parent behavioral rules, deep ancestry enrichment).
* `spectre-graph`: 2 unit tests (budgeted lazy min-heap eviction queue, full execution chain extraction).
* `spectre-rules`: 7 integration tests (Pratt AST parsing, nested parentheses, `AND`/`OR`/`NOT`, sequence list `OR`, `|all` `AND`, CIDR subnets, precompiled regexes).
* `spectre-rules`: 1 benchmark test (100,000 synthetic AST evaluations).

### 4.2 Run AST Evaluation Benchmark
To run the high-throughput AST evaluation benchmark and view throughput statistics:
```bash
cargo test -p spectre-rules --test benchmark_eval -- --nocapture
```
Expected output:
```text
Evaluated 100000 events in ~39 ms (rate: ~2,550,000 evals/sec, latency: ~0.39 µs/eval)
```

---

## 5. Execution Modes

### 5.1 Interactive Terminal UI (TUI) Mode
The recommended mode for interactive inspection and testing:

```bash
# Simulated mock mode with TUI (unprivileged, no root required)
./target/release/spectre-agent --mock --tui

# Production kernel eBPF mode with TUI (requires root / CAP_BPF)
sudo ./target/release/spectre-agent --tui
```

#### TUI Navigation & Controls:
| Key | Action |
|---|---|
| `[1]` - `[4]` | Jump directly to tab (`[1] Dashboard`, `[2] Lineage Tree`, `[3] Security Alerts`, `[4] Chain Inspector`) |
| `[Tab]` / `[Shift-Tab]` | Cycle forward and backward through tabs |
| `[↑ / ↓]` or `[j / k]` | Navigate and select process chains in Tab 4 (Chain Inspector) |
| `[F]` | Cycle chain filter (`ALL (LIVE + OLD)` ➔ `LIVE REAL-TIME` ➔ `OLD / HISTORICAL`) |
| `[Home]` / `[End]` | Jump to top / bottom of process chain list |
| `[X]` | Clear security alerts feed |
| `[Q]` / `[Ctrl-C]` | Cleanly exit and restore terminal screen |

### 5.2 Headless / Daemon Mode (Systemd / Piping)
For production daemon deployments, log shipping, or automated piping:

```bash
# Unprivileged mock mode (stdout logging)
./target/release/spectre-agent --mock

# Production eBPF mode (stdout logging)
sudo ./target/release/spectre-agent
```

---

## 6. Configuration & Logging

Logging verbosity can be controlled using the standard `RUST_LOG` environment variable:
```bash
# Info-level logging (alerts, startup, pipeline stats)
RUST_LOG=info ./target/release/spectre-agent --mock

# Debug-level logging (per-event ingestion and graph updates)
RUST_LOG=debug ./target/release/spectre-agent --mock
```

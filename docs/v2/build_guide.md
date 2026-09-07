# Spectre V2 Build & Operations Guide

## 1. Environment & Prerequisites

Spectre V2 compiles on Linux systems. The user-space daemon is written in Rust, and the kernel-space telemetry probe is written in C and compiled with Clang's BPF backend.

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
v2/
├── Cargo.toml               # Workspace manifest (spectre-agent, spectre-graph, spectre-rules)
├── README.md                # V2 technical overview and verified benchmarks
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
│       └── pipeline.rs      # Atomic throughput and drops metrics tracker
├── spectre-graph/           # Generational process graph library
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs           # StableDiGraph, ProcessKey(pid, start_time_ns), min-heap GC
└── spectre-rules/           # Sigma AST engine library
    ├── Cargo.toml
    └── src/
        ├── lib.rs           # Engine facade
        ├── ast.rs           # AstNode enum definitions
        ├── parser.rs        # Pratt Top-Down Operator Precedence parser
        └── evaluator.rs     # Spec-compliant matcher, regex cache, CIDR evaluator
```

---

## 3. Compilation

### 3.1 Compile Kernel eBPF Sensor
Compile `src/sensor.c` into BPF bytecode using the provided `Makefile`:
```bash
make -C v2/ebpf-c
```
This generates `v2/ebpf-c/sensor.o`.

### 3.2 Compile User-Space Agent
Compile all crates in the workspace in release mode:
```bash
cargo build --release --workspace --manifest-path=v2/Cargo.toml
```
The compiled binaries and libraries are located in `v2/target/release/`. The primary daemon binary is `v2/target/release/spectre-agent`.

---

## 4. Verification & Testing

Spectre V2 includes automated unit tests, integration tests, and performance benchmarks.

### 4.1 Run Full Test Suite
```bash
cargo test --workspace --manifest-path=v2/Cargo.toml
```
All 15 tests across the workspace should pass:
* `spectre-agent`: 4 unit tests (telemetry envelope deserialization, PID safety invariants).
* `spectre-agent`: 2 integration tests (parent behavioral rules, deep ancestry enrichment).
* `spectre-graph`: 1 unit test (budgeted lazy min-heap eviction queue).
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

### 5.1 Mock Mode (Unprivileged, No Root Required)
For development, verification, and testing on systems without BPF privileges:
```bash
./v2/target/release/spectre-agent --mock
```
* Bypasses the eBPF kernel loader.
* Feeds synthetic telemetry (`fork` and `exec` events) through the ingestion pipeline.
* Exercises graph lineage enrichment, rule evaluation, and active containment alerts.

### 5.2 Production eBPF Mode (Requires Root)
To monitor live kernel system calls:
```bash
sudo ./v2/target/release/spectre-agent
```
* Loads `v2/ebpf-c/sensor.o` into the Linux kernel using `aya`.
* Attaches to the `syscalls/sys_enter_execve` tracepoint.
* Streams execution events directly through the 4MB kernel ring buffer.
* Automatically enriches events with process tree ancestry and evaluates loaded Sigma rules in real time.

---

## 6. Configuration & Logging

Logging verbosity can be controlled using the standard `RUST_LOG` environment variable:
```bash
# Info-level logging (alerts, startup, pipeline stats)
RUST_LOG=info ./v2/target/release/spectre-agent --mock

# Debug-level logging (per-event ingestion and graph updates)
RUST_LOG=debug ./v2/target/release/spectre-agent --mock
```

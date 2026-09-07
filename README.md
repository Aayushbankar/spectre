# Project Spectre: Host Intrusion Detection & Response Engine

Project Spectre is an open-source Host-based Intrusion Detection and Active Response System (HIDS/EDR).

The repository contains two distinct implementations representing the architectural evolution of the system:
1. **Spectre V2 (`/v2`)**: The primary high-performance engine written in **Rust** and **C (eBPF)**. It provides zero-gap kernel event capture, a Pratt AST parser for Sigma detection rules, generational graph lineage tracking, and race-free active mitigation via Linux `pidfd`.
2. **Spectre V1 (Root / `spectre/`)**: The initial proof-of-concept written in **Python**. It uses user-space polling via `psutil`, in-memory graph modeling via `NetworkX`, and a FastAPI dashboard. It serves as an experimental baseline and prototype.

---

## Technical Comparison: V1 (Python PoC) vs. V2 (Rust / eBPF Engine)

| Architectural Dimension | Spectre V1 (Python Prototype) | Spectre V2 (Hardened Rust / eBPF) |
|---|---|---|
| **Telemetry Ingestion** | User-space polling (`psutil.process_iter()`) at 500ms intervals | Kernel-level tracepoint hooking (`sys_enter_execve`) via eBPF |
| **Transient Process Detection** | Blind to processes that spawn and exit between polling cycles | Zero-gap capture; events buffered in kernel BPF Ring Buffer (4MB) |
| **Command-Line Capture** | Reads `/proc/<pid>/cmdline` (susceptible to TOCTOU and tampering) | Reads user-space `argv` pointers via `bpf_probe_read_user_str()` before execution |
| **Process Identity & Collisions** | Raw `u32` PID (vulnerable to kernel PID recycling collisions) | Composite generational key `ProcessKey { pid, start_time_ns }` |
| **Sigma Rule Parsing** | Naive 3-token whitespace splitter (`split_whitespace()`) | Top-Down Operator Precedence (Pratt) AST parser supporting arbitrary `AND`, `OR`, `NOT`, and `(...)` |
| **Modifier & Value Support** | Exact and basic substring matches | Sequence value lists (default `OR`), `\|all` chaining (`AND`), CIDR subnet matching (`ipnet`), precompiled regex cache (`Arc<Regex>`) |
| **Graph Data Structure** | `networkx.DiGraph` with linear sweep pruning | `petgraph::stable_graph::StableDiGraph` with $O(K \log M)$ min-heap lazy eviction queue |
| **Garbage Collection Overhead** | Periodic linear scan ($O(\|V\| + \|E\|)$) locking the graph | Decoupled background task yielding after 256 nodes; lock hold time < 30 µs |
| **Mitigation & Containment** | Unchecked POSIX `kill(pid, sig)` (race condition on recycled PIDs) | Safe `pidfd_send_signal` targeting, PID $\le 2$ safety guards, top-down `SIGSTOP` freeze, bottom-up `SIGKILL` |
| **Evaluation Throughput** | ~200 – 500 evaluations/sec | **2,557,939 evaluations/sec** (measured in release benchmark) |
| **Memory Consumption** | ~65 – 180 MB RSS (Python interpreter + NetworkX) | **4.8 MB RSS** (Rust static release binary) |
| **Binary Footprint** | Multi-file Python package + runtime dependencies | **4.8 MB** single static ELF executable (`spectre-agent`) |

---

## Spectre V2 (Rust & eBPF)

Spectre V2 is located in the [`v2/`](v2/) directory.

### Subsystem Overview
* **`v2/ebpf-c/`**: eBPF C sensor code hooking `sys_enter_execve`, walking argument strings directly into a 4MB BPF Ring Buffer.
* **`v2/spectre-agent/`**: The core daemon. Handles binary envelope deserialization, background graph GC, graph-backed lineage enrichment (`ParentImage`, `AncestorImages`), pipeline metrics, and `pidfd` signal dispatch.
* **`v2/spectre-rules/`**: Pratt parser and Sigma AST evaluator. Pre-compiles regular expressions and parses complex boolean conditions.
* **`v2/spectre-graph/`**: Generational process graph using `StableDiGraph` and `BinaryHeap` lazy eviction.

### Quickstart (V2)

#### 1. Compile eBPF Bytecode
```bash
make -C v2/ebpf-c
```

#### 2. Build Release Binaries
```bash
cargo build --release --workspace --manifest-path=v2/Cargo.toml
```

#### 3. Run Test Suite
```bash
cargo test --workspace --manifest-path=v2/Cargo.toml
```

#### 4. Run the Agent
* **Mock Mode** (Unprivileged, runs simulated telemetry and tests detection pipeline):
  ```bash
  ./v2/target/release/spectre-agent --mock
  ```
* **Kernel eBPF Mode** (Requires root / `CAP_BPF` + `CAP_PERFMON`):
  ```bash
  sudo ./v2/target/release/spectre-agent
  ```

For detailed specifications, see:
* [Spectre V2 Architecture Specification](docs/v2/architecture.md)
* [Spectre V2 Build & Operations Guide](docs/v2/build_guide.md)
* [Spectre V2 Audit & Remediation Ledger](docs/v2/audit_and_remediation.md)

---

## Spectre V1 (Python Prototype)

The Python prototype is retained in the root directory for educational and experimental reference.

### Setup and Running (V1)

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .

# Run CLI
spectre --help

# Run monitoring loop
spectre run --interval 0.5 --threshold 15
```

---

## Repository Layout

```text
.
├── docs/                     # Technical specifications, audits, and V1 reports
│   ├── v2/                   # V2 architectural specs, build guides, and remediation
│   │   ├── architecture.md
│   │   ├── build_guide.md
│   │   └── audit_and_remediation.md
│   ├── design_doc.md         # Original master design document (V1)
│   └── progress.md           # Progress history of V1 milestones
├── v2/                       # Hardened Rust & eBPF implementation
│   ├── Cargo.toml            # Workspace definition (resolver = "2")
│   ├── README.md             # V2 technical overview & benchmarks
│   ├── ebpf-c/               # Kernel eBPF sensor (C)
│   ├── spectre-agent/        # Userspace daemon & mitigation (Rust)
│   ├── spectre-graph/        # Generational process graph (Rust)
│   └── spectre-rules/        # Pratt Sigma AST evaluator (Rust)
├── spectre/                  # V1 Python prototype modules
│   ├── api/                  # FastAPI REST endpoints
│   ├── dashboard/            # Vanilla JS static UI
│   ├── detectors/            # Rule scoring logic
│   ├── graph/                # NetworkX process graph
│   └── sensor/               # psutil process polling
└── tests/                    # V1 Python pytest test suites
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
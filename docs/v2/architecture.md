# Spectre V2 Architecture

## Overview
Spectre V2 is a complete rewrite in Rust and eBPF, designed to provide zero-gap, true real-time visibility into kernel events (processes, files, network), coupled with a correct implementation of Sigma rule logic and stateful behavioral tracking.

## Core Components

### 1. eBPF Sensor (Kernel Space)
- Written in Rust using `aya-ebpf` or C using `libbpf`.
- Hooks: `sys_enter_execve`, `sched_process_fork`, `sys_enter_openat`, `security_socket_connect`.
- Reads `char **argv` and path buffers directly from kernel space to defeat TOCTOU.
- Sends events via BPF Ring Buffer to Userspace.

### 2. Event Ingestion Pipeline (Userspace)
- Rust async consumer (Tokio) reading the ring buffer.
- Deduplicates, orders, and structures events into internal schemas (Process, FileAccess, NetworkConnect).

### 3. Sigma Rule Engine
- **Parser:** A custom Abstract Syntax Tree (AST) parser that properly handles logical operators (`and`, `or`, `not`).
- **Modifiers:** Implements exact match, `contains`, `startswith`, `endswith`, `re` (regex), and `cidr`.
- **Evaluator:** Traverses the AST against incoming structured events to determine matches.

### 4. Process-Resource Graph
- In-memory graph built on `petgraph`.
- Nodes: Processes, Files, Sockets.
- Edges: `SPAWNS`, `READS`, `WRITES`, `CONNECTS`.
- Periodically pruned using a lock-free TTL sliding-window garbage collector.

### 5. Mitigation Engine
- High-severity behavioral triggers invoke `bpf_send_signal` directly via eBPF to SIGKILL offenders instantly.


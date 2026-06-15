# Spectre V2 Build & Development Guide

## Prerequisites
- Rust (stable + nightly for eBPF)
- `cargo-bpf` or `aya` toolchain prerequisites (`bpftool`, `llvm`, `clang`).
- Linux Kernel version >= 5.8 (for bpf ring buffers).
- Root privileges for execution.

## Project Structure
```text
spectre-v2/
├── xtask/             # Build scripts / orchestration
├── spectre-ebpf/      # Kernel-space eBPF programs (Rust/C)
├── spectre-agent/     # Userspace Rust agent
├── spectre-rules/     # Sigma parser & Graph engine library
└── docs/              # Architectural specs
```

## Build Steps
1. **Compile eBPF Program:**
   ```bash
   cargo xtask build-ebpf
   ```
2. **Compile Userspace Agent:**
   ```bash
   cargo build --release
   ```

## Development Cycle
- When changing eBPF code, always run the `xtask` to recompile the ELF binary before running the agent.
- Use `RUST_LOG=debug` to run the agent for verbose output.

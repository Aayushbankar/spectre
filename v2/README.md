# Spectre V2 (Rebuild)

This is the fully rebuilt Spectre HIDS Engine in Rust and eBPF.

## Achievements over V1:
- **eBPF Sensor:** True real-time process monitoring hooked directly at `sched_process_exec`. Absolutely no `psutil` or `/proc` polling is required for PID/Comm extraction, defeating TOCTOU races out of the box.
- **Sigma AST Engine:** A functional Sigma parser that properly ingests logical conditions and supports modifiers (e.g., `contains`, `endswith`, `regex`) unlike the non-functional stub in V1.
- **Petgraph Integration:** The sliding-window process tracking is deeply integrated and active on every event via `petgraph`.
- **Memory Safe & High Performance:** Achieved via Rust.

## To Run
```bash
cargo build --release
```

*Note: The eBPF sensor requires root to load.*
If running without root, use the `--mock` flag to see the AST and Graph in action:
```bash
./target/release/spectre-agent --mock
```

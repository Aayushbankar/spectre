# Project Spectre

Project Spectre is a lightweight, local-first **behavioral Host Intrusion Detection System (HIDS)**. Instead of relying on static file signatures, Spectre models the grammar of host processes and resource actions to detect anomalous execution chains and behaviors.

Rather than asking:
> *"Is this file known?"*

Spectre asks:
> *"Does this sequence of actions make sense on this machine?"*

---

## 🚀 Quick Start (V0 Process Monitor PoC)

Spectre is currently on **V0 (Process Monitor PoC)**. This version acts as the baseline telemetry monitor, tracking new process spawns and reconstructing their entire ancestry chain (from child up to the init daemon / systemd).

### Prerequisites
* Python 3.8+
* Linux operating system

### Installation & Run

1. **Clone & Navigate to directory:**
   ```bash
   cd spectre
   ```

2. **Create a virtual environment & install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run the process monitor:**
   ```bash
   python main.py
   ```

4. **Tune Polling Frequency (Optional):**
   Tune the polling loop speed to find the sweet spot between capturing fast processes and keeping CPU usage minimal (target `<5%` CPU, `<200MB` RAM).
   ```bash
   # Run with a 100ms interval (default is 0.5s)
   python main.py --interval 0.1
   ```

---

## 📂 Project Structure & Documentation

* **[docs/design_doc.md](docs/design_doc.md)**: The master design document listing the vision, principles, core entity relations, and the 17-stage incremental SDLC roadmap.
* **[docs/progress.md](docs/progress.md)**: The current progress tracker of the system's increments.
* **[docs/v0_report.md](docs/v0_report.md)**: Technical overview of the V0 Process Monitor implementation and sample trace logs.
* **[main.py](main.py)**: The entrypoint script containing the V0 process-polling and ancestry-tracing engine.
* **[requirements.txt](requirements.txt)**: List of dependencies (`psutil`).

---

## 🛠️ Incremental SDLC Roadmap

Spectre is evolving step-by-step:
* **V0 (Current)**: Process Monitor PoC.
* **V1 (Next)**: Rule-based behavior, scoring chains, and generating human-explainable alerts.
* **V2**: Resource tracing (files, sockets, read/write/connect events).
* **V3**: Sliding window event expiration using NetworkX graphs.
* *See [progress.md](docs/progress.md) for the full 17-step roadmap.*

# Project Spectre

Project Spectre is a lightweight, local-first **behavioral Host Intrusion Detection System (HIDS)**. Instead of relying on static file signatures, Spectre models the grammar of host processes and resource actions to detect anomalous execution chains and behaviors.

Rather than asking:
> *"Is this file known?"*

Spectre asks:
> *"Does this sequence of actions make sense on this machine?"*

---

## 🚀 Quick Start (V4 Detection Engine)

Spectre is currently on **V4 (Detection Engine)**. This version introduces dynamic JSON rules loading, process-resource rule matching, and weighted threat score accumulation across process session trees.

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

> [!IMPORTANT]
> **Quiet vs. Verbose Output Modes**
> * **Quiet Mode (Default)**: Running `python main.py` runs quietly. It will **only** print to the terminal when a security alert is triggered (e.g., shell spawning downloader tools like `curl`).
> * **Verbose Mode**: Running `python main.py --verbose` (or `-v`) prints **all** process spawns, file reads/writes, and network connections, along with the NetworkX graph metrics, in the terminal in real time as they occur.

3. **Run the HIDS detector (Quiet Mode - prints security alerts only):**
   ```bash
   python main.py
   ```

4. **Run in Verbose Mode with Custom Rules & Threshold:**
   ```bash
   python main.py --verbose --rules rules.json --threshold 20 --interval 0.1
   ```

---

## 🧪 E2E Verification Tests

V4 includes an automated E2E verification test suite to simulate and assert threat escalation behaviors under `tests/v4/`.

Run the test suite directly:
```bash
python3 tests/v4/run_test.py
```

---

## 📂 Project Structure & Documentation

* **[docs/design_doc.md](docs/design_doc.md)**: The master design document listing the vision, principles, core entity relations, and the 17-stage incremental SDLC roadmap.
* **[docs/progress.md](docs/progress.md)**: The current progress tracker of the system's increments.
* **[docs/v0_report.md](docs/v0_report.md)**: Technical overview of the V0 Process Monitor implementation.
* **[docs/v1_report.md](docs/v1_report.md)**: Technical overview of the V1 Rule-Based Detector and explanation engine.
* **[docs/v2_report.md](docs/v2_report.md)**: Technical overview of the V2 Resource Tracking architecture.
* **[docs/v3_report.md](docs/v3_report.md)**: Technical overview of the V3 sliding window graph model and pruning mechanics.
* **[docs/v4_report.md](docs/v4_report.md)**: Technical overview of the V4 Detection Engine and E2E test suite.
* **[main.py](main.py)**: Orchestration script running the detector.
* **[rules.json](rules.json)**: JSON configuration containing all behavioral rules.
* **[sensor/](sensor/)**: Telemetry collection wrapper extracting process ancestry and active resource state.
* **[graph/](graph/)**: NetworkX sliding window graph implementation with event-pruning queues.
* **[rules/](rules/)**: Rules dataclass and preset list of suspicious behavior profiles.
* **[detectors/](detectors/)**: Evaluates active process chains against the behavioral rules.
* **[alerts/](alerts/)**: Explanation builder, console tree printer, and logging handlers.
* **[tests/](tests/)**: Version-specific automated test suites and simulation triggers.

---

## 🛠️ Incremental SDLC Roadmap

Spectre is evolving step-by-step:
* **V0**: Process Monitor PoC.
* **V1**: Rule-based behavior, scoring chains, and generating human-explainable alerts.
* **V2**: Resource tracing (files, sockets, read/write/connect/listen events).
* **V3**: Sliding window event expiration using NetworkX graphs.
* **V4 (Current)**: Detection Engine upgrades (dynamic JSON rules, weighted session scoring, custom threat thresholds).
* **V5 (Next)**: Attack Mapping (MITRE ATT&CK integration).
* *See [progress.md](docs/progress.md) for the full 17-step roadmap.*

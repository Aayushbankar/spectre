<div align="center">
  <h1>Project Spectre</h1>
  <p><b>A Behavioral Host Intrusion Detection System (HIDS)</b></p>
  
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+"></a>
    <a href="https://github.com/Aayushbankar/spectre/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
    <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE-ATT%26CK-red.svg" alt="MITRE ATT&CK"></a>
    <a href="#"><img src="https://img.shields.io/badge/Build-Passing-brightgreen.svg" alt="Build Status"></a>
  </p>
  
  <p><i>Instead of asking "Is this file known?", Spectre asks "Does this sequence of actions make sense?"</i></p>
</div>

---

## Table of Contents
- [Overview](#overview)
- [Why Spectre?](#why-spectre)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage & CLI Reference](#usage--cli-reference)
- [Configuration (Writing Rules)](#configuration-writing-rules)
- [Testing & Verification](#testing--verification)
- [Documentation & Roadmap](#documentation--roadmap)
- [Acknowledgments & External Links](#acknowledgments--external-links)

---

## Overview

**Project Spectre** is a lightweight, local-first **behavioral Host Intrusion Detection System (HIDS)**. Rather than relying heavily on static file signatures, Spectre models the grammar of host processes and resource actions to detect anomalous execution chains and behaviors. 

Currently on **V10 (Active Containment)**, Spectre tracks process lineages, monitors file and network I/O, evaluates threats in real-time, provides MITRE ATT&CK context, scans payloads via YARA, and can actively quarantine or terminate malicious process trees.

---

## Why Spectre?

Traditional endpoint protection platforms (EPP) and antiviruses (AV) often rely heavily on static signatures—checking file hashes against a known database of malware. This approach completely fails against **zero-day threats**, **fileless malware**, and **"living off the land"** techniques where attackers abuse legitimate system binaries (like `powershell`, `curl`, or `bash`).

Spectre shifts the security paradigm from *static characteristics* to *dynamic relationships*. By continuously tracking process ancestry (who spawned who) and correlating it with resource access (who touched which file, who opened which socket), Spectre identifies malicious **intent** rather than malicious **files**.

**Example Attack Chain Detected:**
```text
nginx (Web Server)
└── bash (Interactive Shell)
    ├── curl (Downloads payload)
    │   └── [WRITE] -> /tmp/malware.sh
    └── sh (Executes payload)
        └── [CONNECT] -> 192.168.1.50:4444 (C2 Server)
```

---

## Architecture

The system operates across a 4-stage pipeline:

```text
+---------------------+      +---------------------+      +---------------------+
|                     |      |                     |      |                     |
|  1. OS Telemetry    |----->|  2. Graph Builder   |----->| 3. Detection Engine |
|  (psutil, /proc)    |      |  (NetworkX Memory)  |      |  (Rules & Scoring)  |
|                     |      |                     |      |                     |
+---------------------+      +---------------------+      +---------------------+
                                                                     |
                                                                     v
                                                          +---------------------+
                                                          |                     |
                                                          |  4. Action & Alert  |
                                                          | (Containment, REST) |
                                                          |                     |
                                                          +---------------------+
```

1. **Telemetry Sensing (`psutil`)**: Continuously polls the OS for process spawns, file descriptors, and network sockets.
2. **Graph Construction (`NetworkX`)**: Events are normalized into a sliding-window, directed process-resource graph, automatically pruning stale events to prevent memory leaks.
3. **Detection Engine**: The active graph is evaluated against JSON-configurable behavioral rules. Threat scores accumulate along process lineage chains.
4. **Action & Visualization (`FastAPI` & `Next.js`)**: Once a threshold is breached, Spectre fires an alert, maps it to MITRE ATT&CK, runs a deep-scan via YARA, and can actively freeze/kill the process tree.

---

## Key Features

- **Process Ancestry Tracking**: Reconstructs complete execution lineages, handling PID recycling and short-lived processes safely.
- **Resource Monitoring**: Tracks I/O operations including `READ`/`WRITE` for files, and `CONNECT`/`LISTEN` for sockets.
- **Behavioral Detection Engine**: Scores chains of events dynamically using JSON-configurable rules.
- **Threat Enrichment**: 
  - **MITRE ATT&CK**: Alerts are mapped automatically to ATT&CK tactics (e.g., *T1059 - Command and Scripting Interpreter*).
  - **YARA Integration**: Scans suspicious files on-the-fly using the `yara-python` engine.
- **Active Containment**: Configurable actions (`--contain stop` or `kill`) to instantly freeze or terminate entire threat process trees.
- **Persistence & API**: Events and alerts are stored in a local SQLite database and exposed via a FastAPI REST interface.
- **Live Dashboard**: Real-time web dashboard powered by Next.js to monitor the graph, alerts, and system telemetry.

---

## Getting Started

### Prerequisites

- Python 3.8 or newer
- Linux Operating System (for accurate `/proc` mapping and `psutil` compatibility)
- Dependencies: `psutil`, `networkx`, `fastapi`, `yara-python`, `uvicorn`

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Aayushbankar/spectre.git
   cd spectre
   ```

2. **Set up virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

---

## Usage & CLI Reference

Spectre provides a highly configurable Command Line Interface (CLI) for tuning the engine's sensitivity and enabling specific modules.

### Basic Usage

> [!IMPORTANT]
> **Quiet Mode vs. Verbose Mode**
> By default, `python main.py` runs in **Quiet Mode**, meaning it will only log to the terminal when a critical alert threshold is breached. To see the graph updating in real-time, use the `--verbose` (`-v`) flag.

**Run with Active Containment & REST API:**
```bash
python main.py --verbose --contain kill --api --yara-rules yara_rules
```

### Full CLI Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--interval` | Polling interval in seconds (controls telemetry speed). | `0.5` |
| `--log-file` | Path to the security alerts output log file. | `spectre_alerts.log` |
| `--verbose`, `-v` | Enable verbose mode to print all process/resource events. | `False` |
| `--window-size`, `-w`| Sliding time window in seconds for event expiration. | `60.0` |
| `--rules`, `-r` | Path to the behavioral rules JSON configuration file. | `rules.json` |
| `--threshold`, `-t` | Threat score threshold for triggering high-severity alerts. | `15` |
| `--api` | Enable the FastAPI REST API and Dashboard server. | `Disabled` |
| `--api-port` | Port for the REST API server. | `8000` |
| `--db` | Path to SQLite database for event persistence. | `spectre.db` |
| `--yara-rules` | Directory containing YARA rule files (`.yar`/`.yara`). | `yara_rules` |
| `--contain` | Mitigation action to take on a breach (`none`, `stop`, `kill`). | `none` |

---

## Configuration (Writing Rules)

Spectre uses a decoupled `rules.json` file for behavioral detection. You can write your own custom rules to monitor specific chains in your environment.

**Example: Detecting a web server spawning a shell**
```json
[
  {
    "name": "Web Server Shell Spawn",
    "parent": "nginx|apache2",
    "child": "bash|sh|dash",
    "resource": null,
    "score": 20,
    "description": "A web server process spawned a shell interpreter, indicating a potential web shell.",
    "mitre_id": "T1505.003"
  }
]
```
*If an `nginx` process spawns `bash`, this rule assigns a high threat score of 20, immediately breaching the default threshold of 15 and triggering an alert.*

---

## Testing & Verification

Spectre includes an automated E2E verification test suite to simulate and assert threat escalation behaviors (like spawning web shells, executing curl, and touching sensitive files).

Run the V10 testing suite:
```bash
python3 tests/v10/run_test.py
```

---

## Documentation & Roadmap

Detailed architectural notes and version progression can be found in the `docs/` directory:

* **[Master Design Document](docs/design_doc.md)**: Vision, entity relations, and the 17-stage SDLC roadmap.
* **[Progress Tracker](docs/progress.md)**: Current completion status of the project.
* **[GTU Internship Submission](docs/gtu_submission_details.md)**: Details for project submission.

**Incremental SDLC Roadmap (Current Status):**
- [x] **V0-V3**: Process Monitor, Rule Engine, Resource Tracking, Graph Memory.
- [x] **V4-V5**: Detection Engine, MITRE ATT&CK Mapping.
- [x] **V6-V8**: SQLite Persistence, REST API, Live Dashboard.
- [x] **V9**: YARA Engine Integration.
- [x] **V10**: Active Containment (SIGSTOP/SIGKILL).
- [ ] **V11**: Attack Replay Framework (Atomic Red Team).
- [ ] **V12**: OS Telemetry Upgrades (eBPF, auditd).
- [ ] **V13-V17**: Machine Learning, Graph Embeddings, Multi-host Agent.

*(Individual version reports v0-v10 are also available in the docs folder).*

---

## Acknowledgments & External Links

Spectre is built on the shoulders of giants. We heavily rely on the following open-source frameworks and security standards:

- **[psutil](https://github.com/giampaolo/psutil)**: For cross-platform OS-level process and system monitoring.
- **[NetworkX](https://networkx.org/)**: For sliding-window directed graph processing and ancestry modeling.
- **[FastAPI](https://fastapi.tiangolo.com/)**: For exposing the high-performance telemetry API.
- **[YARA](https://virustotal.github.io/yara/)**: The pattern matching swiss knife for malware researchers.
- **[MITRE ATT&CK®](https://attack.mitre.org/)**: The globally-accessible knowledge base of adversary tactics and techniques.

---
<div align="center">
  <i>Engineered for deep contextual visibility and zero-day resilience.</i>
</div>

# Project Progress Tracker

This document tracks the implementation progress of Project Spectre through the incremental SDLC roadmap.

## Summary Roadmap

| Version | Feature Goal | Status | Completed Date | Notes |
| :--- | :--- | :---: | :--- | :--- |
| **V0** | Process Monitor PoC | **Completed** | 2026-06-23 | Console tree representation of ancestry chains using `psutil`. |
| **V1** | Rule-based Detector | **Completed** | 2026-06-24 | Tree building, scoring, explanation, alert logging. |
| **V2** | Resource Tracking | **Completed** | 2026-06-24 | Files, Sockets, and READ/WRITE/CONNECT/LISTEN events. |
| **V3** | Sliding Window Graph | **Completed** | 2026-06-24 | Event expiration, cleanup, rolling memory using `networkx`. |
| **V4** | Detection Engine | **Completed** | 2026-06-24 | Weighted scoring, JSON rules, thresholding. |
| **V5** | Attack Mapping | *Not Started* | - | MITRE ATT&CK integration. |
| **V6** | Persistence | *Not Started* | - | SQLite storage for events, alerts, and scores. |
| **V7** | REST API | *Not Started* | - | FastAPI endpoints for querying events, alerts, and chains. |
| **V8** | Dashboard | *Not Started* | - | Next.js, TailwindCSS frontend with force-directed graphs. |
| **V9** | YARA Integration | *Not Started* | - | Hash lookup and string signature file scans. |
| **V10**| Containment | *Not Started* | - | Tree killing, process quarantining, SIGTERM/SIGSTOP actions. |
| **V11**| Attack Replay | *Not Started* | - | Atomic Red Team simulation runner. |
| **V12**| Telemetry Upgrades | *Not Started* | - | eBPF, auditd, and procfs event sourcing. |
| **V13**| Machine Learning | *Not Started* | - | Isolation Forest / One-class SVM anomaly detection. |
| **V14**| Graph Embeddings | *Not Started* | - | Node2Vec / DeepWalk modeling. |
| **V15**| Multi-host Support | *Not Started* | - | Kafka / Redis streams agent-collector transport. |
| **V16**| LLM Explanations | *Not Started* | - | AI-generated alert chain summaries. |
| **V17**| Research Branch | *Not Started* | - | Temporal Graph Networks / continuous-time learning. |

---

## Detailed Milestones

### V0: Process Monitor PoC
* **Deliverable**: Console-based process tree logger.
* **Outcome**: Implemented recycled PID matching, safely handle short-lived processes, trace lineages to root, print formatted ASCII trees.
* **Artifacts**:
  * Code: [main.py](file:///mnt/work/projects/spectre/main.py)
  * Report: [v0_report.md](file:///mnt/work/projects/spectre/docs/v0_report.md)

### V1: Rule-based Detector
* **Deliverable**: Process-to-process spawn pattern matching engine with alert generation and explanation blocks.
* **Outcome**: Built decoupled modules for rules mapping, alert evaluation, and threat-focused logging. Tested and triggered alerts for web shells, curl downloads, and ncat configurations.
* **Artifacts**:
  * Code: [main.py](file:///mnt/work/projects/spectre/main.py) | [sensor/](file:///mnt/work/projects/spectre/sensor/) | [rules/](file:///mnt/work/projects/spectre/rules/) | [detectors/](file:///mnt/work/projects/spectre/detectors/) | [alerts/](file:///mnt/work/projects/spectre/alerts/)
  * Report: [v1_report.md](file:///mnt/work/projects/spectre/docs/v1_report.md)

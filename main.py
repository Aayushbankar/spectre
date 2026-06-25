#!/usr/bin/env python3
import sys
import argparse
from sensor import ProcessSensor
from rules import load_rules_from_file
from detectors import DetectionEngine
from alerts import Alert, AlertLogger, format_process_resource_tree
from graph import ProcessResourceGraph
from storage import SpectreDB

def print_raw_process_tree(chain):
    """
    Prints a raw process-resource tree to stdout (when running with --verbose).
    """
    if not chain:
        return
    print("\n[EVENT DETECTED]")
    tree_lines = format_process_resource_tree(chain)
    for line in tree_lines:
        print(line)
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Spectre V6: SQLite Persistence")
    parser.add_argument(
        "--interval", 
        type=float, 
        default=0.5, 
        help="Polling interval in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--log-file", 
        type=str, 
        default="spectre_alerts.log", 
        help="Path to the security alerts log file (default: spectre_alerts.log)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose mode to print all process/resource events and sub-threshold alerts (default: print threshold alerts only)"
    )
    parser.add_argument(
        "--window-size", "-w",
        type=float,
        default=60.0,
        help="Sliding time window in seconds for event expiration (default: 60.0)"
    )
    parser.add_argument(
        "--rules", "-r",
        type=str,
        default="rules.json",
        help="Path to the behavioral rules JSON configuration file (default: rules.json)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=15,
        help="Threat score threshold for triggering high-severity alerts (default: 15)"
    )
    parser.add_argument(
        "--db",
        type=str,
        default="spectre.db",
        help="Path to SQLite database for event persistence (default: spectre.db)"
    )
    args = parser.parse_args()

    print(f"[*] Starting Spectre V6 HIDS...")
    print(f"[*] Alert Log file: {args.log_file}")
    print(f"[*] Database: {args.db}")
    print(f"[*] Polling interval: {args.interval}s")
    print(f"[*] Sliding Graph window size: {args.window_size}s")
    print(f"[*] Threat Threshold: {args.threshold}")
    
    # Load rules dynamically
    rules = load_rules_from_file(args.rules)
    print(f"[*] Loaded {len(rules)} behavioral rules from '{args.rules}':")
    for rule in rules:
        mitre_str = rule.get_mitre_str()
        mitre_suffix = f" | MITRE: {mitre_str}" if mitre_str else ""
        print(f"    - {rule.name} (Score: {rule.score}){mitre_suffix}")

    # Initialize components
    sensor = ProcessSensor(interval=args.interval)
    detector = DetectionEngine(rules=rules)
    alert_logger = AlertLogger(log_file=args.log_file)
    graph = ProcessResourceGraph(window_size=args.window_size)
    db = SpectreDB(db_path=args.db)

    print(f"[*] Initial host process snapshot captured.")
    print(f"[*] Active host intrusion and resource monitoring running. Press Ctrl+C to stop.\n" + "="*60)
    sys.stdout.flush()

    # Track threat scores of process sessions (keyed by the oldest monitored ancestor process)
    # leader_key -> {"score": int, "triggered_rules": set, "events": list}
    session_scores = {}
    
    # Track the last logged score for each session to prevent alert spam
    last_logged_score = {}

    try:
        for chain in sensor.start_monitoring():
            # Update running processes database
            graph.update_active_processes(sensor.known_processes)
            
            # Feed current telemetry chain to the NetworkX graph
            graph.add_chain(chain)
            
            # Expire old events and nodes past the window size
            graph.expire_old_events()
            
            # Find the oldest monitored ancestor in this chain (the session leader)
            session_leader = chain[0]
            leader_key = (session_leader["pid"], session_leader["create_time"])
            
            if leader_key not in session_scores:
                session_scores[leader_key] = {
                    "score": 0,
                    "triggered_rules": set(),
                    "events": []
                }
            
            session_info = session_scores[leader_key]
            
            # Evaluate current chain for behavior matches
            matches = detector.evaluate_chain(chain)
            
            for rule, proc, detail in matches:
                # Unique signature for the matched behavior event
                sig = (rule.id, proc["pid"], proc["create_time"], detail)
                
                if sig not in session_info["triggered_rules"]:
                    session_info["triggered_rules"].add(sig)
                    session_info["score"] += rule.score
                    
                    mitre_str = rule.get_mitre_str()
                    event_data = {
                        "rule_name": rule.name,
                        "score": rule.score,
                        "offending_proc": proc["name"],
                        "pid": proc["pid"],
                        "detail": detail,
                        "mitre": mitre_str
                    }
                    session_info["events"].append(event_data)
                    
                    # Persist event to SQLite
                    db.insert_event(
                        event_type=rule.id,
                        proc_pid=proc["pid"],
                        proc_name=proc["name"],
                        detail=detail,
                        mitre=mitre_str
                    )
                    
                    # Update session score in SQLite
                    db.upsert_session(
                        leader_pid=session_leader["pid"],
                        leader_name=session_leader["name"],
                        leader_ctime=session_leader["create_time"],
                        total_score=session_info["score"]
                    )
                    
                    # Log warning to alert log file
                    mitre_log = f" | MITRE: {mitre_str}" if mitre_str else ""
                    log_msg = (
                        f"[WARNING] Process '{proc['name']}' (PID: {proc['pid']}) triggered "
                        f"rule '{rule.name}' (Score: {rule.score}) | Event: {detail}{mitre_log} | "
                        f"Session Leader PID: {session_leader['pid']} (Total Score: {session_info['score']}/{args.threshold})"
                    )
                    alert_logger.logger.warning(log_msg)
                    
                    if args.verbose:
                        mitre_v = f" [{mitre_str}]" if mitre_str else ""
                        print(f"[*] [WARNING] {proc['name']} (PID: {proc['pid']}) triggered '{rule.name}' (+{rule.score}){mitre_v} | Total Session Score: {session_info['score']}/{args.threshold}")
                        sys.stdout.flush()

            # Check if session score crossed/increased past the threshold
            current_score = session_info["score"]
            if current_score >= args.threshold:
                if current_score > last_logged_score.get(leader_key, 0):
                    last_logged_score[leader_key] = current_score
                    
                    # Format dynamic multi-event explanation
                    explanation = (
                        f"Process session leader '{session_leader['name']}' (PID: {session_leader['pid']}) "
                        f"accumulated threat score {current_score} which exceeds the alert threshold of {args.threshold}!\n"
                        f"Triggered behaviors:\n"
                    )
                    for ev in session_info["events"]:
                        mitre_part = f" | MITRE: {ev['mitre']}" if ev.get('mitre') else ""
                        explanation += f"  - {ev['rule_name']} (Score: {ev['score']}) | Process '{ev['offending_proc']}' (PID: {ev['pid']}) -> {ev['detail']}{mitre_part}\n"
                    
                    # Log high severity alert
                    alert = Alert(
                        rule_id="session_threshold_exceeded",
                        rule_name="Process Session Exceeded Threat Threshold",
                        score=current_score,
                        chain=chain,
                        explanation=explanation
                    )
                    alert_logger.log_alert(alert)
                    
                    # Persist alert to SQLite
                    db.insert_alert(
                        rule_id="session_threshold_exceeded",
                        rule_name="Process Session Exceeded Threat Threshold",
                        score=current_score,
                        chain=chain,
                        explanation=explanation
                    )

            # In verbose mode, print raw tree and graph stats
            if args.verbose:
                print_raw_process_tree(chain)
                stats = graph.get_stats()
                print(f"[GRAPH STATE] Nodes: {stats['total_nodes']} (Proc: {stats['processes']}, File: {stats['files']}, Sock: {stats['sockets']}), Edges: {stats['edges']}")
                sys.stdout.flush()

    except KeyboardInterrupt:
        db.close()
        print("\n[*] Stopping Spectre V6 HIDS.")
        sys.exit(0)

if __name__ == "__main__":
    main()

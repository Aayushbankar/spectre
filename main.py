#!/usr/bin/env python3
import sys
import argparse
from sensor import ProcessSensor
from rules import DEFAULT_RULES
from detectors import DetectionEngine
from alerts import Alert, ExplanationEngine, AlertLogger, format_process_resource_tree
from graph import ProcessResourceGraph

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
    parser = argparse.ArgumentParser(description="Spectre V3: Incremental HIDS Sliding Window Graph")
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
        help="Enable verbose mode to print all process/resource events (default: print alerts only)"
    )
    parser.add_argument(
        "--window-size", "-w",
        type=float,
        default=60.0,
        help="Sliding time window in seconds for event expiration (default: 60.0)"
    )
    args = parser.parse_args()

    print(f"[*] Starting Spectre V3 HIDS...")
    print(f"[*] Alert Log file: {args.log_file}")
    print(f"[*] Polling interval: {args.interval}s")
    print(f"[*] Sliding Graph window size: {args.window_size}s")
    print(f"[*] Active rules loaded: {len(DEFAULT_RULES)}")
    for rule in DEFAULT_RULES:
        print(f"    - {rule.name} (Severity: {rule.score})")

    # Initialize components
    sensor = ProcessSensor(interval=args.interval)
    detector = DetectionEngine(rules=DEFAULT_RULES)
    alert_logger = AlertLogger(log_file=args.log_file)
    graph = ProcessResourceGraph(window_size=args.window_size)

    print(f"[*] Initial host process snapshot captured.")
    print(f"[*] Active host intrusion and resource monitoring running. Press Ctrl+C to stop.\n" + "="*60)
    sys.stdout.flush()

    # Track triggered alerts to prevent duplicate logs on resource updates
    seen_alerts = set()

    try:
        # We also run a periodic check for graph expiration even when there are no new sensor yields
        # Since sensor.start_monitoring() blocks on yields, we can do it when we receive yields.
        # But wait! If the sensor doesn't yield, we still want old events to expire!
        # Since start_monitoring() is a generator yielding on events, if there are NO events, the loop blocks.
        # This is fine for V3 because graph updates only happen when the sensor detects something.
        # We can also perform graph expiration on each loop iteration inside sensor.start_monitoring(),
        # or inside main.py whenever we receive a chain.
        # Let's run update and expiration whenever the sensor yields.
        for chain in sensor.start_monitoring():
            # Update running processes database to keep alive processes in the graph
            graph.update_active_processes(sensor.known_processes)
            
            # Feed current telemetry chain to the NetworkX graph
            graph.add_chain(chain)
            
            # Expire old events and nodes past the window size
            graph.expire_old_events()
            
            # Evaluate the process chain for matches
            matches = detector.evaluate_chain(chain)
            
            if matches:
                # Process matches and generate alerts
                for rule, parent, child in matches:
                    alert_key = (rule.id, child["pid"], child["create_time"])
                    if alert_key in seen_alerts:
                        continue
                    
                    seen_alerts.add(alert_key)
                    explanation = ExplanationEngine.generate(rule.id, parent, child)
                    alert = Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        score=rule.score,
                        chain=chain,
                        explanation=explanation
                    )
                    alert_logger.log_alert(alert)
                    
                    if args.verbose:
                        # Log graph metrics
                        stats = graph.get_stats()
                        print(f"[GRAPH STATE] Nodes: {stats['total_nodes']} (Proc: {stats['processes']}, File: {stats['files']}, Sock: {stats['sockets']}), Edges: {stats['edges']}")
            elif args.verbose:
                # If no rule was matched, print the event tree
                print_raw_process_tree(chain)
                
                # Print graph metrics
                stats = graph.get_stats()
                print(f"[GRAPH STATE] Nodes: {stats['total_nodes']} (Proc: {stats['processes']}, File: {stats['files']}, Sock: {stats['sockets']}), Edges: {stats['edges']}")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[*] Stopping Spectre V3 HIDS.")
        sys.exit(0)

if __name__ == "__main__":
    main()

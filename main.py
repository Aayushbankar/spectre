#!/usr/bin/env python3
import sys
import argparse
from sensor import ProcessSensor
from rules import DEFAULT_RULES
from detectors import DetectionEngine
from alerts import Alert, ExplanationEngine, AlertLogger, format_process_resource_tree

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
    parser = argparse.ArgumentParser(description="Spectre V2: Incremental HIDS Resource Tracker")
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
    args = parser.parse_args()

    print(f"[*] Starting Spectre V2 HIDS...")
    print(f"[*] Alert Log file: {args.log_file}")
    print(f"[*] Polling interval: {args.interval}s")
    print(f"[*] Active rules loaded: {len(DEFAULT_RULES)}")
    for rule in DEFAULT_RULES:
        print(f"    - {rule.name} (Severity: {rule.score})")

    # Initialize components
    sensor = ProcessSensor(interval=args.interval)
    detector = DetectionEngine(rules=DEFAULT_RULES)
    alert_logger = AlertLogger(log_file=args.log_file)

    print(f"[*] Initial host process snapshot captured.")
    print(f"[*] Active host intrusion and resource monitoring running. Press Ctrl+C to stop.\n" + "="*60)
    sys.stdout.flush()

    # Track triggered alerts to prevent duplicate logs on resource updates
    # Elements: (rule_id, child_pid, child_create_time)
    seen_alerts = set()

    try:
        # Start monitoring new process spawns and resource updates
        for chain in sensor.start_monitoring():
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
            elif args.verbose:
                # If no rule was matched, only print the event tree in verbose mode
                print_raw_process_tree(chain)

    except KeyboardInterrupt:
        print("\n[*] Stopping Spectre V2 HIDS.")
        sys.exit(0)

if __name__ == "__main__":
    main()

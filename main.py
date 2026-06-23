#!/usr/bin/env python3
import sys
import argparse
from sensor import ProcessSensor
from rules import DEFAULT_RULES
from detectors import DetectionEngine
from alerts import Alert, ExplanationEngine, AlertLogger

def print_raw_process_tree(chain):
    """
    Prints a raw process chain to stdout (V0 fallback when running with --verbose).
    """
    if not chain:
        return
    print("\n[SPAWN DETECTED]")
    for i, proc in enumerate(chain):
        cmd_str = " ".join(proc['cmdline']) if proc['cmdline'] else proc['name']
        if len(cmd_str) > 80:
            cmd_str = cmd_str[:77] + "..."
        display_str = f"{proc['name']} (PID: {proc['pid']}) [Cmd: {cmd_str}]"
        if i == 0:
            print(display_str)
        else:
            indent = "    " * (i - 1)
            print(f"{indent}└── {display_str}")
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Spectre V1: Incremental HIDS Rule-Based Detector")
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
        help="Enable verbose mode to print all process spawns (default: print alerts only)"
    )
    args = parser.parse_args()

    print(f"[*] Starting Spectre V1 HIDS...")
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
    print(f"[*] Active host intrusion monitoring running. Press Ctrl+C to stop.\n" + "="*60)
    sys.stdout.flush()

    try:
        # Start monitoring new process spawn events
        for chain in sensor.start_monitoring():
            # Evaluate the process chain for matches
            matches = detector.evaluate_chain(chain)
            
            if matches:
                # Process matches and generate alerts
                for rule, parent, child in matches:
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
                # If no rule was matched, only print the process tree in verbose mode
                print_raw_process_tree(chain)

    except KeyboardInterrupt:
        print("\n[*] Stopping Spectre V1 HIDS.")
        sys.exit(0)

if __name__ == "__main__":
    main()

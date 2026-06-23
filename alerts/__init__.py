import time
import logging
import sys
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    score: int
    chain: List[Dict]
    explanation: str
    timestamp: float = field(default_factory=time.time)

class ExplanationEngine:
    """
    Generates human-readable, detailed explanations for security alerts
    describing what happened, why it is suspicious, and which processes were involved.
    """
    @staticmethod
    def generate(rule_id: str, parent: Dict, child: Dict) -> str:
        parent_cmd = " ".join(parent['cmdline']) if parent['cmdline'] else parent['name']
        child_cmd = " ".join(child['cmdline']) if child['cmdline'] else child['name']
        
        # Truncate command lines if they are too long
        if len(parent_cmd) > 80:
            parent_cmd = parent_cmd[:77] + "..."
        if len(child_cmd) > 80:
            child_cmd = child_cmd[:77] + "..."

        if rule_id == "web_server_shell":
            return (
                f"Web server '{parent['name']}' (PID: {parent['pid']}) spawned an interactive shell '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}]. "
                f"This process pattern is highly suspicious and typical of web shell access or remote code execution (RCE) attempts."
            )
        elif rule_id == "shell_network_tool":
            return (
                f"Shell '{parent['name']}' (PID: {parent['pid']}) spawned network tool '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}]. "
                f"This may indicate active host reconnaissance, port scanning, or the establishment of outbound traffic redirection."
            )
        elif rule_id == "shell_downloader":
            return (
                f"Shell '{parent['name']}' (PID: {parent['pid']}) spawned transfer utility '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}]. "
                f"This is a common behavior when downloading secondary payloads, scripts, or post-exploitation toolkits."
            )
        elif rule_id == "web_server_compiler":
            return (
                f"Web server '{parent['name']}' (PID: {parent['pid']}) spawned compiler/interpreter '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}]. "
                f"This suggests compile-on-site exploits or the execution of server-side automation scripts by an unauthorized user."
            )
        else:
            return (
                f"Process '{child['name']}' (PID: {child['pid']}) [Cmd: {child_cmd}] was spawned by "
                f"'{parent['name']}' (PID: {parent['pid']}) [Cmd: {parent_cmd}], violating rule '{rule_id}'."
            )

class AlertLogger:
    """
    Handles logging of security alerts to console and to file, formatting
    each alert into a readable, detailed report.
    """
    def __init__(self, log_file: str = "spectre_alerts.log"):
        self.logger = logging.getLogger("SpectreHIDS")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        # Create file handler to log security alerts
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

    def log_alert(self, alert: Alert):
        """
        Logs a security alert to the log file and prints a formatted
        warning block directly to console/stdout.
        """
        # Log to file
        log_msg = f"[ALERT] {alert.rule_name} (Score: {alert.score}) - Explanation: {alert.explanation}"
        self.logger.warning(log_msg)

        # Print detailed warning block to console
        print("\n" + "!" * 60)
        print(f"⚠️  SECURITY ALERT: {alert.rule_name.upper()}")
        print(f"Severity Score: {alert.score}/20")
        print(f"Explanation:    {alert.explanation}")
        print("\nExecution Chain:")
        
        # Print the process chain tree
        for i, proc in enumerate(alert.chain):
            cmd_str = " ".join(proc['cmdline']) if proc['cmdline'] else proc['name']
            if len(cmd_str) > 80:
                cmd_str = cmd_str[:77] + "..."
            display_str = f"{proc['name']} (PID: {proc['pid']}) [Cmd: {cmd_str}]"
            
            if i == 0:
                print(f"  {display_str}")
            else:
                indent = "      " * (i - 1)
                print(f"  {indent}└── {display_str}")
        
        print("!" * 60)
        sys.stdout.flush()

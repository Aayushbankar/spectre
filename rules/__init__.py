import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class BehavioralRule:
    id: str
    name: str
    score: int
    description: str
    
    # Process ancestry matching criteria
    parent_names: Optional[List[str]] = None
    child_names: Optional[List[str]] = None
    ancestor_names: Optional[List[str]] = None
    descendant_names: Optional[List[str]] = None
    
    # Process resource matching criteria (V4)
    process_names: Optional[List[str]] = None
    file_paths: Optional[List[str]] = None
    file_events: Optional[List[str]] = None    # e.g., ["READ", "WRITE"]
    socket_events: Optional[List[str]] = None  # e.g., ["CONNECT", "LISTEN"]

    @classmethod
    def from_dict(cls, data: Dict) -> "BehavioralRule":
        return cls(
            id=data["id"],
            name=data["name"],
            score=data["score"],
            description=data["description"],
            parent_names=data.get("parent_names"),
            child_names=data.get("child_names"),
            ancestor_names=data.get("ancestor_names"),
            descendant_names=data.get("descendant_names"),
            process_names=data.get("process_names"),
            file_paths=data.get("file_paths"),
            file_events=data.get("file_events"),
            socket_events=data.get("socket_events")
        )

# Default hardcoded fallback rules
DEFAULT_RULES: List[BehavioralRule] = [
    BehavioralRule(
        id="web_server_shell",
        name="Web Server Spawning Shell",
        score=20,
        description="A web server process spawned an interactive shell. This is a common pattern for web shells and remote code execution.",
        parent_names=["nginx", "apache2", "httpd", "lighttpd", "node", "tomcat"],
        child_names=["bash", "sh", "dash", "zsh", "ash"]
    ),
    BehavioralRule(
        id="shell_network_tool",
        name="Shell Spawning Network Tool",
        score=15,
        description="A shell process spawned a network utility, which could indicate scanning, reconnaissance, or port forwarding.",
        parent_names=["bash", "sh", "dash", "zsh", "ash"],
        child_names=["nc", "netcat", "ncat", "nmap", "socat", "hydra"]
    ),
    BehavioralRule(
        id="shell_downloader",
        name="Shell Spawning Downloader",
        score=10,
        description="A shell process spawned a web transfer utility, potentially attempting to download a secondary payload.",
        parent_names=["bash", "sh", "dash", "zsh", "ash"],
        child_names=["curl", "wget", "tftp", "ftp"]
    ),
    BehavioralRule(
        id="web_server_compiler",
        name="Web Server Spawning Compiler or Interpreter",
        score=18,
        description="A web server process spawned a compiler, build tool, or scripting interpreter. This is highly suspicious and common in exploit delivery.",
        parent_names=["nginx", "apache2", "httpd", "lighttpd", "node", "tomcat"],
        child_names=["gcc", "g++", "make", "python", "python3", "perl", "ruby", "php"]
    )
]

def load_rules_from_file(filepath: str) -> List[BehavioralRule]:
    """
    Loads custom behavioral rules from a JSON file.
    Falls back to DEFAULT_RULES if file does not exist or fails to parse.
    """
    if not os.path.exists(filepath):
        print(f"[!] Rule file {filepath} not found. Using default preset rules.")
        return DEFAULT_RULES
        
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                print(f"[!] Invalid rule file format (must be a list). Using default rules.")
                return DEFAULT_RULES
            
            rules = []
            for item in data:
                try:
                    rules.append(BehavioralRule.from_dict(item))
                except KeyError as e:
                    print(f"[!] Missing required key {e} in rule {item.get('id', 'unknown')}. Skipping rule.")
            return rules
    except Exception as e:
        print(f"[!] Failed to parse rule file {filepath}: {e}. Using default rules.")
        return DEFAULT_RULES

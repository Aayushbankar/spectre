from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class BehavioralRule:
    id: str
    name: str
    score: int
    description: str
    parent_names: Optional[List[str]] = None
    child_names: Optional[List[str]] = None
    ancestor_names: Optional[List[str]] = None
    descendant_names: Optional[List[str]] = None

# Default pre-defined rules for Spectre V1
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

import time
import psutil
from typing import Dict, List, Tuple, Generator, Optional, Set

class ProcessSensor:
    """
    Sensor component that monitors host processes on Linux using psutil,
    detecting new spawns and resource access (Files and Sockets),
    yielding their updated ancestry tree.
    """
    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self.known_processes: Dict[int, float] = {}
        # Maps (pid, create_time) -> {"files": list of dicts, "connections": list of dicts}
        self.process_resources: Dict[Tuple[int, float], Dict] = {}
        # Active processes we are monitoring files and sockets for
        self.monitored_processes: Set[Tuple[int, float]] = set()
        self._initialize_snapshot()

    def _is_ignored_process(self, proc: psutil.Process) -> bool:
        """
        Ignores IDE and agent processes to avoid tracking internal IPC/logs.
        """
        try:
            name = proc.name().lower()
            cmdline_str = " ".join(proc.cmdline()).lower()
            if "antigravity" in name or "antigravity" in cmdline_str:
                return True
            if "language_server" in name or "language_server" in cmdline_str:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _is_ignored_file(self, path: str) -> bool:
        """
        Filters out shared libraries, pyc files, caches, localization
        files, and IDE configuration files to prevent console spam.
        """
        if not path:
            return True
        path_lower = path.lower()
        if "antigravity" in path_lower or "language_server" in path_lower:
            return True
        if path.endswith(".so") or ".so." in path or path.endswith(".pyc") or "__pycache__" in path:
            return True
        
        ignored_prefixes = [
            "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
            "/usr/share/locale/", "/usr/share/zoneinfo/",
            "/var/cache/", "/etc/ld.so.cache"
        ]
        for prefix in ignored_prefixes:
            if path.startswith(prefix):
                return True
        return False

    def _get_process_files(self, proc: psutil.Process) -> List[Dict]:
        """
        Retrieves files opened by the process, classifying them as READ or WRITE.
        """
        files = []
        try:
            for f in proc.open_files():
                if self._is_ignored_file(f.path):
                    continue
                # Determine read or write event based on file mode flags
                event = "READ"
                if "w" in f.mode or "a" in f.mode or "+" in f.mode:
                    event = "WRITE"
                
                files.append({
                    "path": f.path,
                    "event": event
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return files

    def _get_process_connections(self, proc: psutil.Process) -> List[Dict]:
        """
        Retrieves active connections or local listeners established by the process.
        """
        connections = []
        try:
            for conn in proc.net_connections():
                if conn.raddr:
                    # Ignore localhost connections for active outbound connections
                    if conn.raddr.ip in ("127.0.0.1", "::1", "localhost"):
                        continue
                    raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                    connections.append({
                        "raddr": raddr_str,
                        "status": conn.status,
                        "event": "CONNECT"
                    })
                elif conn.status == "LISTEN" and conn.laddr:
                    laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
                    connections.append({
                        "raddr": laddr_str,
                        "status": conn.status,
                        "event": "LISTEN"
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections

    def _safe_get_process_info(self, proc: psutil.Process) -> Optional[Dict]:
        """
        Safely retrieves key information from a Process instance.
        """
        try:
            with proc.oneshot():
                pid = proc.pid
                ctime = proc.create_time()
                key = (pid, ctime)
                
                res = self.process_resources.get(key, {"files": [], "connections": []})
                
                return {
                    "pid": pid,
                    "name": proc.name(),
                    "create_time": ctime,
                    "cmdline": proc.cmdline(),
                    "files": res["files"],
                    "connections": res["connections"]
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _initialize_snapshot(self):
        """
        Populates the initial known process dictionary to avoid flagging existing processes.
        """
        for proc in psutil.process_iter():
            info = self._safe_get_process_info(proc)
            if info:
                self.known_processes[info["pid"]] = info["create_time"]

    def _trace_ancestry(self, pid: int) -> List[Dict]:
        """
        Traces the ancestry of a process starting from a PID up to the root.
        """
        chain = []
        current_pid = pid
        visited_pids = set()

        while current_pid and current_pid not in visited_pids:
            visited_pids.add(current_pid)
            try:
                proc = psutil.Process(current_pid)
                info = self._safe_get_process_info(proc)
                if not info:
                    break
                
                chain.append(info)
                parent = proc.parent()
                if parent:
                    current_pid = parent.pid
                else:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        chain.reverse()
        return chain

    def start_monitoring(self) -> Generator[List[Dict], None, None]:
        """
        Runs the monitoring loop, yielding the ancestor chain for each new process
        or when a monitored process accesses a new resource (file or socket).
        """
        while True:
            time.sleep(self.interval)
            
            current_processes: Dict[int, float] = {}
            new_processes_detected: List[Tuple[int, float]] = []

            # 1. Capture current running processes
            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    ctime = proc.create_time()
                    current_processes[pid] = ctime
                    
                    if pid not in self.known_processes or self.known_processes[pid] != ctime:
                        new_processes_detected.append((pid, ctime))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # 2. Process spawns
            for pid, ctime in new_processes_detected:
                self.known_processes[pid] = ctime
                try:
                    proc = psutil.Process(pid)
                    if self._is_ignored_process(proc):
                        continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                chain = self._trace_ancestry(pid)
                if chain:
                    # Monitor resources ONLY for the newly spawned process
                    self.monitored_processes.add((pid, ctime))
                    yield chain

            # 3. Update resources for all monitored processes
            updated_processes = []
            dead_monitored = []
            
            for key in list(self.monitored_processes):
                pid, ctime = key
                try:
                    # Check if process is still running and is the same execution
                    if pid in current_processes and current_processes[pid] == ctime:
                        proc = psutil.Process(pid)
                        
                        current_files = self._get_process_files(proc)
                        current_conns = self._get_process_connections(proc)
                        
                        if key not in self.process_resources:
                            self.process_resources[key] = {"files": [], "connections": []}
                            
                        entry = self.process_resources[key]
                        existing_files = {(f["path"], f["event"]) for f in entry["files"]}
                        existing_conns = {(c["raddr"], c["event"]) for c in entry["connections"]}
                        
                        updated = False
                        for f in current_files:
                            if (f["path"], f["event"]) not in existing_files:
                                entry["files"].append(f)
                                updated = True
                                
                        for c in current_conns:
                            if (c["raddr"], c["event"]) not in existing_conns:
                                entry["connections"].append(c)
                                updated = True
                                
                        if updated:
                            updated_processes.append(key)
                    else:
                        dead_monitored.append(key)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    dead_monitored.append(key)
            
            # Clean up dead monitored processes from active polling set
            for key in dead_monitored:
                self.monitored_processes.discard(key)
                
            # Yield updated chains for processes that had resource updates
            for pid, ctime in updated_processes:
                chain = self._trace_ancestry(pid)
                if chain:
                    yield chain

            # 4. Clean up exited known processes
            exited_pids = [pid for pid in self.known_processes if pid not in current_processes]
            for pid in exited_pids:
                del self.known_processes[pid]

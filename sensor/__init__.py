import time
import psutil
from typing import Dict, List, Tuple, Generator, Optional

class ProcessSensor:
    """
    Sensor component that monitors host processes on Linux using psutil,
    detecting new spawns and yielding their ancestry tree.
    """
    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self.known_processes: Dict[int, float] = {}
        self._initialize_snapshot()

    def _safe_get_process_info(self, proc: psutil.Process) -> Optional[Dict]:
        """
        Safely retrieves key information from a Process instance.
        """
        try:
            with proc.oneshot():
                return {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "create_time": proc.create_time(),
                    "cmdline": proc.cmdline(),
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
        Runs the monitoring loop, yielding the ancestor chain for each new process.
        """
        while True:
            time.sleep(self.interval)
            
            current_processes: Dict[int, float] = {}
            new_processes_detected: List[Tuple[int, float]] = []

            # Capture current running processes
            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    ctime = proc.create_time()
                    current_processes[pid] = ctime
                    
                    if pid not in self.known_processes or self.known_processes[pid] != ctime:
                        new_processes_detected.append((pid, ctime))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Process and yield spawns
            for pid, ctime in new_processes_detected:
                self.known_processes[pid] = ctime
                chain = self._trace_ancestry(pid)
                if chain:
                    yield chain

            # Clean up exited processes
            exited_pids = [pid for pid in self.known_processes if pid not in current_processes]
            for pid in exited_pids:
                del self.known_processes[pid]

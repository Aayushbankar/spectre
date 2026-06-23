#!/usr/bin/env python3
import time
import sys
import argparse
import psutil
from typing import Dict, List, Tuple, Optional

# Track known processes as a dictionary mapping PID to its creation time.
# This prevents issues with recycled PIDs.
known_processes: Dict[int, float] = {}

def safe_get_process_info(proc: psutil.Process) -> Optional[Dict]:
    """
    Safely retrieves key information from a psutil.Process instance.
    Handles ephemeral processes that might terminate during inspection.
    """
    try:
        # We fetch details in a single block to reduce the chance of NoSuchProcess mid-execution
        with proc.oneshot():
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "create_time": proc.create_time(),
                "cmdline": proc.cmdline(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def trace_ancestry(pid: int) -> List[Dict]:
    """
    Traces the ancestry of a process starting from the given PID up to the root.
    Returns a list of process info dictionaries from oldest ancestor to the target PID.
    """
    chain = []
    current_pid = pid
    visited_pids = set()  # Prevent infinite loops in case of corrupt OS tables

    while current_pid and current_pid not in visited_pids:
        visited_pids.add(current_pid)
        try:
            proc = psutil.Process(current_pid)
            info = safe_get_process_info(proc)
            if not info:
                break
            
            chain.append(info)
            
            # Move to the parent process
            parent = proc.parent()
            if parent:
                current_pid = parent.pid
            else:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break

    # Reverse the chain so it goes from oldest ancestor to the newest child
    chain.reverse()
    return chain

def print_process_tree(chain: List[Dict]) -> None:
    """
    Prints a list of processes formatted as an execution chain tree.
    """
    if not chain:
        return
    
    print("\n[SPAWN DETECTED]")
    for i, proc in enumerate(chain):
        # Format command line for additional context if present
        cmd_str = " ".join(proc['cmdline']) if proc['cmdline'] else proc['name']
        # Limit command line length for readability
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
    parser = argparse.ArgumentParser(description="Spectre V0: Incremental HIDS Process Monitor PoC")
    parser.add_argument(
        "--interval", 
        type=float, 
        default=0.5, 
        help="Polling interval in seconds (default: 0.5)"
    )
    args = parser.parse_args()

    print(f"[*] Starting Spectre V0 Process Monitor...")
    print(f"[*] Polling interval: {args.interval}s")
    print(f"[*] Base system OS: Linux")
    print(f"[*] Populating initial process table snapshot...")

    # Populate the initial process table
    initial_count = 0
    for proc in psutil.process_iter():
        info = safe_get_process_info(proc)
        if info:
            known_processes[info["pid"]] = info["create_time"]
            initial_count += 1

    print(f"[*] Monitored processes in snapshot: {initial_count}")
    print(f"[*] Active monitoring enabled. Press Ctrl+C to stop.\n" + "-"*50)
    sys.stdout.flush()

    try:
        while True:
            time.sleep(args.interval)
            
            # Take a snapshot of currently running processes
            current_processes: Dict[int, float] = {}
            new_processes_detected: List[Tuple[int, float]] = []

            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    # We get create_time directly to keep it fast
                    ctime = proc.create_time()
                    current_processes[pid] = ctime
                    
                    # Check if this process is new or recycled
                    if pid not in known_processes or known_processes[pid] != ctime:
                        new_processes_detected.append((pid, ctime))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Process new spawns
            for pid, ctime in new_processes_detected:
                # Add/update in our tracking dictionary
                known_processes[pid] = ctime
                
                # Trace and print the ancestor chain
                chain = trace_ancestry(pid)
                if chain:
                    print_process_tree(chain)

            # Prune exited processes from tracking
            # This ensures memory usage doesn't grow over time
            exited_pids = [pid for pid in known_processes if pid not in current_processes]
            for pid in exited_pids:
                del known_processes[pid]

    except KeyboardInterrupt:
        print("\n[*] Stopping Spectre V0 Process Monitor.")
        sys.exit(0)

if __name__ == "__main__":
    main()

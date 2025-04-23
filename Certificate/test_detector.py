import os
import time
import math
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict

WATCH_DIR = "testfolder"
SCORE_THRESHOLD = 8
MONITOR_WINDOW = 8
ENTROPY_LIMIT = 7.5
CHANGE_THRESHOLD = 6
LOG_FILE = "detector_log.txt"

# For logging
process_scores = defaultdict(int)
file_entropy = {}
file_change_count = defaultdict(list)

def log_to_file(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def calculate_entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0
    for count in freq:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def read_entropy(filepath):
    try:
        with open(filepath, "rb") as f:
            return calculate_entropy(f.read())
    except:
        return 0

def get_python_process():
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'python' in p.name().lower() or 'python' in ' '.join(p.cmdline()).lower():
                return p
        except:
            continue
    return None

def log_process_tree(proc):
    try:
        print(f"[TREE] Process Tree for PID {proc.pid}:")
        current = proc
        level = 0
        while current:
            print(f"{'    '*level}- PID: {current.pid}, Name: {current.name()}, Executable: {current.exe()}")
            current = current.parent()
            level += 1
    except Exception as e:
        print(f"[TREE ERROR] {e}")

def handle_flag(pid, reason):
    try:
        proc = psutil.Process(pid)
        log_message = (
            f"\n[ALERT 🚨] Suspicious Process Detected:\n"
            f"Reason      : {reason}\n"
            f"Name        : {proc.name()}\n"
            f"PID         : {pid}\n"
            f"Executable  : {proc.exe()}\n"
        )
        print(log_message)
        log_to_file(log_message)

        # Log the process tree
        log_process_tree(proc)

        # Terminate all child processes of the suspicious process
        children = proc.children(recursive=True)
        if children:
            for child in children:
                try:
                    child.terminate()
                    child.wait(timeout=2)
                    log_to_file(f"[ACTION] Child process {child.pid} terminated gracefully.")
                except psutil.TimeoutExpired:
                    child.kill()
                    log_to_file(f"[ACTION] Child process {child.pid} forcefully killed.")
        else:
            log_to_file(f"[INFO] No child processes found for PID {pid}.")

        # Terminate the suspicious process
        proc.terminate()
        proc.wait(timeout=2)
        log_to_file(f"[ACTION] Suspicious process {pid} terminated gracefully.")
    except psutil.TimeoutExpired:
        proc.kill()
        log_to_file(f"[ACTION] Suspicious process {pid} forcefully killed.")
    except psutil.AccessDenied:
        log_to_file(f"[ERROR] Access Denied: Could not terminate PID {pid}. Run this script as Administrator.")
    except Exception as e:
        log_to_file(f"[ERROR] Termination failed for PID {pid}: {e}")

def log_open_files(proc):
    try:
        open_files = proc.open_files()
        if open_files:
            print(f"[INFO] Open files for PID {proc.pid}:")
            for file in open_files:
                print(f"  - {file.path}")
        else:
            print(f"[INFO] No open files found for PID {proc.pid}.")
    except psutil.AccessDenied:
        print(f"[ERROR] Access denied while retrieving open files for PID {proc.pid}.")
    except Exception as e:
        print(f"[ERROR] Failed to retrieve open files for PID {proc.pid}: {e}")

def log_loaded_modules(proc):
    try:
        modules = proc.memory_maps()
        if modules:
            print(f"[INFO] Loaded modules for PID {proc.pid}:")
            for module in modules:
                print(f"  - {module.path}")
        else:
            print(f"[INFO] No loaded modules found for PID {proc.pid}.")
    except psutil.AccessDenied:
        print(f"[ERROR] Access denied while retrieving loaded modules for PID {proc.pid}.")
    except Exception as e:
        print(f"[ERROR] Failed to retrieve loaded modules for PID {proc.pid}: {e}")

class RansomDetector(FileSystemEventHandler):
    def log_event(self, event_type, path):
        proc = get_python_process()
        pid = proc.pid if proc else "Unknown"
        exe = proc.exe() if proc else "Unknown"
        log_message = f"[LOG] Event: {event_type} | Path: {path} | PID: {pid} | Executable: {exe}"
        print(log_message)
        log_to_file(log_message)

        if proc:
            try:
                # Log child processes
                children = proc.children(recursive=True)
                if children:
                    print(f"[INFO] Child Processes of PID {pid}:")
                    for child in children:
                        print(f"  - PID: {child.pid}, Executable: {child.exe()}")
                else:
                    print(f"[INFO] No child processes found for PID {pid}.")

                # # Log open files
                # log_open_files(proc)

                # # Log loaded modules
                # log_loaded_modules(proc)
            except psutil.AccessDenied:
                print(f"[ERROR] Access denied while retrieving information for PID {pid}.")
            except Exception as e:
                print(f"[ERROR] Failed to retrieve information for PID {pid}: {e}")

    def on_modified(self, event):
        if event.is_directory:
            return
        self.log_event("Modified", event.src_path)

        path = Path(event.src_path)
        if not path.exists():
            return

        entropy = read_entropy(path)
        path_str = str(path)
        old_entropy = file_entropy.get(path_str, 0)

        # Entropy delta
        entropy_delta = entropy - old_entropy
        file_entropy[path_str] = entropy  # update regardless

        # Log every change
        print(f"[MONITOR] {path.name} | entropy: {entropy:.2f} | delta: {entropy_delta:.2f}")

        # Track how many times this file is written
        now = time.time()
        file_change_count[path_str].append(now)

        # Only keep recent
        file_change_count[path_str] = [t for t in file_change_count[path_str] if now - t < MONITOR_WINDOW]
        if len(file_change_count[path_str]) >= 2:
            print(f"[INFO] Rapid write activity on {path.name}")

        # Attempt to find python process and attribute suspicion
        proc = get_python_process()
        if not proc:
            return

        score = 0
        if entropy > ENTROPY_LIMIT:
            score += 4
        if entropy_delta > 1:
            score += 2
        if len(file_change_count[path_str]) > 2:
            score += 3
        if path.suffix in {'.locked', '.fun', '.enc'}:
            score += 2

        process_scores[proc.pid] += score
        print(f"[DEBUG] PID {proc.pid} score: {process_scores[proc.pid]}")

        if process_scores[proc.pid] >= SCORE_THRESHOLD:
            handle_flag(proc.pid, "Score threshold exceeded")

    def on_created(self, event):
        if event.is_directory:
            return
        self.log_event("Created", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.log_event("Deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self.log_event("Renamed", f"{event.src_path} -> {event.dest_path}")

def run():
    observer = Observer()
    handler = RansomDetector()
    observer.schedule(handler, WATCH_DIR, recursive=True)
    observer.start()
    print(f"[INFO] Monitoring started on: {WATCH_DIR}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    run()

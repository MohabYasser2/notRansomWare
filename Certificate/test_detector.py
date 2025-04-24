import os
import time
import math
import psutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import ctypes  # For checking admin privileges

WATCH_DIR = "testfolder"
SCORE_THRESHOLD = 8
MONITOR_WINDOW = 4
ENTROPY_LIMIT = 7.5
CHANGE_THRESHOLD = 6
LOG_FILE = "detector_log.txt"

# For logging
process_scores = defaultdict(int)
file_entropy = {}
file_change_count = defaultdict(list)

def log_to_file(message):
    """
    Log messages to the log file using UTF-8 encoding to support all Unicode characters.
    """
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
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

def find_suspicious_process(filepath):
    """
    Identify the process responsible for accessing the given file.
    """
    current_pid = os.getpid()
    suspicious = None
    try:
        for proc in psutil.process_iter(['pid', 'open_files', 'name', 'ppid']):
            if proc.pid == current_pid:
                continue
            try:
                open_files = proc.open_files()
                for f in open_files:
                    if f.path == filepath:
                        suspicious = proc
                        return suspicious
                # Check child processes for indirect writes
                for child in proc.children(recursive=True):
                    try:
                        open_files = child.open_files()
                        for f in open_files:
                            if f.path == filepath:
                                return child
                    except:
                        continue
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception as e:
        log_to_file(f"[ERROR] Suspicious process scan failed: {e}")
    return suspicious

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
    """
    Terminate the main process and all its children.
    """
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
                except psutil.NoSuchProcess:
                    log_to_file(f"[INFO] Child process {child.pid} no longer exists.")
        else:
            log_to_file(f"[INFO] No child processes found for PID {pid}.")

        # Terminate the suspicious process
        try:
            proc.terminate()
            proc.wait(timeout=2)
            log_to_file(f"[ACTION] Suspicious process {pid} terminated gracefully.")
        except psutil.TimeoutExpired:
            proc.kill()
            log_to_file(f"[ACTION] Suspicious process {pid} forcefully killed.")
        except psutil.NoSuchProcess:
            log_to_file(f"[INFO] Suspicious process {pid} no longer exists.")
    except psutil.AccessDenied:
        log_to_file(f"[ERROR] Access Denied: Could not terminate PID {pid}. Run this script as Administrator.")
    except psutil.NoSuchProcess:
        log_to_file(f"[INFO] Process {pid} no longer exists.")
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

def is_admin():
    """
    Check if the script is running with administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin_permissions():
    """
    Attempt to restart the script with administrator privileges.
    """
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    except Exception as e:
        log_to_file(f"[ERROR] Failed to request admin permissions: {e}")

class DetectorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Detector")
        self.monitoring = False
        self.observer = None

        # Create UI components
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.log_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.permissions_button = tk.Button(root, text="Grant Permissions", command=self.grant_permissions)
        self.permissions_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.close_button = tk.Button(root, text="Close", command=self.close_app)
        self.close_button.pack(side=tk.RIGHT, padx=10, pady=10)

    def log_message(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log_message("[INFO] Monitoring started.")
            self.observer = Observer()
            handler = RansomDetector(ui=self)
            self.observer.schedule(handler, WATCH_DIR, recursive=True)
            Thread(target=self.observer.start, daemon=True).start()

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            if self.observer:
                self.observer.stop()
                self.observer.join()
            self.log_message("[INFO] Monitoring stopped.")

    def grant_permissions(self):
        if is_admin():
            self.log_message("[INFO] Script is already running with administrator privileges.")
        else:
            self.log_message("[INFO] Attempting to grant administrator permissions...")
            request_admin_permissions()

    def close_app(self):
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()

class RansomDetector(FileSystemEventHandler):
    def __init__(self, ui=None):
        self.ui = ui

    def log_event(self, event_type, path):
        proc = find_suspicious_process(path)
        if proc:
            pid = proc.pid
            exe = proc.exe()
        else:
            pid = "Unknown"
            exe = "Unknown"
            log_to_file("[ERROR] Failed to detect Python process. Ensure the script has sufficient permissions.")

        log_message = f"[LOG] Event: {event_type} | Path: {path} | PID: {pid} | Executable: {exe}"
        print(log_message)
        log_to_file(log_message)

        if self.ui:
            self.ui.log_message(log_message)

        if proc:
            try:
                children = proc.children(recursive=True)
                if children:
                    print(f"[INFO] Child Processes of PID {pid}:")
                    for child in children:
                        print(f"  - PID: {child.pid}, Executable: {child.exe()}")
                else:
                    print(f"[INFO] No child processes found for PID {pid}.")
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

        entropy_delta = entropy - old_entropy
        file_entropy[path_str] = entropy

        print(f"[MONITOR] {path.name} | entropy: {entropy:.2f} | delta: {entropy_delta:.2f}")

        now = time.time()
        file_change_count[path_str].append(now)

        file_change_count[path_str] = [t for t in file_change_count[path_str] if now - t < MONITOR_WINDOW]
        if len(file_change_count[path_str]) >= 2:
            print(f"[INFO] Rapid write activity on {path.name}")

        proc = find_suspicious_process(path_str)
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
    root = tk.Tk()
    app = DetectorUI(root)
    root.mainloop()

if __name__ == "__main__":
    run()

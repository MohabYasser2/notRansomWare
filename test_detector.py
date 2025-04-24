from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import os.path
import threading
import time
import psutil
import math
from pathlib import Path
from collections import defaultdict
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from threading import Thread
import win32file
import win32con

# Update WATCH_DIR to ensure it matches the directory used by encryption scripts
WATCH_DIR = "path_to_encryption_scripts_directory"  # Replace with the actual directory path
SCORE_THRESHOLD = 15
LOG_FILE = "detector_log.txt"

# Feature weights
WEIGHTS = {
    "rapid_modification": 5,
    "mass_deletion": 4,
    "mass_writes": 4,
    "high_cpu": 3,
    "encrypted_files": 6,
    "weird_extensions": 3,
    "critical_access": 7,
    "api_hooks": 8,  # Placeholder for future implementation
    "memory_analysis": 8,  # Placeholder for future implementation
    "network_traffic": 5,  # Placeholder for future implementation
}

# Extensions considered suspicious
SUSPICIOUS_EXTENSIONS = {".fun", ".dog", ".wcry", ".encrypted"}

# For tracking process scores and file activities
process_scores = defaultdict(int)
file_activity = defaultdict(list)

# Cache for open files
open_files_cache = {}
event_queue = Queue()
executor = ThreadPoolExecutor(max_workers=5)

def log_to_file(message):
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

def read_entropy(filepath, max_bytes=1048576):
    try:
        with open(filepath, "rb") as f:
            return calculate_entropy(f.read(max_bytes))
    except:
        return 0

# Dictionary to track historical file access
historical_file_access = defaultdict(set)
last_access_time = defaultdict(float)

def update_open_files_cache():
    while True:
        new_cache = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                file_paths = [f.path for f in proc.open_files()]
                normalized_files = [os.path.abspath(os.path.normcase(f)) for f in file_paths]
                new_cache[proc.pid] = normalized_files
                
                # Update historical access records
                for f in normalized_files:
                    historical_file_access[f].add(proc.pid)
                    last_access_time[f] = time.time()
            except Exception:
                continue
        
        # Clean up historical records older than 30 seconds
        current_time = time.time()
        expired_files = [f for f, t in last_access_time.items() if current_time - t > 30]
        for f in expired_files:
            if f in historical_file_access:
                del historical_file_access[f]
                del last_access_time[f]
        
        global open_files_cache
        open_files_cache = new_cache
        time.sleep(0.2)   # Faster refresh for better detection

def find_suspicious_process(filepath):
    # Normalize the incoming filepath
    normalized_fp = os.path.abspath(os.path.normcase(filepath))
    
    # Method 1: Check current open files cache
    for pid, files in open_files_cache.items():
        if normalized_fp in files:
            try:
                return psutil.Process(pid)
            except psutil.NoSuchProcess:
                continue
    
    # Method 2: Check historical file access
    if normalized_fp in historical_file_access and historical_file_access[normalized_fp]:
        recent_pids = list(historical_file_access[normalized_fp])
        for pid in sorted(recent_pids, reverse=True):  # Try most recent first
            try:
                proc = psutil.Process(pid)
                log_to_file(f"[INFO] Found process from historical access: PID={pid}, Name={proc.name()}")
                return proc
            except psutil.NoSuchProcess:
                continue
    
    # Method 3: Check for partial path matches (handle path variants)
    filename = os.path.basename(normalized_fp)
    for pid, files in open_files_cache.items():
        for file_path in files:
            if filename in file_path:
                try:
                    proc = psutil.Process(pid)
                    log_to_file(f"[INFO] Found process by partial path match: PID={pid}, Name={proc.name()}")
                    return proc
                except psutil.NoSuchProcess:
                    continue
    
    log_to_file(f"[DEBUG] File not in open_files_cache: {filepath}")

    # fallback: pick process started within last 5 seconds
    now = time.time()
    candidates = []
    for proc in psutil.process_iter(['pid','name','create_time']):
        try:
            if now - proc.create_time() <= 5:
                candidates.append(proc)
        except Exception:
            continue

    if candidates:
        # choose the newest process
        chosen = max(candidates, key=lambda p: p.create_time())
        delay = now - chosen.create_time()
        log_to_file(f"[DEBUG] Fallback by create_time: PID={chosen.pid}, EXE={chosen.name()}, started {delay:.2f}s ago")
        return chosen

    return None

# Async entropy calculation
def async_entropy_check(filepath, callback):
    def task():
        entropy = read_entropy(filepath, max_bytes=8192)  # Read only first 8 KB
        callback(filepath, entropy)
    executor.submit(task)

# Process events from the queue
def event_processor():
    while True:
        try:
            event = event_queue.get()
            process_event(*event)
        except Exception as e:
            log_to_file(f"[ERROR] Event processing error: {e}")

# Function to get all child processes of a given process
def get_child_processes(parent_pid):
    try:
        parent = psutil.Process(parent_pid)
        children = parent.children(recursive=True)
        return children
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []

def log_process_tree(parent_pid):
    """Log the process tree starting from parent_pid"""
    try:
        parent = psutil.Process(parent_pid)
        log_to_file(f"[PROCESS] Parent: PID={parent_pid}, Name={parent.name()}, Exe={parent.exe()}")
        
        children = get_child_processes(parent_pid)
        if children:
            log_to_file(f"[PROCESS] Found {len(children)} child processes for PID {parent_pid}")
            for child in children:
                try:
                    log_to_file(f"[PROCESS] Child: PID={child.pid}, Name={child.name()}, Exe={child.exe()}, Parent={parent_pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    log_to_file(f"[ERROR] Failed to log child process {child.pid}: {e}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log_to_file(f"[ERROR] Failed to log process tree for PID {parent_pid}: {e}")

def handle_flag(proc, reason):
    try:
        print(f"[ALERT] PID: {proc.pid}, EXE: {proc.exe()} flagged as malicious. Reason: {reason}")
        log_to_file(f"[ALERT] PID: {proc.pid}, EXE: {proc.exe()} flagged as malicious. Reason: {reason}")
        
        # Log the process tree before termination
        log_process_tree(proc.pid)
        
        # Terminate children first (in reverse order of creation to properly handle process hierarchies)
        children = get_child_processes(proc.pid)
        if children:
            log_to_file(f"[ACTION] Terminating {len(children)} child processes of PID {proc.pid}")
            for child in reversed(children):
                try:
                    child_name = child.name()
                    child_pid = child.pid
                    child.terminate()
                    log_to_file(f"[ACTION] Child process {child_pid} ({child_name}) terminated.")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    log_to_file(f"[ERROR] Failed to terminate child process {child.pid}: {e}")
        
        # Terminate the parent process
        proc.terminate()
        proc.wait(timeout=2)
        print(f"[ACTION] Process {proc.pid} terminated.")
        log_to_file(f"[ACTION] Process {proc.pid} terminated.")
    except Exception as e:
        print(f"[ERROR] Failed to terminate process {proc.pid}: {e}")
        log_to_file(f"[ERROR] Failed to terminate process {proc.pid}: {e}")

def monitor_cpu_usage():
    for proc in psutil.process_iter(['pid', 'cpu_percent', 'name']):
        try:
            cpu_usage = proc.cpu_percent(interval=0.5)  # Reduced interval for faster checks
            if cpu_usage > 80:  # High CPU usage threshold
                if process_scores[proc.pid] % WEIGHTS["high_cpu"] != 0:  # Avoid redundant logging
                    process_scores[proc.pid] += WEIGHTS["high_cpu"]
                    log_to_file(f"[INFO] High CPU usage detected: PID={proc.pid}, EXE={proc.exe()}, CPU={cpu_usage}%, Score={process_scores[proc.pid]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def monitor_directory():
    global WATCH_DIR
    ACTIONS = {
        1: "Created",
        2: "Deleted",
        3: "Updated",
        4: "Renamed from",
        5: "Renamed to"
    }

    FILE_LIST_DIRECTORY = 0x0001
    h_directory = win32file.CreateFile(
        WATCH_DIR,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                8192,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            for action, file in results:
                full_path = os.path.join(WATCH_DIR, file)
                event_type = ACTIONS.get(action, "Unknown")
                event_queue.put((event_type, full_path))  # Add to queue
        except Exception as e:
            log_to_file(f"[ERROR] Directory monitoring error: {e}")

def process_event(event_type, filepath):
    proc = find_suspicious_process(filepath)
    if not proc:
        log_to_file(f"[WARNING] No process identified for event '{event_type}', File: {filepath}")
        return

    # Check and log any child processes
    children = get_child_processes(proc.pid)
    if children:
        process_scores[proc.pid] += len(children)  # Increase score based on number of children
        log_to_file(f"[INFO] Process {proc.pid} ({proc.name()}) has {len(children)} child processes - increasing score")
        # Log detailed information about each child process
        for child in children:
            try:
                log_to_file(f"[INFO] Child process: PID={child.pid}, Name={child.name()}, Exe={child.exe()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                log_to_file(f"[ERROR] Failed to access child process info: {e}")

    # Rapid file modification
    now = time.time()
    file_activity[filepath].append(now)
    file_activity[filepath] = [t for t in file_activity[filepath] if now - t < 5]  # 5-second window
    if len(file_activity[filepath]) > 5:  # Threshold for rapid modifications
        process_scores[proc.pid] += WEIGHTS["rapid_modification"]

    # Mass deletion
    if event_type == "Deleted":
        process_scores[proc.pid] += WEIGHTS["mass_deletion"]

    # Mass writes
    if event_type == "Created":
        process_scores[proc.pid] += WEIGHTS["mass_writes"]

    # Encrypted files (async entropy check)
    if event_type == "Created":
        async_entropy_check(filepath, lambda fp, ent: (
            process_scores.update({proc.pid: process_scores[proc.pid] + WEIGHTS["encrypted_files"]})
            if ent > 7.0 else None
        ))

    # Weird extensions
    if Path(filepath).suffix in SUSPICIOUS_EXTENSIONS:
        process_scores[proc.pid] += WEIGHTS["weird_extensions"]

    # Log and print process score
    log_to_file(f"[INFO] Event: {event_type}, File: {filepath}, PID: {proc.pid}, EXE: {proc.exe()}, Score: {process_scores[proc.pid]}")

    # Flag and terminate process if score exceeds threshold
    if process_scores[proc.pid] >= SCORE_THRESHOLD:
        handle_flag(proc, "Score threshold exceeded")

class BehaviorDetectorUI:
    def __init__(self, root):
        global WATCH_DIR
        self.root = root
        self.root.title("Behavior Detector")
        self.monitoring = False

        # UI Components
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.log_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.select_dir_button = tk.Button(root, text="Select Directory", command=self.select_directory)
        self.select_dir_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.view_logs_button = tk.Button(root, text="View Logs", command=self.view_logs)
        self.view_logs_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.clear_logs_button = tk.Button(root, text="Clear Logs", command=self.clear_logs)
        self.clear_logs_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.close_button = tk.Button(root, text="Close", command=self.close_app)
        self.close_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.log_message(f"[INFO] Watching directory: {WATCH_DIR}")

    def log_message(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def select_directory(self):
        global WATCH_DIR
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            WATCH_DIR = selected_dir
            self.log_message(f"[INFO] Watching directory changed to: {WATCH_DIR}")

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log_message("[INFO] Monitoring started.")
            Thread(target=monitor_directory, daemon=True).start()
            Thread(target=self.cpu_monitor_thread, daemon=True).start()

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("[INFO] Monitoring stopped.")

    def view_logs(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as log_file:
                logs = log_file.read()
            log_window = tk.Toplevel(self.root)
            log_window.title("Logs")
            log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=80, height=20)
            log_text.insert(tk.END, logs)
            log_text.pack(padx=10, pady=10)
            log_text.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Logs", "No logs available.")

    def clear_logs(self):
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            self.log_message("[INFO] Logs cleared.")
        else:
            self.log_message("[INFO] No logs to clear.")

    def close_app(self):
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()

    def cpu_monitor_thread(self):
        while self.monitoring:
            monitor_cpu_usage()
            time.sleep(1)

# Start background threads
def start_background_threads():
    threading.Thread(target=update_open_files_cache, daemon=True).start()
    threading.Thread(target=event_processor, daemon=True).start()

def run_ui():
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
    start_background_threads()
    root = tk.Tk()
    app = BehaviorDetectorUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_ui()

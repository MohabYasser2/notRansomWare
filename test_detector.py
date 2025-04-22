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

# For logging
process_scores = defaultdict(int)
file_entropy = {}
file_change_count = defaultdict(list)

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

def handle_flag(pid, reason):
    try:
        proc = psutil.Process(pid)
        print(f"\n[ALERT 🚨] Suspicious Process Detected:")
        print(f"Reason      : {reason}")
        print(f"Name        : {proc.name()}")
        print(f"PID         : {pid}")
        print(f"Executable  : {proc.exe()}")

        # Try soft terminate first
        proc.terminate()
        try:
            proc.wait(timeout=2)
            print("[ACTION] Process terminated gracefully.")
        except psutil.TimeoutExpired:
            print("[WARN] Graceful termination failed, force killing...")
            proc.kill()
            proc.wait()
            print("[ACTION] Process forcefully killed.")
    except psutil.AccessDenied:
        print(f"[ERROR] Access Denied: Could not terminate PID {pid}. Run this script as Administrator.")
    except Exception as e:
        print(f"[ERROR] Termination failed for PID {pid}: {e}")


class RansomDetector(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

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

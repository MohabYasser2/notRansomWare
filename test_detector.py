import os
import tkinter as tk
from tkinter import filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import threading
import getpass
import os.path

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, log_file):
        self.log_file = log_file
        # Store the absolute path of the log file to check against
        self.log_file_abs_path = os.path.abspath(log_file)

    def log_change(self, change_type, file_path, extra=""):
        # Skip logging if the modified file is the log file itself
        if os.path.abspath(file_path) == self.log_file_abs_path:
            return
            
        modifier = getpass.getuser()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} - {change_type:<10} - {file_path} - Modified by: {modifier} {extra}\n"
        with open(self.log_file, "a") as log:
            log.write(log_entry)
        print(log_entry.strip())  # Also print to console

    def on_modified(self, event):
        if not event.is_directory:
            self.log_change("Modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_change("Created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_change("Deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.log_change("Moved", event.dest_path, f"(from: {event.src_path})")

def start_monitoring(folder_path, status_label):
    # Create log file in a parent directory instead of the monitored directory
    parent_dir = os.path.dirname(folder_path)
    folder_name = os.path.basename(folder_path)
    log_file = os.path.join(parent_dir, f"{folder_name}_file_changes.log")
    
    event_handler = FileChangeHandler(log_file)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()
    status_label.config(text=f"Monitoring: {folder_path}", fg="green")
    print(f"✅ Monitoring started on: {folder_path}\nLogging to: {log_file}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        observer.stop()
        observer.join()
        status_label.config(text="Monitoring stopped", fg="red")

def select_folder(status_label):
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        threading.Thread(target=start_monitoring, args=(folder_selected, status_label), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Folder Monitor")
    root.geometry("350x150")

    tk.Label(root, text="File Activity Monitor", font=("Arial", 14)).pack(pady=10)
    status_label = tk.Label(root, text="Monitoring not started", fg="red", font=("Arial", 10))
    status_label.pack(pady=5)
    tk.Button(root, text="Select Folder to Monitor", command=lambda: select_folder(status_label)).pack(pady=10)
    tk.Button(root, text="Exit", command=root.quit).pack(pady=5)

    root.mainloop()

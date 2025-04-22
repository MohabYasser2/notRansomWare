import sys
import time
import logging
import os
import tkinter as tk
from tkinter import filedialog, scrolledtext
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging to write to both a file and the console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("file_system_monitor.log"),
        logging.StreamHandler()
    ]
)

def log_to_ui(log_widget, message):
    """Log a message to the UI log widget."""
    log_widget.config(state='normal')
    log_widget.insert(tk.END, message + '\n')
    log_widget.see(tk.END)  # Auto-scroll to the end
    log_widget.config(state='disabled')

# Update logging configuration to include a custom handler
class UILogHandler(logging.Handler):
    def __init__(self, log_widget):
        super().__init__()
        self.log_widget = log_widget

    def emit(self, record):
        log_entry = self.format(record)
        # Add a more user-friendly format for the log entry
        formatted_entry = f"[{record.levelname}] {record.asctime}: {record.getMessage()}"
        log_to_ui(self.log_widget, formatted_entry)

class FileSystemMonitorHandler(FileSystemEventHandler):
    """Custom event handler for monitoring file system events."""

    def __init__(self, log_file):
        super().__init__()
        self.log_file = log_file

    def on_created(self, event):
        if event.src_path == self.log_file:
            return
        logging.info(f"File created: {event.src_path}")

    def on_modified(self, event):
        if event.src_path == self.log_file:
            return
        logging.info(f"File modified: {event.src_path}")

    def on_deleted(self, event):
        if event.src_path == self.log_file:
            return
        logging.info(f"File deleted: {event.src_path}")

    def on_moved(self, event):
        if event.src_path == self.log_file or event.dest_path == self.log_file:
            return
        logging.info(f"File moved: from {event.src_path} to {event.dest_path}")

def start_monitoring(path, log_widget):
    """Start the file system monitoring in a separate thread."""
    log_file = "file_system_monitor.log"
    event_handler = FileSystemMonitorHandler(log_file)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    try:
        observer.start()
        log_to_ui(log_widget, f"Monitoring started on directory: {path}")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_to_ui(log_widget, "Monitoring stopped by user.")
    except Exception as e:
        log_to_ui(log_widget, f"An error occurred: {e}")
    finally:
        observer.stop()
        observer.join()

def select_directory(log_widget):
    """Open a dialog to select a directory and start monitoring."""
    path = filedialog.askdirectory(title="Select Directory to Monitor")
    if not path:
        log_to_ui(log_widget, "No directory selected.")
        return

    log_to_ui(log_widget, f"Selected directory: {path}")
    monitoring_thread = Thread(target=start_monitoring, args=(path, log_widget), daemon=True)
    monitoring_thread.start()

def create_ui():
    """Create a friendly UI for the file system monitor."""
    root = tk.Tk()
    root.title("File System Monitor")

    # Instructions label
    instructions = tk.Label(root, text="Step 1: Click 'Select Directory' to choose a folder to monitor.\nStep 2: View logs below.", justify=tk.LEFT)
    instructions.pack(pady=10)

    # Button to select directory
    select_button = tk.Button(root, text="Select Directory", command=lambda: select_directory(log_widget))
    select_button.pack(pady=5)

    # ScrolledText widget to display logs
    log_widget = scrolledtext.ScrolledText(root, width=80, height=20, state='normal')
    log_widget.pack(pady=10)
    log_widget.config(state='disabled')  # Make the log widget read-only

    # Attach UILogHandler to the logging system
    ui_log_handler = UILogHandler(log_widget)
    ui_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(ui_log_handler)

    # Start the Tkinter main loop
    root.mainloop()

if __name__ == "__main__":
    create_ui()
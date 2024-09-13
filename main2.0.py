import os
import time
import shutil
import psutil
import hashlib
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from tkinter import Tk, Label, Button, Text, END, messagebox

# Setup logging
logging.basicConfig(filename="ransomware_log.log", level=logging.INFO)

# Backup and Monitor Directory
BACKUP_DIR = 'backup/'
MONITOR_DIR = '/'
ENCRYPTION_KEY_FILE = 'encryption_key.key'


# Encryption Functions
def generate_encryption_key():
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key


def load_encryption_key():
    return open(ENCRYPTION_KEY_FILE, 'rb').read()


def encrypt_file(filepath, key):
    with open(filepath, 'rb') as file:
        data = file.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(filepath, 'wb') as file:
        file.write(encrypted)


# Backup Function
def backup_files():
    logging.info("Starting backup...")
    key = load_encryption_key()
    for foldername, subfolders, filenames in os.walk(MONITOR_DIR):
        for filename in filenames:
            file_path = os.path.join(foldername, filename)
            backup_path = os.path.join(BACKUP_DIR, filename)
            shutil.copy2(file_path, backup_path)
            encrypt_file(backup_path, key)
    logging.info("Backup completed successfully.")
    display_log("Backup completed successfully.")


# File Monitoring Class
class RansomwareMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = {}
        self.suspicious_files = []
        self.suspicious_modifications = []
        self.time_threshold = timedelta(minutes=1)  # Time window for 3 rapid modifications

    def calculate_hash(self, filepath):
        """Calculate MD5 hash for a given file."""
        md5_hash = hashlib.md5()
        try:
            with open(filepath, "rb") as file:
                for byte_block in iter(lambda: file.read(4096), b""):
                    md5_hash.update(byte_block)
            return md5_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash: {e}")
            return None

    def on_modified(self, event):
        if event.is_directory:
            return
        file_hash = self.calculate_hash(event.src_path)
        if file_hash:
            if event.src_path not in self.file_hashes:
                self.file_hashes[event.src_path] = file_hash
            else:
                if self.file_hashes[event.src_path] != file_hash:
                    logging.warning(f"Suspicious file modification detected: {event.src_path}")
                    self.suspicious_files.append(event.src_path)
                    self.suspicious_modifications.append(datetime.now())
                    self.take_action()

    def take_action(self):
        self.suspicious_modifications = [
            mod_time for mod_time in self.suspicious_modifications
            if datetime.now() - mod_time <= self.time_threshold
        ]
        if len(self.suspicious_modifications) >= 3:
            logging.error("Potential ransomware activity detected. Taking action.")
            backup_files()
            alert_user()
            isolate_system()


def alert_user():
    logging.error("ALERT: Suspicious activity detected. Check logs for details.")
    messagebox.showerror("Alert", "Suspicious activity detected. Check logs for details.")


def isolate_system():
    logging.error("Isolating system to prevent further damage...")
    # You can add logic to isolate the system here (e.g., disconnect from network or shutdown)
    # messagebox.showwarning("Isolating System", "System is being isolated from the network.")


# Vulnerability Check Functions
def check_system_vulnerabilities():
    display_log("Checking system vulnerabilities...")

    # Check open ports
    open_ports = [conn.laddr.port for conn in psutil.net_connections() if conn.status == 'LISTEN']
    if any(port in open_ports for port in [3389, 445, 135]):
        logging.warning(f"Open ports found: {open_ports}. These may be vulnerable.")
        display_log(f"Open ports found: {open_ports}")
    else:
        logging.info("No vulnerable ports detected.")
        display_log("No vulnerable ports detected.")

    # Check if antivirus is running
    if "antivirus" not in (p.name().lower() for p in psutil.process_iter()):
        logging.warning("No active antivirus detected. This is a vulnerability.")
        display_log("No active antivirus detected.")
    else:
        display_log("Antivirus detected and running.")

    logging.info("System vulnerability check completed.")


# GUI Functions
def display_log(message):
    output_box.insert(END, message + "\n")
    output_box.see(END)


def start_monitoring():
    global observer
    event_handler = RansomwareMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    display_log("Monitoring started.")


def stop_monitoring():
    global observer
    observer.stop()
    observer.join()
    display_log("Monitoring stopped.")


def scan_ports():
    display_log("Scanning for open ports...")
    open_ports = [conn.laddr.port for conn in psutil.net_connections() if conn.status == 'LISTEN']
    display_log(f"Open ports: {open_ports}")


# Main App GUI
def run_app():
    global output_box
    app = Tk()
    app.title("Anti-Ransomware Tool")
    app.geometry("600x400")

    Label(app, text="Anti-Ransomware Protection Tool", font=("Arial", 16)).pack(pady=10)

    Button(app, text="Start Vulnerability Check", command=check_system_vulnerabilities).pack(pady=5)
    Button(app, text="Start Monitoring", command=start_monitoring).pack(pady=5)
    Button(app, text="Stop Monitoring", command=stop_monitoring).pack(pady=5)
    Button(app, text="Scan Ports", command=scan_ports).pack(pady=5)

    output_box = Text(app, height=10, width=70)
    output_box.pack(pady=10)

    app.mainloop()


if __name__ == "__main__":
    if not os.path.exists(ENCRYPTION_KEY_FILE):
        generate_encryption_key()

    run_app()

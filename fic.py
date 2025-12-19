import hashlib
import os
import json
import time
import hmac
import sys
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# --- CONFIGURATION ---
BASELINE_FILE = "baseline.json"
# In a real app, store this in an Environment Variable (os.environ.get('SECRET_KEY'))
KEY_FILE = "key.key" 

# --- UTILITIES ---

def load_key():
    if not os.path.exists(KEY_FILE):
        print("Generating new encryption key...")
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

def calculate_file_hash(filepath):
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (OSError, IOError):
        return None

def send_alert(message, severity="INFO"):
    """
    Handles alerting. Currently prints to console.
    Uncomment the requests section to enable Webhooks (Discord/Slack).
    """
    # 1. Console Alert
    colors = {"INFO": "\033[94m", "WARNING": "\033[93m", "CRITICAL": "\033[91m", "END": "\033[0m"}
    print(f"{colors.get(severity, '')}[{severity}] {message}{colors['END']}")

# --- SECURITY & STORAGE ---

class BaselineManager:
    """Handles loading and saving the baseline with HMAC security."""
    
    def __init__(self, baseline_file, key):
        self.baseline_file = baseline_file
        self.key = key

    def _compute_signature(self, data_str):
        """Computes HMAC-SHA256 signature for the data."""
        return hmac.new(self.key, data_str.encode(), hashlib.sha256).hexdigest()

    def save_baseline(self, data):
        """Saves path:hash dictionary with a cryptographic signature."""
        json_dump = json.dumps(data, sort_keys=True)
        signature = self._compute_signature(json_dump)
        
        package = {
            "data": data,
            "signature": signature
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(package, f, indent=4)
        print(f"Baseline saved securely to {self.baseline_file}")

    def load_baseline(self):
        """Loads baseline and verifies integrity."""
        if not os.path.exists(self.baseline_file):
            return {}

        with open(self.baseline_file, 'r') as f:
            package = json.load(f)

        # Verify Signature
        data = package.get("data", {})
        stored_sig = package.get("signature", "")
        
        # Recompute signature to check for tampering
        json_dump = json.dumps(data, sort_keys=True)
        computed_sig = self._compute_signature(json_dump)

        if hmac.compare_digest(stored_sig, computed_sig):
            return data
        else:
            send_alert("BASELINE TAMPERED WITH! DO NOT TRUST THIS SYSTEM.", "CRITICAL")
            sys.exit(1)

# --- REAL-TIME MONITORING ---

class IntegrityHandler(FileSystemEventHandler):
    """Reacts to file system events in real-time."""
    
    def __init__(self, baseline_manager):
        self.baseline_manager = baseline_manager
        self.baseline = self.baseline_manager.load_baseline()

    def _process_event(self, filepath, event_type):
        # Ignore the baseline file itself
        if os.path.basename(filepath) == BASELINE_FILE:
            return

        filepath = os.path.abspath(filepath)

        if event_type == "deleted":
            if filepath in self.baseline:
                send_alert(f"File Deleted: {filepath}", "CRITICAL")
                # Optional: Update in-memory baseline or keep alerting
                del self.baseline[filepath]

        elif event_type in ["created", "modified"]:
            new_hash = calculate_file_hash(filepath)
            if not new_hash: return # File might be locked or temp

            if filepath not in self.baseline:
                send_alert(f"New File Detected: {filepath}", "WARNING")
                self.baseline[filepath] = new_hash
            elif self.baseline[filepath] != new_hash:
                send_alert(f"File Modified: {filepath}", "CRITICAL")
                self.baseline[filepath] = new_hash

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "created")

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "deleted")

# --- MAIN EXECUTION ---

def create_initial_baseline(directory, manager):
    baseline = {}
    print(f"Scanning {directory} (including hidden files)...")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.abspath(os.path.join(root, file))
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
            
            h = calculate_file_hash(filepath)
            if h:
                baseline[filepath] = h
    
    manager.save_baseline(baseline)

def start_monitoring(directory, manager):
    print(f"Starting Real-Time Monitor on: {directory}")
    print("Press Ctrl+C to stop.")
    
    event_handler = IntegrityHandler(manager)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python secure_monitor.py <init|monitor> <directory>")
        sys.exit(1)

    action = sys.argv[1]
    target_dir = os.path.abspath(sys.argv[2])
    
    # Initialize the Security Manager
    manager = BaselineManager(BASELINE_FILE, KEY_FILE)

    if action == "init":
        create_initial_baseline(target_dir, manager)
    elif action == "monitor":
        # Ensure baseline exists before monitoring
        if not os.path.exists(BASELINE_FILE):
            print("No baseline found. Running init first...")
            create_initial_baseline(target_dir, manager)
        start_monitoring(target_dir, manager)
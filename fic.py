import hashlib
import os
import json
import time
import hmac
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Configuration
BASELINE_FILE = "baseline.json"

def calculate_file_hash(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read the file in chunks to avoid using too much memory on large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (OSError, IOError) as e:
        print(f"Error reading {filepath}: {e}")
        return None

def create_baseline(directory):
    """Scans the directory and saves file hashes to a baseline file."""
    baseline = {}
    print(f"Creating baseline for: {directory}...")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            # Skip the baseline file itself if it's in the target directory
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
                
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                baseline[filepath] = file_hash

    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=4)
    
    print(f"Baseline created! Saved {len(baseline)} file records to {BASELINE_FILE}")

def check_integrity(directory):
    """Compares current file hashes against the saved baseline."""
    if not os.path.exists(BASELINE_FILE):
        print("Baseline file not found! Please run 'init' first.")
        return

    with open(BASELINE_FILE, 'r') as f:
        baseline = json.load(f)

    print(f"Checking integrity for: {directory}...\n")
    
    current_files = set()
    files_changed = False

    # 1. Check for modified and new files
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
            
            current_files.add(filepath)
            current_hash = calculate_file_hash(filepath)

            if filepath not in baseline:
                print(f"[NEW] File created: {filepath}")
                files_changed = True
            elif baseline[filepath] != current_hash:
                print(f"[MODIFIED] File changed: {filepath}")
                files_changed = True

    # 2. Check for deleted files
    for filepath in baseline:
        if filepath not in current_files:
            print(f"[DELETED] File missing: {filepath}")
            files_changed = True

    if not files_changed:
        print("No changes detected. System is secure.")

def main():
    if len(sys.argv) < 3:
        print("Usage: python integrity_checker.py <action> <directory>")
        print("Actions: init (create baseline), check (verify integrity)")
        return

    action = sys.argv[1]
    directory = sys.argv[2]

    if action == "init":
        create_baseline(directory)
    elif action == "check":
        check_integrity(directory)
    else:
        print("Invalid action. Use 'init' or 'check'.")

if __name__ == "__main__":
    main()
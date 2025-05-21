# Apache License
# Version 2.0, January 2004
# http://www.apache.org/licenses/

# Copyright 2025 emanoyhl and emanoyhl.net find me at github.com/emanoyhl 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import os
import json
import time
#import jsonpickle
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class IntegrityChecker:
    def __init__(self, directory, hash_file='hashes.json'):
        self.directory = directory
        self.hash_file = os.path.abspath(hash_file)  # Store absolute path for consistency
        self.saved_hashes = {}
        self.last_alert_time = 0  # Track the last alert time for compromised integrity
        self.alert_cooldown = 5  # Cooldown period in seconds
        self.last_compromised_time = None  # Track when integrity was last compromised

        # Load saved hashes if the hash file exists
        if os.path.exists(self.hash_file):
            with open(self.hash_file, 'r') as f:
                self.saved_hashes = json.load(f)
                print(f"Loaded hashes: {self.saved_hashes}")

    def calculate_hash(self, file_path):
        """Generate the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()

    def save_hashes(self):
        """Save the hashes of all files in the directory to a JSON file."""
        hashes = {}
        for file_name in os.listdir(self.directory):
            file_path = os.path.join(self.directory, file_name)
            if os.path.isfile(file_path) and file_path != self.hash_file:
                hashes[os.path.abspath(file_path)] = self.calculate_hash(file_path)  # Use absolute path
                print(f"Hash for {file_path}: {hashes[os.path.abspath(file_path)]}")  # Debugging output

        with open(self.hash_file, 'w') as f:
            json.dump(hashes, f)
        self.saved_hashes = hashes

    def check_integrity(self, file_path):
        """Check the integrity of a single file."""
        current_hash = self.calculate_hash(file_path)
        saved_hash = self.saved_hashes.get(os.path.abspath(file_path))  # Use absolute path for comparison

        # Debugging output
        print(f"Checking integrity for: {file_path}")
        print(f"Current hash: {current_hash}")
        print(f"Saved hash: {saved_hash}")

        current_time = time.time()

        if saved_hash is None:
            print(f"No hash found for {file_path}.")
        elif current_hash != saved_hash:
            if self.last_compromised_time is None:  # First time alerting for this file
                print(f"ALERT!! Change detected in file: {file_path} - integrity compromised, hash changed.")
                self.last_compromised_time = current_time  # Update time of compromise
        else:
            if self.last_compromised_time is not None:
                time_compromised = current_time - self.last_compromised_time
                print(f"INTEGRITY RESTORED for {file_path}. Compromised for {time_compromised:.2f} seconds.")
                self.last_compromised_time = None  # Reset the compromise time

class ChangeHandler(FileSystemEventHandler):
    def __init__(self, checker):
        self.checker = checker

    def on_modified(self, event):
        if os.path.isfile(event.src_path) and event.src_path != self.checker.hash_file:
            print(f"Change detected in {event.src_path}. Checking integrity...")
            self.checker.check_integrity(event.src_path)

    def on_created(self, event):
        if os.path.isfile(event.src_path):
            print(f"New file detected: {event.src_path}. Calculating hash...")
            self.checker.save_hashes()  # Update hashes to include new file

if __name__ == '__main__':
    directory_to_watch = '.'  # Current directory
    checker = IntegrityChecker(directory_to_watch)
    checker.save_hashes()  # Save initial hashes

    # Set up the watchdog observer
    event_handler = ChangeHandler(checker)
    observer = Observer()
    observer.schedule(event_handler, path=directory_to_watch, recursive=False)
    observer.start()

    try:
        print("Monitoring for changes. Press Ctrl+C to exit.")
        while True:
            pass  # Keep the program running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
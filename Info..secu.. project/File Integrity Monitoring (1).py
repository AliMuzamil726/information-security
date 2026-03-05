"""
File Integrity Monitor (FIM) - Information Security Academic Project
=====================================================================

CIA Triad Implementation:
- Confidentiality: Password-protected access controls
- Integrity: SHA-256 hashing for detecting unauthorized modifications
- Availability: Automatic restoration from backup vault

Security Concepts Demonstrated:
1. Cryptographic Hashing (SHA-256) - Digital fingerprinting
2. Baseline Comparison - Known-good state verification
3. Real-time Monitoring - Continuous integrity verification
4. Incident Response - Automated detection and alerting
5. Access Control - Password-based authentication
6. Backup & Recovery - Data availability assurance
"""

import os
import hashlib
import json
import time
import threading
import shutil
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import winsound

class FileIntegrityMonitor:
    """
    Core FIM Engine implementing cryptographic integrity verification
    """
    
    # Security Configuration
    ADMIN_PASSWORD = "admin123"  # Production: Use secure password storage
    BASELINE_FILE = ".baseline.db"
    BACKUP_VAULT = ".backup_vault"
    SCAN_INTERVAL = 5  # seconds
    
    def __init__(self, monitor_path=None):
        """
        Initialize FIM with secure defaults
        
        Args:
            monitor_path: Directory to monitor (None = prompt user)
        """
        self.monitor_path = monitor_path
        self.baseline = {}  # Stores file:hash mappings (known-good state)
        self.is_monitoring = False
        self.monitoring_thread = None
        self.alert_active = False
        self.beep_thread = None
        
        # UI will be set by GUI class
        self.ui_callback = None
        
    def calculate_sha256(self, filepath):
        """
        Generate SHA-256 cryptographic hash of file contents
        
        Security Purpose: Creates unique digital fingerprint
        - Any modification (even 1 bit) produces completely different hash
        - Collision resistance: Infeasible to create fake file with same hash
        
        Args:
            filepath: Path to file
            
        Returns:
            str: 64-character hexadecimal SHA-256 hash
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, "rb") as f:
                # Read file in chunks to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            self.log(f"ERROR: Cannot hash {filepath}: {e}", "error")
            return None
    
    def get_baseline_path(self):
        """Get full path to hidden baseline database"""
        return os.path.join(self.monitor_path, self.BASELINE_FILE)
    
    def get_vault_path(self):
        """Get full path to hidden backup vault"""
        return os.path.join(self.monitor_path, self.BACKUP_VAULT)
    
    def create_baseline(self):
        """
        Security Control: Establish Known-Good State (Baseline)
        
        Process:
        1. Scan all files in monitored directory
        2. Calculate cryptographic hash for each file
        3. Store hashes in persistent metadata file
        4. Create backup copies in hidden vault
        
        This baseline serves as the "trusted reference" for integrity checks
        """
        if not self.monitor_path or not os.path.exists(self.monitor_path):
            self.log("ERROR: Invalid monitor path", "error")
            return False
        
        self.log("Creating baseline (establishing known-good state)...", "info")
        self.baseline = {}
        
        # Create hidden backup vault
        vault_path = self.get_vault_path()
        if not os.path.exists(vault_path):
            os.makedirs(vault_path)
            # Make directory hidden on Windows
            if os.name == 'nt':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(vault_path, 2)  # Hidden
                except:
                    pass
        
        # Scan directory and create baseline
        file_count = 0
        for root, dirs, files in os.walk(self.monitor_path):
            # Skip hidden directories (baseline and vault)
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                if filename.startswith('.'):  # Skip hidden files
                    continue
                    
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.monitor_path)
                
                # Calculate hash
                file_hash = self.calculate_sha256(filepath)
                if file_hash:
                    self.baseline[relative_path] = file_hash
                    file_count += 1
                    
                    # Create backup in vault (Data Availability)
                    self.backup_file(filepath, relative_path)
                    
                    self.log(f"Baseline: {relative_path} → {file_hash[:16]}...", "info")
        
        # Persist baseline to hidden file
        self.save_baseline()
        
        self.log(f"✓ Baseline created: {file_count} files secured", "success")
        return True
    
    def backup_file(self, source_path, relative_path):
        """
        Data Availability: Store original copy for recovery
        
        Args:
            source_path: Full path to source file
            relative_path: Relative path for vault organization
        """
        try:
            vault_file_path = os.path.join(self.get_vault_path(), relative_path)
            os.makedirs(os.path.dirname(vault_file_path), exist_ok=True)
            shutil.copy2(source_path, vault_file_path)
        except Exception as e:
            self.log(f"Backup failed for {relative_path}: {e}", "error")
    
    def save_baseline(self):
        """
        Persist baseline to hidden metadata file
        
        Security Note: In production, encrypt this file to prevent tampering
        """
        baseline_path = self.get_baseline_path()
        try:
            with open(baseline_path, 'w') as f:
                json.dump(self.baseline, f, indent=2)
            
            # Make file hidden on Windows
            if os.name == 'nt':
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(baseline_path, 2)
                except:
                    pass
        except Exception as e:
            self.log(f"ERROR: Cannot save baseline: {e}", "error")
    
    def load_baseline(self):
        """
        Load existing baseline from persistent storage
        
        Returns:
            bool: True if baseline loaded successfully
        """
        baseline_path = self.get_baseline_path()
        
        if not os.path.exists(baseline_path):
            return False
        
        try:
            with open(baseline_path, 'r') as f:
                self.baseline = json.load(f)
            self.log(f"✓ Baseline loaded: {len(self.baseline)} files", "info")
            return True
        except Exception as e:
            self.log(f"ERROR: Cannot load baseline: {e}", "error")
            return False
    
    def verify_integrity(self):
        """
        Integrity Verification: Compare current state vs baseline
        
        Security Process:
        1. Scan current directory
        2. Calculate hashes of all files
        3. Compare with baseline (known-good state)
        4. Detect: modifications, deletions, unauthorized additions
        
        Returns:
            list: Anomalies detected (empty list = integrity verified)
        """
        if not self.baseline:
            self.log("WARNING: No baseline exists", "warning")
            return []
        
        anomalies = []
        current_files = {}
        
        # Scan current state
        for root, dirs, files in os.walk(self.monitor_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                if filename.startswith('.'):
                    continue
                    
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.monitor_path)
                
                file_hash = self.calculate_sha256(filepath)
                if file_hash:
                    current_files[relative_path] = file_hash
        
        # Detect modifications
        for file_path, baseline_hash in self.baseline.items():
            if file_path not in current_files:
                # File deleted
                anomalies.append({
                    'type': 'DELETED',
                    'file': file_path,
                    'details': 'File removed from monitored directory'
                })
            elif current_files[file_path] != baseline_hash:
                # File modified
                anomalies.append({
                    'type': 'MODIFIED',
                    'file': file_path,
                    'baseline_hash': baseline_hash,
                    'current_hash': current_files[file_path]
                })
        
        # Detect new files (unauthorized additions)
        for file_path in current_files:
            if file_path not in self.baseline:
                anomalies.append({
                    'type': 'NEW',
                    'file': file_path,
                    'hash': current_files[file_path]
                })
        
        return anomalies
    
    def restore_file(self, relative_path):
        """
        Incident Response: Restore file from backup vault
        
        Data Availability: Recover from integrity breach
        
        Args:
            relative_path: Path relative to monitored directory
            
        Returns:
            bool: True if restoration successful
        """
        vault_file = os.path.join(self.get_vault_path(), relative_path)
        target_file = os.path.join(self.monitor_path, relative_path)
        
        if not os.path.exists(vault_file):
            self.log(f"ERROR: No backup found for {relative_path}", "error")
            return False
        
        try:
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            shutil.copy2(vault_file, target_file)
            self.log(f"✓ RESTORED: {relative_path} from backup vault", "success")
            return True
        except Exception as e:
            self.log(f"ERROR: Restoration failed for {relative_path}: {e}", "error")
            return False
    
    def authorize_change(self, relative_path, new_hash):
        """
        Access Control: Update baseline after authorized change
        
        Args:
            relative_path: File path
            new_hash: New SHA-256 hash to authorize
        """
        self.baseline[relative_path] = new_hash
        self.save_baseline()
        
        # Update backup vault
        source_path = os.path.join(self.monitor_path, relative_path)
        if os.path.exists(source_path):
            self.backup_file(source_path, relative_path)
        
        self.log(f"✓ AUTHORIZED: {relative_path} baseline updated", "info")
    
    def remove_from_baseline(self, relative_path):
        """Remove deleted file from baseline"""
        if relative_path in self.baseline:
            del self.baseline[relative_path]
            self.save_baseline()
            self.log(f"✓ Baseline updated: {relative_path} removed", "info")
    
    def add_to_baseline(self, relative_path, file_hash):
        """Add new file to baseline after authorization"""
        self.baseline[relative_path] = file_hash
        self.save_baseline()
        
        # Create backup
        source_path = os.path.join(self.monitor_path, relative_path)
        if os.path.exists(source_path):
            self.backup_file(source_path, relative_path)
        
        self.log(f"✓ AUTHORIZED: {relative_path} added to baseline", "info")
    
    def start_monitoring(self):
        """
        Real-time Monitoring: Continuous integrity verification
        
        Background thread performs periodic scans every 5 seconds
        """
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.log("✓ Real-time monitoring ACTIVE", "success")
    
    def stop_monitoring(self):
        """Stop monitoring thread"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        self.log("Monitoring STOPPED", "warning")
    
    def _monitoring_loop(self):
        """
        Background monitoring loop
        
        Security Process:
        1. Wait for scan interval
        2. Verify integrity
        3. If anomalies detected → Trigger incident response
        """
        while self.is_monitoring:
            time.sleep(self.SCAN_INTERVAL)
            
            if not self.is_monitoring:
                break
            
            self.log("Scanning for integrity violations...", "info")
            anomalies = self.verify_integrity()
            
            if anomalies:
                # SECURITY BREACH DETECTED
                self.log(f"⚠ ALERT: {len(anomalies)} integrity violation(s) detected!", "alert")
                self.trigger_alert(anomalies)
            else:
                self.log("✓ Integrity verified - All files secure", "success")
    
    def trigger_alert(self, anomalies):
        """
        Incident Response: Alert on integrity breach
        
        Args:
            anomalies: List of detected violations
        """
        if self.alert_active:
            return  # Already alerting
        
        self.alert_active = True
        
        # Start continuous beep alert
        self.beep_thread = threading.Thread(target=self._continuous_beep, daemon=True)
        self.beep_thread.start()
        
        # Trigger UI alert
        if self.ui_callback:
            self.ui_callback(anomalies)
    
    def _continuous_beep(self):
        """Continuous audio alert for security breach"""
        while self.alert_active:
            try:
                winsound.Beep(1000, 300)  # 1000Hz, 300ms
                time.sleep(0.5)
            except:
                break  # winsound not available on non-Windows
    
    def stop_alert(self):
        """Stop audio alert"""
        self.alert_active = False
        if self.beep_thread:
            self.beep_thread.join(timeout=2)
    
    def log(self, message, level="info"):
        """
        Logging callback for UI
        
        Args:
            message: Log message
            level: info, success, warning, error, alert
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        if self.ui_callback:
            # Pass to UI for display
            pass
        
        print(log_entry)  # Console output


class SecurityDashboardGUI:
    """
    Professional Cybersecurity Dashboard UI
    
    Dark theme interface for security monitoring operations
    """
    
    def __init__(self):
        self.fim = FileIntegrityMonitor()
        self.fim.ui_callback = self.handle_alert
        
        self.root = tk.Tk()
        self.root.title("File Integrity Monitor - Security Dashboard")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Dark theme colors
        self.bg_dark = "#1e1e1e"
        self.bg_medium = "#2d2d2d"
        self.bg_light = "#3e3e3e"
        self.text_color = "#e0e0e0"
        self.accent_green = "#00ff00"
        self.accent_red = "#ff3333"
        self.accent_yellow = "#ffcc00"
        self.accent_blue = "#00aaff"
        
        self.root.configure(bg=self.bg_dark)
        
        # Intercept close event (Exit Protection)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.setup_ui()
        self.status_secure()
        
    def setup_ui(self):
        """Build professional security dashboard interface"""
        
        # Header
        header_frame = tk.Frame(self.root, bg=self.bg_dark, height=80)
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🛡️ FILE INTEGRITY MONITOR",
            font=("Consolas", 24, "bold"),
            bg=self.bg_dark,
            fg=self.accent_green
        )
        title_label.pack(side=tk.LEFT)
        
        # Status indicator
        self.status_frame = tk.Frame(header_frame, bg=self.bg_dark)
        self.status_frame.pack(side=tk.RIGHT, padx=10)
        
        self.status_light = tk.Canvas(
            self.status_frame,
            width=30,
            height=30,
            bg=self.bg_dark,
            highlightthickness=0
        )
        self.status_light.pack(side=tk.LEFT, padx=(0, 10))
        self.status_circle = self.status_light.create_oval(5, 5, 25, 25, fill=self.accent_green)
        
        self.status_label = tk.Label(
            self.status_frame,
            text="SECURE",
            font=("Consolas", 16, "bold"),
            bg=self.bg_dark,
            fg=self.accent_green
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg=self.bg_medium, relief=tk.RAISED, bd=2)
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            control_frame,
            text="CONTROL PANEL",
            font=("Consolas", 12, "bold"),
            bg=self.bg_medium,
            fg=self.text_color
        ).pack(pady=(10, 5))
        
        # Monitor path
        path_frame = tk.Frame(control_frame, bg=self.bg_medium)
        path_frame.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(
            path_frame,
            text="Monitor Path:",
            font=("Consolas", 10),
            bg=self.bg_medium,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.path_entry = tk.Entry(
            path_frame,
            font=("Consolas", 10),
            bg=self.bg_light,
            fg=self.text_color,
            insertbackground=self.text_color,
            width=40
        )
        self.path_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(
            path_frame,
            text="Browse",
            command=self.browse_folder,
            bg=self.bg_light,
            fg=self.text_color,
            font=("Consolas", 10),
            cursor="hand2"
        ).pack(side=tk.LEFT)
        
        # Action buttons
        button_frame = tk.Frame(control_frame, bg=self.bg_medium)
        button_frame.pack(pady=(0, 15))
        
        self.btn_create = tk.Button(
            button_frame,
            text="Create Baseline",
            command=self.create_baseline,
            bg=self.accent_blue,
            fg="black",
            font=("Consolas", 11, "bold"),
            width=18,
            cursor="hand2",
            relief=tk.RAISED,
            bd=3
        )
        self.btn_create.pack(side=tk.LEFT, padx=5)
        
        self.btn_start = tk.Button(
            button_frame,
            text="Start Monitoring",
            command=self.start_monitoring,
            bg=self.accent_green,
            fg="black",
            font=("Consolas", 11, "bold"),
            width=18,
            cursor="hand2",
            relief=tk.RAISED,
            bd=3
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = tk.Button(
            button_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            bg=self.accent_yellow,
            fg="black",
            font=("Consolas", 11, "bold"),
            width=18,
            cursor="hand2",
            relief=tk.RAISED,
            bd=3,
            state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        # Event Log
        log_frame = tk.Frame(self.root, bg=self.bg_medium, relief=tk.RAISED, bd=2)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(
            log_frame,
            text="SECURITY EVENT LOG",
            font=("Consolas", 12, "bold"),
            bg=self.bg_medium,
            fg=self.text_color
        ).pack(pady=(10, 5))
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=("Consolas", 9),
            bg=self.bg_dark,
            fg=self.text_color,
            insertbackground=self.text_color,
            height=20,
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.log_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        
        # Configure text tags for colored logs
        self.log_text.tag_config("info", foreground=self.text_color)
        self.log_text.tag_config("success", foreground=self.accent_green)
        self.log_text.tag_config("warning", foreground=self.accent_yellow)
        self.log_text.tag_config("error", foreground=self.accent_red)
        self.log_text.tag_config("alert", foreground=self.accent_red, font=("Consolas", 9, "bold"))
        
        # Redirect FIM logging to UI
        self.fim.log = self.log_message
        
        self.log_message("System initialized. Select directory to monitor.", "info")
    
    def log_message(self, message, level="info"):
        """
        Add timestamped message to event log
        
        Args:
            message: Log message
            level: info, success, warning, error, alert
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry, level)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def browse_folder(self):
        """Select directory to monitor"""
        folder = filedialog.askdirectory(title="Select Folder to Monitor")
        if folder:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folder)
            self.fim.monitor_path = folder
            self.log_message(f"Monitor path set: {folder}", "info")
            
            # Check for existing baseline
            if self.fim.load_baseline():
                self.log_message("Existing baseline detected. Verifying integrity...", "info")
                anomalies = self.fim.verify_integrity()
                if anomalies:
                    self.log_message(f"⚠ WARNING: {len(anomalies)} change(s) detected while offline!", "alert")
                    self.handle_alert(anomalies)
                else:
                    self.log_message("✓ Integrity verified - No changes during downtime", "success")
    
    def create_baseline(self):
        """Create new baseline"""
        if not self.fim.monitor_path:
            messagebox.showerror("Error", "Please select a folder to monitor first")
            return
        
        if self.fim.is_monitoring:
            messagebox.showwarning("Warning", "Stop monitoring before creating new baseline")
            return
        
        confirm = messagebox.askyesno(
            "Create Baseline",
            "This will create a new baseline and backup vault.\n\n"
            "Any existing baseline will be overwritten.\n\nContinue?"
        )
        
        if confirm:
            success = self.fim.create_baseline()
            if success:
                messagebox.showinfo("Success", "Baseline created successfully!")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if not self.fim.monitor_path:
            messagebox.showerror("Error", "Please select a folder to monitor first")
            return
        
        if not self.fim.baseline:
            messagebox.showerror("Error", "Please create a baseline first")
            return
        
        self.fim.start_monitoring()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_create.config(state=tk.DISABLED)
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.fim.stop_monitoring()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_create.config(state=tk.NORMAL)
        self.status_secure()
    
    def status_secure(self):
        """Update status indicator to SECURE"""
        self.status_light.itemconfig(self.status_circle, fill=self.accent_green)
        self.status_label.config(text="SECURE", fg=self.accent_green)
    
    def status_breach(self):
        """Update status indicator to BREACH"""
        self.status_light.itemconfig(self.status_circle, fill=self.accent_red)
        self.status_label.config(text="BREACH", fg=self.accent_red)
    
    def handle_alert(self, anomalies):
        """
        Security Incident Response: Handle detected anomalies
        
        Process:
        1. Update status to BREACH
        2. Display anomalies
        3. Require admin authentication
        4. Present response options (Authorize or Restore)
        
        Args:
            anomalies: List of detected violations
        """
        self.status_breach()
        
        # Create alert window (modal - blocks main window)
        alert_window = tk.Toplevel(self.root)
        alert_window.title("⚠ SECURITY ALERT - INTEGRITY BREACH DETECTED")
        alert_window.geometry("700x550")
        alert_window.configure(bg=self.bg_dark)
        alert_window.resizable(False, False)
        alert_window.transient(self.root)
        alert_window.grab_set()  # Modal window
        
        # Alert header
        tk.Label(
            alert_window,
            text="⚠ SECURITY BREACH DETECTED ⚠",
            font=("Consolas", 18, "bold"),
            bg=self.bg_dark,
            fg=self.accent_red
        ).pack(pady=(20, 10))
        
        tk.Label(
            alert_window,
            text=f"{len(anomalies)} Integrity Violation(s) Detected",
            font=("Consolas", 12),
            bg=self.bg_dark,
            fg=self.text_color
        ).pack(pady=(0, 20))
        
        # Anomaly details
        details_frame = tk.Frame(alert_window, bg=self.bg_medium, relief=tk.RAISED, bd=2)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        details_text = scrolledtext.ScrolledText(
            details_frame,
            font=("Consolas", 9),
            bg=self.bg_dark,
            fg=self.text_color,
            height=12,
            state=tk.NORMAL
        )
        details_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        for anomaly in anomalies:
            details_text.insert(tk.END, f"\nType: {anomaly['type']}\n", "header")
            details_text.insert(tk.END, f"File: {anomaly['file']}\n")
            
            if anomaly['type'] == 'MODIFIED':
                details_text.insert(tk.END, f"Baseline Hash: {anomaly['baseline_hash']}\n")
                details_text.insert(tk.END, f"Current Hash:  {anomaly['current_hash']}\n")
            elif anomaly['type'] == 'NEW':
                details_text.insert(tk.END, f"Hash: {anomaly['hash']}\n")
            
            details_text.insert(tk.END, "-" * 70 + "\n")
        
        details_text.tag_config("header", foreground=self.accent_yellow, font=("Consolas", 9, "bold"))
        details_text.config(state=tk.DISABLED)
        
        # Authentication section
        auth_frame = tk.Frame(alert_window, bg=self.bg_dark)
        auth_frame.pack(pady=(0, 20))
        
        tk.Label(
            auth_frame,
            text="Admin Authentication Required:",
            font=("Consolas", 11, "bold"),
            bg=self.bg_dark,
            fg=self.accent_yellow
        ).pack()
        
        password_frame = tk.Frame(auth_frame, bg=self.bg_dark)
        password_frame.pack(pady=10)
        
        tk.Label(
            password_frame,
            text="Password:",
            font=("Consolas", 10),
            bg=self.bg_dark,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        password_entry = tk.Entry(
            password_frame,
            font=("Consolas", 10),
            bg=self.bg_light,
            fg=self.text_color,
            show="*",
            width=20
        )
        password_entry.pack(side=tk.LEFT)
        password_entry.focus()
        
        # Action buttons
        button_frame = tk.Frame(alert_window, bg=self.bg_dark)
        button_frame.pack(pady=(0, 20))
        
        def authenticate_and_authorize():
            """Authorize changes after authentication"""
            if password_entry.get() != FileIntegrityMonitor.ADMIN_PASSWORD:
                messagebox.showerror("Access Denied", "Incorrect password!", parent=alert_window)
                return
            
            # Authorize all changes
            for anomaly in anomalies:
                if anomaly['type'] == 'MODIFIED':
                    self.fim.authorize_change(anomaly['file'], anomaly['current_hash'])
                elif anomaly['type'] == 'NEW':
                    self.fim.add_to_baseline(anomaly['file'], anomaly['hash'])
                elif anomaly['type'] == 'DELETED':
                    self.fim.remove_from_baseline(anomaly['file'])
            
            self.fim.stop_alert()
            self.status_secure()
            alert_window.destroy()
            messagebox.showinfo("Authorized", "All changes have been authorized and baseline updated.")
        
        def authenticate_and_restore():
            """Restore files from backup after authentication"""
            if password_entry.get() != FileIntegrityMonitor.ADMIN_PASSWORD:
                messagebox.showerror("Access Denied", "Incorrect password!", parent=alert_window)
                return
            
            # Restore modified/deleted files
            restored = 0
            for anomaly in anomalies:
                if anomaly['type'] in ['MODIFIED', 'DELETED']:
                    if self.fim.restore_file(anomaly['file']):
                        restored += 1
                elif anomaly['type'] == 'NEW':
                    # Remove unauthorized new files
                    try:
                        os.remove(os.path.join(self.fim.monitor_path, anomaly['file']))
                        self.log_message(f"✓ REMOVED unauthorized file: {anomaly['file']}", "success")
                        restored += 1
                    except Exception as e:
                        self.log_message(f"ERROR removing {anomaly['file']}: {e}", "error")
            
            self.fim.stop_alert()
            self.status_secure()
            alert_window.destroy()
            messagebox.showinfo("Restored", f"Successfully restored {restored} file(s) from backup vault.")
        
        tk.Button(
            button_frame,
            text="Authorize Changes",
            command=authenticate_and_authorize,
            bg=self.accent_yellow,
            fg="black",
            font=("Consolas", 11, "bold"),
            width=20,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            button_frame,
            text="Restore from Backup",
            command=authenticate_and_restore,
            bg=self.accent_green,
            fg="black",
            font=("Consolas", 11, "bold"),
            width=20,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=10)
        
        # Bind Enter key to first button
        password_entry.bind('<Return>', lambda e: authenticate_and_authorize())
    
    def on_closing(self):
        """
        Exit Protection: Prevent unauthorized shutdown
        
        Access Control: Requires admin password to close application
        """
        auth_window = tk.Toplevel(self.root)
        auth_window.title("Authentication Required")
        auth_window.geometry("400x200")
        auth_window.configure(bg=self.bg_dark)
        auth_window.resizable(False, False)
        auth_window.transient(self.root)
        auth_window.grab_set()
        
        tk.Label(
            auth_window,
            text="🔒 Admin Authentication Required",
            font=("Consolas", 14, "bold"),
            bg=self.bg_dark,
            fg=self.accent_yellow
        ).pack(pady=(20, 10))
        
        tk.Label(
            auth_window,
            text="Enter password to close FIM:",
            font=("Consolas", 10),
            bg=self.bg_dark,
            fg=self.text_color
        ).pack(pady=10)
        
        password_entry = tk.Entry(
            auth_window,
            font=("Consolas", 12),
            bg=self.bg_light,
            fg=self.text_color,
            show="*",
            width=20
        )
        password_entry.pack(pady=10)
        password_entry.focus()
        
        def verify_and_close():
            if password_entry.get() == FileIntegrityMonitor.ADMIN_PASSWORD:
                self.fim.stop_monitoring()
                self.fim.stop_alert()
                auth_window.destroy()
                self.root.destroy()
            else:
                messagebox.showerror("Access Denied", "Incorrect password!", parent=auth_window)
                password_entry.delete(0, tk.END)
        
        tk.Button(
            auth_window,
            text="Close FIM",
            command=verify_and_close,
            bg=self.accent_red,
            fg="white",
            font=("Consolas", 11, "bold"),
            width=15,
            cursor="hand2"
        ).pack(pady=20)
        
        password_entry.bind('<Return>', lambda e: verify_and_close())
    
    def run(self):
        """Start GUI event loop"""
        self.root.mainloop()


def main():
    """
    Entry Point: File Integrity Monitor
    
    Academic Project: Demonstrates CIA Triad implementation
    - Confidentiality: Password-protected access
    - Integrity: Cryptographic hash verification
    - Availability: Backup vault for recovery
    """
    print("=" * 70)
    print("File Integrity Monitor (FIM) - Information Security Project")
    print("Implementing CIA Triad: Confidentiality, Integrity, Availability")
    print("=" * 70)
    print()
    
    # Launch GUI
    app = SecurityDashboardGUI()
    app.run()


if __name__ == "__main__":
    main()
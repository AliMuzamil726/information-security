import os, sys, json, time, threading, shutil, random, string, ctypes, hashlib
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet
import bcrypt
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
import winsound

# ---------------------------- CONFIGURATION ---------------------------- #
DEFAULT_SCAN_INTERVAL = 5
LOG_FILE = "changes.log"

# ---------------------------- HELPER FUNCTIONS ------------------------ #
def generate_random_string(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def make_hidden_windows(path):
    if os.name == 'nt':
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 2)
        except:
            pass

# ---------------------------- FIM CLASS ------------------------------- #
class FileIntegrityMonitor:
    def __init__(self):
        self.monitor_path = None
        self.baseline_file = ".baseline.db"
        self.vault_dir = generate_random_string()
        self.baseline = {}
        self.is_monitoring = False
        self.alert_active = False
        self.scan_interval = DEFAULT_SCAN_INTERVAL
        self.f = Fernet(Fernet.generate_key())
        self.tray_icon = None
        self.monitor_thread = None
        self.beep_thread = None
        self.password_hash = None
        self.ui_callback = None

    def get_baseline_path(self):
        return os.path.join(self.monitor_path, self.baseline_file) if self.monitor_path else None

    def get_vault_path(self):
        return os.path.join(self.monitor_path, self.vault_dir) if self.monitor_path else None

    def hash_file(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def backup_file(self, source_path, rel_path):
        vault_path = self.get_vault_path()
        if not vault_path: return
        vault_file = os.path.join(vault_path, rel_path)
        os.makedirs(os.path.dirname(vault_file), exist_ok=True)
        try:
            shutil.copy2(source_path, vault_file)
        except Exception:
            pass

    def create_baseline(self):
        if not self.monitor_path or not os.path.exists(self.monitor_path):
            return False

        self.baseline = {}
        vault_path = self.get_vault_path()
        os.makedirs(vault_path, exist_ok=True)
        make_hidden_windows(vault_path)

        for root, dirs, files in os.walk(self.monitor_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                if f.startswith('.'): continue
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.monitor_path)
                file_hash = self.hash_file(full_path)
                if file_hash:
                    self.baseline[rel_path] = file_hash
                    self.backup_file(full_path, rel_path)

        self.save_baseline()
        return True

    def save_baseline(self):
        try:
            data = json.dumps(self.baseline).encode()
            encrypted = self.f.encrypt(data)
            with open(self.get_baseline_path(), 'wb') as f:
                f.write(encrypted)
            make_hidden_windows(self.get_baseline_path())
        except Exception:
            pass

    def start_monitoring(self):
        if self.is_monitoring: return
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.is_monitoring = False
        self.stop_alert()

    def monitor_loop(self):
        while self.is_monitoring:
            time.sleep(self.scan_interval)
            anomalies = self.verify_integrity()
            if anomalies and not self.alert_active:
                self.trigger_alert(anomalies)

    def verify_integrity(self):
        if not self.monitor_path: return []
        anomalies = []
        current_files = {}
        for root, dirs, files in os.walk(self.monitor_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                if f.startswith('.'): continue
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.monitor_path)
                h = self.hash_file(full_path)
                if h: current_files[rel_path] = h

        for f, baseline_hash in self.baseline.items():
            if f not in current_files:
                anomalies.append({'type':'DELETED','file':f})
            elif current_files[f] != baseline_hash:
                anomalies.append({'type':'MODIFIED','file':f})

        for f in current_files:
            if f not in self.baseline:
                anomalies.append({'type':'NEW','file':f})
        return anomalies

    def trigger_alert(self, anomalies):
        self.alert_active = True
        self.beep_thread = threading.Thread(target=self.continuous_beep, daemon=True)
        self.beep_thread.start()
        if self.ui_callback:
            self.ui_callback(anomalies)

    def stop_alert(self):
        self.alert_active = False

    def continuous_beep(self):
        while self.alert_active:
            winsound.Beep(1000, 300)
            time.sleep(0.5)

# ---------------------------- GUI CLASS ------------------------------- #
class SecurityDashboardGUI:
    def __init__(self):
        self.fim = FileIntegrityMonitor()
        self.fim.ui_callback = self.handle_alert

        self.root = tk.Tk()
        self.root.title("Secure FIM Dashboard")
        self.root.geometry("950x650")
        self.root.configure(bg="#121212")
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        self.setup_styles()
        self.setup_ui()

        self.icon_image = self.create_tray_icon_image()
        self.tray_icon = pystray.Icon("FIM", self.icon_image, "Secure FIM", menu=pystray.Menu(
            item("Show", self.show_from_tray),
            item("Exit", self.exit_app)
        ))
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff", background="#2d2d2d", borderwidth=0, padding=10)
        style.map("TButton", background=[('active', '#3d3d3d')])
        style.configure("Status.TLabel", font=("Segoe UI", 12, "bold"), foreground="#a0a0a0", background="#1a1a1a")

    def setup_ui(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.sidebar = tk.Frame(self.root, bg="#1a1a1a", width=250)
        self.sidebar.grid(row=0, column=0, sticky="nswe")
        self.sidebar.grid_propagate(False)

        self.main_view = tk.Frame(self.root, bg="#121212")
        self.main_view.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)
        self.main_view.grid_rowconfigure(1, weight=1)
        self.main_view.grid_columnconfigure(0, weight=1)

        tk.Label(self.sidebar, text="FIM CONTROL", font=("Segoe UI", 16, "bold"), bg="#1a1a1a", fg="#ffffff").pack(pady=(30, 20))
        ttk.Button(self.sidebar, text="1. Select Target Folder", command=self.select_folder).pack(fill="x", padx=20, pady=10)
        ttk.Button(self.sidebar, text="2. Generate Baseline", command=self.create_baseline).pack(fill="x", padx=20, pady=10)
        ttk.Button(self.sidebar, text="3. Start Monitoring", command=self.start_monitoring).pack(fill="x", padx=20, pady=10)
        ttk.Button(self.sidebar, text="4. Stop Monitoring", command=self.stop_monitoring).pack(fill="x", padx=20, pady=10)

        self.status_var = tk.StringVar(value="SYSTEM IDLE")
        self.status_label = ttk.Label(self.sidebar, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.pack(side="bottom", pady=30)

        tk.Label(self.main_view, text="Event Logs", font=("Segoe UI", 14), bg="#121212", fg="#a0a0a0", anchor="w").grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.log_text = scrolledtext.ScrolledText(self.main_view, bg="#1e1e1e", fg="#4af626", font=("Consolas", 10), borderwidth=0, highlightthickness=1, highlightbackground="#333333")
        self.log_text.grid(row=1, column=0, sticky="nswe")
        self.log_text.config(state=tk.DISABLED)

    def log_message(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        tag = level.lower()
        self.log_text.tag_config("info", foreground="#cccccc")
        self.log_text.tag_config("alert", foreground="#ff3333", font=("Consolas", 10, "bold"))
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.fim.monitor_path = folder
            self.log_message(f"Path set: {folder}")

    def create_baseline(self):
        if self.fim.create_baseline():
            self.status_var.set("BASELINE SECURED")
            self.log_message("Baseline generation complete.", "info")

    def start_monitoring(self):
        self.fim.start_monitoring()
        self.status_var.set("MONITORING ACTIVE")
        self.status_label.configure(foreground="#4af626")

    def stop_monitoring(self):
        self.fim.stop_monitoring()
        self.status_var.set("SYSTEM IDLE")
        self.status_label.configure(foreground="#a0a0a0")

    def handle_alert(self, anomalies):
        self.log_message(f"CRITICAL: {len(anomalies)} anomalies detected!", "alert")

    def create_tray_icon_image(self):
        img = Image.new('RGB', (64,64), color='#121212')
        d = ImageDraw.Draw(img)
        d.ellipse([16, 16, 48, 48], fill="#4af626")
        return img

    def hide_to_tray(self):
        self.root.withdraw()

    def show_from_tray(self):
        self.root.deiconify()

    def exit_app(self):
        self.fim.stop_monitoring()
        self.tray_icon.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SecurityDashboardGUI()
    app.run()
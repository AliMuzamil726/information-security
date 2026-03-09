"""
=============================================================
  INFORMATION SECURITY TOOLKIT - Single File Version
  Compatible: Windows + Linux + Mac
  Run: python main.py
=============================================================
"""

import sys
import os
import re
import math
import string
import socket
import subprocess
import platform
import threading
import getpass
import json
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── ANSI Colors ──────────────────────────────────────────────────────────────
R     = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW= "\033[1;33m"
CYAN  = "\033[1;36m"
DIM   = "\033[2m"

# Enable ANSI colors on Windows
if platform.system() == "Windows":
    os.system("color")

# ═══════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════
def print_banner():
    print(f"""
{CYAN}
  ██╗███╗   ██╗███████╗ ██████╗ ███████╗███████╗ ██████╗
  ██║████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██╔════╝
  ██║██╔██╗ ██║█████╗  ██║   ██║███████╗█████╗  ██║
  ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██╔══╝  ██║
  ██║██║ ╚████║██║     ╚██████╔╝███████║███████╗╚██████╗
  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
{R}
  {BOLD}INFORMATION SECURITY TOOLKIT  v1.0{R}
  {DIM}Professional Python Cybersecurity Suite{R}
  {DIM}─────────────────────────────────────────{R}
  {YELLOW}[!] For educational & authorized use only{R}
""")


# ═══════════════════════════════════════════════════════════════════
#  1. PASSWORD STRENGTH CHECKER
# ═══════════════════════════════════════════════════════════════════
COMMON_PASSWORDS = {
    "password","123456","password123","admin","letmein","qwerty",
    "abc123","monkey","iloveyou","welcome","dragon","master",
    "sunshine","princess","shadow","superman","football","pass"
}

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += 32
    if charset == 0: return 0.0
    return len(password) * math.log2(charset)

def check_password():
    print(f"\n{CYAN}{'='*55}")
    print(f"        PASSWORD STRENGTH CHECKER")
    print(f"{'='*55}{R}")

    while True:
        try:
            password = getpass.getpass(f"\n  Enter password to analyze (or 'back'): ")
        except Exception:
            password = input("  Enter password: ")

        if password.lower() == "back":
            return
        if not password:
            print(f"  {YELLOW}[!] Password cannot be empty.{R}")
            continue

        checks = {
            "min_length":         len(password) >= 8,
            "good_length":        len(password) >= 12,
            "great_length":       len(password) >= 16,
            "has_lowercase":      bool(re.search(r'[a-z]', password)),
            "has_uppercase":      bool(re.search(r'[A-Z]', password)),
            "has_digits":         bool(re.search(r'\d', password)),
            "has_special":        bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            "no_common":          password.lower() not in COMMON_PASSWORDS,
            "no_sequential":      not bool(re.search(r'(012|123|234|345|456|789|abc|bcd)', password.lower())),
            "no_repeated":        not bool(re.search(r'(.)\1{2,}', password)),
        }

        score = sum([
            checks["min_length"], checks["good_length"], checks["great_length"],
            checks["has_lowercase"], checks["has_uppercase"], checks["has_digits"],
            checks["has_special"] * 2, checks["no_common"] * 2,
            checks["no_sequential"], checks["no_repeated"]
        ])
        entropy = calculate_entropy(password)
        pct = score / 12
        strength = (
            f"{GREEN}VERY STRONG 🟢{R}" if pct >= 0.85 else
            f"{YELLOW}STRONG 🟡{R}"     if pct >= 0.65 else
            f"{YELLOW}MODERATE 🟠{R}"   if pct >= 0.45 else
            f"{RED}WEAK 🔴{R}"
        )

        print(f"\n{CYAN}{'='*55}{R}")
        print(f"  Password  : {'*' * len(password)} ({len(password)} chars)")
        print(f"  Strength  : {strength}")
        print(f"  Score     : {score}/12")
        print(f"  Entropy   : {entropy:.1f} bits\n")

        labels = {
            "min_length": "Min length (8+)", "good_length": "Good length (12+)",
            "great_length": "Great length (16+)", "has_lowercase": "Lowercase letters",
            "has_uppercase": "Uppercase letters", "has_digits": "Digits (0-9)",
            "has_special": "Special characters", "no_common": "Not a common password",
            "no_sequential": "No sequential patterns", "no_repeated": "No repeated chars",
        }
        for k, label in labels.items():
            icon = f"{GREEN}✓{R}" if checks[k] else f"{RED}✗{R}"
            print(f"  [{icon}] {label}")

        print(f"{CYAN}{'='*55}{R}")
        if input("\n  Check another? (y/n): ").strip().lower() != "y":
            break


# ═══════════════════════════════════════════════════════════════════
#  2. PORT SCANNER
# ═══════════════════════════════════════════════════════════════════
KNOWN_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB"
}

def scan_port(host, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = sock.recv(512).decode("utf-8", errors="ignore").strip()
                banner = raw.split("\n")[0][:50] if raw else ""
            except: pass
            finally: sock.close()
            return {"port": port, "service": KNOWN_PORTS.get(port, "Unknown"), "banner": banner}
        sock.close()
    except: pass
    return None

def port_scanner():
    print(f"\n{CYAN}{'='*55}")
    print(f"             PORT SCANNER")
    print(f"{'='*55}{R}")
    print(f"  {YELLOW}[!] Only scan systems you own or have permission.{R}\n")

    host = input("  Target host/IP (or 'back'): ").strip()
    if host.lower() == "back": return

    try:
        ip = socket.gethostbyname(host)
        print(f"  {GREEN}[*] Resolved: {host} → {ip}{R}")
    except:
        print(f"  {RED}[!] Cannot resolve: {host}{R}")
        return

    print(f"\n  Scan Profiles:")
    print(f"  [1] Quick (1-1024)  [2] Web  [3] Database  [4] Custom")
    choice = input("  Select [1-4]: ").strip()

    profiles = {
        "1": list(range(1, 1025)),
        "2": [80, 443, 8080, 8443, 8000, 8888],
        "3": [1433, 1521, 3306, 5432, 6379, 27017],
    }

    if choice in profiles:
        ports = profiles[choice]
    elif choice == "4":
        try:
            s = int(input("  Start port: "))
            e = int(input("  End port: "))
            ports = list(range(s, e+1))
        except:
            print(f"  {RED}[!] Invalid range.{R}")
            return
    else:
        print(f"  {RED}[!] Invalid choice.{R}")
        return

    print(f"\n  {CYAN}[*] Scanning {len(ports)} ports...{R}\n")
    start = datetime.now()
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r: open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - start).total_seconds()

    print(f"\n{CYAN}{'='*60}{R}")
    print(f"  HOST: {host} ({ip}) | Time: {elapsed:.2f}s | Open: {len(open_ports)}")
    print(f"{'='*60}")
    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'-'*8} {'-'*15} {'-'*30}")
        for p in open_ports:
            print(f"  {p['port']:<8} {p['service']:<15} {p['banner'][:35] or '-'}")
    else:
        print(f"  {YELLOW}No open ports found.{R}")
    print(f"{CYAN}{'='*60}{R}")
    input(f"\n  {DIM}Press Enter to continue...{R}")


# ═══════════════════════════════════════════════════════════════════
#  3. NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════════
import ipaddress

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(
            ["ping", param, "1", "-w" if platform.system().lower()=="windows" else "-W", "1000" if platform.system().lower()=="windows" else "1", str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        if r.returncode == 0:
            try: hostname = socket.gethostbyaddr(str(ip))[0]
            except: hostname = "Unknown"
            return {"ip": str(ip), "hostname": hostname}
    except: pass
    return None

def network_scanner():
    print(f"\n{CYAN}{'='*55}")
    print(f"           NETWORK SCANNER")
    print(f"{'='*55}{R}")
    print(f"  Example: 192.168.1.0/24\n")

    cidr = input("  Enter network CIDR (or 'back'): ").strip()
    if cidr.lower() == "back": return

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except:
        print(f"  {RED}[!] Invalid CIDR.{R}")
        return

    hosts = list(network.hosts())
    print(f"\n  {CYAN}[*] Scanning {len(hosts)} hosts...{R}\n")
    live = []

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in hosts}
        done = 0
        for f in as_completed(futures):
            done += 1
            r = f.result()
            if r:
                live.append(r)
                print(f"  {GREEN}[+] LIVE:{R} {r['ip']:<18} {r['hostname']}")
            if done % 20 == 0:
                print(f"  {DIM}[~] Progress: {done}/{len(hosts)}{R}")

    print(f"\n{CYAN}{'='*55}{R}")
    print(f"  Scan complete — {GREEN}{len(live)} host(s) found{R}")
    print(f"{CYAN}{'='*55}{R}")
    input(f"\n  {DIM}Press Enter to continue...{R}")


# ═══════════════════════════════════════════════════════════════════
#  4. FILE ENCRYPTION / DECRYPTION (AES-256)
# ═══════════════════════════════════════════════════════════════════
def file_encryptor():
    print(f"\n{CYAN}{'='*55}")
    print(f"        FILE ENCRYPTION / DECRYPTION")
    print(f"{'='*55}{R}")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes, padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print(f"  {RED}[!] 'cryptography' not installed.{R}")
        print(f"  {YELLOW}    Run: pip install cryptography{R}")
        input(f"\n  {DIM}Press Enter to continue...{R}")
        return

    MAGIC = b"INFOSEC1"

    def derive_key(password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=200_000, backend=default_backend())
        return kdf.derive(password.encode())

    print("  [1] Encrypt  [2] Decrypt  [0] Back")
    choice = input("\n  Choice: ").strip()
    if choice == "0": return

    filepath = input("  File path: ").strip().strip('"')
    if not os.path.isfile(filepath):
        print(f"  {RED}[!] File not found.{R}")
        return

    try:
        password = getpass.getpass("  Password: ")
    except:
        password = input("  Password: ")

    try:
        if choice == "1":
            with open(filepath, "rb") as f: data = f.read()
            salt = os.urandom(16); iv = os.urandom(16)
            key = derive_key(password, salt)
            padder = padding.PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            enc = cipher.encryptor()
            ct = enc.update(padded) + enc.finalize()
            out = filepath + ".enc"
            with open(out, "wb") as f: f.write(MAGIC + salt + iv + ct)
            print(f"  {GREEN}✓ Encrypted → {out}{R}")
            print(f"  {YELLOW}[!] Keep password safe — cannot recover without it!{R}")

        elif choice == "2":
            with open(filepath, "rb") as f: data = f.read()
            if not data.startswith(MAGIC):
                print(f"  {RED}[!] Invalid file or not encrypted by this tool.{R}")
                return
            offset = len(MAGIC)
            salt = data[offset:offset+16]; offset += 16
            iv = data[offset:offset+16]; offset += 16
            ct = data[offset:]
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec = cipher.decryptor()
            padded = dec.update(ct) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(padded) + unpadder.finalize()
            out = filepath[:-4] if filepath.endswith(".enc") else filepath + ".dec"
            if os.path.exists(out): out += ".decrypted"
            with open(out, "wb") as f: f.write(plain)
            print(f"  {GREEN}✓ Decrypted → {out}{R}")
        else:
            print(f"  {RED}[!] Invalid choice.{R}")
    except Exception as e:
        print(f"  {RED}[!] Error: {e}{R}")
        if choice == "2": print(f"  {YELLOW}    Hint: Wrong password?{R}")

    input(f"\n  {DIM}Press Enter to continue...{R}")


# ═══════════════════════════════════════════════════════════════════
#  5. LOG ANALYZER
# ═══════════════════════════════════════════════════════════════════
LOG_PATTERNS = {
    "ssh_failed":     re.compile(r"Failed password for (\S+) from ([\d.]+)", re.I),
    "ssh_success":    re.compile(r"Accepted password for (\S+) from ([\d.]+)", re.I),
    "sql_injection":  re.compile(r"(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|--|%27)", re.I),
    "xss_attempt":    re.compile(r"(<script|javascript:|onerror=|alert\()", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\%2F)", re.I),
    "ip_address":     re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"),
}

def generate_sample_log(path):
    sample = """Jan 10 10:01:12 server sshd: Failed password for root from 192.168.1.100 port 22
Jan 10 10:01:15 server sshd: Failed password for admin from 192.168.1.100 port 22
Jan 10 10:01:18 server sshd: Failed password for ubuntu from 192.168.1.100 port 22
Jan 10 10:01:21 server sshd: Failed password for user from 192.168.1.100 port 22
Jan 10 10:01:24 server sshd: Failed password for test from 192.168.1.100 port 22
Jan 10 10:01:27 server sshd: Failed password for pi from 192.168.1.100 port 22
Jan 10 10:05:01 server sshd: Accepted password for john from 10.0.0.5 port 22
192.168.1.50 - - "GET /login?id=1 UNION SELECT * FROM users-- HTTP/1.1" 200
192.168.1.51 - - "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200
192.168.1.52 - - "GET /../../etc/passwd HTTP/1.1" 403
"""
    with open(path, "w") as f: f.write(sample)

def log_analyzer():
    print(f"\n{CYAN}{'='*55}")
    print(f"            LOG ANALYZER")
    print(f"{'='*55}{R}")
    print("  [1] Analyze a log file")
    print("  [2] Generate & analyze sample log")
    print("  [0] Back")

    choice = input("\n  Choice: ").strip()
    if choice == "0": return

    if choice == "2":
        path = os.path.join(os.path.expanduser("~"), "fim_sample.log")
        generate_sample_log(path)
        print(f"  {GREEN}[*] Sample log: {path}{R}")
    elif choice == "1":
        path = input("  Log file path: ").strip().strip('"')
    else:
        print(f"  {RED}[!] Invalid.{R}")
        return

    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  {RED}[!] {e}{R}")
        return

    failed = defaultdict(list)
    success = []
    sql_inj = []
    xss = []
    traversal = []
    ip_freq = Counter()
    threats = []

    for i, line in enumerate(lines, 1):
        for ip in LOG_PATTERNS["ip_address"].findall(line):
            ip_freq[ip] += 1
        m = LOG_PATTERNS["ssh_failed"].search(line)
        if m: failed[m.group(2)].append(m.group(1))
        m = LOG_PATTERNS["ssh_success"].search(line)
        if m: success.append(f"{m.group(1)} from {m.group(2)}")
        if LOG_PATTERNS["sql_injection"].search(line): sql_inj.append(i)
        if LOG_PATTERNS["xss_attempt"].search(line): xss.append(i)
        if LOG_PATTERNS["path_traversal"].search(line): traversal.append(i)

    for ip, users in failed.items():
        if len(users) >= 5:
            threats.append(f"{RED}[HIGH] BRUTE FORCE:{R} {ip} → {len(users)} attempts")
    if sql_inj: threats.append(f"{RED}[CRITICAL] SQL INJECTION:{R} {len(sql_inj)} pattern(s)")
    if xss:     threats.append(f"{YELLOW}[HIGH] XSS ATTEMPT:{R} {len(xss)} pattern(s)")
    if traversal: threats.append(f"{YELLOW}[MEDIUM] PATH TRAVERSAL:{R} {len(traversal)} pattern(s)")

    print(f"\n{CYAN}{'='*60}{R}")
    print(f"  LOG ANALYSIS — {len(lines)} lines")
    print(f"{'='*60}")
    print(f"\n  {BOLD}THREATS ({len(threats)}):{R}")
    for t in threats: print(f"  {t}")
    if not threats: print(f"  {GREEN}No major threats detected.{R}")

    print(f"\n  {BOLD}FAILED LOGINS:{R}")
    for ip, users in sorted(failed.items(), key=lambda x: -len(x[1]))[:5]:
        print(f"  {ip:<18} → {RED}{len(users)} attempts{R}")

    print(f"\n  {BOLD}TOP SOURCE IPs:{R}")
    for ip, cnt in ip_freq.most_common(5):
        print(f"  {ip:<18} → {cnt} hits")

    print(f"{CYAN}{'='*60}{R}")
    input(f"\n  {DIM}Press Enter to continue...{R}")


# ═══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════
def main():
    print_banner()

    while True:
        print(f"\n{BOLD}  MAIN MENU{R}")
        print(f"  {DIM}{'─'*40}{R}")
        print(f"  {CYAN}[1]{R}  Password Strength Checker")
        print(f"  {CYAN}[2]{R}  Port Scanner")
        print(f"  {CYAN}[3]{R}  Network Scanner")
        print(f"  {CYAN}[4]{R}  File Encryption / Decryption")
        print(f"  {CYAN}[5]{R}  Log Analyzer")
        print(f"  {CYAN}[0]{R}  Exit")
        print(f"  {DIM}{'─'*40}{R}")

        choice = input(f"\n  {BOLD}Enter choice:{R} ").strip()

        if   choice == "1": check_password()
        elif choice == "2": port_scanner()
        elif choice == "3": network_scanner()
        elif choice == "4": file_encryptor()
        elif choice == "5": log_analyzer()
        elif choice == "0":
            print(f"\n  {GREEN}[*] Stay Secure! 🔐{R}\n")
            sys.exit(0)
        else:
            print(f"  {YELLOW}[!] Invalid choice.{R}")

if __name__ == "__main__":
    main()

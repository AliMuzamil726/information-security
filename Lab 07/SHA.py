import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext
from colorama import init

init(autoreset=True)


# Convert bytes to hex (same logic as Java)
def bytes_to_hex(byte_data):
    return ''.join(f"{byte:02X}" for byte in byte_data)


# SHA1 function
def sha1_hash(text):
    return hashlib.sha1(text.encode()).digest()


# Explanation generator (educational part)
def explain_sha1(text):
    return f"""
🔐 SHA-1 PROCESS EXPLANATION

1. INPUT:
   "{text}"

2. CONVERSION:
   Text is converted into binary format.

3. PROCESSING:
   SHA-1 applies mathematical compression:
   - Bitwise operations (AND, OR, XOR)
   - Rotations
   - Modular additions

4. BLOCKING:
   Data is processed in 512-bit blocks.

5. FINAL OUTPUT:
   A fixed 160-bit (20-byte) hash is generated.

⚠ SHA-1 is now considered cryptographically weak
✔ Modern systems use SHA-256 instead
"""


# GUI Function
def generate_hash():
    text = entry.get()

    if not text:
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, "❌ Please enter a value!")
        return

    result = sha1_hash(text)
    hex_result = bytes_to_hex(result)

    output_box.delete(1.0, tk.END)

    output_box.insert(tk.END, "🔹 INPUT:\n", "title")
    output_box.insert(tk.END, f"{text}\n\n", "normal")

    output_box.insert(tk.END, "🔹 SHA-1 HASH:\n", "title")
    output_box.insert(tk.END, f"{hex_result}\n\n", "hash")

    output_box.insert(tk.END, explain_sha1(text), "info")


# ---------------- GUI WINDOW ----------------
root = tk.Tk()
root.title("SHA-1 Visual Cryptography Tool")
root.geometry("750x600")
root.config(bg="#1e1e1e")

# Title
title = tk.Label(root, text="SHA-1 HASH GENERATOR", font=("Arial", 18, "bold"),
                 fg="white", bg="#1e1e1e")
title.pack(pady=10)

# Input frame
frame = tk.Frame(root, bg="#1e1e1e")
frame.pack()

entry = tk.Entry(frame, width=40, font=("Arial", 14))
entry.pack(side=tk.LEFT, padx=10)

btn = tk.Button(frame, text="Generate SHA-1", command=generate_hash,
                bg="#00c853", fg="white", font=("Arial", 12, "bold"))
btn.pack(side=tk.LEFT)

# Output box
output_box = scrolledtext.ScrolledText(root, width=85, height=25,
                                       font=("Consolas", 11),
                                       bg="#121212", fg="white",
                                       insertbackground="white")

output_box.pack(pady=15)

# Text styles
output_box.tag_config("title", foreground="#00e5ff", font=("Arial", 11, "bold"))
output_box.tag_config("hash", foreground="#00ff90", font=("Consolas", 12, "bold"))
output_box.tag_config("info", foreground="#ffffff")

# Run GUI
root.mainloop()

"""
===============================
        SHA-1 ALGORITHM
===============================

SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function
designed by the NSA in 1993 and standardized in 1995 (FIPS 180-1).

It takes any input and produces a fixed 160-bit (20-byte) hash value.

------------------------------------------------
STEP 1: INPUT MESSAGE
------------------------------------------------
- Take input string (e.g., "srm")
- Convert it into binary format (ASCII → bits)

------------------------------------------------
STEP 2: PADDING
------------------------------------------------
- Append a single '1' bit to the message
- Add '0' bits until length ≡ 448 (mod 512)
- Append original message length (64-bit value)

👉 Result: Message becomes multiple of 512-bit blocks

------------------------------------------------
STEP 3: INITIALIZATION
------------------------------------------------
SHA-1 uses 5 initial 32-bit hash values:

H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0

------------------------------------------------
STEP 4: PROCESS BLOCKS (512-bit each)
------------------------------------------------
For each block:

- Break block into 16 words (32-bit each)
- Extend to 80 words using bitwise operations

------------------------------------------------
STEP 5: MAIN COMPRESSION (80 ROUNDS)
------------------------------------------------
For i = 0 to 79:

- Apply logical functions:
  - AND, OR, XOR, NOT
- Use bitwise left rotation
- Add constants depending on round range

Round functions:
  0–19  : (B AND C) OR ((NOT B) AND D)
  20–39 : B XOR C XOR D
  40–59 : (B AND C) OR (B AND D) OR (C AND D)
  60–79 : B XOR C XOR D

------------------------------------------------
STEP 6: UPDATE HASH VALUES
------------------------------------------------
After processing each block:

- Add results to H0, H1, H2, H3, H4

------------------------------------------------
STEP 7: FINAL OUTPUT
------------------------------------------------
- Concatenate:
  H0 || H1 || H2 || H3 || H4

- Convert to hexadecimal string

👉 Final output = 160-bit SHA-1 hash

------------------------------------------------
IMPORTANT NOTE:
------------------------------------------------
- SHA-1 is now considered cryptographically weak
- Vulnerable to collision attacks (Google 2017 SHAttered attack)
- Modern systems use SHA-256 or SHA-3 instead

===============================
END OF SHA-1 ALGORITHM
===============================
"""
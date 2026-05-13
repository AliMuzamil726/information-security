import tkinter as tk
from tkinter import scrolledtext
import random


# ---------------- CORE DSA LOGIC ----------------
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, 200):
        if n % i == 0 and n != i:
            return False
    return True


def next_prime(n):
    while not is_prime(n):
        n += 1
    return n


def mod_inverse(a, m):
    return pow(a, -1, m)


# ---------------- GUI CLASS ----------------
class DSASimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("DSA Step-by-Step Visual Simulator")
        self.root.geometry("800x600")

        self.step = 0

        # Output box
        self.out = scrolledtext.ScrolledText(root, height=25, width=90)
        self.out.pack(pady=10)

        # Button
        self.btn = tk.Button(root, text="Next Step ▶", command=self.next_step,
                             bg="green", fg="white", font=("Arial", 12, "bold"))
        self.btn.pack()

        self.init_values()

    # ---------------- INITIAL VALUES ----------------
    def init_values(self):
        self.p = next_prime(10600)
        self.q = self.p - 1
        self.g = 2

        self.x = random.randint(1, self.q)
        self.y = pow(self.g, self.x, self.p)

        self.k = random.randint(1, self.q)
        self.hash_val = random.randint(1000, 9999)

    # ---------------- DISPLAY FUNCTION ----------------
    def show(self, text):
        self.out.insert(tk.END, text + "\n")
        self.out.see(tk.END)

    # ---------------- STEP-BY-STEP FLOW ----------------
    def next_step(self):

        if self.step == 0:
            self.show("\n🔐 STEP 1: Public Key Generation")
            self.show(f"p = {self.p}")
            self.show(f"q = {self.q}")
            self.show(f"g = {self.g}")

        elif self.step == 1:
            self.show("\n🔐 STEP 2: Private Key Generation")
            self.show(f"x (private key) = {self.x}")
            self.show(f"y (public key) = {self.y}")

        elif self.step == 2:
            self.show("\n✍ STEP 3: Message Hash + Random k")
            self.show(f"hash(m) = {self.hash_val}")
            self.show(f"k (random) = {self.k}")

        elif self.step == 3:
            self.show("\n✍ STEP 4: Signature Generation")
            self.r = pow(self.g, self.k, self.p) % self.q
            self.k_inv = mod_inverse(self.k, self.q)
            self.s = (self.k_inv * (self.hash_val + self.x * self.r)) % self.q

            self.show(f"r = {self.r}")
            self.show(f"s = {self.s}")

        elif self.step == 4:
            self.show("\n🔎 STEP 5: Verification Start")

            w = mod_inverse(self.s, self.q)
            u1 = (self.hash_val * w) % self.q
            u2 = (self.r * w) % self.q

            v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p
            v = v % self.q

            self.show(f"w = {w}")
            self.show(f"u1 = {u1}")
            self.show(f"u2 = {u2}")
            self.show(f"v = {v}")
            self.show(f"r = {self.r}")

            if v == self.r:
                self.show("\n✅ SIGNATURE VERIFIED SUCCESSFULLY!")
            else:
                self.show("\n❌ SIGNATURE VERIFICATION FAILED!")

        else:
            self.show("\n🔁 Simulation Complete. Restart program to run again.")
            self.btn.config(state="disabled")

        self.step += 1


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = DSASimulator(root)
    root.mainloop()

"""
========================================================
        DIGITAL SIGNATURE ALGORITHM (DSA)
                ALGORITHMS (COMMENT FORM)
========================================================

--------------------------------------------------------
ALGORITHM 1: KEY GENERATION
--------------------------------------------------------

1. Start
2. Choose a base number (e.g., 10600)
3. Find next prime number p such that:
      p is the smallest prime ≥ base value
4. Compute q such that:
      q is a prime factor of (p - 1)
5. Choose generator g:
      g = random value mod p
      g = g^((p - 1) / q) mod p
6. Generate private key:
      x = random integer in range (1 to q)
7. Generate public key:
      y = g^x mod p
8. Output:
      Public Key  = (p, q, g, y)
      Private Key = x
9. End


--------------------------------------------------------
ALGORITHM 2: DIGITAL SIGNATURE GENERATION
--------------------------------------------------------

1. Start
2. Input message m
3. Compute hash of message:
      h = hash(m)
4. Select random integer:
      k ∈ (1, q)
5. Compute:
      r = (g^k mod p) mod q
6. Compute modular inverse:
      k_inv = k^(-1) mod q
7. Compute signature value:
      s = k_inv * (h + x * r) mod q
8. Output signature:
      Signature = (r, s)
9. End


--------------------------------------------------------
ALGORITHM 3: DIGITAL SIGNATURE VERIFICATION
--------------------------------------------------------

1. Start
2. Input:
      Message m
      Signature (r, s)
      Public key (p, q, g, y)
3. Compute hash:
      h = hash(m)
4. Compute:
      w  = s^(-1) mod q
      u1 = (h * w) mod q
      u2 = (r * w) mod q
5. Compute verification value:
      v = (g^u1 * y^u2 mod p) mod q
6. Compare:
      If v == r → VALID SIGNATURE
      Else → INVALID SIGNATURE
7. End


--------------------------------------------------------
ALGORITHM 4: STEP-BY-STEP VISUAL SIMULATION FLOW
--------------------------------------------------------

1. Start GUI application
2. Initialize values:
      p, q, g
      x (private key)
      y (public key)
      k (random value)
      hash(m)
3. Display Step 1:
      Show public parameters (p, q, g)
4. Display Step 2:
      Show private key x and public key y
5. Display Step 3:
      Show hash(m) and random k
6. Display Step 4:
      Compute and display signature (r, s)
7. Display Step 5:
      Compute verification values (w, u1, u2, v)
8. Check:
      If v == r → SUCCESS
      Else → FAILURE
9. End simulation

========================================================
END OF DSA ALGORITHMS
========================================================
"""    
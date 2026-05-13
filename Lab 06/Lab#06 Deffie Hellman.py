#1
from colorama import Fore, Style, init
import math

init(autoreset=True)

# ---------------- PRIME CHECK ----------------
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

    return True


def main():

    print(Fore.CYAN + Style.BRIGHT + "\n===== DIFFIE-HELLMAN KEY EXCHANGE =====\n")

    # ---------------- PUBLIC PARAMETERS ----------------
    print(Fore.YELLOW + ">>> PUBLIC PARAMETERS")

    p = int(input(Fore.WHITE + "Enter prime number (p): "))

    if not is_prime(p):
        print(Fore.RED + Style.BRIGHT + "\n✖ ERROR: p must be a PRIME number only!\n")
        print(Fore.YELLOW + "Please restart the program and enter a valid prime.\n")
        return

    g = int(input(Fore.WHITE + f"Enter primitive root (g) of {p}: "))

    # ---------------- PRIVATE KEYS ----------------
    print(Fore.MAGENTA + "\n>>> PRIVATE KEYS (SECRET)")
    x = int(input(Fore.WHITE + "Person 1 private key (x): "))
    y = int(input(Fore.WHITE + "Person 2 private key (y): "))

    print(Fore.GREEN + "\n✔ Keys stored securely (not shared)\n")

    # ---------------- PUBLIC KEYS ----------------
    print(Fore.BLUE + Style.BRIGHT + ">>> PUBLIC KEY FORMULAS")

    print(Fore.WHITE + f"A = g^x mod p = {g}^{x} mod {p}")
    print(Fore.WHITE + f"B = g^y mod p = {g}^{y} mod {p}")

    A = pow(g, x, p)
    B = pow(g, y, p)

    print(Fore.BLUE + Style.BRIGHT + "\n>>> PUBLIC KEY VALUES")
    print(Fore.WHITE + f"Person 1 Public Key (A) = {A}")
    print(Fore.WHITE + f"Person 2 Public Key (B) = {B}")

    # ---------------- SECRET COMPUTATION ----------------
    print(Fore.MAGENTA + Style.BRIGHT + "\n>>> SECRET KEY FORMULAS")

    print(Fore.WHITE + f"S1 = B^x mod p = {B}^{x} mod {p}")
    print(Fore.WHITE + f"S2 = A^y mod p = {A}^{y} mod {p}")

    S1 = pow(B, x, p)
    S2 = pow(A, y, p)

    print(Fore.CYAN + Style.BRIGHT + "\n>>> SECRET KEY VALUES")
    print(Fore.CYAN + f"Person 1 Secret Key = {S1}")
    print(Fore.CYAN + f"Person 2 Secret Key = {S2}")

    # ---------------- RESULT ----------------
    print(Fore.YELLOW + Style.BRIGHT + "\n>>> FINAL RESULT")

    if S1 == S2:
        print(Fore.GREEN + f"✔ Shared Secret Key Successfully Generated: {S1}")
    else:
        print(Fore.RED + "✖ Error: Keys do not match")

    print(Fore.CYAN + "\n===== END OF EXCHANGE =====\n")


if __name__ == "__main__":
    main()
    """
    it is basically key exchange algorithm

==================== DIFFIE-HELLMAN (JAVA STYLE IMPLEMENTATION) ====================

1. INPUT PHASE
   - Read prime number p
   - Read primitive root g of p
   - Read private key x (Alice)
   - Read private key y (Bob)

2. PUBLIC KEY GENERATION

   Alice computes:
       R1 = g^x mod p

   Bob computes:
       R2 = g^y mod p

3. KEY EXCHANGE
   - Alice sends R1 to Bob
   - Bob sends R2 to Alice

4. SHARED SECRET KEY GENERATION

   Alice computes:
       k1 = R2^x mod p

   Bob computes:
       k2 = R1^y mod p

5. FINAL RESULT
   - If k1 == k2 → shared secret established successfully

6. CORE FORMULA

   k1 = (g^y)^x mod p = g^(xy) mod p
   k2 = (g^x)^y mod p = g^(xy) mod p

====================================================================================


"""

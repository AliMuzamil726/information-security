import random
import math
from colorama import Fore, init

init(autoreset=True)


class RSAVisual:

    # ================= PRIME GENERATION =================
    def generate_prime(self, bits):

        while True:

            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1

            if pow(2, num - 1, num) == 1:
                return num

    # ================= KEY GENERATION =================
    def keygen(self, bit_len=16):

        print(Fore.CYAN + "\n================ RSA KEY GENERATION ================\n")

        p = self.generate_prime(bit_len)
        q = self.generate_prime(bit_len)

        print(Fore.YELLOW + f"Prime p = {p}")
        print(Fore.YELLOW + f"Prime q = {q}\n")

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

        d = pow(e, -1, phi)

        print(Fore.GREEN + "✔ Public Key (e, n)")
        print(f"e = {e}, n = {n}")

        print(Fore.MAGENTA + "\n✔ Private Key (d)")
        print(f"d = {d}\n")

        return (e, n, d)

    # ================= ENCRYPT =================
    def encrypt(self, m, e, n):

        print(Fore.CYAN + "\n================ ENCRYPTION PROCESS ================\n")

        print(Fore.YELLOW + f"Message (m) = {m}")

        print("\nFormula:")
        print("c = m^e mod n\n")

        print("Step-by-step exponentiation (conceptual):")

        result = pow(m, e, n)

        print(f"c = {m}^{e} mod {n}")
        print(f"c = {result}\n")

        return result

    # ================= DECRYPT =================
    def decrypt(self, c, d, n):

        print(Fore.CYAN + "\n================ DECRYPTION PROCESS ================\n")

        print(Fore.YELLOW + f"Cipher (c) = {c}")

        print("\nFormula:")
        print("m = c^d mod n\n")

        result = pow(c, d, n)

        print(f"m = {c}^{d} mod {n}")
        print(f"m = {result}\n")

        return result


# ================= MAIN =================
if __name__ == "__main__":

    rsa = RSAVisual()

    e, n, d = rsa.keygen()

    message = int(input("Enter numeric message: "))

    cipher = rsa.encrypt(message, e, n)

    plain = rsa.decrypt(cipher, d, n)

    print(Fore.CYAN + "\n================ FINAL RESULT ================\n")

    print("Original Message :", message)
    print("Encrypted Value  :", cipher)
    print("Decrypted Value  :", plain)

    print(Fore.GREEN + "\n✔ RSA PROCESS COMPLETED SUCCESSFULLY\n")

    """
==================== RSA ALGORITHM WORKFLOW ====================

1. KEY GENERATION PHASE

   Step 1: Generate two large prime numbers
       p, q = large random probable primes

   Step 2: Compute modulus
       n = p * q
       (n is part of public + private key)

   Step 3: Compute Euler’s Totient
       φ(n) = (p - 1) * (q - 1)

   Step 4: Choose public exponent e
       - e is a prime number
       - Condition:
             gcd(e, φ(n)) = 1
       - If not valid → increment until valid

   Step 5: Compute private key d
       d = modular inverse of e mod φ(n)

   FINAL KEYS:
       Public Key  = (e, n)
       Private Key = (d, n)

------------------------------------------------------------

2. ENCRYPTION PROCESS

   Input:
       Message (bytes)

   Step 1: Convert message → integer
       m = bytes_to_int(message)

   Step 2: RSA encryption formula
       c = m^e mod n

   Step 3: Convert ciphertext integer → bytes

   Output:
       Ciphertext (bytes)

------------------------------------------------------------

3. DECRYPTION PROCESS

   Input:
       Ciphertext (bytes)

   Step 1: Convert ciphertext → integer
       c = bytes_to_int(ciphertext)

   Step 2: RSA decryption formula
       m = c^d mod n

   Step 3: Convert integer → bytes

   Step 4: Decode bytes → original string

   Output:
       Plaintext

------------------------------------------------------------

4. BYTE CONVERSION LOGIC

   - Message is converted using UTF-8 encoding
   - RSA works on INTEGER values, not characters
   - Therefore:
         bytes → integer → RSA → integer → bytes

------------------------------------------------------------

5. PRIMALITY TEST (SIMPLIFIED)

   - Random number generated using bit length
   - Ensures:
         number is odd
         high bit is set (correct size)
   - Fermat test:
         if (2^(n-1) mod n == 1) → probably prime

   NOTE:
       This is a probabilistic test (not cryptographically strong like Miller-Rabin)

------------------------------------------------------------

6. CORE RSA IDEA

   Encryption:
       c = m^e mod n

   Decryption:
       m = c^d mod n

   Security depends on:
       → difficulty of factoring n = p * q

------------------------------------------------------------

7. KEY CONCEPTS

   - RSA = Asymmetric cryptography
   - Two keys: Public + Private
   - Based on number theory
   - Security = integer factorization problem

==============================================================
"""
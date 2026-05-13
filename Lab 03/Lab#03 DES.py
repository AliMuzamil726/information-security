from Crypto.Cipher import DES
from colorama import Fore, Style, init

init(autoreset=True)


# ==================== PADDING ====================
def pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ==================== FAKE FEISTEL VISUAL (EDUCATION ONLY) ====================
def show_des_rounds():
    print(Fore.CYAN + "\n================ DES FEISTEL ROUNDS ================\n")

    for i in range(1, 17):

        print(Fore.YELLOW + f"🔁 ROUND {i}")

        print("   L(i) = R(i-1)")
        print("   R(i) = L(i-1) XOR F(R(i-1), K(i))")

        print("   F-function:")
        print("      Expansion (32 → 48 bits)")
        print("      XOR with Round Key")
        print("      S-box substitution")
        print("      P-box permutation\n")

    print(Fore.GREEN + "✔ 16 Feistel Rounds Completed (DES Core)\n")


# ==================== ENCRYPT ====================
def encrypt(key: bytes, plaintext: bytes) -> bytes:

    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(plaintext)

    return cipher.encrypt(padded)


# ==================== DECRYPT ====================
def decrypt(key: bytes, ciphertext: bytes) -> bytes:

    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted)


# ==================== MAIN ====================
def main():

    print(Fore.CYAN + "\n===================================")
    print("        DATA ENCRYPTION STANDARD")
    print("===================================\n")

    # KEY INPUT
    while True:
        key_hex = input(Fore.YELLOW + "Enter 8-byte KEY (16 hex chars): ")

        if len(key_hex) != 16:
            print(Fore.RED + "Invalid key length!")
            continue

        try:
            key = bytes.fromhex(key_hex)
            break
        except:
            print(Fore.RED + "Invalid hex format!")

    print(Fore.GREEN + "\n✔ Key Loaded:", key.hex())

    # MESSAGE INPUT
    msg = input(Fore.YELLOW + "\nEnter message: ")
    msg_bytes = msg.encode()

    # ================= VISUAL ROUNDS =================
    show_des_rounds()

    # ================= REAL ENCRYPTION =================
    print(Fore.CYAN + "\n================ REAL ENCRYPTION ================\n")

    encrypted = encrypt(key, msg_bytes)

    print(Fore.RED + "Ciphertext (HEX):")
    print(encrypted.hex())

    # ================= REAL DECRYPTION =================
    print(Fore.CYAN + "\n================ REAL DECRYPTION ================\n")

    decrypted = decrypt(key, encrypted)

    print(Fore.GREEN + "Recovered Text:")
    print(decrypted.decode())

    # ================= SUMMARY =================
    print(Fore.CYAN + "\n===================================")
    print("         FINAL SUMMARY")
    print("===================================\n")

    print("✔ DES = 16 Feistel Rounds")
    print("✔ Real encryption + decryption done")
    print("✔ Educational round visualization shown\n")


if __name__ == "__main__":
    main()



# Li = Ri-1
# Ri = Li-1 XOR F(Ri-1, Ki)


""" 
==================== DES ALGORITHM WORKFLOW ====================

1. INPUT PHASE
   - Take plaintext from user
   - Take 8-byte (64-bit) symmetric key in hex format
   - Convert key → bytes
   - Convert plaintext → bytes (UTF-8)

2. PADDING (PKCS#5)
   - DES works on 8-byte (64-bit) blocks only
   - If data length is not multiple of 8:
       pad_len = 8 - (len % 8)
       Add 'pad_len' bytes, each containing value pad_len

   Example:
       data = "HELLO" (5 bytes)
       padding = 3 bytes → [3,3,3]
       final block = 8 bytes

3. BLOCK DIVISION
   - Split padded plaintext into 8-byte blocks

4. ENCRYPTION (DES CORE PROCESS)

   For each 8-byte block:

   Step 1: Initial Permutation (IP)
       - Rearranges bits of 64-bit block

   Step 2: Split Block
       - L0 = left 32 bits
       - R0 = right 32 bits

   Step 3: 16 Feistel Rounds

       For i = 1 to 16:
           Li = Ri-1
           Ri = Li-1 XOR F(Ri-1, Ki)

       F-function:
           a) Expand R (32 → 48 bits)
           b) XOR with round key Ki
           c) Pass through S-boxes (non-linear substitution)
           d) Permutation (P-box)

   Step 4: Swap halves (L16, R16)

   Step 5: Final Permutation (FP = IP⁻¹)
       - Produces ciphertext block

5. OUTPUT
   - Combine all encrypted blocks
   - Convert to HEX for display

6. DECRYPTION (Reverse Process)

   - Use same key
   - Same steps but round keys in reverse order
   - After decryption:
       remove PKCS#5 padding
       return original plaintext

==================== IMPORTANT NOTES ====================

- DES is a symmetric algorithm (same key for encryption/decryption)
- Block size: 8 bytes (64 bits)
- Key size: 8 bytes (64 bits, effective 56 bits)
- ECB mode encrypts each block independently (not secure for real systems)
- S-box is the main source of security (non-linearity)

=========================================================
"""
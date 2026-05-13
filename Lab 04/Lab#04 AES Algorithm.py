import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from colorama import Fore, init

init(autoreset=True)


class AESRealVisual:

    # ---------------- KEY ----------------
    @staticmethod
    def generate_key():
        return os.urandom(16)

    # ---------------- VISUAL ROUNDS (EXPLANATION ONLY) ----------------
    @staticmethod
    def show_rounds():

        print(Fore.CYAN + "\n================ AES INTERNAL ROUNDS =================\n")

        for r in range(1, 11):

            print(Fore.YELLOW + f"🔁 ROUND {r}")

            print("  [SubBytes]     → Byte substitution (confusion)")
            print("  [ShiftRows]    → Row shifting (diffusion)")

            if r != 10:
                print("  [MixColumns]   → Column mixing (math transformation)")
            else:
                print("  [MixColumns]   → NOT USED in final round")

            print("  [AddRoundKey]  → XOR with round key\n")

        print(Fore.GREEN + "✔ 10 Rounds Completed (AES-128)\n")

    # ---------------- ENCRYPT ----------------
    @staticmethod
    def encrypt(text, key):

        print(Fore.CYAN + "\n================ REAL ENCRYPTION STARTED ================\n")

        iv = os.urandom(16)

        # Padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()

        # AES Cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        cipher_bytes = encryptor.update(padded_data) + encryptor.finalize()

        final_data = iv + cipher_bytes
        encoded = base64.b64encode(final_data).decode()

        print(Fore.GREEN + "✔ REAL AES Encryption Done\n")
        print(Fore.YELLOW + "Ciphertext (Base64):")
        print(encoded + "\n")

        return encoded

    # ---------------- DECRYPT ----------------
    @staticmethod
    def decrypt(encoded, key):

        print(Fore.CYAN + "\n================ REAL DECRYPTION STARTED ================\n")

        data = base64.b64decode(encoded)

        iv = data[:16]
        cipher_bytes = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded = decryptor.update(cipher_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()

        print(Fore.GREEN + "✔ REAL AES Decryption Done\n")
        print(Fore.BLUE + "Recovered Plaintext:")
        print(plain.decode() + "\n")

        return plain.decode()


# ================= MAIN =================
if __name__ == "__main__":

    print(Fore.CYAN + "\n======================================")
    print("        AES REAL SYSTEM")
    print("======================================\n")

    text = input("Enter text to encrypt: ")

    # Key generation
    key = AESRealVisual.generate_key()

    print(Fore.MAGENTA + "\n🔑 Generated Key:")
    print(key.hex())

    # 🔁 VISUAL ROUNDS (EXPLANATION)
    AESRealVisual.show_rounds()

    # 🔐 REAL ENCRYPTION
    encrypted = AESRealVisual.encrypt(text, key)

    # 🔓 REAL DECRYPTION
    AESRealVisual.decrypt(encrypted, key)

    """
==================== AES ENCRYPTION / DECRYPTION ALGORITHM ====================

1. INPUT PHASE
   - Take plaintext string from user
   - Convert string → UTF-8 bytes internally

2. KEY INITIALIZATION
   - Predefined symmetric key (16 bytes = 128-bit AES key)
     Example:
         encryptionKey = b"ABCDEFGHIJKLMNOP"

   - This key is used for:
         Encryption + Decryption (symmetric cryptography)

3. INITIALIZATION VECTOR (IV)
   - Mode used: CBC (Cipher Block Chaining)
   - IV = same as encryption key (NOT secure in real systems, but used here for learning/demo)

4. PADDING (PKCS7)
   - AES works on 16-byte blocks (128 bits)
   - If plaintext is not multiple of 16 bytes:
         add padding bytes

   Formula:
         pad_len = 16 - (len % 16)
         each padding byte = pad_len

   Example:
         "HELLO" → padded to 16 bytes

5. ENCRYPTION PROCESS

   Step 1: Create AES Cipher
       AES(key, CBC mode, IV)

   Step 2: Apply Padding
       plaintext → padded plaintext

   Step 3: Encrypt
       cipherText = AES_Encrypt(padded_data)

   Step 4: Encode Output
       - Convert binary ciphertext → Base64 string
       (for readable transmission/storage)

   OUTPUT:
       Base64 Encrypted String

6. DECRYPTION PROCESS

   Step 1: Base64 Decode
       encryptedText → bytes

   Step 2: AES Decryption
       ciphertext → padded_plaintext

   Step 3: Remove Padding
       PKCS7 unpadding applied

   Step 4: Convert Bytes → String
       UTF-8 decoding

   OUTPUT:
       Original Plaintext

==================== AES WORKFLOW DIAGRAM ====================

Plaintext
   ↓
UTF-8 Encoding
   ↓
PKCS7 Padding (16-byte blocks)
   ↓
AES-CBC Encryption (Key + IV)
   ↓
Ciphertext (Binary)
   ↓
Base64 Encoding
   ↓
Encrypted String

Decryption (Reverse Process):
Base64 → AES Decrypt → Remove Padding → Original Text

==================== IMPORTANT CONCEPTS ====================

- AES = Advanced Encryption Standard (Rijndael algorithm, 2001 NIST)
- Block size = 128 bits (16 bytes)
- Key size = 128/192/256 bits (here 128-bit used)
- CBC mode = each block depends on previous block
- PKCS7 padding = ensures full block alignment
- Base64 = encoding for safe string representation

==================== SECURITY NOTE ====================

- Using KEY as IV is NOT secure in real-world cryptography
- CBC mode requires random IV for strong security

===============================================================================
| Version | Key Size | Rounds    |
| ------- | -------- | --------- |
| AES-128 | 128-bit  | 10 rounds |
| AES-192 | 192-bit  | 12 rounds |
| AES-256 | 256-bit  | 14 rounds |

"""
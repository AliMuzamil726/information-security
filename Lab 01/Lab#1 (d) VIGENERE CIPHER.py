from colorama import Fore, Style, init

init(autoreset=True)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ================= KEY GENERATION =================
def generate_key(text, key):
    key = key.upper()
    out, j = "", 0

    print(Fore.CYAN + "\n🔑 KEY EXPANSION PROCESS")

    for ch in text.upper():
        if ch in ALPHABET:
            out += key[j % len(key)]
            j += 1
        else:
            out += ch

    print(Fore.YELLOW + "Expanded Key:")
    print(out + "\n")

    return out


# ================= CORE PROCESS =================
def process(text, key, mode):

    text = text.upper()
    key = generate_key(text, key)

    result = ""

    print(Fore.CYAN + "\n📊 CHARACTER-BY-CHARACTER PROCESS\n")

    for i, (t, k) in enumerate(zip(text, key)):

        if t not in ALPHABET:
            result += t
            continue

        ti = ALPHABET.index(t)
        ki = ALPHABET.index(k)

        if mode == "enc":
            value = (ti + ki) % 26
            operation = "+"
        else:
            value = (ti - ki + 26) % 26
            operation = "-"

        enc_char = ALPHABET[value]
        result += enc_char

        print(Fore.YELLOW + f"Step {i+1}")
        print(f"Text Char : {t} ({ti})")
        print(f"Key Char  : {k} ({ki})")
        print(f"Formula   : ({ti} {operation} {ki}) mod 26 = {value}")
        print(Fore.GREEN + f"Result    : {enc_char}\n")

    return result


# ================= ENCRYPT =================
def encrypt(text, key):
    print(Fore.MAGENTA + "\n🔐 ENCRYPTION STARTED")
    return process(text, key, "enc")


# ================= DECRYPT =================
def decrypt(text, key):
    print(Fore.MAGENTA + "\n🔓 DECRYPTION STARTED")
    return process(text, key, "dec")


# ================= MAIN =================
print(Fore.CYAN + "\n======================================")
print("        VIGENÈRE CIPHER SYSTEM")
print("======================================\n")

plain_text = input(Fore.YELLOW + "Enter plaintext: ")
key = input(Fore.YELLOW + "Enter key: ")

# ENCRYPT
cipher = encrypt(plain_text, key)

print(Fore.RED + "\n===== FINAL CIPHER TEXT =====")
print(cipher)

# DECRYPT
decrypted = decrypt(cipher, key)

print(Fore.GREEN + "\n===== FINAL PLAINTEXT =====")
print(decrypted)

print(Fore.CYAN + "\n======================================")
print("         PROCESS COMPLETED")
print("======================================\n")
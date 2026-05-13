from colorama import Fore, Style, init

init(autoreset=True)
#hi
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def caesar(text, key):
    out = ""
    for ch in text.upper():
        if ch in ALPHABET:
            i = ALPHABET.index(ch)
            out += ALPHABET[(i + key) % 26]
        else:
            out += ch
    return out
# ================= MAIN =================
print(Fore.CYAN + "\n===== CAESAR CIPHER ENCRYPTION SYSTEM =====\n")

msg = input(Fore.YELLOW + "Enter plain text: ")
key = int(input(Fore.YELLOW + "Enter key (0-25): "))

print(Fore.BLUE + "\n--- PROCESSING ---")

enc = caesar(msg, key)
dec = caesar(enc, -key)

print(Fore.RED + "\n===== RESULT =====")

print(Fore.GREEN + "Encrypted Text: " + enc)
print(Fore.MAGENTA + "Decrypted Text: " + dec)

print(Fore.CYAN + "\n===== CAESAR CIPHER COMPLETED =====\n")
#Changeing
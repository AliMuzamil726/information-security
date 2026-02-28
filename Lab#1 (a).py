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


msg = input("Enter plain text: ")
key = int(input("Enter key (0-25): "))

enc = caesar(msg, key)
dec = caesar(enc, -key)

print("Encrypted:", enc)
print("Decrypted:", dec)
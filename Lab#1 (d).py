ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def generate_key(text, key):
    key = key.upper()
    out, j = "", 0

    for ch in text:
        if ch in ALPHABET:
            out += key[j % len(key)]
            j += 1
        else:
            out += ch

    return out


def process(text, key, mode):
    text = text.upper()
    key = generate_key(text, key)
    out = ""

    for t, k in zip(text, key):
        if t in ALPHABET:
            ti = ALPHABET.index(t)
            ki = ALPHABET.index(k)
            value = (ti + ki) % 26 if mode == "enc" else (ti - ki + 26) % 26
            out += ALPHABET[value]
        else:
            out += t

    return out


def encrypt(plain_text, key):
    return process(plain_text, key, "enc")


def decrypt(cipher_text, key):
    return process(cipher_text, key, "dec")


plain_text = input("Enter plaintext: ")
key = input("Enter key: ")

cipher = encrypt(plain_text, key)
print("Encrypted Text:", cipher)

decrypted = decrypt(cipher, key)
print("Decrypted Text:", decrypted)
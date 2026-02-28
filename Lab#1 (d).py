ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Convert text to numbers
def text_to_numbers(text):
    return [ALPHABET.index(c) for c in text]

# Convert numbers to text
def numbers_to_text(nums):
    return "".join(ALPHABET[n % 26] for n in nums)

# Repeat key to match plaintext length (Step 2)
def generate_key(plain_text, key):
    key = key.upper()
    key_repeated = ""
    j = 0

    for i in range(len(plain_text)):
        if plain_text[i] in ALPHABET:
            key_repeated += key[j % len(key)]
            j += 1
        else:
            key_repeated += plain_text[i]

    return key_repeated

# Encryption (Step 4)
def encrypt(plain_text, key):
    plain_text = plain_text.upper()
    key = generate_key(plain_text, key)

    cipher_text = ""

    for p, k in zip(plain_text, key):
        if p in ALPHABET:
            Pi = ALPHABET.index(p)
            Ki = ALPHABET.index(k)

            Ei = (Pi + Ki) % 26   # Ei = (Pi + Ki) mod 26
            cipher_text += ALPHABET[Ei]
        else:
            cipher_text += p

    return cipher_text

# Decryption (Step 5)
def decrypt(cipher_text, key):
    cipher_text = cipher_text.upper()
    key = generate_key(cipher_text, key)

    plain_text = ""

    for c, k in zip(cipher_text, key):
        if c in ALPHABET:
            Ei = ALPHABET.index(c)
            Ki = ALPHABET.index(k)

            Di = (Ei - Ki + 26) % 26   # Di = (Ei - Ki + 26) mod 26
            plain_text += ALPHABET[Di]
        else:
            plain_text += c

    return plain_text


# -------- MAIN PROGRAM --------
plain_text = input("Enter plaintext: ")
key = input("Enter key: ")

cipher = encrypt(plain_text, key)
print("Encrypted Text:", cipher)

decrypted = decrypt(cipher, key)
print("Decrypted Text:", decrypted)
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# List of prime numbers between 1 and 26
PRIMES = {2, 3, 5, 7, 11, 13, 17, 19, 23}


def caesar(text, key):
    result = ""
    for ch in text.upper():
        if ch in ALPHABET:
            index = ALPHABET.index(ch)
            new_index = (index + key) % 26
            result += ALPHABET[new_index]
        else:
            result += ch
    return result


# --- Input Section ---
msg = input("Enter plain text: ")

try:
    key = int(input("Enter key (1-26 and prime only): "))

    # Check range
    if key < 1 or key > 26:
        raise ValueError("Key must be between 1 and 26.")

    # Check prime condition
    if key not in PRIMES:
        raise ValueError("Key must be a prime number (2,3,5,7,11,13,17,19,23).")

except ValueError as e:
    print("Error:", e)
    exit()

# --- Encryption / Decryption ---
enc = caesar(msg, key)
dec = caesar(enc, -key)

print("Encrypted:", enc)
print("Decrypted:", dec)
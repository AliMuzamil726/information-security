ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PRIMES = {2, 3, 5, 7, 11, 13, 17, 19, 23}


def caesar(text, key):
    result = []
    for ch in text.upper():
        if ch in ALPHABET:
            idx = ALPHABET.index(ch)
            result.append(ALPHABET[(idx + key) % 26])
        else:
            result.append(ch)
    return "".join(result)


def validate_key(raw_key):
    key = int(raw_key)
    if key < 1 or key > 26:
        raise ValueError("Key must be between 1 and 26.")
    if key not in PRIMES:
        raise ValueError("Key must be a prime number (2,3,5,7,11,13,17,19,23).")
    return key


def main():
    message = input("Enter plain text: ")
    try:
        key = validate_key(input("Enter key (1-26 and prime only): "))
    except ValueError as exc:
        print("Error:", exc)
        return

    encrypted = caesar(message, key)
    decrypted = caesar(encrypted, -key)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()

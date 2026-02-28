ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J merged with I


def generate_key_matrix(key):
    chars = []
    for ch in (key.upper().replace("J", "I") + ALPHABET):
        if ch in ALPHABET and ch not in chars:
            chars.append(ch)
    return [chars[i:i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = "".join(ch for ch in text.upper().replace("J", "I") if ch in ALPHABET)
    out, i = "", 0

    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            out += a + "X"
            i += 1
        else:
            out += a + b
            i += 2

    return out if len(out) % 2 == 0 else out + "X"


def find_position(matrix, ch):
    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)


def encrypt(plain_text, matrix):
    out = ""
    for i in range(0, len(plain_text), 2):
        a, b = plain_text[i], plain_text[i + 1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            out += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            out += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            out += matrix[r1][c2] + matrix[r2][c1]

    return out


def decrypt(cipher_text, matrix):
    out = ""
    for i in range(0, len(cipher_text), 2):
        a, b = cipher_text[i], cipher_text[i + 1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            out += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:
            out += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        else:
            out += matrix[r1][c2] + matrix[r2][c1]

    return out


def main():
    key = input("Enter key: ")
    matrix = generate_key_matrix(key)

    print("\nKey Matrix:")
    for row in matrix:
        print(row)

    plain = input("\nEnter plain text: ")
    prepared = prepare_text(plain)
    cipher = encrypt(prepared, matrix)
    decoded = decrypt(cipher, matrix)

    print("Prepared Text:", prepared)
    print("Encrypted Text:", cipher)
    print("Decrypted Text:", decoded)


main()
def generate_key_order(key):
    key = key.upper()
    order = [0] * len(key)
    for rank, (idx, _) in enumerate(sorted(enumerate(key), key=lambda x: (x[1], x[0])), 1):
        order[idx] = rank
    return order


def encrypt(plain_text, key):
    plain_text = plain_text.replace(" ", "").upper()
    cols = len(key)
    rows = -(-len(plain_text) // cols)

    matrix = [
        [plain_text[r * cols + c] if r * cols + c < len(plain_text) else 'X' for c in range(cols)]
        for r in range(rows)
    ]

    key_order = generate_key_order(key)
    cipher_text = ""
    for num in range(1, cols + 1):
        col_index = key_order.index(num)
        for r in range(rows):
            cipher_text += matrix[r][col_index]
    return cipher_text


def decrypt(cipher_text, key):
    cols = len(key)
    rows = len(cipher_text) // cols
    key_order = generate_key_order(key)
    matrix = [['' for _ in range(cols)] for _ in range(rows)]

    index = 0
    for num in range(1, cols + 1):
        col_index = key_order.index(num)
        for r in range(rows):
            matrix[r][col_index] = cipher_text[index]
            index += 1

    plain_text = ""
    for r in range(rows):
        for c in range(cols):
            plain_text += matrix[r][c]
    return plain_text.rstrip('X')


plain_text = input("Enter plaintext: ")
key = input("Enter key: ")

cipher = encrypt(plain_text, key)
print("Encrypted Text:", cipher)

print("Decrypted Text:", decrypt(cipher, key))

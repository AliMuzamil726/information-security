import numpy as np

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Convert text to numbers
def text_to_numbers(text):
    return [ALPHABET.index(char) for char in text]

# Convert numbers to text
def numbers_to_text(nums):
    return "".join(ALPHABET[num % 26] for num in nums)

# Prepare plaintext
def prepare_text(text, n):
    text = text.upper().replace(" ", "")
    while len(text) % n != 0:
        text += "X"
    return text

# Modular inverse (for determinant)
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("❌ Key matrix is not invertible modulo 26")

# Compute matrix inverse mod 26 (FIXED)
def matrix_inverse(matrix):
    det = int(round(np.linalg.det(matrix)))
    det_mod = det % 26

    det_inv = mod_inverse(det_mod, 26)

    # Adjugate matrix method (avoids float errors)
    matrix_adj = np.round(det * np.linalg.inv(matrix)).astype(int)
    inv_matrix = (det_inv * matrix_adj) % 26

    return inv_matrix

# Encryption
def encrypt(plain_text, key_matrix):
    n = key_matrix.shape[0]
    plain_text = prepare_text(plain_text, n)
    cipher_text = ""

    for i in range(0, len(plain_text), n):
        block = plain_text[i:i+n]
        vector = np.array(text_to_numbers(block)).reshape(n, 1)

        cipher_vector = np.dot(key_matrix, vector) % 26
        cipher_text += numbers_to_text(cipher_vector.flatten())

    return cipher_text

# Decryption
def decrypt(cipher_text, key_matrix):
    n = key_matrix.shape[0]
    inv_matrix = matrix_inverse(key_matrix)
    plain_text = ""

    for i in range(0, len(cipher_text), n):
        block = cipher_text[i:i+n]
        vector = np.array(text_to_numbers(block)).reshape(n, 1)

        plain_vector = np.dot(inv_matrix, vector) % 26
        plain_text += numbers_to_text(plain_vector.flatten())

    return plain_text


# -------- MAIN PROGRAM --------
n = int(input("Enter matrix size n: "))

print("Enter key matrix row by row:")
key = []
for _ in range(n):
    key.append(list(map(int, input().split())))

key_matrix = np.array(key)

plain_text = input("Enter plaintext: ")

cipher = encrypt(plain_text, key_matrix)
print("Encrypted Text:", cipher)

decrypted = decrypt(cipher, key_matrix)
print("Decrypted Text:", decrypted)
import math
import numpy as np

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def text_to_numbers(text):
    return [ALPHABET.index(ch) for ch in text]


def numbers_to_text(nums):
    return "".join(ALPHABET[n % 26] for n in nums)


def prepare_text(text, n):
    text = "".join(ch for ch in text.upper() if ch in ALPHABET)
    while len(text) % n != 0:
        text += "X"
    return text


def mod_inverse(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Key matrix is not invertible modulo 26")


def matrix_is_valid(matrix):
    det = int(round(np.linalg.det(matrix)))
    return math.gcd(det % 26, 26) == 1


def matrix_inverse(matrix):
    det = int(round(np.linalg.det(matrix)))
    det_inv = mod_inverse(det % 26)
    adj = np.round(det * np.linalg.inv(matrix)).astype(int)
    return (det_inv * adj) % 26


def run_blocks(text, matrix, n):
    out = ""
    for i in range(0, len(text), n):
        block = text[i:i + n]
        vec = np.array(text_to_numbers(block)).reshape(n, 1)
        out += numbers_to_text((matrix @ vec % 26).flatten())
    return out


def encrypt(plain_text, key_matrix):
    n = key_matrix.shape[0]
    return run_blocks(prepare_text(plain_text, n), key_matrix, n)


def decrypt(cipher_text, key_matrix):
    n = key_matrix.shape[0]
    return run_blocks(cipher_text, matrix_inverse(key_matrix), n)


def read_key_matrix(n):
    while True:
        print("Enter key matrix row by row:")
        key = [list(map(int, input().split())) for _ in range(n)]
        key_matrix = np.array(key)

        if key_matrix.shape != (n, n):
            print("Error: Enter exactly", n, "numbers in each row. Try again.\n")
            continue

        if not matrix_is_valid(key_matrix):
            print("Error: Key matrix is not invertible modulo 26. Enter another matrix.\n")
            continue

        return key_matrix


def main():
    n = int(input("Enter matrix size n: "))
    key_matrix = read_key_matrix(n)

    plain_text = input("Enter plaintext: ")
    cipher = encrypt(plain_text, key_matrix)
    decrypted = decrypt(cipher, key_matrix)

    print("Encrypted Text:", cipher)
    print("Decrypted Text:", decrypted)


main()
import numpy as np
import math
from colorama import Fore, init

init(autoreset=True)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ================= TEXT ↔ NUMBERS =================
def text_to_numbers(text):
    return [ALPHABET.index(ch) for ch in text]


def numbers_to_text(nums):
    return "".join(ALPHABET[n % 26] for n in nums)


# ================= PREPARE TEXT =================
def prepare_text(text, n):
    text = "".join(ch for ch in text.upper() if ch in ALPHABET)

    while len(text) % n != 0:
        text += "X"

    return text


# ================= MATRIX VALIDITY =================
def mod_inverse(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise Exception("Matrix not invertible")


def matrix_is_valid(matrix):
    det = int(round(np.linalg.det(matrix)))
    return math.gcd(det % 26, 26) == 1


def matrix_inverse(matrix):
    det = int(round(np.linalg.det(matrix)))
    det_inv = mod_inverse(det % 26)

    adj = np.round(det * np.linalg.inv(matrix)).astype(int)

    return (det_inv * adj) % 26


# ================= VISUAL BLOCK PROCESS =================
def process_blocks(text, matrix, n, mode="enc"):

    result = ""

    print(Fore.CYAN + "\n================ BLOCK PROCESSING ================\n")

    for i in range(0, len(text), n):

        block = text[i:i+n]
        vec = np.array(text_to_numbers(block)).reshape(n, 1)

        print(Fore.YELLOW + f"🔹 Block: {block}")
        print("Vector:")
        print(vec.flatten())

        print("\nMatrix:")
        print(matrix)

        if mode == "enc":
            print(Fore.MAGENTA + "\nFormula:")
            print("C = K × P mod 26\n")
            transformed = (matrix @ vec) % 26
        else:
            print(Fore.MAGENTA + "\nFormula:")
            print("P = K⁻¹ × C mod 26\n")
            transformed = (matrix @ vec) % 26

        print("Result Vector:")
        print(transformed.flatten())

        result += numbers_to_text(transformed.flatten())

        print(Fore.GREEN + "✔ Converted Block\n")
        print("------------------------------------------------\n")

    return result


# ================= ENCRYPT =================
def encrypt(text, key_matrix):
    return process_blocks(prepare_text(text, key_matrix.shape[0]), key_matrix, key_matrix.shape[0], "enc")


# ================= DECRYPT =================
def decrypt(text, key_matrix):
    inv = matrix_inverse(key_matrix)
    return process_blocks(text, inv, key_matrix.shape[0], "dec")


# ================= MAIN =================
def main():

    print(Fore.CYAN + "\n======================================")
    print("        HILL CIPHER VISUAL SYSTEM")
    print("======================================\n")

    n = int(input("Enter matrix size (n): "))

    print(Fore.YELLOW + "\nEnter KEY MATRIX row by row:")

    key = []
    for _ in range(n):
        key.append(list(map(int, input().split())))

    key_matrix = np.array(key)

    print(Fore.BLUE + "\n✔ Key Matrix:")
    print(key_matrix)

    if not matrix_is_valid(key_matrix):
        print(Fore.RED + "\nMatrix NOT invertible mod 26!")
        return

    text = input(Fore.YELLOW + "\nEnter plaintext: ")

    # ================= ENCRYPT =================
    print(Fore.CYAN + "\n================ ENCRYPTION =================\n")

    cipher = encrypt(text, key_matrix)

    print(Fore.RED + "\n✔ CIPHER TEXT:")
    print(cipher)

    # ================= DECRYPT =================
    print(Fore.CYAN + "\n================ DECRYPTION =================\n")

    plain = decrypt(cipher, key_matrix)

    print(Fore.GREEN + "\n✔ RECOVERED TEXT:")
    print(plain)


if __name__ == "__main__":
    main()
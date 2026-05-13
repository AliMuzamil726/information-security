from colorama import Fore, init

init(autoreset=True)

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J merged with I


# ================= KEY MATRIX =================
def generate_key_matrix(key):

    chars = []

    for ch in (key.upper().replace("J", "I") + ALPHABET):

        if ch in ALPHABET and ch not in chars:
            chars.append(ch)

    matrix = [chars[i:i+5] for i in range(0, 25, 5)]

    print(Fore.CYAN + "\n🔑 KEY MATRIX (5x5)\n")

    for row in matrix:
        print(" ".join(row))

    return matrix


# ================= TEXT PREPARATION =================
def prepare_text(text):

    text = "".join(ch for ch in text.upper().replace("J", "I") if ch in ALPHABET)

    result = ""
    i = 0

    print(Fore.CYAN + "\n📌 DIGRAPH FORMATION:\n")

    while i < len(text):

        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"

        if a == b:
            result += a + "X"
            print(f"{a}X")
            i += 1
        else:
            result += a + b
            print(f"{a}{b}")
            i += 2

    if len(result) % 2 != 0:
        result += "X"

    return result


# ================= FIND POSITION =================
def find(matrix, ch):

    for r, row in enumerate(matrix):
        if ch in row:
            return r, row.index(ch)

    return None


# ================= ENCRYPT =================
def encrypt(text, matrix):

    print(Fore.CYAN + "\n🔐 ENCRYPTION STEPS\n")

    out = ""

    for i in range(0, len(text), 2):

        a, b = text[i], text[i+1]

        pos_a = find(matrix, a)
        pos_b = find(matrix, b)
        
        if pos_a is None or pos_b is None:
            continue
        
        r1, c1 = pos_a
        r2, c2 = pos_b

        print(Fore.YELLOW + f"Pair: {a}{b}")

        # SAME ROW
        if r1 == r2:
            print("Rule: Same Row → shift right")

            out += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]

        # SAME COLUMN
        elif c1 == c2:
            print("Rule: Same Column → shift down")

            out += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]

        # RECTANGLE RULE
        else:
            print("Rule: Rectangle Swap")

            out += matrix[r1][c2] + matrix[r2][c1]

        print(Fore.GREEN + "Result added\n")

    return out


# ================= DECRYPT =================
def decrypt(text, matrix):

    print(Fore.CYAN + "\n🔓 DECRYPTION STEPS\n")

    out = ""

    for i in range(0, len(text), 2):

        a, b = text[i], text[i+1]

        pos_a = find(matrix, a)
        pos_b = find(matrix, b)
        
        if pos_a is None or pos_b is None:
            continue
        
        r1, c1 = pos_a
        r2, c2 = pos_b

        print(Fore.YELLOW + f"Pair: {a}{b}")

        if r1 == r2:
            print("Rule: Same Row → shift left")
            out += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]

        elif c1 == c2:
            print("Rule: Same Column → shift up")
            out += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]

        else:
            print("Rule: Rectangle Swap Reverse")
            out += matrix[r1][c2] + matrix[r2][c1]

        print(Fore.GREEN + "Recovered\n")

    return out


# ================= MAIN =================
def main():

    print(Fore.CYAN + "\n===================================")
    print("      PLAYFAIR CIPHER SYSTEM")
    print("===================================\n")

    key = input("Enter key: ")

    matrix = generate_key_matrix(key)

    text = input(Fore.YELLOW + "\nEnter plaintext: ")

    prepared = prepare_text(text)

    print(Fore.MAGENTA + "\nPrepared Text:")
    print(prepared)

    cipher = encrypt(prepared, matrix)

    print(Fore.RED + "\n===== CIPHER TEXT =====")
    print(cipher)

    plain = decrypt(cipher, matrix)

    print(Fore.GREEN + "\n===== DECRYPTED TEXT =====")
    print(plain)

    print(Fore.CYAN + "\n===================================")
    print("        PROCESS COMPLETED")
    print("===================================\n")


if __name__ == "__main__":
    main()
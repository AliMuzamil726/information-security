from colorama import Fore, Style, init

init(autoreset=True)


class Railfence:
    def process(self):

        print(Fore.CYAN + "\n===== RAIL FENCE / COLUMNAR STYLE ENCRYPTION =====\n")

        # 1. Key input
        print(Fore.YELLOW + "Enter key:")
        word_key = input().strip()

        print(Fore.BLUE + "\nKey (Original):")
        print(" ".join(list(word_key)))

        # sorted key
        sorted_chars = sorted(list(word_key))
        print(Fore.BLUE + "\nKey (Sorted):")
        print(" ".join(sorted_chars))

        # numerical representation
        sorted_with_indices = sorted([(char, idx) for idx, char in enumerate(word_key)])
        key_num = [item[1] for item in sorted_with_indices]

        print(Fore.MAGENTA + "\nKEY : NUMERICAL REPRESENTATION")
        print(Fore.WHITE + " ".join(map(str, key_num)))

        # 2. Plain text
        print(Fore.YELLOW + "\nEnter PLAIN TEXT:")
        plain = input().strip()

        print(Fore.GREEN + "\nPlain Text:")
        print(plain)

        cols = len(word_key)
        length = len(plain)

        # padding
        if length % cols != 0:
            rows = (length // cols) + 1
            plain_padded = plain + 'X' * (cols - (length % cols))
        else:
            rows = length // cols
            plain_padded = plain

        print(Fore.CYAN + "\n--- Matrix Formation ---\n")

        # build matrix
        mat = []
        idx = 0
        for i in range(rows):
            row = []
            for j in range(cols):
                row.append(plain_padded[idx])
                idx += 1
            mat.append(row)

        # print matrix
        for row in mat:
            print(" ".join(row))

        # encryption
        enctxt = ""
        for k in range(cols):
            p = 0
            for index, val in enumerate(key_num):
                if val == k:
                    p = index
                    break

            for r in range(rows):
                enctxt += mat[r][p]

        print(Fore.RED + "\n===== CIPHER TEXT =====")
        print(Fore.WHITE + enctxt)

        # decryption matrix
        cmat = [['' for _ in range(cols)] for _ in range(rows)]

        q = 0
        for k in range(cols):
            p = 0
            for index, val in enumerate(key_num):
                if val == k:
                    p = index
                    break

            for r in range(rows):
                cmat[r][p] = enctxt[q]
                q += 1

        print(Fore.CYAN + "\n--- Decryption Matrix ---\n")
        for row in cmat:
            print(" ".join(row))

        # final plaintext
        ptext = ""
        for r in range(rows):
            for c in range(cols):
                ptext += cmat[r][c]

        ptext = ptext[:length]

        print(Fore.GREEN + "\n===== FINAL PLAIN TEXT =====")
        print(ptext)
        print(Fore.CYAN + "\nEncryption-Decryption Completed\n")


if __name__ == "__main__":
    rf = Railfence()
    rf.process()
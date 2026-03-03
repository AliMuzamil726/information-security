# Full DES Implementation
# (All S-boxes included)

from textwrap import wrap

# ---------- Helper Functions ----------

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def shift_left(block, n):
    return block[n:] + block[:n]

def xor(a, b):
    return ''.join('0' if i == j else '1' for i, j in zip(a, b))

def sbox_substitution(block48):
    result = ""
    blocks = wrap(block48, 6)

    for i, block in enumerate(blocks):
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        result += format(S_BOXES[i][row][col], '04b')

    return result

# ---------- Key Schedule ----------

def generate_keys(key64):
    key56 = permute(key64, PC1)
    C, D = key56[:28], key56[28:]
    keys = []

    for shift in SHIFT_TABLE:
        C = shift_left(C, shift)
        D = shift_left(D, shift)
        keys.append(permute(C + D, PC2))

    return keys

# ---------- DES Function ----------

def des(block64, keys, encrypt=True):
    block = permute(block64, IP)
    L, R = block[:32], block[32:]

    if not encrypt:
        keys = keys[::-1]

    for i in range(16):
        expanded = permute(R, E)
        temp = xor(expanded, keys[i])
        substituted = sbox_substitution(temp)
        permuted = permute(substituted, P)
        new_R = xor(L, permuted)
        L, R = R, new_R

    combined = R + L
    return permute(combined, FP)

# ---------- MAIN ----------

# Input 64-bit key & plaintext in binary
key = input("Enter 64-bit key (binary): ")
plaintext = input("Enter 64-bit plaintext (binary): ")

keys = generate_keys(key)

cipher = des(plaintext, keys, encrypt=True)
print("Encrypted:", cipher)

decrypted = des(cipher, keys, encrypt=False)
print("Decrypted:", decrypted)
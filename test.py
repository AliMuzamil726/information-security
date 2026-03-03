#!/usr/bin/env python3
"""Secure File Encryption System (AES-256 + Password-Based Key Derivation)."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import shutil
import subprocess
from pathlib import Path

MAGIC = b"SFE2"
SALT_SIZE = 16
IV_SIZE = 16
ENC_KEY_SIZE = 32
MAC_KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000
HMAC_SIZE = 32


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


def ensure_openssl_available() -> None:
    if shutil.which("openssl") is None:
        raise EnvironmentError("OpenSSL is required but was not found in PATH.")


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=ENC_KEY_SIZE + MAC_KEY_SIZE,
    )
    return key_material[:ENC_KEY_SIZE], key_material[ENC_KEY_SIZE:]


def openssl_encrypt_cbc(plaintext: bytes, enc_key: bytes, iv: bytes) -> bytes:
    command = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-K",
        enc_key.hex(),
        "-iv",
        iv.hex(),
        "-nosalt",
    ]
    result = subprocess.run(command, input=plaintext, capture_output=True)
    if result.returncode != 0:
        raise EncryptionError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def openssl_decrypt_cbc(ciphertext: bytes, enc_key: bytes, iv: bytes) -> bytes:
    command = [
        "openssl",
        "enc",
        "-d",
        "-aes-256-cbc",
        "-K",
        enc_key.hex(),
        "-iv",
        iv.hex(),
        "-nosalt",
    ]
    result = subprocess.run(command, input=ciphertext, capture_output=True)
    if result.returncode != 0:
        raise DecryptionError("Ciphertext decryption failed.")
    return result.stdout


def encrypt_file(input_file: Path, output_file: Path, password: str) -> None:
    if not input_file.exists() or not input_file.is_file():
        raise EncryptionError(f"Input file does not exist or is not a file: {input_file}")

    ensure_openssl_available()

    plaintext = input_file.read_bytes()
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    enc_key, mac_key = derive_keys(password, salt)

    ciphertext = openssl_encrypt_cbc(plaintext, enc_key, iv)
    header_and_data = MAGIC + salt + iv + ciphertext
    tag = hmac.new(mac_key, header_and_data, hashlib.sha256).digest()

    output_file.write_bytes(header_and_data + tag)


def decrypt_file(input_file: Path, output_file: Path, password: str) -> None:
    if not input_file.exists() or not input_file.is_file():
        raise DecryptionError(f"Input file does not exist or is not a file: {input_file}")

    ensure_openssl_available()

    blob = input_file.read_bytes()
    minimum_size = len(MAGIC) + SALT_SIZE + IV_SIZE + HMAC_SIZE + 1
    if len(blob) < minimum_size:
        raise DecryptionError("Encrypted file is too small or corrupted.")

    if not blob.startswith(MAGIC):
        raise DecryptionError("Invalid encrypted file format (missing SFE2 header).")

    tag = blob[-HMAC_SIZE:]
    content = blob[:-HMAC_SIZE]

    offset = len(MAGIC)
    salt = content[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    iv = content[offset : offset + IV_SIZE]
    offset += IV_SIZE
    ciphertext = content[offset:]

    enc_key, mac_key = derive_keys(password, salt)
    expected_tag = hmac.new(mac_key, content, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise DecryptionError("Authentication failed. Wrong password or tampered file.")

    plaintext = openssl_decrypt_cbc(ciphertext, enc_key, iv)
    output_file.write_bytes(plaintext)


def get_password(password: str | None, confirm: bool = False) -> str:
    if password:
        return password

    first = getpass.getpass("Enter password: ")
    if confirm:
        second = getpass.getpass("Confirm password: ")
        if first != second:
            raise ValueError("Passwords do not match.")

    if not first:
        raise ValueError("Password cannot be empty.")
    return first


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure File Encryption System using AES-256-CBC + PBKDF2-HMAC-SHA256 + HMAC"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path, help="Path to plaintext file")
    enc.add_argument("output", type=Path, help="Path to encrypted file")
    enc.add_argument("-p", "--password", help="Password used for key derivation")

    dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", type=Path, help="Path to encrypted file")
    dec.add_argument("output", type=Path, help="Path to decrypted plaintext file")
    dec.add_argument("-p", "--password", help="Password used for key derivation")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            password = get_password(args.password, confirm=True)
            encrypt_file(args.input, args.output, password)
            print(f"Encrypted '{args.input}' -> '{args.output}'")

        elif args.command == "decrypt":
            password = get_password(args.password)
            decrypt_file(args.input, args.output, password)
            print(f"Decrypted '{args.input}' -> '{args.output}'")

    except (EncryptionError, DecryptionError, ValueError, EnvironmentError) as error:
        print(f"Error: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

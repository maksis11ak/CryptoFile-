# cryptographer_python.py — криптограф (шифрование файлов) на Python

import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import time

def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_file: str, output_file: str, password: str):
    # Генерируем соль и nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # Читаем файл по частям и шифруем
    # Для больших файлов используем потоковое шифрование: но AESGCM требует весь plaintext,
    # поэтому мы будем читать весь файл в память (для простоты).
    # В реальном проекте можно разбить на части, но здесь оставим как есть.
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    print(f"Шифрование... размер: {len(plaintext)} байт")
    # Прогресс-бар (имитация)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Записываем: соль (16) + nonce (12) + ciphertext
    with open(output_file, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)
    print(f"Файл зашифрован: {output_file}")

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"Ошибка дешифрования: {e}")
        sys.exit(1)

    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Файл расшифрован: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Шифрование/дешифрование файлов AES-256-GCM")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Режим работы')
    parser.add_argument('input', help='Входной файл')
    parser.add_argument('output', help='Выходной файл')
    parser.add_argument('password', help='Пароль')
    args = parser.parse_args()

    if args.mode == 'encrypt':
        encrypt_file(args.input, args.output, args.password)
    else:
        decrypt_file(args.input, args.output, args.password)

if __name__ == '__main__':
    main()

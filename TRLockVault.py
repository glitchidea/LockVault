#!/usr/bin/env python3

#Cryptic dosya.txt aes --key 0123456789abcdef0123456789abcdef
#sudo sed -i 's/\r$//' /usr/local/bin/Downloader

import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from PIL import Image
import io
import os
import hashlib
import base64
from Cryptodome.Cipher import Blowfish, ARC4

def caesar_cipher_decrypt(file_path, shift):
    """Caesar şifrelemesi ile şifrelenmiş dosyayı çözer."""
    def shift_char(c):
        if 'a' <= c <= 'z':
            return chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        if 'A' <= c <= 'Z':
            return chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        return c
    
    with open(file_path, 'r') as f:
        data = f.read()
    
    decrypted_data = ''.join(shift_char(c) for c in data)
    
    output_path = file_path.replace('.caesar', '.dec')
    with open(output_path, 'w') as f:
        f.write(decrypted_data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def steganography_extract(file_path):
    """Steganografi ile gizlenmiş mesajı çıkarır."""
    image = Image.open(file_path)
    pixels = image.load()
    
    width, height = image.size
    binary_message = ''
    
    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            binary_message += str(pixel[0] & 1)
            if len(binary_message) % 8 == 0 and binary_message[-8:] == '00000000':
                break
        if len(binary_message) % 8 == 0 and binary_message[-8:] == '00000000':
            break
    
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message) - 8, 8))
    
    output_path = file_path.replace('.png', '.txt')
    with open(output_path, 'w') as f:
        f.write(message)
    
    print(f"Mesaj çıkarıldı! Çıkarılan mesaj dosyası: {output_path}")

def aes_decrypt(file_path, key):
    """AES ile şifrelenmiş dosyayı çözer."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

    with open(file_path, 'rb') as f:
        iv = f.read(16)  # IV boyutu
        encrypted_data = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def des_decrypt(file_path, key):
    """DES ile şifrelenmiş dosyayı çözer."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

    with open(file_path, 'rb') as f:
        iv = f.read(8)  # IV boyutu
        encrypted_data = f.read()
    
    cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def blowfish_decrypt(file_path, key):
    """Blowfish ile şifrelenmiş dosyayı çözer."""
    from Cryptodome.Cipher import Blowfish

    with open(file_path, 'rb') as f:
        iv = f.read(Blowfish.block_size)
        encrypted_data = f.read()
    
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def rsa_decrypt(file_path, private_key):
    """RSA ile şifrelenmiş dosyayı çözer."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives import hashes

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def rc4_decrypt(file_path, key):
    """RC4 ile şifrelenmiş dosyayı çözer."""
    from Cryptodome.Cipher import ARC4

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")

def otp_decrypt(file_path, key):
    """One-time pad ile şifrelenmiş dosyayı çözer."""
    import os

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    if len(key) < len(encrypted_data):
        raise ValueError("Anahtar dosyadan daha kısa olamaz.")
    
    decrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, key))
    
    output_path = file_path.replace('.otp', '.dec')
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Şifre çözme başarılı! Çözülen dosya: {output_path}")




# AES Encryption
def aes_encrypt(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

# DES Encryption
def des_encrypt(file_path, key):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()
        padder = padding.PKCS7(algorithms.DES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

# Blowfish Encryption
def blowfish_encrypt(file_path, key):
    from Cryptodome.Cipher import Blowfish
    from Cryptodome.Random import get_random_bytes
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=get_random_bytes(Blowfish.block_size))

    with open(file_path, 'rb') as f:
        data = f.read()
        encrypted_data = cipher.encrypt(data)

    with open(file_path + '.enc', 'wb') as f:
        f.write(cipher.iv + encrypted_data)

# RSA Encryption
def rsa_encrypt(file_path, public_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives import hashes

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = public_key.encrypt(
        data,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

# RC4 Encryption
def rc4_encrypt(file_path, key):
    from Cryptodome.Cipher import ARC4
    cipher = ARC4.new(key)

    with open(file_path, 'rb') as f:
        data = f.read()
        encrypted_data = cipher.encrypt(data)

    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

# MD5 Hashing
def md5_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    with open(file_path + '.md5', 'w') as f:
        f.write(hash_md5.hexdigest())

# SHA Hashing
def sha_hash(file_path):
    hash_sha = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha.update(chunk)

    with open(file_path + '.sha256', 'w') as f:
        f.write(hash_sha.hexdigest())

# Steganography
def steganography_embed(file_path, message):
    image = Image.open(file_path)
    pixels = image.load()
    
    width, height = image.size
    message = message + chr(0)  # Add end of message character
    
    binary_message = ''.join(format(ord(i), '08b') for i in message)
    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                pixel = list(pixels[x, y])
                pixel[0] = (pixel[0] & ~1) | int(binary_message[data_index])
                data_index += 1
                if data_index >= len(binary_message):
                    break
                pixels[x, y] = tuple(pixel)
        if data_index >= len(binary_message):
            break
    
    image.save(file_path + '.png')

# Caesar Cipher
def caesar_cipher_encrypt(file_path, shift):
    def shift_char(c):
        if 'a' <= c <= 'z':
            return chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
        if 'A' <= c <= 'Z':
            return chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
        return c
    
    with open(file_path, 'r') as f:
        data = f.read()
    
    encrypted_data = ''.join(shift_char(c) for c in data)
    
    with open(file_path + '.caesar', 'w') as f:
        f.write(encrypted_data)

# One-time Pad Encryption
def otp_encrypt(file_path, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import os
    
    if len(key) < os.path.getsize(file_path):
        raise ValueError("Key must be at least as long as the file")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    encrypted_data = bytes(a ^ b for a, b in zip(data, key))
    
    with open(file_path + '.otp', 'wb') as f:
        f.write(encrypted_data)

def main():
    parser = argparse.ArgumentParser(description="Dosya şifreleme ve şifre çözme aracı.")
    parser.add_argument('file', help="İşlem yapılacak dosya yolu")
    parser.add_argument('method', choices=[
        'aes', 'des', 'blowfish', 'rsa', 'rc4', 'md5', 'sha', 
        'steganography', 'caesar', 'otp', 'aes-decrypt', 'des-decrypt', 
        'blowfish-decrypt', 'rsa-decrypt', 'rc4-decrypt', 'otp-decrypt'
    ], help="Şifreleme veya şifre çözme yöntemi")
    parser.add_argument('--key', help="Şifreleme anahtarını belirtir (hex formatında veya metin).", type=str)
    parser.add_argument('--shift', help="Sezar şifrelemesi için kaydırma miktarı", type=int)

    
    args = parser.parse_args()
    
    file_path = args.file
    method = args.method
    key = args.key
    shift = args.shift
    
    if method == 'aes':
        if not key:
            key = os.urandom(32)
        else:
            key = bytes.fromhex(key)
        aes_encrypt(file_path, key)
    
    elif method == 'des':
        if not key:
            key = os.urandom(8)
        else:
            key = bytes.fromhex(key)
        des_encrypt(file_path, key)
    
    elif method == 'blowfish':
        if not key:
            key = os.urandom(16)
        else:
            key = bytes.fromhex(key)
        blowfish_encrypt(file_path, key)
    
    elif method == 'rsa':
        if not key:
            raise ValueError("RSA şifreleme için anahtar gereklidir.")
        key = serialization.load_pem_public_key(
            bytes(key, 'utf-8'),
            backend=default_backend()
        )
        rsa_encrypt(file_path, key)
    
    elif method == 'rc4':
        if not key:
            key = os.urandom(16)
        else:
            key = bytes.fromhex(key)
        rc4_encrypt(file_path, key)
    
    elif method == 'md5':
        md5_hash(file_path)
    
    elif method == 'sha':
        sha_hash(file_path)
    
    elif method == 'steganography':
        if not key:
            raise ValueError("Steganography için mesaj gereklidir.")
        steganography_embed(file_path, key)
    
    elif method == 'caesar':
        if shift is None:
            raise ValueError("Caesar şifrelemesi için kaydırma miktarı gereklidir.")
        caesar_cipher_encrypt(file_path, shift)
    
    elif method == 'otp':
        if not key:
            key = os.urandom(os.path.getsize(file_path))
        else:
            key = bytes.fromhex(key)
        otp_encrypt(file_path, key)
    
    elif method == 'aes-decrypt':
        if not key:
            raise ValueError("AES şifre çözme için anahtar gereklidir.")
        key = bytes.fromhex(key)
        aes_decrypt(file_path, key)
    
    elif method == 'des-decrypt':
        if not key:
            raise ValueError("DES şifre çözme için anahtar gereklidir.")
        key = bytes.fromhex(key)
        des_decrypt(file_path, key)
    
    elif method == 'blowfish-decrypt':
        if not key:
            raise ValueError("Blowfish şifre çözme için anahtar gereklidir.")
        key = bytes.fromhex(key)
        blowfish_decrypt(file_path, key)
    
    elif method == 'rsa-decrypt':
        if not key:
            raise ValueError("RSA şifre çözme için özel anahtar gereklidir.")
        private_key = serialization.load_pem_private_key(
            bytes(key, 'utf-8'),
            password=None,
            backend=default_backend()
        )
        rsa_decrypt(file_path, private_key)
    
    elif method == 'rc4-decrypt':
        if not key:
            raise ValueError("RC4 şifre çözme için anahtar gereklidir.")
        key = bytes.fromhex(key)
        rc4_decrypt(file_path, key)
    
    elif method == 'otp-decrypt':
        if not key:
            raise ValueError("OTP şifre çözme için anahtar gereklidir.")
        key = bytes.fromhex(key)
        otp_decrypt(file_path, key)
    
    elif method == 'caesar-decrypt':
        if shift is None:
            raise ValueError("Caesar şifrelemesi için kaydırma miktarı gereklidir.")
        caesar_cipher_decrypt(file_path, shift)
    
    elif method == 'steganography-extract':
        steganography_extract(file_path)


    print(f"İşlem başarılı! Dosya {method} yöntemi ile işlendi.")

if __name__ == "__main__":
    main()

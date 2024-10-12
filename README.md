# File Encryption and Decryption Tool

## Overview

This project is a comprehensive Python tool designed for file encryption and decryption using various algorithms. It supports multiple methods, including symmetric and asymmetric encryption, hashing, and steganography. Users can secure their sensitive files, extract hidden messages, and verify file integrity effortlessly.

## Features

- **Encryption Algorithms**: 
  - AES
  - DES
  - Blowfish
  - RSA
  - RC4
  - One-Time Pad (OTP)

- **Decryption**: Easily decrypt files encrypted with the aforementioned algorithms.

- **Hashing**: Generate MD5 and SHA-256 hashes for file integrity verification.

- **Steganography**: Embed messages within images and extract them later.

- **Caesar Cipher**: Simple text encryption and decryption using the classic Caesar cipher method.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/repository.git
   ```

2. **Install Dependencies**:
   Ensure you have Python 3.x installed. You can install the required libraries using pip:
   ```bash
   pip install cryptography Pillow pycryptodome
   ```

## Usage

Run the tool from the command line:

```bash
python tool.py <file_path> <method> [options]
```

### Arguments

- `file_path`: The path to the file you want to process.
- `method`: Choose from the following methods:
  - `aes`
  - `des`
  - `blowfish`
  - `rsa`
  - `rc4`
  - `md5`
  - `sha`
  - `steganography`
  - `caesar`
  - `otp`
  - `aes-decrypt`
  - `des-decrypt`
  - `blowfish-decrypt`
  - `rsa-decrypt`
  - `rc4-decrypt`
  - `otp-decrypt`

### Options

- `--key`: Specify the encryption key (in hex format or as plain text).
- `--shift`: Specify the shift amount for Caesar cipher encryption.

### Example Commands

- **Encrypt a file with AES**:
  ```bash
  python tool.py myfile.txt aes --key 0123456789abcdef0123456789abcdef
  ```

- **Decrypt a file with RSA**:
  ```bash
  python tool.py myfile.enc rsa-decrypt --key my_private_key.pem
  ```

- **Generate MD5 hash**:
  ```bash
  python tool.py myfile.txt md5
  ```

- **Embed a message in an image using steganography**:
  ```bash
  python tool.py myimage.png steganography --key "Hidden message"
  ```

## Security Considerations

- Ensure that your keys are kept secure and not hardcoded in your scripts.
- Always use strong, unique keys for encryption.
- Regularly update your libraries to mitigate vulnerabilities.


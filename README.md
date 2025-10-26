# DES-AES Meet-in-the-Middle Key Recovery

A small C program that performs a meet-in-the-middle key recovery attack against a composite DES-AES double-encryption scheme. Given a known plaintext / ciphertext pair and a dictionary of candidate passwords (MD5 hash + password), the program tries to recover the two keys used.

## Table of contents

- [Prerequisites](#prerequisites)
- [Build](#build)
- [Usage](#usage)
- [Input file formats](#input-file-formats)
- [Project structure](#project-structure)

## Prerequisites

- A C compiler (GCC recommended on Windows via MinGW / WSL or GCC/clang on Linux).
- OpenSSL development libraries (headers and linkable libraries).
- Windows or Linux. The examples below show Windows (PowerShell) and Linux commands.

## Build

Open a terminal in the project folder and run the appropriate gcc command.

Windows (PowerShell / MinGW):

```powershell
gcc main.c -o des_aes_attack.exe -I "C:\Program Files\OpenSSL-Win64\include" -L "C:\Program Files\OpenSSL-Win64\lib" -lssl -lcrypto -lws2_32 -lcrypt32
```

## Usage

Place the two input files in the same folder as the executable:

- `PlaintextCiphertext.txt` — contains a plaintext and the corresponding ciphertext (base64) on separate lines.
- `passwords.txt` — dictionary file with an MD5 hash and the candidate password separated by whitespace on each line.

Run the program:

```powershell
.\des_aes_attack.exe
```

Output:

- The recovered keys (if found) will be printed to the terminal and written to `keys.txt`.

## Input file formats

`PlaintextCiphertext.txt` (two lines):

```
This is a sample message
qwertyuiopasdfghjklzxcvbnm==
```

First line: plaintext (UTF-8 text). Second line: base64-encoded ciphertext corresponding to that plaintext.

`passwords.txt` (one candidate per line):

```
e99a18c428cb38d5f260853678922e03 password123
5f4dcc3b5aa765d61d8327deb882cf99 letmein
```

Format: `<md5hash> <password>` (whitespace-separated). The program uses the hashes/passwords according to its internal algorithm — keep the same layout.

## Project structure

- `main.c` — main program source.
- `README.md` — this file.
- `PlaintextCiphertext.txt` — sample input (plaintext + base64 ciphertext).
- `passwords.txt` — sample dictionary (md5 hash + password).
- `keys.txt` — output file created by the program when keys are recovered.

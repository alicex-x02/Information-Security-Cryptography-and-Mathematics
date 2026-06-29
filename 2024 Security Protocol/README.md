# Security-Protocol
2024 보안프로토콜

# Mini TLS & Padding Oracle Attack

A simple Python project for practicing a TLS-like handshake protocol, encrypted communication, and a padding oracle attack.

## Files

```text
.
├── MINI TLS (1).py
└── padding_oracle_attack (1).py
```

## Overview

This repository contains two security programming practice files.

### `MINI TLS (1).py`

Implements a simplified TLS-style client.

Main features:

- ClientHello / ServerHello handshake
- Server certificate reception
- RSA encryption of PreMasterSecret
- MasterSecret and key derivation using HKDF
- AES-CBC encrypted communication
- HMAC-SHA256 message authentication
- Encrypted echo mode communication

### `padding_oracle_attack (1).py`

Extends the Mini TLS implementation to perform a padding oracle attack.

Main features:

- TLS-like handshake
- Encrypted request/response communication
- Padding oracle attack against AES-CBC ciphertext
- Brute-force mode
- Fast search mode using precomputed values
- Padding length detection mode
- Image decryption using the recovered key

## Tech Stack

- Python
- Socket Programming
- RSA
- AES-CBC
- HMAC-SHA256
- HKDF
- Padding Oracle Attack

## Requirements

Install the required Python packages:

```bash
pip install pycryptodome pillow
```

## How to Run

### Mini TLS

```bash
python "MINI TLS (1).py"
```

### Padding Oracle Attack

```bash
python "padding_oracle_attack (1).py"
```

## Notes

- The server IP and port are hardcoded in the source code.
- This project is for educational purposes only.
- The padding oracle attack code is intended for a controlled practice environment.
- Some file paths in the image decryption part may need to be modified depending on the local environment.

## Purpose

This project was implemented to understand:

- How TLS-style handshakes work
- How symmetric keys are derived after key exchange
- How encrypted communication can be protected with MACs
- Why AES-CBC padding validation can become vulnerable
- How padding oracle attacks recover plaintext from ciphertext

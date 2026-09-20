# FoC - Digital Signature Server

[![Language](https://img.shields.io/badge/Language-C%2B%2B11-blue.svg)](https://isocpp.org/)
[![Cryptography](https://img.shields.io/badge/Library-OpenSSL-green.svg)](https://www.openssl.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Client--Server-orange.svg)]()
[![University](https://img.shields.io/badge/University-Pisa-red.svg)](https://www.unipi.it/)

[Specifications](Specifications.pdf) | [Technical Report](Report.pdf) | [Source Code](src/)

This repository contains the design, implementation, and security verification of a **Digital Signature Server (DSS)** using a C++ Client-Server architecture and the OpenSSL cryptographic library.

The project was developed for the **Foundations of Cybersecurity** course (Master of Science in Computer Engineering, **Università di Pisa**).

---

## Project Overview

The Digital Signature Server acts as a central **Trusted Third Party (TTP)** for an organization. It allows registered employees to securely generate, store, and manage RSA public-private key pairs, digitally sign organizational documents, retrieve public keys of colleagues, and revoke key pairs.

All communication between client and server takes place over a custom authenticated and encrypted transport protocol that guarantees:
- **Mutual Authentication**: Server authentication via RSA certificate/key and client authentication via PBKDF2-derived user credentials.
- **Perfect Forward Secrecy (PFS)**: Established using Ephemeral Diffie-Hellman key exchange.
- **Confidentiality & Integrity**: Authenticated encryption via AES-128-GCM with per-message IV and 16-byte authentication tags.
- **Replay Attack Mitigation**: Session-bound 128-bit pseudo-random nonces.

---

## Cryptographic Parameters & Protocol Specifications

| Security Primitive | Algorithm / Parameter | Details / Specification |
| :--- | :---: | :--- |
| **Session Key Exchange** | Ephemeral Diffie-Hellman | PFS enabled per session |
| **Symmetric Encryption** | AES-128-GCM | 128-bit key, 12-byte IV, 16-byte Tag |
| **Digital Signatures** | RSA-3072 | SHA-256 digest, public exponent $e = 65537$ |
| **Key Storage** | Encrypted PEM | Private keys encrypted at rest on server |
| **Password Derivation** | PBKDF2-HMAC-SHA256 | 16-byte random salt, 100,000 iterations |
| **Replay Protection** | 128-bit Nonce | Pseudo-random nonce per transaction |

---

## System Architecture & Client Commands

Once a secure authenticated channel is established, the client provides an interactive menu supporting five core operations:

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **CreateKeys** | `CreateKeys` | Generates a new RSA-3072 key pair for the user and stores it encrypted on the server |
| **SignDoc** | `SignDoc <filepath>` | Sends a document to the server to compute and receive its RSA digital signature |
| **GetPublicKey** | `GetPublicKey <username>` | Fetches and locally saves the public key of any registered network user |
| **DeleteKeys** | `DeleteKeys` | Revokes and deletes the RSA key pair associated with the requesting user |
| **Stop** | `Stop` | Terminates session and disconnects cleanly from the server |

---

## Repository Structure

```
.
├── src/                C++ source code (client.cpp, server.cpp, utils.cpp)
├── include/            C++ header files (constants.hpp, utils.hpp)
├── scripts/            Utility scripts (exec.sh, generate_users.py)
├── data/               Database files (users.txt, revoked.txt)
├── documents/          Sample documents for signature testing (document.txt)
├── keys/               DH parameters (dhparam.pem) and server RSA keys
├── public_keys/        Directory where fetched public keys are stored locally
├── signatures/         Directory where generated signatures are stored
├── makefile            Build system configuration
├── Specifications.pdf  Official course project specifications
└── Report.pdf          Final technical report detailing protocol design
```

---

## Requirements & Compilation

### Prerequisites

- **Compiler**: `g++` with C++11 or higher support
- **Libraries**: OpenSSL (`libssl-dev`, `libcrypto`)
- **Tools**: `make`, `python3`

### Building the Project

Compile client and server executables:

```bash
make
```

Clean object files and binaries:

```bash
make clean
```

---

## Execution Guide

### 1. Generating User Credentials (Optional)

To regenerate `data/users.txt` with PBKDF2 salt and password hashes:

```bash
python3 scripts/generate_users.py
```

### 2. Starting the Server

Run the server executable by passing the listening port (e.g., 4242):

```bash
./server 4242
```

### 3. Starting the Client

In a separate terminal window:

```bash
./client
```

Alternatively, on Linux systems with `gnome-terminal`:

```bash
bash scripts/exec.sh
```

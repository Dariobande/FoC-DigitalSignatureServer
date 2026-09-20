# Digital Signature Server (DSS)

## Project Information

- **Course**: Foundations of Cybersecurity (FoC) A.Y. 2024-2025
- **Degree Program**: Master of Science in Computer Engineering
- **Institution**: University of Pisa
- **Author**: Dario Bandecchi

## General Overview

This repository contains the implementation of a **Digital Signature Server (DSS)** based on a Client-Server architecture written in C++ using the OpenSSL library.

The server acts as a central Trusted Third Party (TTP) for an organization, enabling registered employees to:
- Securely generate and store RSA asymmetric key pairs.
- Digitally sign organizational documents.
- Retrieve public keys of other registered users to verify signatures.
- Revoke and delete their own key pairs.

All client-server communications are conducted over a secure channel that guarantees mutual authentication, confidentiality, integrity, and Perfect Forward Secrecy (PFS).

## Security Architecture and Cryptographic Design

- **Authentication and Handshake**:
  - Ephemeral Diffie-Hellman key exchange ensuring Perfect Forward Secrecy (PFS).
  - Mutual authentication using user credentials and the server's pre-generated RSA key/certificate.
  - Protection against replay attacks using 128-bit pseudo-random nonces per session.
- **Credential Protection**:
  - User passwords are stored as hashes derived via **PBKDF2-HMAC-SHA256** using a 16-byte random salt and 100,000 iterations.
- **Channel Encryption (Session Key)**:
  - **AES-128-GCM** authenticated encryption for commands and responses.
  - Per-message protection using unique Initialization Vectors (IV) and 16-byte authentication tags.
- **RSA Key Management**:
  - Generation of RSA-3072 bit keys with public exponent 65537.
  - Storage of user private keys on the server in encrypted PEM format.

## Client Features and Commands

After establishing a secure connection with the server, authenticated users can invoke the following commands:

1. `CreateKeys`: Generates and securely stores an RSA key pair on the server for the requesting user.
2. `SignDoc <filepath>`: Transmits a document to the server to obtain an RSA digital signature.
3. `GetPublicKey <username>`: Fetches the public key of a specific registered user.
4. `DeleteKeys`: Revokes and deletes the user's RSA key pair from the server.
5. `Stop`: Terminates the session and disconnects from the server cleanly.

## Repository Structure

```
.
├── src/                C++ source files (client.cpp, server.cpp, utils.cpp)
├── include/            C++ header files (constants.hpp, utils.hpp)
├── scripts/            Utility scripts (exec.sh, generate_users.py)
├── data/               User credentials database and revocation list (users.txt, revoked.txt)
├── documents/          Sample documents for signature testing (document.txt)
├── keys/               DH parameters and RSA keys for server and registered users
├── public_keys/        Directory where fetched public keys are saved locally by clients
├── signatures/         Directory where generated digital signature files are stored
├── makefile            Build configuration file
├── Specifications.pdf  Official project specifications and requirements
└── Report.pdf          Final project report detailing system design and cryptographic choices
```

## System Requirements and Dependencies

- **Operating System**: Linux / macOS / WSL
- **Compiler**: `g++` (supporting C++11 or higher)
- **Libraries**: OpenSSL (`libssl-dev`, `libcrypto`)
- **Tools**: `make`, `python3`

## Building and Running

### 1. Compilation

To compile both client and server binaries:

```bash
make
```

To clean compiled object files and executables:

```bash
make clean
```

### 2. User Generation (Optional)

To regenerate the sample user database (`data/users.txt`) with PBKDF2 hashes:

```bash
python3 scripts/generate_users.py
```

### 3. Running the Server

Start the server by passing the listening port (e.g., 4242):

```bash
./server 4242
```

### 4. Running the Client

In a separate terminal window, start the client application:

```bash
./client
```

Alternatively, on Linux systems with `gnome-terminal`, you can run the automated execution script:

```bash
bash scripts/exec.sh
```

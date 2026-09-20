import hashlib
import os
import binascii

SALT_SIZE = 16
HASH_SIZE = 32
ITERATIONS = 100_000

# Lista di utenti (username, password in chiaro)
users = [
    ("alice", "password123"),
    ("bob", "qwerty"),
    ("carol", "ciao1234")
]

def to_colon_hex(data: bytes) -> str:
    # Converte in stringa esadecimale con ":" tra ogni byte e tutto in maiuscolo
    return ':'.join(f"{b:02X}" for b in data)

with open("data/users.txt", "w") as f:
    for username, password in users:
        salt = os.urandom(SALT_SIZE)
        hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=HASH_SIZE)

        salt_hex = to_colon_hex(salt)
        hash_hex = to_colon_hex(hash_bytes)

        # Delimitatore tra i campi = "|"
        f.write(f"{username}|{salt_hex}|{hash_hex}|0\n")

#!/usr/bin/python

# code taken from https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html
# must have pycryptodome version 3.7.0 or higher installed

import json

from typing import Dict
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# generates a random 256-bit key


def chacha20_keygen() -> bytes:
    key = get_random_bytes(32)
    return key

# takes ASCII plaintext then encrypts with a 256-bit key


def chacha20_encrypt(plaintext, key) -> Dict[str, bytes]:
    b64info = None

    header = b"AAD"
    raw_plaintext = plaintext.encode("ascii")
    cipher = ChaCha20_Poly1305.new(key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(raw_plaintext)

    jk = ["header", "ciphertext", "tag", "nonce"]
    jv = [header, ciphertext, tag, cipher.nonce]

    info = dict(zip(jk, jv))

    b64info = {x: b64encode(info[x]) for x in jk}
    return b64info

# takes dictionary of the header, ciphertext, tag, and nonce then decrypts with a 256-bit key


def chacha20_decrypt(b64info, key):
    plaintext: str = ''

    try:
        jk = ["header", "ciphertext", "tag", "nonce"]
        info = {x: b64decode(b64info[x]) for x in jk}

        cipher = ChaCha20_Poly1305.new(key, nonce=info["nonce"])
        cipher.update(info["header"])
        raw_plaintext = cipher.decrypt_and_verify(info["ciphertext"], info["tag"])
        plaintext = raw_plaintext.decode("ascii")

    except ValueError:
        print("Decryption Error: MAC Mismatch")
    except KeyError:
        print("Decryption Error: Incorrect Decryption")

    return plaintext


# driver function
print("Enter message to encrypt: ", end="")
message = input()
print("Initial plaintext: " + message)

secretkey = chacha20_keygen()
result = chacha20_encrypt(message, secretkey)
print("Result: " + str(result))

decrypted = chacha20_decrypt(result, secretkey)
print("Decrypted message: " + decrypted)

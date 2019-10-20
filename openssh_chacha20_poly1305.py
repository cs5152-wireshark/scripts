#!/usr/bin/python

# code taken from https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html
# must have pycryptodome version 3.7.0 or higher installed

import json
import argparse

from typing import Tuple, Union, cast
from io import BufferedReader
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# generates a random 256-bit key


def keygen_512bit() -> bytes:
    key = get_random_bytes(64)
    return key

# takes bytes for all inputs, will return the bytes of the final packet to be sent over the wire


def openssh_chacha20_poly1305_encrypt(key, pkt_seq_number, pkt_length, pkt_payload) -> bytes:
    # if numeric fields are not bytes, convert them to bytes
    if isinstance(pkt_seq_number, int):
        pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='little')
    if isinstance(pkt_length, int):
        pkt_length = pkt_length.to_bytes(4, byteorder='little')

    # encrypt the packet length
    cipher1 = ChaCha20.ChaCha20Cipher(key=key[:32], nonce=pkt_seq_number)
    encrypted_pkt_length = cipher1.encrypt(pkt_length)

    # encrypte the packet payload and generate a tag, using the encrypted packet length as AAD
    cipher2 = ChaCha20_Poly1305.ChaCha20Poly1305Cipher(
        key=key[32:], nonce=pkt_seq_number)
    cipher2.update(encrypted_pkt_length)
    encrypted_pkt_payload, tag = cipher2.encrypt_and_digest(pkt_payload)

    assert(len(encrypted_pkt_length) == 4)
    assert(len(tag) == 16)

    return encrypted_pkt_length + encrypted_pkt_payload + tag


# takes the bytes of the whole packet sent over the wire,
def openssh_chacha20_poly1305_decrypt(key, pkt_seq_number, pkt) -> bytes:
    # if numeric fields are not bytes, convert them to bytes
    if isinstance(pkt_seq_number, int):
        pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='little')

    # decrypt the packet length
    cipher1 = ChaCha20.ChaCha20Cipher(key=key[:32], nonce=pkt_seq_number)
    pkt_length = cipher1.decrypt(pkt[:4])

    # decrypt and verify the packet payload and encrypted packet length
    cipher2 = ChaCha20_Poly1305.ChaCha20Poly1305Cipher(
        key=key[32:], nonce=pkt_seq_number)
    cipher2.update(pkt[:4])
    pkt_payload = cipher2.decrypt_and_verify(pkt[4:-16], pkt[-16:])

    return pkt_payload


def tuple_split(p: str) -> Tuple[str, Union[str, None]]:
    ps = p.split('=')
    if len(ps) < 2:
        return (ps[0], None)
    return (ps[0], ps[1])


def parse_debug_file(packet_file: BufferedReader):
    payload = packet_file.readlines()

    seq_number = 1
    key0: bytes = b''
    key1: bytes = b''

    for line in map(lambda l: l.decode("utf-8"), payload):
        if not line.startswith('debug1: DUMP|'):
            continue
        parts = line.split('|')
        mapped = map(tuple_split, parts)
        obj = dict(mapped)

        if "KEY_DUMP_0" in obj:
            raw_key0 = obj["KEY_DUMP_0"]
            if isinstance(raw_key0, str):
                key0 = bytes.fromhex(raw_key0)
                print("[REKEY] 0: ", key1.hex())
        elif "KEY_DUMP_1" in obj:
            raw_key1 = obj["KEY_DUMP_1"]
            if isinstance(raw_key1, str):
                key1 = bytes.fromhex(raw_key1)
                print("[REKEY] 1: ", key1.hex())
        elif "ENCRYPT" in obj:
            raw_seqnr = obj["SEQNR"]
            raw_len = obj["LEN"]
            raw_src = obj["SRC"]

            if isinstance(raw_seqnr, str):
                seq_number = int(raw_seqnr)
            if isinstance(raw_len, str):
                packet_payload_length = int(raw_len)
            if isinstance(raw_src, str):
                packet_payload = bytes.fromhex(raw_src[:packet_payload_length])

            otw_packet = openssh_chacha20_poly1305_encrypt(
                key0, seq_number, packet_payload_length, packet_payload)

            decrypted_payload: bytes = openssh_chacha20_poly1305_decrypt(
                key0, seq_number, otw_packet)

            print("[PACKET] ", decrypted_payload)
        else:
            print("[UNKNOWN] ", line)


# main function
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "file", help="filename of packet to use (required)", type=str)
    parser.add_argument(
        "-m", "--mode", help="encryption or decryption", type=int)
    args = parser.parse_args()

    try:
        with open(args.file, mode='rb') as packet:
            parse_debug_file(packet)
    except FileNotFoundError:
        payload = b"Default SSH Payload"
        payload_length = len(payload)

if __name__ == "__main__":
    main()

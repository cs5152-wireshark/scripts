#!/usr/bin/python

# code taken from https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html
# must have pycryptodome version 3.7.0 or higher installed

import json

from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# generates a random 256-bit key
def keygen_512bit():
	key = get_random_bytes(64)
	return key

# takes bytes for all inputs, will return the bytes of the final packet to be sent over the wire
def openssh_chacha20_poly1305_encrypt(key, pkt_seq_number, pkt_length, pkt_payload):
	# if numeric fields are not bytes, convert them to bytes
	if isinstance(pkt_seq_number, int):
		pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='little')
	if isinstance(pkt_length, int):
		pkt_length = pkt_length.to_bytes(4, byteorder='little')
	
	# encrypt the packet length
	cipher1 = ChaCha20.new(key=key[:32], nonce=pkt_seq_number)
	encrypted_pkt_length = cipher1.encrypt(pkt_length)
	
	# encrypte the packet payload and generate a tag, using the encrypted packet length as AAD
	cipher2 = ChaCha20_Poly1305.new(key=key[32:], nonce=pkt_seq_number)
	cipher2.update(encrypted_pkt_length)
	encrypted_pkt_payload, tag = cipher2.encrypt_and_digest(pkt_payload)
	
	assert(len(encrypted_pkt_length) == 4)
	assert(len(tag) == 16)
	
	return encrypted_pkt_length + encrypted_pkt_payload + tag


# takes the bytes of the whole packet sent over the wire, 
def openssh_chacha20_poly1305_decrypt(key, pkt_seq_number, pkt):
	# if numeric fields are not bytes, convert them to bytes
	if isinstance(pkt_seq_number, int):
		pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='little')
	
	# decrypt the packet length
	cipher1 = ChaCha20.new(key=key[:32], nonce=pkt_seq_number)
	pkt_length = cipher1.decrypt(pkt[:4])
	
	# decrypt and verify the packet payload and encrypted packet length
	cipher2 = ChaCha20_Poly1305.new(key=key[32:], nonce=pkt_seq_number)
	cipher2.update(pkt[:4])
	pkt_payload = cipher2.decrypt_and_verify(pkt[4:-16], pkt[-16:])
	
	return pkt_payload



# driver function
payload = b"SSH Payload"
payload_length = len(payload)

seq_number = 1
k = keygen_512bit()

otw_packet = openssh_chacha20_poly1305_encrypt(k, seq_number, payload_length, payload)

print(b64encode(otw_packet))

decrypted_payload = openssh_chacha20_poly1305_decrypt(k, seq_number, otw_packet)

print(decrypted_payload)

exit(0)

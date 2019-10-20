#!/usr/bin/python

# code examples inspired from https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html
# must have pycryptodome version 3.7.0 or higher installed

from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


### generates a random 512-bit (64-byte) key
def keygen_512bit():
	key = get_random_bytes(64)
	return key


### takes the plaintext payload (bytes), a key (bytes), and a sequence
### number (bytes, int) and encrypts it into the OTW packet
def openssh_chacha20_poly1305_encrypt(key, pkt_seq_number, pkt_payload):
	pkt_length = len(pkt_payload).to_bytes(4, byteorder='big')

	# if numeric fields are not bytes, convert them to bytes
	if isinstance(pkt_seq_number, int):
		pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='big')

	assert(len(pkt_length) == 4)
	
	# encrypt the packet length
	cipher1 = ChaCha20.new(key=key[32:], nonce=pkt_seq_number)
	encrypted_pkt_length = cipher1.encrypt(pkt_length)
	
	# encrypt the packet payload and generate a tag, using the encrypted packet length as AAD
	# TODO: The encrypted packet length is not the AAD, we cannot do this correctly until we know what it is
	cipher2 = ChaCha20_Poly1305.new(key=key[:32], nonce=pkt_seq_number)
	cipher2.update(encrypted_pkt_length)
	encrypted_pkt_payload, tag = cipher2.encrypt_and_digest(pkt_payload)
	
	assert(len(encrypted_pkt_length) == 4)
	assert(len(tag) == 16)
	
	return encrypted_pkt_length + encrypted_pkt_payload + tag


### takes the whole packet sent over the wire (bytes), decrypts it using
### the given key (bytes) and sequence number (bytes, int) as a nonce
def openssh_chacha20_poly1305_decrypt(key, pkt_seq_number, pkt):
	# if numeric fields are not bytes, convert them to bytes
	if isinstance(pkt_seq_number, int):
		pkt_seq_number = pkt_seq_number.to_bytes(8, byteorder='big')
	
	# decrypt the packet length
	cipher1 = ChaCha20.new(key=key[32:], nonce=pkt_seq_number)
	pkt_length = cipher1.decrypt(pkt[:4])
	
	# Temporary solution: decrypt the packet payload without verifying the tag
	cipher2 = ChaCha20.new(key=key[:32], nonce=pkt_seq_number)
	cipher2.seek(64)
	pkt_payload = cipher2.decrypt(pkt[4:-16])
	
	# TODO: verify the tag and decrypt the packet payload
	#cipher2 = ChaCha20_Poly1305.new(key=key[:32], nonce=pkt_seq_number)
	#cipher2.update(pkt[:4])
	#pkt_payload = cipher2.decrypt_and_verify(pkt[4:-16], pkt[-16:])
	
	assert(len(pkt_payload) == int.from_bytes(pkt_length, byteorder='big'))
	
	return pkt_payload



### driver function
payload = b"SSH Payload"

seq_number = 1
k = keygen_512bit()

otw_packet = openssh_chacha20_poly1305_encrypt(k, seq_number, payload)

print("OTW packet: ", end='')
print(otw_packet)

decrypted_payload = openssh_chacha20_poly1305_decrypt(k, seq_number, otw_packet)

print("Decrypted payload: ", end='')
print(decrypted_payload)

exit(0)

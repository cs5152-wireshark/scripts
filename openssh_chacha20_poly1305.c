/*H**********************************************************************
* C Port of the OpenSSH ChaCha20-Poly1305 encryption/decryption script 
* using libgcrypt.
*H***********************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>


#define POKE_U64(p, v) \
	do { \
		const u_int64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} while (0)
	
#define PEEK_U64(p) \
	(((u_int64_t)(((const u_char *)(p))[0]) << 56) | \
	 ((u_int64_t)(((const u_char *)(p))[1]) << 48) | \
	 ((u_int64_t)(((const u_char *)(p))[2]) << 40) | \
	 ((u_int64_t)(((const u_char *)(p))[3]) << 32) | \
	 ((u_int64_t)(((const u_char *)(p))[4]) << 24) | \
	 ((u_int64_t)(((const u_char *)(p))[5]) << 16) | \
	 ((u_int64_t)(((const u_char *)(p))[6]) << 8) | \
	  (u_int64_t)(((const u_char *)(p))[7]))

#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))

#define POKE_U32(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)
	
typedef unsigned char byte_t;

// forward declarations
void test1();
void test2();

// max number of lines, max characters per line
enum { MAXL = 40, MAXC = 260 };

unsigned char* datahex(char* string) {
    if(string == NULL) 
       return NULL;
    size_t slength = strlen(string);
    if((slength % 2) != 0) // must be even
       return NULL;
    size_t dlength = slength / 2;
    unsigned char* data = malloc(dlength);
    memset(data, 0, dlength);
    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F') 
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
          free(data);
          return NULL;
        }
        data[(index/2)] += value << (((index + 1) % 2) * 4);
        index++;
    }
    return data;
}

/* This function takes a 512-bit key, a sequence number, and a packet payload+length
 * and encrypts it into an OpenSSH packet to be sent over the wire which it stores in
 * the outbuf buffer. It will return the gcrypt error codes.
 */
gcry_error_t
openssh_chacha20_poly1305_encrypt(const byte_t *key, uint64_t pkt_seq_number, const byte_t *pkt_payload, uint32_t pkt_payload_len, byte_t *outbuf) {
	// cipher1 encrypts packet length, cipher2 encrypts packet payload
	gcry_cipher_hd_t cipher1, cipher2;
	gcry_error_t err = 0;
	
	// split the 512-bit key into two 256-bit keys (K1 and K2)
	byte_t k1[32];
	byte_t k2[32];
	memcpy(k1, (key + 32), 32);
	memcpy(k2, key, 32);
	
	// convert the sequence number from 64-bit unsigned int to 64-bit big endian byte array
	byte_t seqbuf[8];
	POKE_U64(seqbuf, pkt_seq_number);
	
	// convert packet payload length from 32-bit unsigned int to 32-bit big endian byte array
	byte_t lenbuf[4];
	POKE_U32(lenbuf, pkt_payload_len);

	// encrypt packet length
	err = gcry_cipher_open (&cipher1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher1, k1, 32);
	err = gcry_cipher_setiv(cipher1, seqbuf, 8);
	err = gcry_cipher_encrypt(cipher1, outbuf, 4, lenbuf, 4);

	//set initial block count to 1
	const byte_t ctrbuf[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
	byte_t ctrseqbuf[16];
	memcpy(ctrseqbuf, ctrbuf, 8);
	memcpy(ctrseqbuf + 8, seqbuf, 8);
	
	// encrypt packet payload
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, ctrseqbuf, 16); // pass in both the initial block counter and initialization vector
	err = gcry_cipher_encrypt(cipher2, (outbuf + 4), pkt_payload_len, pkt_payload, pkt_payload_len);
	
	return err;
}

/* This function takes a 512-bit key, a sequence number, and an encrypted packet+length
 * and decrypts it into the packet payload which it stores in the outbuf buffer. It will
 * return the gcrypt error codes.
 */
gcry_error_t
openssh_chacha20_poly1305_decrypt(const byte_t *key, uint64_t pkt_seq_number, const byte_t *encrypted_pkt, uint32_t encrypted_pkt_len, byte_t *outbuf) {
	// cipher1 decrypts packet length header, cipher2 decrypts packet payload
	gcry_cipher_hd_t cipher1, cipher2;
    gcry_error_t err = 0;

	// split the 512-bit key into two 256-bit keys (K1 and K2)
	byte_t k1[32];
	byte_t k2[32];
	memcpy(k1, (key + 32), 32);
	memcpy(k2, key, 32);
	
	// convert the sequence number from 64-bit unsigned int to 64-bit big endian byte array
	byte_t seqbuf[8];
	POKE_U64(seqbuf, pkt_seq_number);
	
	// set up variables for reading packet payload length
	byte_t lenbuf[4];
	uint32_t payload_len;
	
	// decrypt packet payload length and convert it from 32-bit big endian byte array to 32-bit unsigned int
	err = gcry_cipher_open (&cipher1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher1, k1, 32);
	err = gcry_cipher_setiv(cipher1, seqbuf, 8);
	err = gcry_cipher_decrypt(cipher1, lenbuf, 4, encrypted_pkt, 4);
	payload_len = PEEK_U32(lenbuf);
	
	// ensure that the length field is accurate
	if(payload_len + 20 != encrypted_pkt_len) {
		err |= GPG_ERR_USER_1;
		return err;
	};
	
	//set initial block count to 1
	const byte_t ctrbuf[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
	byte_t ctrseqbuf[16];
	memcpy(ctrseqbuf, ctrbuf, 8);
	memcpy(ctrseqbuf + 8, seqbuf, 8);
	
	// decrypt packet payload and store the output in out
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, ctrseqbuf, 16); // pass in both the initial block counter and initialization vector
	err = gcry_cipher_decrypt(cipher2, outbuf, payload_len, encrypted_pkt + 4, payload_len);

	/* TODO: Verify the MAC tag before we decrypt the packet payload
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, seqbuf, 8);
	err = gcry_cipher_checktag(cipher2, tagbuf, 16);
	err = gcry_cipher_decrypt(cipher2, lenbuf, 4, encrypted_pkt, 4);
	*/
	
	return err;
}

void printhex(byte_t *buf, size_t n) {
	for(int i = 0; i < n; ++i)
		printf("%02hhx", *(buf + i));
	printf("\n");
}

int main(int argc, char *argv[])
{
    // STEP 1: Read in the input file

//     FILE *fpr;
//     char (*file)[MAXC] = NULL; // pointer to array of type char [MAXC]
//     int i,n = 0;
// 
//     // Char pointer for delimited string
//     char *ptr;
//     // current line
//     int line = 0;
//     /*Opening the input file in "r" mode*/
//     fpr = fopen(argv[1], "r");
// 
//     /* check if input file is valid */
//     if (fpr == NULL) {
// 		puts("invalid input file");
// 		return 0;
// 	}
//     if (!(file = malloc (MAXL * sizeof *file))) { /* allocate MAXL arrays */
//         fprintf (stderr, "error: virtual memory exhausted.\n");
//         return 0;
//     }
// 
//     while (n < MAXL && fgets (file[n], MAXC, fpr)) { /* read each line */
//         char *p = file[n];                  /* assign pointer */
//         for (; *p && *p != '\n'; p++) {}     /* find 1st '\n'  */
//         *p = 0, n++;                         /* nul-termiante  */
//     }
// 
//     if (fpr != stdin) fclose (fpr);   /* close file if not stdin */
//     // for (i = 0; i < n; i++) printf ("%s\n", file[i]);
//     int length = sizeof(file);
// 
//     // STEP 2: File tokenizing
//     int line_index = -1;
//     int word_index = 0;
//     // 10 rows of 10 split words of max len 260 characters
//     char words[10][10][260];
//     for (int i = 0; i < length; i++) {
//         char *line = file[i];
//         int init_size = sizeof(line);
//         char delim[] = "|";
// 
//         char *ptr = strtok(line, delim);
// 
//         while(ptr != NULL)
//         {
//             //printf("'%s'\n", ptr);
//             if (ptr[0] == 'd') {
//                 line_index ++ ;
//                 word_index = 0;
//                // printf("\n");
//             }
//             strcpy(words[line_index][word_index], ptr);
//             //printf("%s ", ptr);
//             //printf("'%s'\n", words[line_index][word_index]);
//             word_index ++;
//             ptr = strtok(NULL, delim);
//         }
//     }
// 
//     // STEP 3: Get the keys
//     
//     byte_t char_key0[139];
//     byte_t char_key1[139];
// 
//     strncpy(char_key0, words[0][1]+11, 128);
//     strncpy(char_key1, words[1][1]+11, 128);
// 
//     uint8_t * key0; 
//     uint8_t * key1;
// 
//     key0 = datahex(char_key0);
//     key1 = datahex(char_key1);
// 
//     uint8_t key0_first[32];
//     memcpy(key0_first, key0, 32);

	
	test1();

    // https://github.com/Chronic-Dev/libgcrypt/blob/master/tests/basic.c
/*
    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    int block_length = gcry_cipher_get_algo_blklen(GCRY_CIPHER_CHACHA20);
    int key_length = gcry_cipher_get_algo_keylen (GCRY_CIPHER_CHACHA20);

    err = gcry_cipher_open (&handle, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
    err = gcry_cipher_setkey (handle, key0_first, key_length);
    
    //Create a 96-bit nonce.  In some protocols, this is known as the Initialization Vector
    gcry_create_nonce (handle, 96);
    // gcry_cipher_setiv (handle, NULL, 0);

    // get plaintext length
    char str_len_char[5];
    strncpy(str_len_char, words[2][3] + 4, 5);
    int str_length = atoi(str_len_char);

    // get plaintext
    int len = str_length * 2 + 40;
    char plaintext[len + 1];
    strncpy(plaintext, words[2][5]+4, len);
    plaintext[len] = '\0';
    unsigned char* plaintext_bytes = datahex(plaintext);
    unsigned char output_len[4];
    err = gcry_cipher_decrypt (handle,
				 output_len, 4, plaintext_bytes, 8);

    unsigned char output[MAXL];

    err = gcry_cipher_decrypt (handle,
				 output, block_length, plaintext_bytes + 4, str_length + 20);
    printf("err: %i\n", err);

    printf("len: %i src: %s\n", str_length, plaintext);
    printf("len: %i str: %x%x%x%x%x\n", str_length, output[0],output[1],output[2],output[3],output[4]);

    free(file);*/

    return 0;
}

// This test uses the encrypt function with some random hardcoded key
void test1() {
	gcry_error_t err;

	// hardcoded 512-bit key
	const byte_t key[64] = "\x94\x20\x9c\x70\xe1\xdc\x08\xdd\x70\x2d\x69\x18\xe9\x75\x57\xec\x28\x4f\x5d\xa9\xdd\x47\x65\x4f\x48\x42\xe7\xe6\x71\xa5\xba\xea\x7f\x58\x27\x30\xbf\xcd\xf4\x34\x66\xee\xaa\x00\x05\x1c\x28\x58\x6d\xe3\x39\x96\x15\xc5\x42\xdb\xbd\xb8\x0f\xa9\x0e\x7c\x18\x2d";
	
	// hardcoded sequence number
	const uint64_t seqnum = 1;
	
	// hardcoded payload+length
	const byte_t payload[8] = "Hello!\n\0";
	const uint32_t payload_len = sizeof(payload);
	
	// prepare a buffer to store the encrypted packet
	const uint32_t encrypted_pkt_len = payload_len + 20;
	byte_t encrypted_pkt[encrypted_pkt_len];
	memset(encrypted_pkt, '\0', encrypted_pkt_len);
	
	// Encrypt the packet
	err = openssh_chacha20_poly1305_encrypt(key, seqnum, payload, payload_len, encrypted_pkt);
	if(err != 0) {
		printf("Error: %d", err);
		exit(1);
	}
	
	printf("Encrypted Packet: ");
	printhex(encrypted_pkt, sizeof(encrypted_pkt));
	
	// prepare a buffer to store the decrypted packet
	byte_t decrypted_payload[payload_len];	
	
	// Decrypt the packet
	err = openssh_chacha20_poly1305_decrypt(key, seqnum, encrypted_pkt, encrypted_pkt_len, decrypted_payload);
	if(err != 0) {
		printf("Error: %d", err);
		exit(1);
	}

	printf("Payload: ");
	printhex(decrypted_payload, sizeof(decrypted_payload));
	
	printf("\nPayload text:\n%s\n", decrypted_payload);
	return;
}

// This test uses a real packet
void test2() {
	gcry_error_t err;

	// 512-bit key
	const byte_t key[64] = "\xe5\x8b\x6e\xe1\xba\xad\x11\x07\x5f\x55\xea\xd3\x9c\x8c\xa4\x62\xa9\xc9\xef\x9a\x4b\xcc\xfa\x1d\x5d\x1b\x4b\x88\x52\x24\xb3\x22\x42\xd1\xb3\xc6\xe1\x5e\x57\xd4\x3b\x30\x59\x7b\x3b\xf6\x95\xe6\xe0\xd4\xd7\xba\x61\x58\x28\xeb\x2b\xdd\x6e\xe7\x97\x5b\xae\x77";
	//const byte_t key[64] = "\xba\x91\x1c\x69\xcb\xcb\xab\x6e\x85\x4a\x21\xb6\x1f\x7d\x21\x4a\xff\xd9\x28\x43\x03\x19\x95\x92\x70\x08\x2b\x22\xe9\x1f\x8c\xa6\x4f\xb8\xa5\x34\x82\x4f\x65\x33\x19\x19\x7c\xd5\x51\xc7\xdb\x37\x01\xac\x1c\x9b\x6b\x13\x07\x34\x93\xa6\xc8\xe9\xa2\xdf\xc2\x7a";
	
	// sequence number
	const uint64_t seqnum = 20;
	//const uint64_t seqnum = 15;
	
	// hardcoded payload+length
	const byte_t encrypted_pkt[100] = "\x63\x4a\xd1\xc3\xe3\x27\x58\x69\xd8\x22\xcb\x7d\xcd\x1f\x69\xd8\x2e\xb9\x58\xea\x0b\x18\x38\x55\x8d\x23\xc8\xd8\x41\x19\xa7\x37\x42\x34\xae\xb6\x95\x22\x6a\x89\x6a\x0f\xda\x64\x6b\x3d\x3f\xa9\xa9\x5a\xf4\xba\x19\xba\xb4\xe1\xe5\x77\x5b\x13\x8f\xa9\xb2\xee\x46\x8a\x15\xa3\xe4\x4b\x73\xd5\xe9\x2e\xf8\x4a\x26\x5a\x81\x19\x44\x4b\xad\x22\x14\xcf\xd3\xdb\x84\x94\x5c\x86\x71\xe5\x40\xe7\xaa\xd4\xa5\x47";
	//const byte_t encrypted_pkt[36] = "\x00\x00\x00\x10\x05\x5e\x00\x00\x00\x00\x00\x00\x00\x01\x0d\x68\x6f\xc7\x51\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	const uint32_t encrypted_pkt_len = sizeof(encrypted_pkt);
	
	printf("Encrypted Packet: ");
	printhex(encrypted_pkt, encrypted_pkt_len);
	
	// prepare a buffer to store the decrypted packet
	byte_t decrypted_payload[encrypted_pkt_len - 20];
	
	// Decrypt the packet
	err = openssh_chacha20_poly1305_decrypt(key, seqnum, encrypted_pkt, encrypted_pkt_len, decrypted_payload);
	if(err != 0) {
		printf("Error: %s\n", gcry_strerror(err));
		exit(1);
	}

	printf("Payload: ");
	printhex(decrypted_payload, sizeof(decrypted_payload));
	
	printf("\nPayload text:\n", decrypted_payload);
	
	for(int i = 0; i < sizeof(decrypted_payload); ++i) {
		printf("%c", decrypted_payload[i]);
	}
	printf("\n");
	
	return;
}

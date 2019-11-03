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

int openssh_chacha20_poly1305_decrypt(const byte_t *key, uint64_t pkt_seq_number, const byte_t *encrypted_pkt, byte_t *out) {
	byte_t k1[32];
	byte_t k2[32];
	
	byte_t seqbuf[8];
	POKE_U64(seqbuf, pkt_seq_number);
	
	byte_t lenbuf[4];
	uint32_t payload_len = 0;
	
	memcpy(k1, (key + 32), 32);
	memcpy(k2, key, 32);
	
	// cipher1 decrypts packet length header, cipher2 decrypts packet payload
	gcry_cipher_hd_t cipher1, cipher2;
    gcry_error_t err = 0;
	
	// decrypt packet length
	err = gcry_cipher_open (&cipher1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher1, k1, 32);
	err = gcry_cipher_setiv(cipher1, seqbuf, 8);
	err = gcry_cipher_decrypt(cipher1, lenbuf, 4, encrypted_pkt, 4);
	payload_len = PEEK_U32(lenbuf);
	
	// decrypt packet payload
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, seqbuf, 8);
	err = gcry_cipher_decrypt(cipher2, out, payload_len, encrypted_pkt + 4, payload_len);
	/*
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, seqbuf, 8);
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

    FILE *fpr;
    char (*file)[MAXC] = NULL; // pointer to array of type char [MAXC]
    int i,n = 0;

    // Char pointer for delimited string
    char *ptr;
    // current line
    int line = 0;
    /*Opening the input file in "r" mode*/
    fpr = fopen(argv[1], "r");

    /* check if input file is valid */
    if (fpr == NULL) {
		puts("invalid input file");
		return 0;
	}
    if (!(file = malloc (MAXL * sizeof *file))) { /* allocate MAXL arrays */
        fprintf (stderr, "error: virtual memory exhausted.\n");
        return 0;
    }

    while (n < MAXL && fgets (file[n], MAXC, fpr)) { /* read each line */
        char *p = file[n];                  /* assign pointer */
        for (; *p && *p != '\n'; p++) {}     /* find 1st '\n'  */
        *p = 0, n++;                         /* nul-termiante  */
    }

    if (fpr != stdin) fclose (fpr);   /* close file if not stdin */
    // for (i = 0; i < n; i++) printf ("%s\n", file[i]);
    int length = sizeof(file);

    // STEP 2: File tokenizing
    int line_index = -1;
    int word_index = 0;
    // 10 rows of 10 split words of max len 260 characters
    char words[10][10][260];
    for (int i = 0; i < length; i++) {
        char *line = file[i];
        int init_size = sizeof(line);
        char delim[] = "|";

        char *ptr = strtok(line, delim);

        while(ptr != NULL)
        {
            //printf("'%s'\n", ptr);
            if (ptr[0] == 'd') {
                line_index ++ ;
                word_index = 0;
               // printf("\n");
            }
            strcpy(words[line_index][word_index], ptr);
            //printf("%s ", ptr);
            //printf("'%s'\n", words[line_index][word_index]);
            word_index ++;
            ptr = strtok(NULL, delim);
        }
    }

    // STEP 3: Get the keys
    
    byte_t char_key0[139];
    byte_t char_key1[139];

    strncpy(char_key0, words[0][1]+11, 128);
    strncpy(char_key1, words[1][1]+11, 128);

    uint8_t * key0; 
    uint8_t * key1;

    key0 = datahex(char_key0);
    key1 = datahex(char_key1);

    uint8_t key0_first[32];
    memcpy(key0_first, key0, 32);


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

void test1() {
	gcry_cipher_hd_t cipher1, cipher2;
	gcry_error_t err;

	const byte_t key[64] = "\x94\x20\x9c\x70\xe1\xdc\x08\xdd\x70\x2d\x69\x18\xe9\x75\x57\xec\x28\x4f\x5d\xa9\xdd\x47\x65\x4f\x48\x42\xe7\xe6\x71\xa5\xba\xea\x7f\x58\x27\x30\xbf\xcd\xf4\x34\x66\xee\xaa\x00\x05\x1c\x28\x58\x6d\xe3\x39\x96\x15\xc5\x42\xdb\xbd\xb8\x0f\xa9\x0e\x7c\x18\x2d";
	
	const uint64_t seqnum = 1;
	const byte_t seqbuf[8];
	POKE_U64(seqbuf, seqnum);
	
	const byte_t payload[8] = "Hello!\n\0";
	const uint32_t payload_len = sizeof(payload);
	const byte_t lenbuf[4];
	POKE_U32(lenbuf, payload_len);
	
	byte_t k1[32];
	byte_t k2[32];
	memcpy(k1, (key + 32), 32);
	memcpy(k2, key, 32);

	byte_t encrypted_pkt[payload_len + 20];
	memset(encrypted_pkt, '\0', sizeof(encrypted_pkt));
	
	// encrypt packet length
	err = gcry_cipher_open (&cipher1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher1, k1, 32);
	err = gcry_cipher_setiv(cipher1, seqbuf, 8);
	err = gcry_cipher_encrypt(cipher1, encrypted_pkt, 4, lenbuf, 4);
	
	// encrypt packet payload
	err = gcry_cipher_open (&cipher2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0);
	err = gcry_cipher_setkey(cipher2, k2, 32);
	err = gcry_cipher_setiv(cipher2, seqbuf, 8);
	err = gcry_cipher_encrypt(cipher2, (encrypted_pkt + 4), payload_len, payload, payload_len);

	if(err != 0) {
		printf("Error: %d", err);
		exit(1);
	}
	
	printf("Encrypted Packet: ");
	printhex(encrypted_pkt, sizeof(encrypted_pkt));
	
	byte_t decrypted_payload[payload_len];	
	
	// Test the decrypt function
	err = openssh_chacha20_poly1305_decrypt(key, seqnum, encrypted_pkt, decrypted_payload);
	if(err != 0) {
		printf("Error: %d", err);
		exit(1);
	}

	printf("Payload: ");
	printhex(decrypted_payload, sizeof(decrypted_payload));
	
	printf("\nPayload text:\n%s\n", decrypted_payload);
	return;
}

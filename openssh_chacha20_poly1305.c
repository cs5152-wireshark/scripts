/*H**********************************************************************
* C Port of the OpenSSH ChaCha20-Poly1305 encryption/decryption script 
* using libgcrypt.
*H***********************************************************************/

#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#include <math.h>

// max number of lines, max characters per line
enum { MAXL = 40, MAXC = 260 };

char* substring (const char* input, int offset, int len, char* dest)
{
  int input_len = strlen (input);
  if (offset + len > input_len)
  {
     return NULL;
  }
  strncpy (dest, input + offset, len);
  return dest;
}

uint8_t* datahex(char* string) {

    if(string == NULL) 
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0) // must be even
       return NULL;

    size_t dlength = slength / 2;

    uint8_t* data = malloc(dlength);
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

int main(int argc, char *argv[])
{
    // STEP 1: Read in the input file

    FILE *fpr;
    char (*file)[MAXC] = NULL; /* pointer to array of type char [MAXC] */
    int i,n = 0;

    /*Char pointer for delimited string */
    char *ptr;
    /* current line */
    int line = 0;
    /*Opening the input file in "r" mode*/
    fpr = fopen(argv[1], "r");

    /* check if input file is valid */
    if (fpr == NULL) puts("invalid input file");
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
                printf("\n");
            }
            strcpy(words[line_index][word_index], ptr);
            //printf("%s ", ptr);
            printf("'%s'\n", words[line_index][word_index]);
            word_index ++;
            ptr = strtok(NULL, delim);
        }
    }

    // STEP 3: Get the keys
    
    int max = fmax(strlen(words[0][1]), strlen(words[1][1]));
    char char_key0[max];
    char char_key1[max];

    substring(words[0][1], 11, strlen(words[0][1]), char_key0);
    substring(words[1][1], 11, strlen(words[1][1]), char_key1);

    // for (int j = 11; j< max ; j++){
    //     char_key0[j-11] = words[0][1][j];
    //     char_key1[j-11] = words[1][1][j];
    // } 

    uint8_t * key0; 
    uint8_t * key1;
    key0 = datahex(char_key0);
    key1 = datahex(char_key1);

    printf("%s, %s\n", char_key0, char_key1);
    // https://github.com/Chronic-Dev/libgcrypt/blob/master/tests/basic.c

    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;
    unsigned char output[MAXL];

    int block_length = gcry_cipher_get_algo_blklen(GCRY_CIPHER_CHACHA20);
    int key_length = gcry_cipher_get_algo_keylen (GCRY_CIPHER_CHACHA20);

    err = gcry_cipher_open (&handle, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_CTR, 0);
    err = gcry_cipher_setkey (handle, key0, key_length);
    //A 96-bit nonce.  In some protocols, this is known as the Initialization Vector
    // gcry_create_nonce (handle, 96);
    gcry_cipher_setiv (handle, NULL, 0);

    // err = gcry_cipher_encrypt (handle,
	// 			 output, block_length,
	// 			 ,
	// 			 );





    free(file);

    return 0;
}
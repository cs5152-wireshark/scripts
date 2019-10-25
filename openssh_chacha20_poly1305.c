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
            printf("%s ", ptr);
            //printf("'%s'\n", words[line_index][word_index]);
            word_index ++;
            ptr = strtok(NULL, delim);
        }
    }

    // STEP 3: Get the keys
    
    int max = fmax(sizeof(words[0][1]), sizeof(words[1][1]));
    char char_key0[max];
    char char_key1[max];

    for (int j = 11; j< max ; j++){
        char_key0[j-11] = words[0][1][j];
        char_key1[j-11] = words[1][1][j];
    } 

    int key0, key1;
    key0 = atoi(char_key0);
    key1 = atoi(char_key1);

    printf("%s, %s\n", char_key0, char_key1);
    //printf("%.2x, %.2x\n", char_key0, char_key1);

    free(file);

    return 0;
}
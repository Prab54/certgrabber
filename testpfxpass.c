// Compile: gcc testpfxpass.c -o verifypfx -lcrypto -std=c99
// Run:  ./verifypfx dls/2023_senha122015.pfx common_roots.txt

#include <stdio.h>
#include <errno.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

#define wordslength 21

char **getwords (FILE *fp, int *n, int listlength);

void free_array (char** words, int rows);

int main(int argc, char *argv[])
{
    int i = 0;
    int nwords = 0;
    char **words = NULL;
    int listlength;  // Create a new variable for listlength

    if (argc < 4) {  // Validate number of command-line arguments
        fprintf(stderr, "Usage: %s <pfx file> <dictionary file> <listlength>\n", argv[0]);
        return 1;
    }

    listlength = atoi(argv[3]);  // Convert the 3rd argument to an integer

    char *fname = argv[2];
    FILE *dictionary = fopen (fname, "r");

    if (!dictionary) { 
        fprintf (stderr, "error: file open failed.\n");
        return 1;
    }

    if (!(words = getwords (dictionary, &nwords, listlength))) {
        fprintf (stderr, "error: getwords returned NULL.\n");
        return 1;
    }
    fclose(dictionary);

    PKCS12 *p12;
    FILE *fp = fopen(argv[1], "rb");
    if( fp == NULL ) { perror("fopen"); return 1; }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);

    OpenSSL_add_all_algorithms();
    ERR_load_PKCS12_strings();

    if( p12 == NULL ) { ERR_print_errors_fp(stderr); exit(1); }

    if( PKCS12_verify_mac(p12, NULL, 0) )
    {
        printf("PKCS12 has no password.\n");
    }

    for(i = 0; i < listlength; i++) { 
        if( PKCS12_verify_mac(p12, words[i], -1) )
        {
            printf("%s",words[i]);
            i = listlength;
        }
    }

    return 0;
}

// Rest of the code remains unchanged...



char *my_strdup(const char *s) {
    char *new = malloc(strlen(s) + 1);
    if (new) {
        strcpy(new, s);
    }
    return new;
}

/* read all words 1 per-line, from 'fp', return
 * pointer-to-pointers of allocated strings on 
 * success, NULL otherwise, 'n' updated with 
 * number of words read.
 */
char **getwords (FILE *fp, int *n, int listlength) {

    char **words = NULL;
    char buf[wordslength + 1] = {0};
    int maxlen = listlength > 0 ? listlength : 1;

    if (!(words = calloc (maxlen, sizeof *words))) {
        fprintf (stderr, "getwords() error: virtual memory exhausted.\n");
        return NULL;
    }

    while (fgets (buf, wordslength + 1, fp)) {

        size_t wordlen = strlen (buf);  /* get word length */

        if (buf[wordlen - 1] == '\n')   /* strip '\n' */
            buf[--wordlen] = 0;

        words[(*n)++] = my_strdup (buf);   /* allocate/copy */

        if (*n == maxlen) { /* realloc as required, update maxlen */
            void *tmp = realloc (words, maxlen * 2 * sizeof *words);
            if (!tmp) {
                fprintf (stderr, "getwords() realloc: memory exhausted.\n");
                return words; /* to return existing words before failure */
            }
            words = tmp;
            memset (words + maxlen, 0, maxlen * sizeof *words);
            maxlen *= 2;
        }
    }

    return words;
}

void free_array (char **words, int rows){

    int i;
    for (i = 0; i < rows; i++){
        free (words[i]);
    }
    free(words);
}

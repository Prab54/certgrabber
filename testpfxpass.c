// Compile: gcc testpfxpass.c -o verifypfx -lcrypto -std=c99
// Run:  ./verifypfx dls/2023_senha122015.pfx common_roots.txt

#include <stdio.h>
#include <errno.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

#define listlength 18200
#define wordslength 21

char **getwords (FILE *fp, int *n);
void free_array (char** words, int rows);


int main(int argc, char *argv[])
{
        int i = 0;
        int nwords = 0;
        int loop_max = 50;
        char **words = NULL;  /* file given as argv[1] (default dictionary.txt) */
        char *fname = argc > 1 ? argv[2] : "dictionary.txt";
        FILE *dictionary = fopen (fname, "r");
    
        if (!dictionary) { /* validate file open */
                fprintf (stderr, "error: file open failed.\n");
                return 1;
        }

        if (!(words = getwords (dictionary, &nwords))) {
                fprintf (stderr, "error: getwords returned NULL.\n");
                return 1;
        }
        fclose(dictionary);


//      char *passes[] = {"Geek", "Geeks", "Geekfor","122015","test"};
//        const char *password = argv[2];
        PKCS12 *p12;
        // Load the pfx file.

        FILE *fp = fopen(argv[1], "rb");
        if( fp == NULL ) { perror("fopen"); return 1; }
        p12 = d2i_PKCS12_fp(fp, NULL);
        fclose(fp);

        OpenSSL_add_all_algorithms();
        ERR_load_PKCS12_strings();

        if( p12 == NULL ) { ERR_print_errors_fp(stderr); exit(1); }

        // Note:  No password is not the same as zero-length password.  Check for both.
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
char **getwords (FILE *fp, int *n) {

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

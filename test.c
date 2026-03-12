#include <stdio.h>
#include <string.h>


int main(int argc, char* argv[]){
    if (argc != 3){
        fprintf(stderr, "Usage ./test <haystack> <needle>\n");
        return 0;
    }

    char* str = argv[1];
    char* pattern = argv[2];
    fprintf(stdout,"Haystack %s -- %lu\n", str, strlen(str));
    fprintf(stdout,"Needle %s -- %lu\n", pattern, strlen(pattern));


    char c1,c2;
    int i,j;
    short unsigned int plen = strlen(pattern);
    // for (int k = 0; k < 16; k++) {
    //     if (pattern[k] == '\0')
    //         break;
    //     plen++;
    // }

    if (plen == 0)
        return 0;

    for (i = 0; i < strlen(str); i++){
        for (j = 0; i + j <= plen * 2; j++){
            // c2 = *(pattern+j);
            fprintf(stdout,"[i-%d] --- [j-%d]\n", i,j);
            c2 = pattern[j];
            if (c2 == '\0'){
                fprintf(stdout,"Found match 1\n"); // found match
            }
            if (i + j == plen * 2){
                fprintf(stdout, "Breaking from the first i+j == plen\n");
                break;
            }
            // c1 = *(str+j);
            c1 = str[j];
            if (c1 == '\0'){
                fprintf(stdout,"Not found match 1\n"); // not found match

            }
            if (c1 != c2){
                break;
            }
        }
        if (i + j == plen * 2){
            fprintf(stdout,"Not found match 2\n"); // not found match
            // return 0; // not found
        }
        str++;
    }
    return 0;
}
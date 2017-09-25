//
//  main.c
//  Testing module communication
//
//  Created on 05/09/17.
//

#include <stdio.h> // I/O
#include <stdlib.h> // System()
#include <string.h> // String manipulation

static const int BGMR_OPTION_MAX_BUFFER = 1024;
static const int BGMR_SENTENCE_MAX_BUFFER = 1024;

char *encrypted(char *sentence);
char *decrypted(char *sentence);
char *hashValue(char *sentence);
char quitWithError();

int main(int argc, const char * argv[]) {
    system("clear");
    printf("Welcome to the Crypto Device - Your Guaranteed Encryption\n");
    char option = 'm'; // Default option
    while (option != 'q') {
        printf("\nPress c to cypher, d to decypher, h to hash, q to quit. Type: \n");
        char buffer[BGMR_OPTION_MAX_BUFFER];
        if (fgets(buffer, sizeof(buffer), stdin)) {
            if (1 == sscanf(buffer, "%c", &option)) {
                // Option can be safely used
                char sentence[BGMR_SENTENCE_MAX_BUFFER];
                if (option == 'c') {
                    printf("\nType what you want to cypher: ");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char encryptedSentence[sizeof(sentence)];
                        strcpy(encryptedSentence, encrypted(sentence));
                        printf("\nEncrypted sentence: %s", encryptedSentence);
                    }
                } else if (option == 'd') {
                    printf("\nType what you want to decypher: ");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char decryptedSentence[sizeof(sentence)];
                        strcpy(decryptedSentence, decrypted(sentence));
                        printf("\nDecrypted sentence: %s", decryptedSentence);
                    }
                } else if (option == 'h') {
                    printf("\nType what you want to hash: ");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char hashedSentence[sizeof(sentence)];
                        strcpy(hashedSentence, hashValue(sentence));
                        printf("\nHashed sentence: %s", hashedSentence);
                    }
                } else if (option == 'q') {
                    system("clear");
                    printf("Quitting . . .\n");
                } else {
                    printf("\nPlease try again.");
                }
            } else {
                option = quitWithError();
            }
        } else {
            // fgets() error'ed or EOF
            option = quitWithError();
        }
    }
    return 0;
}

char *encrypted(char *sentence) {
//    bgmr_cypher(sentence);
//    return bgmr_read();
    return "encryption sample";
}

char *decrypted(char *sentence) {
//    bgmr_decypher(sentence);
    //    return bgmr_read();
    return "decryption sample";
}

char *hashValue(char *sentence) {
//    bgmr_hash(sentence);
    //    return bgmr_read();
    return "hash sample";
}

char quitWithError() {
    system("clear");
    printf("\nUnexpected input. Quitting . . . \n");
    return 'q';
}

//
//  testprog.c
//  Testing module communication
//
//  Created on 21/09/17.
//
//  BRUNO AUGUSTO PEDROSO        12662136
//  GIULIANA SALGADO ALEPROTI    12120457
//  MATHEUS DE PAULA NICOLAU     12085957
//  ROGER OBA                    12048534

#include <stdio.h>  // I/O
#include <unistd.h> // open/write/read functions
#include <stdlib.h> // System()
#include <string.h> // String manipulation
#include <errno.h>  // Supplies the error number
#include <fcntl.h>  // File management

static const int BGMR_OPTION_MAX_BUFFER = 1024;
static const int BGMR_SENTENCE_MAX_BUFFER = 1024;
//static char stringRead[BUFFER_LENGTH]; ///< The receive buffer from the LKM
static int deviceDescriptor; // A file descriptor for the crypto device

char *encrypted(char *sentence);
char *decrypted(char *sentence);
char *hashValue(char *sentence);
char quitWithError();
void cleanBuffer(char *buffer);

int main(int argc, const char * argv[]) {
    system("clear");
    printf("Welcome to the Crypto Device - Your Guaranteed Encryption\n");

    ssize_t ret;
    printf("\nStarting crypto device. . .\n");
    deviceDescriptor = open("/dev/cryptochar", O_RDWR); // Open the device with read/write access
    if (deviceDescriptor < 0) {
        perror("Failed to open the crypto device...");
        return errno;
    }

//    printf("Press ENTER to read back from the device...\n");
//    getchar();
//
//    printf("Reading from the device...\n");
//    ret = read(deviceDescriptor, receive, BUFFER_LENGTH);        // Read the response from the LKM
//    if (ret < 0) {
//        perror("Failed to read the message from the device.");
//        return errno;
//    }
//    printf("The received message is: [%s]\n", receive);
//    printf("End of the program\n");
//    return 0;

    char option = 'm'; // Default option
    while (option != 'q') {
        printf("\nPress c to cypher, d to decypher, h to hash, q to quit. Type: \n");
        char buffer[BGMR_OPTION_MAX_BUFFER];
        cleanBuffer(buffer);
        if (fgets(buffer, sizeof(buffer), stdin)) {
            if (1 == sscanf(buffer, "%c", &option)) {
                // Option can be safely used
                char sentence[BGMR_SENTENCE_MAX_BUFFER];
                char sentenceToKernel[BGMR_SENTENCE_MAX_BUFFER+2];
                cleanBuffer(sentence);
                cleanBuffer(sentenceToKernel);
                if (option == 'c') {
                    printf("\nType what you want to cypher: ");
//                    scanf("%[^\n]%*c", sentence); // Read in a string (with spaces)
//                    printf("Read sentence from input: [%s].\n", sentence);
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char encryptedSentence[sizeof(sentence)];
                        sprintf(sentenceToKernel, "%c %s", option, sentence);
                        printf("sentenceToKernel: %s\n", sentenceToKernel);
                        strcpy(encryptedSentence, encrypted(sentenceToKernel));
                        printf("\nEncrypted sentence: %s", encryptedSentence);
                    }
                } else if (option == 'd') {
                    printf("\nType what you want to decypher: ");
//                    scanf("%[^\n]%*c", sentence); // Read in a string (with spaces)
//                    printf("Read sentence from input: [%s].\n", sentence);
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char decryptedSentence[sizeof(sentence)];
                        sprintf(sentenceToKernel, "%c %s", option, sentence);
                        printf("sentenceToKernel: %s\n", sentenceToKernel);
                        strcpy(decryptedSentence, decrypted(sentence));
                        printf("\nDecrypted sentence: %s", decryptedSentence);
                    }
                } else if (option == 'h') {
                    printf("\nType what you want to hash: ");
//                    scanf("%[^\n]%*c", sentence); // Read in a string (with spaces)
//                    printf("Read sentence from input: [%s].\n", sentence);[
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        char hashedSentence[sizeof(sentence)];
                        sprintf(sentenceToKernel, "%c %s", option, sentence);
                        printf("sentenceToKernel: %s\n", sentenceToKernel);
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
    ret = close(deviceDescriptor);
    if (ret < 0) {
        perror("Failed to close the crypto device.");
        return errno;
    }
    return 0;
}

char *encrypted(char *sentence) {
    ssize_t ret = write(deviceDescriptor, sentence, strlen(sentence)); // Write the string to the crypto device
    if (ret < 0) {
        perror("Failed to write the message to the crypto device.");
        return errno;
    }


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
    perror("\nUnexpected user input. Quitting . . . \n");
    return 'q';
}

// MARK: Helper Functions
void cleanBuffer(char *buffer) {
    int i = 0;
    while (buffer[i] != '\0') {
        buffer[i] = '\0';
        i++;
    }
}

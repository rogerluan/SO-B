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
char quitWithError();

int main(int argc, const char * argv[]) {
    system("clear");
    printf("Welcome to the Crypto Device - Your Guaranteed Encryption\n");

    ssize_t ret;
    printf("\nStarting crypto device. . .\n");
    deviceDescriptor = open("/dev/particao", O_RDWR); // Open the device with read/write access
    if (deviceDescriptor < 0) {
        perror("Failed to open the crypto device...");
        return errno;
    }

    char option = 'm'; // Default option
    while (option != 'q') {
        printf("\nPress c to create a new file and write on it, r to read, w to write in a existing file, q to quit. Type: \n");
        char buffer[BGMR_OPTION_MAX_BUFFER];
        cleanBuffer(buffer);
        if (fgets(buffer, sizeof(buffer), stdin)) {
            if (1 == sscanf(buffer, "%c", &option)) {
                // Option can be safely used
                char sentence[BGMR_SENTENCE_MAX_BUFFER];
                cleanBuffer(sentence);

                if (option == 'c') {
                    printf("\nType The name of the file, with extension: \n");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
			FILE *file;
			file = fopen(sentence, "w");
                        printf("\nType what to want to write: \n");

			if (fgets(sentence, sizeof(sentence), stdin)) {
			
			fprintf(file,"%s", sentence);
			}
			fclose(file);
                    }
                } else if (option == 'r') {
                    printf("\nType The name of the file, with extension: \n");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
                        FILE *file;
			file = fopen(sentence, "r");
			if(file == NULL){
                    	printf("\nFile does not exist");
			}
			char c;
			while((c=fgetc(file))!=EOF){
 			  printf("%c",c);
		        }
			fclose(file);
                    }
                } else if (option == 'w') {
                    printf("\nType The name of the file, with extension: \n");
                    if (fgets(sentence, sizeof(sentence), stdin)) {
			FILE *file;
			file = fopen(sentence, "a");	
                        printf("\nType what to want to write: \n");(sentence);
			if (fgets(sentence, sizeof(sentence), stdin)) {
			
			fprintf(file,"%s", sentence);
			fclose(file);
			}
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

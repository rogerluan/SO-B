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
#include <stdlib.h> // strtol()
#include <errno.h> // Supplies the error number
#include <fcntl.h> // File management
#include <string.h> // String manipulation
#include <unistd.h> // Open/write/read functions

#define BUFFER_LENGTH 1024               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main() {
    int fd;
    ssize_t ret;
    char stringToSend[BUFFER_LENGTH];
    printf("Starting device test code example...\n");
    fd = open("/dev/cryptochar", O_RDWR);             // Open the device with read/write access
    if (fd < 0) {
        perror("Failed to open the device...");
        return errno;
    }
    printf("Type in 'c', 'd' or 'h', followed by a space and the sentence:\n");
    scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)
    printf("Writing message to the device [%s].\n", stringToSend);
    ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
    if (ret < 0) {
        perror("Failed to write the message to the device.");
        return errno;
    }

    printf("Press ENTER to read back from the device...\n");
    getchar();

    printf("Reading from the device...\n");
    ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
    if (ret < 0) {
        perror("Failed to read the message from the device.");
        return errno;
    }
    printf("The received message is: [%X]\n", strtol(receive, NULL, strlen(receive)));
    printf("End of the program\n");
    return 0;
}

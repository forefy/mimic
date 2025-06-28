#ifndef HELPERS_H
#define HELPERS_H

#include <stdlib.h>
#include <stdio.h>

// Converts binary data to a hexadecimal string
char* hexify(const unsigned char* data, size_t length) {
    char* hex_string = (char*)malloc(length * 2 + 1);
    if (!hex_string) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + (i * 2), "%02x", data[i]);
    }
    hex_string[length * 2] = '\0';
    return hex_string;
}

#endif // HELPERS_H

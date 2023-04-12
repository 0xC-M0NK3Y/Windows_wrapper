#include <stdio.h>
#include <stdlib.h>

#include "macro.h"

void *copy_file_in_ram(char *filename) {

    FILE    *file;
    size_t  size;
    void    *ret;

    file = fopen(filename, "rb");
    if (file == NULL) {
        DEBUG_PRINTF("Error: failed open wrapped_dll\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);
    ret = malloc(size);
    if (ret == NULL) {
        DEBUG_PRINTF("malloc failed\n");
        return NULL;
    }
    fread(ret, 1, size, file);

    return ret;
}
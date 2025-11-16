#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cfg_tokenizer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit size to avoid excessive memory usage */
    if (size == 0 || size > 65536)
        return 0;

    /* Create a memory stream from the input data */
    FILE *stream = fmemopen((void *)data, size, "r");
    if (!stream)
        return 0;

    /* Tokenize the input */
    char buffer[1024];
    enum Token token;

    /* Parse tokens until end or error */
    do {
        token = next_token(stream, buffer, sizeof(buffer));
    } while (token != TOKEN_END && token != TOKEN_ERROR);

    fclose(stream);
    return 0;
}

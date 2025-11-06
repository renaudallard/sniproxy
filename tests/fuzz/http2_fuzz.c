#include <stdint.h>
#include <stdlib.h>
#include "http2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *hostname = NULL;

    parse_http2_header(data, size, &hostname);

    free(hostname);
    return 0;
}

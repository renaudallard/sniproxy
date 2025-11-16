#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hostname_sanitize.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit size to avoid excessive memory usage */
    if (size == 0 || size > 4096)
        return 0;

    /* Create a mutable copy for sanitization */
    char *hostname = malloc(size + 1);
    if (!hostname)
        return 0;

    memcpy(hostname, data, size);
    hostname[size] = '\0';

    size_t hostname_len = size;
    size_t max_len = 255; /* DNS maximum hostname length */

    /* Test hostname sanitization */
    sanitize_hostname(hostname, &hostname_len, max_len);

    free(hostname);
    return 0;
}

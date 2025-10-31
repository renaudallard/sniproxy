/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http2_huffman.h"

struct hpack_huffman_code {
    uint32_t code;
    uint8_t length;
    int16_t value;
};

#include "http2_huffman_table.inc"

struct huffman_node {
    int16_t child[2];
    int16_t value;
};

static struct huffman_node *huffman_tree;
static size_t huffman_tree_cap;
static size_t huffman_tree_size;
static int huffman_built;

static int build_huffman_tree(void);

static int
build_huffman_tree(void) {
    if (huffman_built)
        return 1;

    huffman_tree_cap = 512;
    huffman_tree = calloc(huffman_tree_cap, sizeof(struct huffman_node));
    if (huffman_tree == NULL)
        return 0;
    huffman_tree_size = 1;

    for (size_t i = 0; i < HPACK_HUFFMAN_TABLE_LENGTH; i++) {
        uint32_t code = hpack_huffman_table[i].code;
        uint8_t length = hpack_huffman_table[i].length;
        int16_t value = hpack_huffman_table[i].value;
        int16_t node = 0;

        for (int bit = length - 1; bit >= 0; bit--) {
            int direction = (code >> bit) & 0x1;
            int16_t next = huffman_tree[node].child[direction];
            if (next == 0) {
                if (huffman_tree_size == huffman_tree_cap) {
                    if (huffman_tree_cap > SIZE_MAX / 2)
                        return 0;

                    size_t new_cap = huffman_tree_cap * 2;
                    struct huffman_node *tmp = realloc(huffman_tree, new_cap * sizeof(struct huffman_node));
                    if (tmp == NULL) {
                        free(huffman_tree);
                        huffman_tree = NULL;
                        huffman_tree_cap = 0;
                        huffman_tree_size = 0;
                        return 0;
                    }
                    memset(tmp + huffman_tree_cap, 0, (new_cap - huffman_tree_cap) * sizeof(struct huffman_node));
                    huffman_tree = tmp;
                    huffman_tree_cap = new_cap;
                }
                next = (int16_t)huffman_tree_size++;
                huffman_tree[node].child[direction] = next;
            }
            node = next;
        }

        huffman_tree[node].value = value;
    }

    huffman_built = 1;
    return 1;
}

int
hpack_decode_huffman(const unsigned char *data, size_t len, char **out, size_t *out_len) {
    if (!build_huffman_tree())
        return -1;

    if (len > (SIZE_MAX - 1) / 2)
        return -1;

    size_t capacity = len * 2 + 1;
    char *buf = malloc(capacity);
    if (buf == NULL)
        return -1;

    size_t pos = 0;
    int16_t node = 0;
    uint32_t bit_buffer = 0;
    unsigned int bit_count = 0;

    for (size_t i = 0; i < len; i++) {
        bit_buffer = (bit_buffer << 8) | data[i];
        bit_count += 8;

        while (bit_count > 0) {
            int bit = (bit_buffer >> (bit_count - 1)) & 0x1;
            bit_count--;
            int16_t next = huffman_tree[node].child[bit];
            if (next == 0) {
                free(buf);
                return -1;
            }
            node = next;
            if (huffman_tree[node].value >= 0) {
                if (pos + 1 >= capacity) {
                    size_t new_cap = capacity * 2;
                    char *tmp = realloc(buf, new_cap);
                    if (tmp == NULL) {
                        free(buf);
                        return -1;
                    }
                    buf = tmp;
                    capacity = new_cap;
                }
                buf[pos++] = (char)huffman_tree[node].value;
                node = 0;
            }
        }
    }

    uint32_t mask;
    if (bit_count == 0)
        mask = 0u;
    else if (bit_count >= 32)
        mask = UINT32_MAX;
    else
        mask = (1u << bit_count) - 1u;
    if (bit_count > 0 && (bit_buffer & mask) != mask) {
        free(buf);
        return -1;
    }

    buf[pos] = '\0';
    *out = buf;
    *out_len = pos;
    return 0;
}

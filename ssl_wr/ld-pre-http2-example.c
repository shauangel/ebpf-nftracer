#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/ssl.h>

typedef int (*ssl_write_func)(SSL *ssl, const void *buf, int num);

static uint32_t read24(const unsigned char *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void write24(unsigned char *p, uint32_t v)
{
    p[0] = (v >> 16) & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = v & 0xff;
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    static ssl_write_func real_SSL_write = NULL;
    if (!real_SSL_write)
        real_SSL_write = (ssl_write_func)dlsym(RTLD_NEXT, "SSL_write");

    fprintf(stderr, "[HOOK] SSL_write called, len=%d\n", num);

    const unsigned char *data = (const unsigned char *)buf;

    /*
      HTTP/2 frame header:
      0-2: length
      3:   type
      4:   flags
      5-8: stream id

      type 0x01 = HEADERS
      type 0x09 = CONTINUATION
    */

    if (num >= 9) {
        uint32_t len = read24(data);
        unsigned char type = data[3];
        unsigned char flags = data[4];

        uint32_t stream_id =
            ((uint32_t)(data[5] & 0x7f) << 24) |
            ((uint32_t)data[6] << 16) |
            ((uint32_t)data[7] << 8) |
            data[8];

        fprintf(stderr,
                "[HOOK] h2 frame? len=%u type=0x%02x flags=0x%02x stream=%u\n",
                len, type, flags, stream_id);

        if (type == 0x01 && stream_id != 0 && num >= 9 + len) {
            const char *name = "x-nf-signature";
            const char *value = "test-signature";

            unsigned char hpack[256];
            size_t pos = 0;

            hpack[pos++] = 0x00;
            hpack[pos++] = (unsigned char)strlen(name);
            memcpy(hpack + pos, name, strlen(name));
            pos += strlen(name);

            hpack[pos++] = (unsigned char)strlen(value);
            memcpy(hpack + pos, value, strlen(value));
            pos += strlen(value);

            int insert_at = 9 + len;
            int new_num = num + pos;

            unsigned char *new_buf = malloc(new_num);
            if (!new_buf)
                return real_SSL_write(ssl, buf, num);

            memcpy(new_buf, data, insert_at);
            memcpy(new_buf + insert_at, hpack, pos);
            memcpy(new_buf + insert_at + pos, data + insert_at, num - insert_at);

            write24(new_buf, len + pos);

            fprintf(stderr,
                    "[HOOK] inserted into HEADERS payload at=%d, +%zu bytes\n",
                    insert_at, pos);

            int ret = real_SSL_write(ssl, new_buf, new_num);
            free(new_buf);
            return ret;
        }
    }

    return real_SSL_write(ssl, buf, num);
}
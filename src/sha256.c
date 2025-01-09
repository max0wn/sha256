#include <stdio.h>

#include "sha256.h"

WORD bswap32(const WORD);

void calculate(const char *M, const size_t len, uint8_t *hash) {
    size_t filled_bytes = len + sizeof(uint8_t) + sizeof(uint64_t);

    size_t k = (BLOCK_SIZE - filled_bytes % BLOCK_SIZE) == BLOCK_SIZE ? 
        0 : BLOCK_SIZE - filled_bytes % BLOCK_SIZE;

    size_t l = filled_bytes + k;

    WORD *schedule = (WORD *)malloc(l + l / BLOCK_SIZE * 48 * sizeof(WORD));

    uint8_t *ptr = (uint8_t *)schedule;

    // Padding & Parsing the Message
    // Preparing the message schedule
    for (int i = 0, j = 0; i < len; i++) {
        *(ptr + (i % 4)) = M[i];

        if ((i + 1) % 4 == 0) {
            ptr += (i % 4) + 1;
        }

        if (i + 1 == len) {
            *(ptr + ((i + 1) % 4)) = 0x80;

            schedule[(i + 1) / 4 + 48 * j] = bswap32(schedule[(i + 1) / 4 + 48 * j]);

            ptr += k + ((i + 1) % 4) + 1;

            if (BLOCK_SIZE - ((len + 1) % BLOCK_SIZE) < k) {
                ptr += 48 * 4;
            }

            for (int i = LONG_BIT - CHAR_BIT, j = 0; i >= 0; i -= CHAR_BIT, j++) {
                *(ptr + 7 - j) = (len * CHAR_BIT >> (i - WORD_BIT)) & 0xFF;
            }
        }

        if ((i + 1) % 4 == 0) {
            schedule[i / 4 + 48 * j] = bswap32(schedule[i / 4 + 48 * j]);
        }

        if ((i + 1) % 64 == 0) {
            ptr += 48 * 4;
            j++;
        }
    }

    // Setting the initial hash value & SHA-256 Hash Computation
    WORD σ0 = 0, σ1 = 0;
    WORD a, b, c, d, e, f, g, h;
    WORD Σ1, Σ0;
    WORD temp1, temp2;
    WORD h0, h1, h2, h3, h4, h5, h6, h7;

    h0 = 0x6a09e667;
    h1 = 0xbb67ae85;
    h2 = 0x3c6ef372;
    h3 = 0xa54ff53a,
    h4 = 0x510e527f;
    h5 = 0x9b05688c;
    h6 = 0x1f83d9ab;
    h7 = 0x5be0cd19;

    for (int i = 16; i < l; i++) {
        σ0 = ROTR(schedule[i - 15], 7) ^ ROTR(schedule[i - 15], 18) ^ schedule[i - 15] >> 3;
        σ1 = ROTR(schedule[i - 2], 17) ^ ROTR(schedule[i - 2], 19) ^ schedule[i - 2] >> 10;
        schedule[i] = schedule[i - 16] + σ0 + schedule[i - 7] + σ1;

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        if ((i + 1) % 64 == 0) {
            for (int j = 0; j < 64; j++) {
                Σ1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
                Σ0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
                temp1 = h + Σ1 + CH(e, f, g) + K[j] + schedule[(i + 1) - 64 + j];
                temp2 = Σ0 + MAJ(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;

            i += 16;
        }
    }

    for (int i = 0; i < 4; i++) {
        hash[i] = (h0 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (h1 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (h2 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (h3 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (h4 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (h5 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (h6 >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (h7 >> (24 - i * 8)) & 0x000000ff;
    }

    free(schedule);
}

WORD bswap32(const WORD value) {
    return (value & 0xFF) << 24 | (value >> 8 & 0xFF) << 16 | (value >> 16 & 0xFF) << 8 | (value >> 24 & 0xFF);
}

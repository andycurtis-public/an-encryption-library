// SPDX-FileCopyrightText: 2024-2025 Knode.ai
// SPDX-License-Identifier: Apache-2.0
// Maintainer: Andy Curtis <contactandyc@gmail.com>
#include "an-encryption-library/encrypt_decrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


int main(void)
{
    // Example plaintext
    const char *plaintext = "Hello, AES-GCM with separate IV+tag buffer!";
    size_t plaintext_len = strlen(plaintext);

    // Allocate the data buffer (for in-place encryption).
    // In GCM, ciphertext length == plaintext length, so we just need `plaintext_len` bytes here.
    uint8_t *data_buf = malloc(plaintext_len);
    if (!data_buf) {
        fprintf(stderr, "Error: Failed to allocate data_buf.\n");
        return EXIT_FAILURE;
    }

    // Copy plaintext into data_buf
    memcpy(data_buf, plaintext, plaintext_len);

    // Allocate the IV+Tag buffer (fixed size = 12 + 16 = 28 bytes)
    uint8_t iv_tag_buf[IV_TAG_SIZE] = {0};

    // Generate the AES-256 key
    uint8_t key[SECURE_KEY_SIZE];
    generate_secure_key(key);

    // On encryption, data_len is initially the size of the plaintext
    size_t data_len = plaintext_len;

    // Encrypt in place
    if (!encrypt_in_place(data_buf, data_len, iv_tag_buf, key)) {
        free(data_buf);
        return EXIT_FAILURE;
    }
    // data_len should remain == plaintext_len after encryption
    printf("Encryption successful. Encrypted length = %zu\n", data_len);

    // Now 'data_buf' contains the ciphertext, and 'iv_tag_buf' contains {IV + Tag}.

    // Decrypt in place
    if (!decrypt_in_place(data_buf, data_len, iv_tag_buf, key)) {
        fprintf(stderr, "Decryption failed.\n");
        free(data_buf);
        return EXIT_FAILURE;
    }
    printf("Decryption successful. Plaintext length: %zu\n", data_len);

    // Add a null terminator for printing
    data_buf[data_len] = '\0';
    printf("Recovered plaintext: %s\n", (char *)data_buf);

    free(data_buf);
    return EXIT_SUCCESS;
}
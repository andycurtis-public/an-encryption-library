// SPDX-FileCopyrightText: 2024-2025 Knode.ai
// SPDX-License-Identifier: Apache-2.0
// Maintainer: Andy Curtis <contactandyc@gmail.com>
#include "an-encryption-library/encrypt_decrypt.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define GCM_IV_SIZE    12  // 96-bit IV recommended for GCM
#define GCM_TAG_SIZE   16  // 128-bit authentication tag

// Generate a random 256-bit key
static void generate_random_key(uint8_t *key) {
    if (RAND_bytes(key, SECURE_KEY_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random key.\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * Encrypt in place using AES-256-GCM, with IV + Tag stored in a separate buffer.
 *
 *  - data:       in-place buffer containing the plaintext on input;
 *                will be overwritten with ciphertext on output.
 *  - data_len:   pointer to the length of the plaintext on input;
 *                on successful output, this will remain the same
 *                (ciphertext is the same length as plaintext in GCM).
 *  - iv_tag:     buffer of length (GCM_IV_SIZE + GCM_TAG_SIZE) = 28 bytes
 *                to store:
 *                  iv_tag[0..11]   => 12-byte IV
 *                  iv_tag[12..27]  => 16-byte GCM Tag
 *  - key:        32-byte AES-256 key
 *
 * Returns true on success, false on failure.
 */
static bool encrypt_in_place_gcm(uint8_t *data, size_t *data_len,
                                 uint8_t *iv_tag, // must be at least 28 bytes
                                 const uint8_t *key)
{
    // 1. Generate random IV and store it in iv_tag[0..11].
    if (RAND_bytes(iv_tag, GCM_IV_SIZE) != 1) {
        fprintf(stderr, "Error: RAND_bytes for IV failed.\n");
        return false;
    }

    // 2. Create and initialize the cipher context.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed.\n");
        return false;
    }

    // 3. Initialize AES-256-GCM (without key/IV first).
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex (AES-256-GCM) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 4. Set the IV length (12 bytes recommended).
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 5. Now set the key and IV (the IV is in iv_tag[0..11]).
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv_tag) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex (key/iv) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 6. Encrypt in-place: data -> data (same buffer).
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, data, &out_len, data, (int)*data_len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptUpdate failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = out_len;

    // 7. Finalize the encryption (GCM typically doesn't add extra ciphertext).
    if (EVP_EncryptFinal_ex(ctx, data + total_len, &out_len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptFinal_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += out_len;

    // 8. Retrieve the GCM tag and store it in iv_tag[12..27].
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE,
                            iv_tag + GCM_IV_SIZE) != 1) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_ctrl (GET_TAG) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    // The ciphertext length in GCM == plaintext length. No size change to *data_len.
    // The tag is stored externally in iv_tag.
    return true;
}

/*
 * Decrypt in place using AES-256-GCM, with IV + Tag stored in a separate buffer.
 *
 *  - data:     buffer containing the ciphertext on input;
 *              will be overwritten with plaintext on output.
 *  - data_len: pointer to the size of the ciphertext on input (same as plaintext size);
 *              updated to the size of the decrypted plaintext on success (same length).
 *  - iv_tag:   buffer containing:
 *                iv_tag[0..11]   => 12-byte IV used during encryption
 *                iv_tag[12..27]  => 16-byte GCM tag
 *  - key:      32-byte AES-256 key
 *
 * Returns true on success, false on failure (including auth failure).
 */
static bool decrypt_in_place_gcm(uint8_t *data, size_t *data_len,
                                 const uint8_t *iv_tag,
                                 const uint8_t *key)
{
    // We expect *data_len to be the ciphertext length (which is same as plaintext length).
    // We also expect iv_tag to have 12 bytes of IV + 16 bytes of tag.

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed.\n");
        return false;
    }

    // 1. Initialize AES-256-GCM for decryption (no key/IV yet).
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Error: EVP_DecryptInit_ex (AES-256-GCM) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 2. Set IV length.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 3. Provide the key and the IV (extracted from iv_tag).
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv_tag) != 1) {
        fprintf(stderr, "Error: EVP_DecryptInit_ex (key/iv) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 4. Set the expected GCM tag (iv_tag[12..27]).
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                            (void *)(iv_tag + GCM_IV_SIZE)) != 1) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_ctrl (SET_TAG) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 5. Decrypt in place
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, data, &out_len, data, (int)*data_len) != 1) {
        fprintf(stderr, "Error: EVP_DecryptUpdate failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = out_len;

    // 6. Finalize. If the tag is invalid, this will fail.
    if (EVP_DecryptFinal_ex(ctx, data + total_len, &out_len) != 1) {
        fprintf(stderr, "Error: Authentication failed (DecryptFinal_ex).\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += out_len;

    EVP_CIPHER_CTX_free(ctx);

    // The plaintext length is the same as the original ciphertext length in GCM.
    *data_len = total_len;

    return true;
}

void generate_secure_key(void *key) {
    generate_random_key((uint8_t *)key);
}

void generate_key_from_string(const char *s, void *key) {
    SHA256((const unsigned char *)s, strlen(s), key);
}

bool encrypt_in_place(void *data, size_t data_len,
                      void *iv_tag,
                      const void *key) {
    return encrypt_in_place_gcm((uint8_t *)data, &data_len, (uint8_t *)iv_tag, (const uint8_t *)key);
}

bool decrypt_in_place(void *data, size_t data_len,
                      const void *iv_tag,
                      const void *key) {
    return decrypt_in_place_gcm((uint8_t *)data, &data_len, (const uint8_t *)iv_tag, (const uint8_t *)key);
}

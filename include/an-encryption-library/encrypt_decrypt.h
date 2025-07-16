// SPDX-FileCopyrightText: 2024-2025 Knode.ai
// SPDX-License-Identifier: Apache-2.0
// Maintainer: Andy Curtis <contactandyc@gmail.com>
#ifndef _encrypt_decrypt_H
#define _encrypt_decrypt_H

#include <stdbool.h>
#include <stddef.h>

#define SECURE_KEY_SIZE       32  // 256-bit key
#define IV_TAG_SIZE           28  // 12-byte IV + 16-byte GCM Tag

void generate_secure_key(void *key);
void generate_key_from_string(const char *s, void *key);

bool encrypt_in_place(void *data, size_t data_len,
                      void *iv_tag,
                      const void *key);

bool decrypt_in_place(void *data, size_t data_len,
                      const void *iv_tag,
                      const void *key);

#endif

# an-encryption-library

Minimal C API for authenticated encryption and decryption using a 256‑bit key and an AEAD mode with a 12‑byte IV and 16‑byte authentication tag (likely AES‑256‑GCM based on sizes). The library focuses on **in‑place** processing to reduce allocations.

> **Status:** Header‑only API description provided. Implementation details (cipher, RNG source, platform requirements) are not included here—adjust this README once the `.c` sources are available.

## Features

* 256‑bit symmetric key (`SECURE_KEY_SIZE = 32`).
* AEAD layout: 12‑byte IV + 16‑byte tag (`IV_TAG_SIZE = 28`).
* In‑place encryption/decryption of arbitrary length buffers.
* Deterministic key derivation from a user string.
* Simple, small surface area (5 functions + 2 constants).

## Header

```c
#include "an-encryption-library/encrypt_decrypt.h"
```

## Constants

| Constant          | Value | Meaning                                                                  |
| ----------------- | ----- | ------------------------------------------------------------------------ |
| `SECURE_KEY_SIZE` | 32    | Size in bytes of a 256‑bit key.                                          |
| `IV_TAG_SIZE`     | 28    | Combined buffer size: 12‑byte IV + 16‑byte authentication tag (GCM tag). |

`iv_tag` buffers you supply **must** be at least `IV_TAG_SIZE` bytes.

## API Summary

```c
void generate_secure_key(void *key);
void generate_key_from_string(const char *s, void *key);

bool encrypt_in_place(void *data, size_t data_len,
                      void *iv_tag,
                      const void *key);

bool decrypt_in_place(void *data, size_t data_len,
                      const void *iv_tag,
                      const void *key);
```

All functions return `void` except the in‑place encryption / decryption which return `true` on success, `false` on failure (e.g., authentication failure during decryption).

### Function Details

| Function                   | Description                                                                                                                     | Notes                                                                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `generate_secure_key`      | Fills `key` (32 bytes) with cryptographically secure random bytes.                                                              | Caller must provide a writable buffer of size `SECURE_KEY_SIZE`.                                                                     |
| `generate_key_from_string` | Derives a 256‑bit key from a UTF‑8 string.                                                                                      | Determinism: same string → same key. Avoid using user passwords directly; prefer a proper KDF with salt & parameters if added later. |
| `encrypt_in_place`         | Encrypts buffer `data` of length `data_len` in place, producing ciphertext in the same buffer and writing IV+Tag into `iv_tag`. | Never reuse the generated IV with the same key for different plaintexts.                                                             |
| `decrypt_in_place`         | Decrypts buffer `data` of length `data_len` in place, using supplied `iv_tag` and `key`; on success the buffer holds plaintext. | Fails (returns `false`) if authentication/tag verification fails.                                                                    |

## Memory Ownership & Buffer Rules

* **Key:** Caller supplies a `uint8_t key[SECURE_KEY_SIZE];` (or similar) to every function.
* **IV/Tag:** Caller supplies a `uint8_t iv_tag[IV_TAG_SIZE];` buffer. After encryption it contains `{IV (12) || TAG (16)}`. During decryption, pass the same bytes back.
* **Data:** Processed in place; allocate a mutable buffer of size equal to your plaintext length.

## Example

```c
#include <stdio.h>
#include <string.h>
#include "an-encryption-library/encrypt_decrypt.h"

int main(void) {
    uint8_t key[SECURE_KEY_SIZE];
    generate_secure_key(key);

    uint8_t iv_tag[IV_TAG_SIZE];

    char message[] = "Secret message"; // Will be overwritten with ciphertext
    size_t len = strlen(message);       // Excludes terminating NUL

    if (!encrypt_in_place(message, len, iv_tag, key)) {
        fprintf(stderr, "Encrypt failed\n");
        return 1;
    }

    // message now holds ciphertext bytes (not NUL terminated)

    if (!decrypt_in_place(message, len, iv_tag, key)) {
        fprintf(stderr, "Decrypt failed (auth?)\n");
        return 1;
    }

    // Restored plaintext in-place; it is *not* NUL terminated if original wasn't counted.
    printf("Decrypted: %.*s\n", (int)len, message);
    return 0;
}
```

## Error Handling

* Check boolean returns of `encrypt_in_place` / `decrypt_in_place`.
* Authentication failure MUST be treated as a **hard error**—do not use or expose the corrupted plaintext.

## Security Notes

| Concern        | Guidance                                                                                                                                                                                                    |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IV Reuse       | MUST be unique per `(key, plaintext encryption)`; never reuse a 12‑byte IV with same key. If library auto‑generates IV internally, ensure randomness; else you must supply uniqueness once such API exists. |
| Key Storage    | Zero keys from memory when no longer needed (e.g., `explicit_bzero`).                                                                                                                                       |
| Key Derivation | `generate_key_from_string` is likely a convenience shortcut; for user passwords prefer a KDF (Argon2, scrypt, PBKDF2) + salt & parameters (not shown in current API).                                       |
| Randomness     | Ensure implementation uses a CSPRNG (e.g., `/dev/urandom`, `getrandom()`, `BCryptGenRandom`, or a vetted library).                                                                                          |
| Data Length    | AEAD typically authenticates length; do not modify ciphertext length or reorder bytes before decryption.                                                                                                    |

## Build & Integration

Until a compiled implementation is provided:

1. Add the `include/` directory to your compiler's include paths: `-Iinclude`.
2. Link against the library object or static archive once available (e.g., `-lan_encryption`).
3. Use a C11 (or later) compiler for `stdbool.h`.

*Example compile (placeholder):*

```bash
gcc -std=c11 -Iinclude -Lan-encryption -lan_encryption example.c -o example
```

Adjust names once actual sources / archive name are defined.

## Testing

Create deterministic tests using `generate_key_from_string` so expected ciphertexts remain stable (given IV control once exposed). For randomized tests, mock or inject the RNG.

## Versioning

Adopt semantic versioning: `MAJOR.MINOR.PATCH`. Starting at `0.1.0` until API stabilizes.

## Roadmap (Suggested)

* Expose function to supply an externally generated IV.
* Add associated data (AAD) support.
* Provide streaming / chunked API.
* Add separate `encrypt()` that outputs to a different buffer.
* Provide formal KDF (Argon2id) and password handling utilities.
* Add constant‑time key comparison helpers.

## License

Apache-2.0 (see SPDX header). You must retain original copyright and SPDX lines in all copies.

## Contributing

1. Fork & branch (`feat/short-description`).
2. Add tests + docs for changes.
3. Run static analysis / linters.
4. Submit PR with clear rationale and security considerations.

## Maintainer

Primary: Andy Curtis ([contactandyc@gmail.com](mailto:contactandyc@gmail.com)).

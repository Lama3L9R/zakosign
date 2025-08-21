#ifndef ZAKOSIGN_HEADER_HASHER_H
#define ZAKOSIGN_HEADER_HASHER_H

#include "prelude.h"
#include "ossl_helper.h"

#include <openssl/sha.h>

#define ZAKO_HASHER_SIZE SHA256_DIGEST_LENGTH

struct zako_hash_stream {
    SHA256_CTX* ctx;
};

/**
 * Oneshot hash buffer and write generated hash into result
 */
bool zako_hash_buffer(uint8_t* buffer, size_t len, uint8_t* result);

/**
 * Verify buffer with given hash
 */
bool zako_hash_verify(uint8_t* buffer, size_t len, uint8_t* sha256);

/**
 * Create new hash stream.
 */
struct zako_hash_stream* zako_hash_stream_new();

/**
 * Stream hash multiple buffers.
 * Pass NULL to buffer to do final and write generated hash into result.
 */
bool zako_hash_stream(struct zako_hash_stream* stream, uint8_t* buffer, size_t len, uint8_t* result);

#endif
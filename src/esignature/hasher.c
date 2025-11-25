#include "hasher.h"

bool zako_hash_buffer(uint8_t* buffer, size_t len, uint8_t* result) {
    SHA256_CTX ctx;

    if (SHA256_Init(&ctx) != 1) {
        ZakoOSSLPrintError("Failed to initialize SHA256 hash context")
        return NULL;
    }

    if (SHA256_Update(&ctx, buffer, len) != 1) {
        ZakoOSSLPrintError("SHA256 Failed to hash block")
        
        return false;
    }

    if (SHA256_Final(result, &ctx) != 1) {
        ZakoOSSLPrintError("SHA256 Failed to finalize block")
        
        return false;
    }

    return true;
}

bool zako_hash_verify(uint8_t* buffer, size_t len, uint8_t* sha256) {
    uint8_t expected[SHA256_DIGEST_LENGTH] = { 0 };
    if (zako_hash_buffer(buffer, len, expected) != 1) {
        return false;
    }

    return memcmp(expected, sha256, SHA256_DIGEST_LENGTH) == 0;
}


struct zako_hash_stream* zako_hash_stream_new() {
    struct zako_hash_stream* stream = ZakoAllocateStruct(zako_hash_stream);

    if (SHA256_Init(stream->ctx) != 1) {
        ZakoOSSLPrintError("Failed to initialize SHA256 hash context")
        return NULL;
    }

    return stream;
}

static bool zako_hash_stream_do_final(struct zako_hash_stream* stream, uint8_t* result) {
    if (SHA256_Final(result, stream->ctx) != 1) {
        ZakoOSSLPrintError("SHA256 Failed to finalize block")
        
        return false;
    }

    return true;
}

static bool zako_hash_stream_update(struct zako_hash_stream* stream, uint8_t* buffer, size_t len) {
    if (SHA256_Update(stream->ctx, buffer, len) != 1) {
        ZakoOSSLPrintError("SHA256 Failed to hash block")
        
        return false;
    }

    return true;
}

bool zako_hash_stream(struct zako_hash_stream* stream, uint8_t* buffer, size_t len, uint8_t* result) {
    if (buffer == NULL) {
        return zako_hash_stream_do_final(stream, result);
    } else {
        return zako_hash_stream_update(stream, buffer, len);
    }
}
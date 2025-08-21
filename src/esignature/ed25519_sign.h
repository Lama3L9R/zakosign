#ifndef ZAKOSIGN_HEADER_ED25519_SIGN_H
#define ZAKOSIGN_HEADER_ED25519_SIGN_H

#include "prelude.h"
#include "ossl_helper.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>


struct zako_stream_sign_context {
    EVP_PKEY* private;
    EVP_MD_CTX* ctx;
};

EVP_PKEY* zako_parse_public(const char* data);
EVP_PKEY* zako_load_public(const char* path);
EVP_PKEY* zako_parse_private(const char* data, char* password);
EVP_PKEY* zako_load_private(const char* path, char* password);
EVP_PKEY* zako_parse_public_raw(uint8_t* data);
bool zako_get_public_raw(EVP_PKEY* key, uint8_t* data);

/**
 * Sign len bytes of buffer with private key, and write the output to result.
 */
bool zako_sign_buffer(EVP_PKEY* key, uint8_t* buffer, size_t len, uint8_t* result);

/**
 * Verify len bytes of buffer with public key, using signature. 
 * 
 */
bool zako_verify_buffer(EVP_PKEY* key, uint8_t* buffer, size_t len, uint8_t* signature);


/**
 * OSSL's Ed25519 Digest is very sexy that this S.H.I.T. does not support streaming...
 * I debuged on this for hours.....
 */
struct zako_stream_sign_context* zako_sign_stream_new(EVP_PKEY* key);

/**
 * Sign len bytes of buffer with private key.
 * When buffer is null, do final will be triggered, and result will be written.
 * 
 * Context will be dropped upon do-final.
 * 
 * OSSL's Ed25519 Digest is very sexy that this S.H.I.T. does not support streaming...
 * I debuged on this for hours.....
 */
bool zako_sign_stream(struct zako_stream_sign_context* context, uint8_t* buffer, size_t len, uint8_t** result);

/**
 * OSSL's Ed25519 Digest is very sexy that this S.H.I.T. does not support streaming...
 * I debuged on this for hours.....
 */
struct zako_stream_sign_context* zako_verify_steam(struct zako_stream_sign_context* context, uint8_t* buffer, size_t len, uint8_t* result);


#endif

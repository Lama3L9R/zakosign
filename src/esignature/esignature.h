#ifndef ZAKOSIGN_HEADER_ESIGNATURE_H
#define ZAKOSIGN_HEADER_ESIGNATURE_H

#include "prelude.h"
#include "cert_helper.h"

#define ZAKO_SIGNATURE_LENGTH 64
#define ZAKO_PUBKEY_LENGTH 32
#define ZAKO_HASH_LENGTH 32
#define ZAKO_MAX_CERITIFICATE_CHAIN 3

#define ZAKO_ESIGNATURE_MAGIC 0x7a616b6f7369676eull
#define ZAKO_ESIGNATURE_VERSION 1

#define ZAKO_ESV_STRICT_MODE    (1 << 0)
#define ZAKO_ESV_INTEGRITY_ONLY (1 << 1)

#define ZAKO_ESV_IMPORTANT_ERROR (1 << 31)

#define ZAKO_ESV_INVALID_HEADER            (1 <<  0) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_UNSUPPORTED_VERSION       (1 <<  2) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_OUTDATED_VERSION          (1 <<  3) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_MISSING_CERTIFICATE       (1 <<  4)
#define ZAKO_ESV_UNTRUST_CERTIFICATE_CHAIN (1 <<  5) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_MISSING_TIMESTAMP         (1 <<  6)
#define ZAKO_ESV_UNTRUSTED_TIMESTAMP       (1 <<  7) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_VERFICATION_FAILED        (1 <<  8) + ZAKO_ESV_IMPORTANT_ERROR
#define ZAKO_ESV_CERTIFICATE_EXPIRED       (1 <<  9)
#define ZAKO_ESV_CERTIFICATE_ERROR         (1 <<  9)
#define ZAKO_ESV_CERTKEY_MISMATCH          (1 << 10) + ZAKO_ESV_IMPORTANT_ERROR

struct zako_der_certificate {
    /**
     * The id of this ceritificate
     */
    uint8_t id;

    /**
     * The size of this ceritificate
     */
    size_t len;
    uint8_t data[];
};

struct zako_custom_field {
    /**
     * Non-duplicate field identifier
     */
    uint8_t id;
    size_t sz;

    uint8_t data[];
};

/**
 * The ceritificate chain for public_key
 */
struct zako_keychain {
    uint8_t public_key[ZAKO_PUBKEY_LENGTH];

    /**
     * The id of ceritificate in certificate_store
     * Leaf certificate comes the first, and does not contains any RootCA
     * 
     * 255 means empty
     */
    uint8_t trustchain[ZAKO_MAX_CERITIFICATE_CHAIN];
};

/**
 * The structure for an esignature
 */
struct zako_esignature {

    /**
     * Struct identifier
     */
    uint64_t magic;

    /**
     * Version
     */
    uint64_t version;

    /**
     * The signing key, including signature chain
     */
    struct zako_keychain key;

    /**
     * Buffer SHA256 hash
     */
    uint8_t hash[ZAKO_HASH_LENGTH];

    /**
     * Signature of data
     */
    uint8_t signature[ZAKO_SIGNATURE_LENGTH];
    
    /**
     * Signature signed date
     */
    uint64_t created_at;

    /**
     * # of certificates
     */
    uint8_t cert_sz;

    /**
     * # of extra fields
     */
    uint8_t extra_fields_sz;

    /**
     * Extra data for certificate store and extra fields
     * Certificats are always stored before extra fields
     * 
     * Valid types are either zako_der_certificate or zako_custom_field
     */
    uint8_t data[];
};

struct zako_esign_context {
    /**
     * Certificate store
     */
    struct zako_der_certificate* certs[200];

    /**
     * # of certificates in certificate store
     */
    uint8_t cert_count;

    struct zako_custom_field* extra_fields[256];

    /**
     * # of custom fields in extra fields
     */
    uint8_t extra_fields_count;

    /**
     * Internal buffer
     */
    struct zako_esignature esig_buf;
};

struct zako_esign_context* zako_esign_new();

/**
 * Adds a certificate to certificate store and returns the id of the input certificate
 * ZakoRootCA is built in, and you don't have to include it.
 * 
 * Capacity is capped at 200 certificates. Upon exceed, 255 is returned.
 * If X509 to DER failed, 254 is returned. 
 */
uint8_t zako_esign_add_certificate(struct zako_esign_context* ctx, X509* certificate);

/**
 * Add certificate to trust chain of the public key.
 * Call zako_esign_add_certificate to obtain an ID for your certificate.
 */
void zako_esign_add_keycert(struct zako_esign_context* ctx, uint8_t id);

/**
 * Set public key
 */
void zako_esign_set_publickey(struct zako_esign_context* ctx, EVP_PKEY* key);

/**
 * Set signature
 */
void zako_esign_set_signature(struct zako_esign_context* ctx, uint8_t* hash, uint8_t* signature);

/**
 * esignature will be created and esign will be free-ed
 */
struct zako_esignature* zako_esign_create(struct zako_esign_context* ctx, size_t* len);

uint32_t zako_esign_verify(struct zako_esignature* esig, uint8_t* buff, size_t len, uint32_t flags);

/**
 * Get error message based on verification error code bit field index
 */
const char* zako_esign_verrcidx2str(uint8_t idx);

#endif

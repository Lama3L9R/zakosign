#include "esignature.h"
#include "ed25519_sign.h"
#include "hasher.h"
#include <time.h>

static char* error_messages[] = {
    "Invalid E-Signature header structure",
    "Unsupported E-Signature version",
    "E-Signature is using an unsupported, outdated version",
    "Signing key does not have a valid certificate",
    "Signing key certificate chain contains invalid/untrusted key",
    "E-Signature does not have a signing date",
    "E-Signature signing date cannot be trusted",
    "E-Signature verification failed",
    "A/Some certificate in trust chain has expired",
    "Error while verifing certificate trust chain",
    "Leaf certificate mismatch with provided public key",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "One or multiple CRITICAL error occured",
};

struct zako_esign_context* zako_esign_new() {
    struct zako_esign_context* ctx = ZakoAllocateStruct(zako_esign_context);

    ctx->esig_buf.key.trustchain[0] = 255; /* L4 */
    ctx->esig_buf.key.trustchain[1] = 255; /* L3 */
    ctx->esig_buf.key.trustchain[2] = 255; /* L2 */

    ctx->esig_buf.magic = ZAKO_ESIGNATURE_MAGIC;
    ctx->esig_buf.version = ZAKO_ESIGNATURE_VERSION;

    ctx->esig_buf.created_at = (uint64_t) time(NULL);
    
    return ctx;
}

static void zako_esign_free(struct zako_esign_context* ctx) {
    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->certs[i] != NULL) {
            free(ctx->certs[i]);
        }
    }

    free(ctx);
}

uint8_t zako_esign_add_certificate(struct zako_esign_context* ctx, X509* certificate) {
    if (ctx->cert_count >= 200) {
        return 255;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio, certificate);

    uint8_t* der_data = NULL;
    size_t der_len = BIO_get_mem_data(bio, (char**)&der_data);

    if (der_len == 0) {
        return 254;
    }

    uint8_t id = ctx->cert_count;
    ctx->cert_count += 1;

    struct zako_der_certificate* fin_cert = (struct zako_der_certificate*) zako_allocate_safe(sizeof(struct zako_der_certificate) + der_len);

    fin_cert->len = der_len;
    fin_cert->id = id;
    memcpy(&fin_cert->data, der_data, der_len);

    ctx->certs[id] = fin_cert;

    BIO_free(bio);

    return id;
}

void zako_esign_set_publickey(struct zako_esign_context* ctx, EVP_PKEY* key) {
    /* Public key size is a known size, so we can safely ignore this */
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
    zako_get_public_raw(key, &ctx->esig_buf.key.public_key);
}

void zako_esign_add_keycert(struct zako_esign_context* ctx, uint8_t id) {
    if (ctx->esig_buf.key.trustchain[0] == 255) {
        ctx->esig_buf.key.trustchain[0] = id;
    } else if (ctx->esig_buf.key.trustchain[1] == 255) {
        ctx->esig_buf.key.trustchain[1] = id;
    } else {
        ctx->esig_buf.key.trustchain[2] = id;
    }
}

void zako_esign_set_signature(struct zako_esign_context* ctx, uint8_t* hash, uint8_t* signature) {
    memcpy(&ctx->esig_buf.signature, signature, ZAKO_SIGNATURE_LENGTH);
    memcpy(&ctx->esig_buf.hash, hash, ZAKO_HASH_LENGTH);
}

struct zako_esignature* zako_esign_create(struct zako_esign_context* ctx, size_t* len) {
    size_t esig_sz = sizeof(struct zako_esignature);

    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->certs[i] != NULL) {
            esig_sz += sizeof(struct zako_der_certificate) + ctx->certs[i]->len;
        }
    }

    *len = esig_sz;

    struct zako_esignature* esignature = (struct zako_esignature*) zako_allocate_safe(esig_sz);
    memcpy(esignature, &ctx->esig_buf, sizeof(struct zako_esignature));

    esignature->cert_sz = ctx->cert_count;

    size_t off = (size_t) &esignature->data;
    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->certs[i] != NULL) {
            size_t sz = sizeof(struct zako_der_certificate) + ctx->certs[i]->len;
            memcpy((void*) off, ctx->certs[i], sz);

            off += sz;
        }
    }

    zako_esign_free(ctx);

    return esignature;
}

static struct zako_der_certificate* zako_keychain_getcert(struct zako_der_certificate** certtbl, uint8_t id) {
    if (id == 255) {
        return NULL;
    }

    return certtbl[id];
}

static uint32_t zako_keychain_verify(struct zako_keychain* kc, struct zako_der_certificate** certtbl) {
    struct zako_trustchain* chain = zako_trustchain_new();
    struct zako_der_certificate* leaf = zako_keychain_getcert(certtbl, kc->trustchain[0]);
    struct zako_der_certificate* l3 = zako_keychain_getcert(certtbl, kc->trustchain[1]);
    struct zako_der_certificate* l2 = zako_keychain_getcert(certtbl, kc->trustchain[2]);

    if (kc->trustchain[0] == 255) {
        return 0;
    }

    zako_trustchain_set_leaf_der(chain, leaf->data, leaf->len);

    if (l3 != NULL) {
        zako_trustchain_add_intermediate_der(chain, l3->data, l3->len);
    }

    if (l2 != NULL) {
        zako_trustchain_add_intermediate_der(chain, l2->data, l2->len);
    }

    int x509_v_result = zako_trustchain_verify(chain);
    uint32_t result = 0;
    switch (x509_v_result) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            result = ZAKO_ESV_CERTIFICATE_EXPIRED;
            goto exit;
        case X509_V_ERR_CERT_UNTRUSTED:
            result = ZAKO_ESV_UNTRUST_CERTIFICATE_CHAIN;
            goto exit;
        default:
            if (x509_v_result != X509_V_OK) {
                result = ZAKO_ESV_CERTIFICATE_ERROR;
                goto exit;
            }

            EVP_PKEY* expected = X509_get_pubkey(chain->leaf);
            EVP_PKEY* got = zako_parse_public_raw(kc->public_key);
            if (!EVP_PKEY_cmp(expected, got)) {
                result = ZAKO_ESV_CERTKEY_MISMATCH;
            }

            EVP_PKEY_free(expected);
            EVP_PKEY_free(got);
            goto exit;
    }

exit:
    zako_trustchain_free(chain);
    return result;
}

uint32_t zako_esign_verify(struct zako_esignature* esig, uint8_t* buff, size_t len, uint32_t flags) {
    if (esig->magic != ZAKO_ESIGNATURE_MAGIC) {
        return ZAKO_ESV_INVALID_HEADER;
    }

    if (esig->version != ZAKO_ESIGNATURE_VERSION) {
        if (esig->version > ZAKO_ESIGNATURE_VERSION) {
            return ZAKO_ESV_UNSUPPORTED_VERSION;
        } else {
            return ZAKO_ESV_OUTDATED_VERSION;
        }
    }

    uint32_t result = 0;
    EVP_PKEY* pubkey = NULL;

    OnFlag(flags, ZAKO_ESV_INTEGRITY_ONLY) {
        goto verify_integrity;
    }

    /* Verify Ceritificates */

    uint8_t cert_count = esig->cert_sz;
    struct zako_der_certificate* cstbl[200] = { 0 };

    uint8_t* data = &esig->data;
    size_t off = (size_t) 0;
    for (uint8_t i = 0; i < cert_count; i ++) {
        struct zako_der_certificate* cert = ApplyOffset(data, +off);
        cstbl[i] = cert;

        off += sizeof(struct zako_der_certificate) + cert->len;
    }

    result |= zako_keychain_verify(&esig->key, &cstbl);

verify_integrity:
    pubkey = zako_parse_public_raw(esig->key.public_key);
    
    if (zako_hash_verify(buff, len, esig->hash) != 1) {
        result |= ZAKO_ESV_VERFICATION_FAILED;
    }

    if (zako_verify_buffer(pubkey, esig->hash, ZAKO_HASH_LENGTH, esig->signature) != 1) {
        result |= ZAKO_ESV_VERFICATION_FAILED;
    }

    EVP_PKEY_free(pubkey);

    uint64_t now = (uint64_t) time(NULL);
    if (esig->created_at == 0) {
        result |= ZAKO_ESV_MISSING_TIMESTAMP;
    } else if (esig->created_at >= now) {
        result |= ZAKO_ESV_UNTRUSTED_TIMESTAMP;
    }

    return result;

}

const char* zako_esign_verrcidx2str(uint8_t idx) {
    if (idx >= 31) {
        return NULL;
    }

    return error_messages[idx];
}


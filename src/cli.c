#include "prelude.h"
#include "param.h"
#include "constants.h"

#include "esignature/ed25519_sign.h"
#include "esignature/file_helper.h"
#include "esignature/esignature.h"
#include "esignature/cert_helper.h"

#include <openssl/x509.h>
#include <stdio.h>

/* What if we are on mars?? How should we tell if one day isn't 86400?
   Temporary workaround: assume we are always on the Earth */
#define SECONDS_ONE_DAY 86400

#define SERIAL_RAND_BITS 159

ZakoCommandHandler(root) {
    if (ZakoFlagParam("version") || ZakoFlag('v')) {
        ConsoleWrite("libzakosign: %s-%s (%i)", ZAKO_LIBRARY_VERSION_STRING, ZAKO_LIBRARY_VERSION_TYPE, ZAKO_ESIGNATURE_VERSION);
        ConsoleWrite("openssl: %s", OPENSSL_VERSION_TEXT);
    } else {
        ConsoleWrite("zakosign - A ELF signing tool");
        ConsoleWrite("For help, please use 'zakosign help'")
    }

    return 0;
}

ZakoCommandHandler(root_help) {
    ConsoleWrite("%s", ZakoConstant(help));
    return 0;
}

ZakoCommandHandler(root_verify) {
    char* input = ZakoParamAt(0);
    bool strict_mode = ZakoFlagParam("strict");
    bool integrity_only = ZakoFlagParam("integrity");

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign verify [options...] <input.elf>")
    }

    if (!zako_sys_file_exist(input)) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    file_handle_t fd = zako_sys_file_open(input);
    uint32_t results = zako_file_verify_esig(fd, 
                            (strict_mode ? ZAKO_ESV_STRICT_MODE : 0) + 
                            (integrity_only ? ZAKO_ESV_INTEGRITY_ONLY : 0));

    if (results != 0) {
        OnFlag(results, ZAKO_ESV_IMPORTANT_ERROR) {
            ConsoleWriteFAIL("Verification failed! (%u)", results);
        } else {
            ConsoleWriteFAIL("Verification partially passed. (%u)", results);
        }
    } else {
        ConsoleWriteOK("Verification passed!");
        goto exit;
    }

    for (uint8_t i = 0; i < sizeof(uint32_t) * 8; i ++) {
        if ((results & (1 << i)) == 0) {
            continue;
        }

        const char* message = zako_file_verrcidx2str(i);
        ConsoleWriteFAIL("  %s", message);
    }

exit:
    zako_sys_file_close(fd);

    exit(results);
    return results;
}

ZakoCommandHandler(root_sign) {
    char* input = ZakoParamAt(0);
    char* key = ZakoParam("key");
    char* password = ZakoParam("password");
    char* output = ZakoParam("output");
    char* pubkey_path = ZakoParam("pubkey");
    bool overwrite = ZakoFlagParam("force") || ZakoFlag('f');

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign sign [options...] --key <private.key> <input.elf>");
        return 1;
    }

    if (key == NULL) {
        ConsoleWrite("Usage: zakosign sign [options...] --key <private.key> <input.elf>");
        return 1;
    }

    if (!zako_sys_file_exist(input)) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    if (!zako_sys_file_exist(key)) {
        ConsoleWriteFAIL("%s does not exist!", key);
        return 1;
    }

    struct zako_esign_context* es_ctx = zako_esign_new();

    /* Gather certificate info */
    struct zako_trustchain* chain = zako_trustchain_new();

    {
        struct zako_param* pr_curr = params;
        bool leaf_set = false;
        while (pr_curr != NULL) {
            if (zako_streq(pr_curr->name, "certificate")) {
                if (!leaf_set) {
                    X509* cert = zako_x509_load_pem(pr_curr->value);

                    if (cert == NULL) {
                        exit(1);
                    }

                    zako_esign_add_keycert(es_ctx, zako_esign_add_certificate(es_ctx, cert));
                    zako_trustchain_set_leaf(chain, cert);

                    leaf_set = true;
                } else {
                    X509* cert = zako_x509_load_pem(pr_curr->value);

                    if (cert == NULL) {
                        exit(1);
                    }

                    zako_esign_add_keycert(es_ctx, zako_esign_add_certificate(es_ctx, cert));
                    zako_trustchain_add_intermediate(chain, cert);
                }
            }

            pr_curr = pr_curr->next;
        }
    }

    /* Gather key info */
    EVP_PKEY* pkey = zako_load_private(key, password);
    EVP_PKEY* pubkey;

    if (pubkey_path != NULL) {
        pubkey = zako_load_public(pubkey_path);

        if (pubkey == NULL) {
            pubkey = pkey;
        }
    } else {
        pubkey = pkey;
    }

    /* Verify public key is valid */
    if (chain->leaf != NULL) { /* Only verify when we have a certificate */
        /* Do full certificate chain verify*/
        int verification = zako_trustchain_verifykey(chain, pubkey);
        if (verification != 0) {
            ConsoleWriteFAIL("Certificate Error! Invalid certificate: ")

            if (verification == -100) {
                ConsoleWriteFAIL("  Public key mismatch (-100)");
            } else {
                ConsoleWriteFAIL("  %s (%i)", X509_verify_cert_error_string(verification), verification)
            }
        }
    }

    zako_esign_set_publickey(es_ctx, pubkey);

    /* Load input / output ELF file */
    file_handle_t target;

    if (output == NULL) {
        target = zako_sys_file_open(input);
    } else {
        target = zako_sys_file_opencopy(input, output, overwrite);
    }

    if ((signed long long) target == ZAKO_FHAND_ERROR) {
        exit(1);
    }
    
    ConsoleWriteOK("Signing...")

    uint8_t result[ZAKO_SIGNATURE_LENGTH] = { 0 };
    uint8_t hash[ZAKO_HASH_LENGTH] = { 0 };
    /* Signature is a known size, so we can safely ignore this */
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
    if (!zako_file_sign(target, pkey, &result, &hash)) {
        ConsoleWriteFAIL("Failed to sign input file")
        return 1;
    }
    size_t target_sz = zako_sys_file_sz(target);

    ConsoleWriteOK("File Signature created: %s (%lu bytes digested)", base64_encode(result, ZAKO_SIGNATURE_LENGTH, NULL), target_sz);
    
    zako_esign_set_signature(es_ctx, hash, result);
    
    size_t len = 0;
    struct zako_esignature* esig = zako_esign_create(es_ctx, &len);

    ConsoleWriteOK("Writing E-Signature info (%lu bytes)...", len);
    if (!zako_file_write_esig(target, esig, len)) {
        exit(1);
    }

    zako_sys_file_close(target);
    free(esig);
    zako_trustchain_free(chain);
    EVP_PKEY_free(pkey);

    ConsoleWriteOK("Done")

    return 0;
}

ZakoCommandHandler(root_key) {
    ConsoleWrite("Usage: zakosign key <option> [args...]")

    return 0;
}

static void zako_cli_write_certificate_info(struct zako_der_certificate* der) {
    X509* x509 = zako_x509_parse_der(der->data, der->len);

    if (x509 == NULL) {
        return;
    }

    {
        X509_NAME* name = X509_get_issuer_name(x509);
        char* line = X509_NAME_oneline(name, NULL, 0);
        ConsoleWriteOK("      Issued by: %s", line);
        OPENSSL_free(line);
    }
 
    {
        X509_NAME* name = X509_get_subject_name(x509);
        char* line = X509_NAME_oneline(name, NULL, 0);
        ConsoleWriteOK("      Subject: %s", line);
        OPENSSL_free(line);
    }

    {
        ASN1_INTEGER* serial = X509_get_serialNumber(x509);
        BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
        char* hex = BN_bn2hex(bn);
        ConsoleWriteOK("      Serial Number: %s", hex);
        OPENSSL_free(hex);
        BN_free(bn);
    }
    
    {
        BASIC_CONSTRAINTS* constraints = X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL);
        if (constraints) {
            ConsoleWriteOK("      CA: %s", constraints->ca ? "Yes" : "No");
            BASIC_CONSTRAINTS_free(constraints);
        }
    }

    {
        BIO* bio = BIO_new(BIO_s_mem());
    
        printf("[+]       Not Before: ");
        ASN1_TIME_print(bio, X509_get0_notBefore(x509));
        char* notBefore;
        long notBefore_len = BIO_get_mem_data(bio, &notBefore);
        printf("%.*s\n", (int)notBefore_len, notBefore);
        BIO_reset(bio);
        
        printf("[+]       Not After : ");
        ASN1_TIME_print(bio, X509_get0_notAfter(x509));
        char* notAfter;
        long notAfter_len = BIO_get_mem_data(bio, &notAfter);
        printf("%.*s\n", (int)notAfter_len, notAfter);

        BIO_free(bio);
    }
}

ZakoCommandHandler(root_info) {
    char* input = ZakoParamAt(0);

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign info <file>")
    }

    if (!zako_sys_file_exist(input)) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    file_handle_t fd = zako_sys_file_open(input);
    struct zako_esignature* esig = zako_file_read_esig(fd);

    if (esig == NULL) {
        ConsoleWriteFAIL("File does not contains a valid E-Signature.");
        return 0;
    }

    ConsoleWriteOK("E-Signature V%lu (%u Certificates, %u Extra fields)", esig->version, esig->cert_sz, esig->extra_fields_sz);
    ConsoleWriteOK("  Checksum: %s", base64_encode(esig->hash, ZAKO_HASH_LENGTH, NULL));
    ConsoleWriteOK("  Signed by: %s", base64_encode(esig->key.public_key, ZAKO_PUBKEY_LENGTH, NULL));

    if (esig->key.trustchain[0] == 255) {
        goto no_cert;
    }

    uint8_t cert_count = esig->cert_sz;
    struct zako_der_certificate* cstbl[200] = { 0 };

    uint8_t* data = &esig->data;
    size_t off = (size_t) 0;
    for (uint8_t i = 0; i < cert_count; i ++) {
        struct zako_der_certificate* cert = ApplyOffset(data, +off);
        cstbl[i] = cert;

        off += sizeof(struct zako_der_certificate) + cert->len;
    }

    ConsoleWriteOK("  Certificates: ");
    ConsoleWriteOK("    Leaf:");
    zako_cli_write_certificate_info(cstbl[esig->key.trustchain[0]]);

    if (esig->key.trustchain[1] == 255) {
        goto no_cert;
    }

    if (esig->key.trustchain[2] == 255) {
        ConsoleWriteOK("    L2:");
        zako_cli_write_certificate_info(cstbl[esig->key.trustchain[1]]);

        goto no_cert;
    } else {
        ConsoleWriteOK("    L3:");
        zako_cli_write_certificate_info(cstbl[esig->key.trustchain[1]]);
    }

    ConsoleWriteOK("    L2:");
    zako_cli_write_certificate_info(cstbl[esig->key.trustchain[2]]);

no_cert:;
    
    struct tm* timeinfo = gmtime((const time_t*) &esig->created_at);
    char time_buffer[32];
    if (timeinfo) {
        strftime(time_buffer, 32, "%Y-%m-%dT%H:%M:%SZ", timeinfo);
        ConsoleWriteOK("  Signed At: %s", time_buffer);
    } else {
        ConsoleWriteOK("  Signed At: <Unknown>");
    }

    ConsoleWriteOK("  Signature: %s", base64_encode(esig->signature, ZAKO_SIGNATURE_LENGTH, NULL));

    zako_sys_file_close(fd);
    return 0;    
}

ZakoCommandHandler(root_key_new) {
    char* foutput = ZakoParamAt(0);

    if (foutput == NULL) {
        ConsoleWrite("Usage: zakosign key new <file>");

        return 1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);;
    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ZakoOSSLPrintError("Failed to generate signing key!");

        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ZakoOSSLPrintError("Failed to generate signing key!");

        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    BIO* out = BIO_new_file(foutput, "w+");

    if (out == NULL) {
        ZakoOSSLPrintError("Failed to create and open output file: %s", foutput);
    }

    if (PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        ZakoOSSLPrintError("Failed to write signing private key!");
    }
    
    BIO_flush(out);
    BIO_free(out);

    BIO* pubout = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(pubout, pkey) <= 0) {
        ZakoOSSLPrintError("Failed to write signing public key!");
    }
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(pubout, &buffer);

    ConsoleWrite("%.*s", (int32_t)buffer->length, buffer->data)


    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}

ZakoCommandHandler(root_key_pub) {
    char* input = ZakoParamAt(0);
    char* password = ZakoParam("--password");

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign key pub <private.pem>");

        return 1;
    }

    if (!zako_sys_file_exist(input)) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    EVP_PKEY* private = zako_load_private(input, password);

    BIO* pubout = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(pubout, private) <= 0) {
        ZakoOSSLPrintError("Failed to write signing public key!");
    }
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(pubout, &buffer);

    ConsoleWrite("%.*s", (int32_t)buffer->length, buffer->data)

    EVP_PKEY_free(private);

    return 0;
}

ZakoCommandHandler(root_cert) {
    ConsoleWrite("Usage: zakosign cert <option> [args...]")

    return 0;
}

#ifndef getline
#define ssize_t size_t
size_t getline(char **lineptr, size_t *n, FILE *stream) {
    char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (lineptr == NULL) {
        return -1;
    }
    if (stream == NULL) {
        return -1;
    }
    if (n == NULL) {
        return -1;
    }
    bufptr = *lineptr;
    size = *n;

    c = fgetc(stream);
    if (c == EOF) {
        return -1;
    }
    if (bufptr == NULL) {
        bufptr = malloc(128);
        if (bufptr == NULL) {
            return -1;
        }
        size = 128;
    }
    p = bufptr;
    while(c != EOF) {
        if ((p - bufptr) > (size - 1)) {
            size = size + 128;
            bufptr = realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
        }
        *p++ = c;
        if (c == '\n') {
            break;
        }
        c = fgetc(stream);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
}
#endif

static char* zako_cli_prompt(const char* prompt) {
    printf("%s", prompt);

    char* line = NULL;
    size_t n = 0;

    ssize_t len = getline(&line, &n, stdin);
    if (len < 0) {
        free(line);
        return NULL;
    }
    
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
    }

    for (size_t i = 0; i < len; i ++) {
        if ((line[i] != '\0') || 
            (line[i] != ' ' ) ||  
            (line[i] != '\n') || 
            (line[i] != '\t')) {
            
            return line;
        }
    }
    
    free(line);
    return NULL;
}

static inline char* zako_cli_noprmt(char* param, const char* prompt) {
    if (param == NULL) {
        return zako_cli_prompt(prompt);
    }

    return param;
}

static bool zako_set_rand_serial(ASN1_INTEGER *ai) {
    BIGNUM *btmp = BN_new();

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        return false;
    }

    if (ai && !BN_to_ASN1_INTEGER(btmp, ai)) {
        return false;
    }


    BN_free(btmp);

    return true;
}

static void zako_cert_add_extinfo(X509* x509, int32_t nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
    if (ex) {
        X509_add_ext(x509, ex, -1);
        X509_EXTENSION_free(ex);
    }
}

static inline X509_EXTENSION* zako_req_make_extinfo(X509_REQ* req, int32_t nid, const char* value) {
    return X509V3_EXT_nconf_nid(NULL, NULL, nid, value);
}

static uint64_t zako_s2i(char* str) {
    char* end = NULL;
    long result = strtol(str, &end, 10);
    
    if (end == str)  {
        return 0;
    }

    return result;
}

ZakoCommandHandler(root_cert_new) {
    char* private_key_path = ZakoParamAt(0);
    char* out_path = ZakoParamAt(1);

    char* password = ZakoParam("password");
    char* ca = ZakoParam("ca");

    char* country = zako_cli_noprmt(ZakoParam("country"), "Country (C): ");
    char* state = zako_cli_noprmt(ZakoParam("state"), "State/Province (ST): ");
    char* city = zako_cli_noprmt(ZakoParam("city"), "Location/City (L): ");
    char* org = zako_cli_noprmt(ZakoParam("org"), "Orgnization (O): ");
    char* ounit = zako_cli_noprmt(ZakoParam("ounit"), "Orgnization Unit (OU): ");
    char* cname = zako_cli_noprmt(ZakoParam("cn"), "Common Name (CN): ");
    char* valid_days = zako_cli_noprmt(ZakoParam("days"), "Valid Days: ");


    if (private_key_path == NULL || out_path == NULL) {
        ConsoleWrite("Usage: zakosign cert new <private-key> <certificate.crt> ");

        return 1;
    }

    if (!zako_sys_file_exist(private_key_path)) {
        ConsoleWriteFAIL("%s does not exist!", private_key_path);
        return 1;
    }

    EVP_PKEY* private = zako_load_private(private_key_path, password);

    X509* x509 = X509_new();

    X509_set_version(x509, X509_VERSION_3);
    zako_set_rand_serial(X509_get_serialNumber(x509));
    X509_set_pubkey(x509, private);

    X509_NAME* name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (const uint8_t*) country, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (const uint8_t*) city, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (const uint8_t*) state, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (const uint8_t*) org, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (const uint8_t*) ounit, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (const uint8_t*) cname, -1, -1, 0);

    X509_set_issuer_name(x509, name);

    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), zako_s2i(valid_days) * SECONDS_ONE_DAY);

    if (ca != NULL) {
        if (zako_streq("true", ca)) {
            zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:TRUE");
            zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment, keyCertSign");
        } else {
            zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:FALSE");
            zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment");
        }
    } else {
        zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:TRUE");
        zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment, keyCertSign");
    }

    zako_cert_add_extinfo(x509, NID_ext_key_usage, "critical, codeSigning");

    if (X509_sign(x509, private, NULL) == 0) {
        ZakoOSSLPrintError("Failed to sign generated certificate!");
        return 1;
    }

    BIO* bio = BIO_new_file(out_path, "w+");

    if (bio == NULL) {
        ConsoleWriteFAIL("Failed to write generated certificate!");
        return 1;
    }

    PEM_write_bio_X509(bio, x509);
    BIO_free(bio);
    X509_free(x509);

    return 0;
}

ZakoCommandHandler(root_cert_request) {
    char* private_key_path = ZakoParamAt(0);
    char* out_path = ZakoParamAt(1);

    char* password = ZakoParam("password");
    char* ca = ZakoParam("ca");

    char* country = zako_cli_noprmt(ZakoParam("country"), "Country (C): ");
    char* state = zako_cli_noprmt(ZakoParam("state"), "State/Province (ST): ");
    char* city = zako_cli_noprmt(ZakoParam("city"), "Location/City (L): ");
    char* org = zako_cli_noprmt(ZakoParam("org"), "Orgnization (O): ");
    char* ounit = zako_cli_noprmt(ZakoParam("ounit"), "Orgnization Unit (OU): ");
    char* cname = zako_cli_noprmt(ZakoParam("cn"), "Common Name (CN): ");
    char* cpwd = zako_cli_noprmt(ZakoParam("cpwd"), "Challenge Password: ");
    char* email = zako_cli_noprmt(ZakoParam("email"), "Requestor Email: ");

    if (private_key_path == NULL || out_path == NULL) {
        ConsoleWrite("Usage: zakosign cert request <private-key> <request> ");
        return 1;
    }

    if (!zako_sys_file_exist(private_key_path)) {
        ConsoleWriteFAIL("%s does not exist!", private_key_path);
        return 1;
    }

    EVP_PKEY* private = zako_load_private(private_key_path, password);

    X509_REQ* req = X509_REQ_new();

    X509_REQ_set_version(req, X509_REQ_VERSION_1);
    X509_REQ_set_pubkey(req, private);

    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (const uint8_t*) country, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (const uint8_t*) city, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (const uint8_t*) state, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (const uint8_t*) org, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (const uint8_t*) ounit, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (const uint8_t*) cname, -1, -1, 0);

    STACK_OF(X509_EXTENSION*) request_exts = sk_X509_EXTENSION_new_null();
    if (ca != NULL) {
        if (zako_streq("true", ca)) {
            sk_X509_EXTENSION_push(request_exts, zako_req_make_extinfo(req, NID_basic_constraints, "critical, CA:TRUE"));
        } else {
            sk_X509_EXTENSION_push(request_exts, zako_req_make_extinfo(req, NID_basic_constraints, "critical, CA:FALSE"));
        }
    } else {
        sk_X509_EXTENSION_push(request_exts, zako_req_make_extinfo(req, NID_basic_constraints, "critical, CA:TRUE"));
    }
    sk_X509_EXTENSION_push(request_exts, zako_req_make_extinfo(req, NID_ext_key_usage, "critical, codeSigning"));

    X509_REQ_add_extensions(req, request_exts);

    if (cpwd != NULL) {
        X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, MBSTRING_ASC, (const uint8_t*) cpwd, -1);
    }

    if (email != NULL) {
        X509_REQ_add1_attr_by_NID(req, NID_pkcs9_emailAddress, MBSTRING_ASC, (const uint8_t*) email, -1);
    }

    if (X509_REQ_sign(req, private, NULL) == 0) {
        ZakoOSSLPrintError("Failed to sign generated certificate request!");
        return 1;
    }

    BIO* bio = BIO_new_file(out_path, "w+");

    if (bio == NULL) {
        ConsoleWriteFAIL("Failed to write generated certificate!");
        return 1;
    }

    PEM_write_bio_X509_REQ(bio, req);

    sk_X509_EXTENSION_pop_free(request_exts, X509_EXTENSION_free);
    BIO_free(bio);
    X509_REQ_free(req);

    return 0;
}

static void zako_print_asn1_type(ASN1_TYPE* type) {
    if (type->type == V_ASN1_BOOLEAN) {
        if (type->value.boolean) {
            printf("true");
        } else {
            printf("false");
        }
    } else if (type->type == V_ASN1_OBJECT) {
        ASN1_OBJECT* obj = type->value.object;

        char buff[256] = { 0 };
        OBJ_obj2txt(buff, 256, obj, 0);

        printf("%s", buff);
    } else if (type->type == V_ASN1_SEQUENCE) {
        ASN1_SEQUENCE_ANY* seq = NULL;
        d2i_ASN1_SEQUENCE_ANY(&seq, &type->value.sequence->data, type->value.sequence->length);

        size_t seq_sz = sk_ASN1_TYPE_num(seq);
        printf("[ ");
        for (size_t i = 0; i < seq_sz; i ++) {
            ASN1_TYPE* t = sk_ASN1_TYPE_value(seq, i);

            zako_print_asn1_type(t);

            if (i + 1 < seq_sz) {
                printf(", ");
            }
        }
        printf(" ]");
    } else {
        char* str = NULL;
        int len = ASN1_STRING_to_UTF8(&str, type->value.asn1_string);

        if (len > 0) {
            printf("%s", str);
            OPENSSL_free(str);
        } else {
            printf("<error (%i)>", type->type);
        }
    }
}

ZakoCommandHandler(root_cert_approve) {
    char* private_key_path = ZakoParamAt(0);
    char* ca_path = ZakoParamAt(1);
    char* request_path = ZakoParamAt(2);
    char* out_path = ZakoParamAt(3);

    char* password = ZakoParam("password");

    EVP_PKEY* private = zako_load_private(private_key_path, password);

    if (private_key_path == NULL || ca_path == NULL || request_path == NULL || out_path == NULL) {
        ConsoleWrite("Usage: zakosign cert approve <private-key> <request> <out.crt>");
        return 1;
    }

    if (!zako_sys_file_exist(private_key_path)) {
        ConsoleWriteFAIL("%s does not exist!", private_key_path);
        return 1;
    }

    if (!zako_sys_file_exist(ca_path)) {
        ConsoleWriteFAIL("%s does not exist!", ca_path);
        return 1;
    }

    if (!zako_sys_file_exist(request_path)) {
        ConsoleWriteFAIL("%s does not exist!", request_path);
        return 1;
    }

    BIO* req_bio = BIO_new_file(request_path, "r");

    if (req_bio == NULL) {
        ConsoleWriteFAIL("Failed to open %s", request_path);
        
        return 1;
    }

    X509_REQ* req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL);
    ConsoleWrite("Certificate Request (v%li):", X509_REQ_get_version(req) + 1)

    ConsoleWrite("  Subject: ")
    X509_NAME* name = X509_REQ_get_subject_name(req);
    int name_entries_sz = X509_NAME_entry_count(name);

    for (int i = 0; i < name_entries_sz; i ++) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);

        char buff[256] = { 0 };
        OBJ_obj2txt(buff, 256, obj, 0);

        char* str = NULL;
        int len = ASN1_STRING_to_UTF8(&str, data);

        if (len > 0) {
            ConsoleWrite("    %s: %s", buff, str);
            OPENSSL_free(str);
        } else {
            ConsoleWrite("    %s: <?>", buff);
        }
    }

    EVP_PKEY* rpkey = X509_REQ_get_pubkey(req);

    uint8_t rpkey_raw[32] = { 0 };
    size_t rpkey_sz = 32;
    EVP_PKEY_get_raw_public_key(rpkey, rpkey_raw, &rpkey_sz);

    ConsoleWrite("  Key: %s (%s)", base64_encode(rpkey_raw, 32, NULL), OBJ_nid2ln(EVP_PKEY_id(rpkey)));
        
    ConsoleWrite("  Attributes:");
    int attr_sz = X509_REQ_get_attr_count(req);
    for (int i = 0; i < attr_sz; i ++) {
        X509_ATTRIBUTE* attr = X509_REQ_get_attr(req, i);

        int value_sz = X509_ATTRIBUTE_count(attr);
        ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
        int nid = OBJ_obj2nid(obj);

        if (nid == NID_ext_req) {
            continue;
        }

        printf("    %s: ", OBJ_nid2ln(nid));
        for (int j = 0; j < value_sz; j ++) {
            ASN1_TYPE* type = X509_ATTRIBUTE_get0_type(attr, j);

            zako_print_asn1_type(type);

            if (j + 1 < value_sz) {
                printf(", ");
            }
        }
        printf("\n");
    }

    ConsoleWrite("  X509v3 Extenstions: ");
    STACK_OF(X509_EXTENSION*) sk_ext = X509_REQ_get_extensions(req);

    size_t ext_sz = sk_X509_EXTENSION_num(sk_ext);
    for (int i = 0; i < ext_sz; i ++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(sk_ext, i);

        if (X509_EXTENSION_get_critical(ext)) {
            printf("    (!) ");
        } else {
            printf("    ");
        }

        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        char buff[128] = { 0 };
        OBJ_obj2txt(buff, 128, obj, 0);

        ASN1_OCTET_STRING* asnstr = X509_EXTENSION_get_data(ext);
        ASN1_TYPE* type = d2i_ASN1_TYPE(NULL, &asnstr->data, asnstr->length);
        
        if (OBJ_obj2nid(obj) == NID_basic_constraints) {
            printf("%s [CA, pathLenConstraint]: ", buff);
        } else {
            printf("%s: ", buff);
        }

        zako_print_asn1_type(type);
        printf("\n");
    }

    if (X509_REQ_verify(req, rpkey) == 1) {
        ConsoleWrite("  Signature Status: VALID");
    } else {
        ConsoleWrite("  Signature Status: (!) INVALID");
    }

    ConsoleWrite("");
    char* days_str = zako_cli_prompt("Approve? (Enter valid days to approve): ");
    uint64_t days = zako_s2i(days_str) * SECONDS_ONE_DAY;

    if (days < SECONDS_ONE_DAY) {
        ConsoleWrite("Invalid number! Cancelling...")
        goto exit;
    }

    BIO* ca_bio = BIO_new_file(ca_path, "r");

    if (ca_bio == NULL) {
        ConsoleWriteFAIL("Failed to open %s", ca_path);
        
        goto exit;
    }

    X509* ca_x509 = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);

    X509* x509 = X509_new();

    X509_set_version(x509, X509_VERSION_3);
    zako_set_rand_serial(X509_get_serialNumber(x509));
    X509_set_pubkey(x509, rpkey);
    X509_set_subject_name(x509, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(x509, X509_get_subject_name(ca_x509));
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), days);

    sk_ext = X509_REQ_get_extensions(req);
    ext_sz = sk_X509_EXTENSION_num(sk_ext);
    for (int i = 0; i < ext_sz; i ++) {
        X509_add_ext(x509, sk_X509_EXTENSION_value(sk_ext, i), -1);
    }
    zako_cert_add_extinfo(x509, NID_subject_key_identifier, "hash");

    if (X509_sign(x509, private, NULL) == 0) {
        ZakoOSSLPrintError("Failed to sign generated certificate!");
        goto x509_fail;
    }
    
    BIO* bio = BIO_new_file(out_path, "w+");

    if (bio == NULL) {
        ConsoleWriteFAIL("Failed to write generated certificate!");
        goto x509_fail;
    }
    PEM_write_bio_X509(bio, x509);

    BIO_free(bio);
x509_fail:    
    X509_free(x509);
exit:
    X509_REQ_free(req);
    BIO_free(req_bio);
    EVP_PKEY_free(private);
    return 0;
}

ZakoCommandHandler(root_cert_issue) {
    char* private_key_path = ZakoParamAt(0);
    char* ca_path = ZakoParamAt(1);
    char* subject_key_path = ZakoParamAt(2);
    char* out_path = ZakoParamAt(3);

    char* password = ZakoParam("password");
    char* ca = ZakoParam("ca");

    if (private_key_path == NULL || ca_path == NULL || subject_key_path == NULL || out_path == NULL) {
        ConsoleWrite("Usage: zakosign cert issue <private-key> <ca.crt> <subject-public-key> <out.crt>");
        return 1;
    }

    if (!zako_sys_file_exist(private_key_path)) {
        ConsoleWriteFAIL("%s does not exist!", private_key_path);
        return 1;
    }

    if (!zako_sys_file_exist(ca_path)) {
        ConsoleWriteFAIL("%s does not exist!", ca_path);
        return 1;
    }

    if (!zako_sys_file_exist(subject_key_path)) {
        ConsoleWriteFAIL("%s does not exist!", subject_key_path);
        return 1;
    }

    char* country = zako_cli_noprmt(ZakoParam("country"), "Country (C): ");
    char* state = zako_cli_noprmt(ZakoParam("state"), "State/Province (ST): ");
    char* city = zako_cli_noprmt(ZakoParam("city"), "Location/City (L): ");
    char* org = zako_cli_noprmt(ZakoParam("org"), "Orgnization (O): ");
    char* ounit = zako_cli_noprmt(ZakoParam("ounit"), "Orgnization Unit (OU): ");
    char* cname = zako_cli_noprmt(ZakoParam("cn"), "Common Name (CN): ");
    char* valid_days = zako_cli_noprmt(ZakoParam("days"), "Valid Days: ");

    EVP_PKEY* private = zako_load_private(private_key_path, password);
    EVP_PKEY* subject = zako_load_private(subject_key_path, password);

    BIO* ca_bio = BIO_new_file(ca_path, "r");
    if (ca_bio == NULL) {
        ConsoleWriteFAIL("Failed to open %s", ca_path);
        
        return 1;
    }

    X509* ca_x509 = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    X509* x509 = X509_new();

    X509_set_version(x509, X509_VERSION_3);
    zako_set_rand_serial(X509_get_serialNumber(x509));
    X509_set_pubkey(x509, subject);
    X509_set_issuer_name(x509, X509_get_subject_name(ca_x509));

    X509_NAME* name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (const uint8_t*) country, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (const uint8_t*) city, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (const uint8_t*) state, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (const uint8_t*) org, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (const uint8_t*) ounit, -1, -1, 0);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (const uint8_t*) cname, -1, -1, 0);
    
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), zako_s2i(valid_days) * SECONDS_ONE_DAY);

    if (ca != NULL) {
        if (zako_streq("true", ca)) {
            zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:TRUE");
            zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment, keyCertSign");
        } else {
            zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:FALSE");
            zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment");
        }
    } else {
        zako_cert_add_extinfo(x509, NID_basic_constraints, "critical, CA:TRUE");
        zako_cert_add_extinfo(x509, NID_key_usage, "critical, digitalSignature, keyEncipherment, keyCertSign");
    }

    zako_cert_add_extinfo(x509, NID_ext_key_usage, "critical, codeSigning");

    if (X509_sign(x509, private, NULL) == 0) {
        ZakoOSSLPrintError("Failed to sign generated certificate!");
        goto exit;
    }

    BIO* bio = BIO_new_file(out_path, "w+");

    if (bio == NULL) {
        ConsoleWriteFAIL("Failed to write generated certificate!");
        goto exit;
    }
    PEM_write_bio_X509(bio, x509);

    BIO_free(bio);
exit:
    X509_free(x509);
    X509_free(ca_x509);
    BIO_free(ca_bio);
    return 0;
}

int main(int argc, char* argv[]) {
    ZakoNewCliApp(true);
        ZakoCommand(root, help);
        ZakoCommand(root, verify);
        ZakoCommand(root, sign);
        ZakoCommand(root, info);
        ZakoCommand(root, key);
            ZakoCommand(root_key, new);
            ZakoCommand(root_key, pub);
        ZakoCommand(root, cert);
            ZakoCommand(root_cert, new);
            ZakoCommand(root_cert, request);
            ZakoCommand(root_cert, approve);
            ZakoCommand(root_cert, issue);
    ZakoRunCliApp();
}

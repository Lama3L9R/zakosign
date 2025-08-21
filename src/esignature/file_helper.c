#include "file_helper.h"

#include <openssl/err.h>

#include "ed25519_sign.h"


static char* error_messages[] = {
    "Failed to map input file into memory (out of memory?)",
    "Input file does not have a valid E-Signature header"
};

bool zako_file_sign(file_handle_t fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash) {

    size_t buf_sz = zako_sys_file_sz(fd);

    void* buffer = zako_sys_file_map(fd, buf_sz);
    
    zako_hash_buffer(buffer, buf_sz, hash);

    if (!zako_sign_buffer(key, hash, ZAKO_HASH_LENGTH, result)) {
        ZakoOSSLPrintError("Failed to sign buffer!");
    }

    zako_sys_file_unmap(buffer, buf_sz);

    return true;
}

bool zako_file_write_esig(file_handle_t fd, struct zako_esignature* esignature, size_t len) {
    uint64_t magic = ZAKO_ESIGNATURE_MAGIC;

    zako_sys_file_append_end(fd, (uint8_t*) esignature, len);
    zako_sys_file_append_end(fd, (uint8_t*) &len, sizeof(size_t));
    zako_sys_file_append_end(fd, (uint8_t*) &magic, sizeof(uint64_t));

    return true;
}

struct zako_esignature* zako_file_read_esig(file_handle_t fd) {
    struct zako_esignature* esign_buf = NULL;

    size_t file_sz = zako_sys_file_sz(fd);

    void* buffer = zako_sys_file_map(fd, file_sz);

    if (buffer == NULL) {
        goto done;
    }

    void* buff_end = ApplyOffset(buffer, +(file_sz));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != ZAKO_ESIGNATURE_MAGIC) {
        goto done;
    }
    
    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > file_sz) {
        goto done;
    }

    esign_buf = (struct zako_esignature*) ApplyOffset(sz, -*sz);

    if (esign_buf->magic != ZAKO_ESIGNATURE_MAGIC || esign_buf->version != ZAKO_ESIGNATURE_VERSION) {
        goto done;
    }

    zako_mdupfield((void**) &esign_buf, *sz);

done:
    zako_sys_file_unmap(buffer, file_sz);
    return esign_buf;
}

uint32_t zako_file_verify_esig(file_handle_t fd, uint32_t flags) {
    size_t file_sz = zako_sys_file_sz(fd);

    void* buffer = zako_sys_file_map(fd, file_sz);

    if (buffer == NULL) {
        return ZAKO_FV_MMAP_FAILED;
    }

    void* buff_end = ApplyOffset(buffer, +(file_sz));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != ZAKO_ESIGNATURE_MAGIC) {
        return ZAKO_FV_INVALID_HEADER;
    }

    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > file_sz) {
        return ZAKO_FV_INVALID_HEADER;
    }

    struct zako_esignature* esign_buf = (struct zako_esignature*) ApplyOffset(sz, -*sz);

    /* Entire file footer is ESignature + ESignatureSize + ESignatureMagic 
         which is *sz + sizeof(sz) + 8 = *sz + 16
       So, original file buffer will be FileSize - *sz - 16 */
    uint32_t result = zako_esign_verify(esign_buf, buffer, file_sz - *sz - 16, flags);

    zako_sys_file_unmap(buffer, file_sz);
    return result;
}

const char* zako_file_verrcidx2str(uint8_t idx) {
    if (idx < 16) {
        return zako_esign_verrcidx2str(idx);
    }

    if (idx >= 31) {
        return NULL;
    }

    return error_messages[idx - 16];
}

#ifndef ZAKOSIGN_HEADER_FILE_HELPER_H
#define ZAKOSIGN_HEADER_FILE_HELPER_H

#include "prelude.h"
#include "hasher.h"
#include "esignature.h"

#include <openssl/evp.h>

#define ZAKO_FV_MMAP_FAILED    (1 << 16)
#define ZAKO_FV_INVALID_HEADER (1 << 17)

bool zako_file_sign(file_handle_t fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash);
bool zako_file_write_esig(file_handle_t fd, struct zako_esignature* esignature, size_t len);

uint32_t zako_file_verify_esig(file_handle_t fd, uint32_t flags);

struct zako_esignature* zako_file_read_esig(file_handle_t fd);

/**
 * Get error message based on verification error code bit field index.
 * Call this function instead of zako_esign_verrcidx2str to get messages like ZAKO_FV_MMAP_FAILED.
 */
const char* zako_file_verrcidx2str(uint8_t idx);

#endif
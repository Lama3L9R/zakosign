#ifndef ZAKOSIGN_HEADER_OSSL_HELPER_H
#define ZAKOSIGN_HEADER_OSSL_HELPER_H

#include "prelude.h"
#include <openssl/err.h>

#define ZakoOSSLPrintError(...) { \
        ConsoleWriteFAIL(__VA_ARGS__); \
        unsigned long err_code; \
        char err_buf[1024]; \
        while ((err_code = ERR_get_error()) != 0) { \
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf)); \
            ConsoleWriteFAIL("  %s (%lu)", err_buf, err_code); \
        } \
    }


#endif
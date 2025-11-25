#ifndef ZAKOSIGN_HEADER_CONSTANTS_H
#define ZAKOSIGN_HEADER_CONSTANTS_H

#include "prelude.h"

#define ZakoDefineConstant(file) \
    extern const uint8_t const_##file[]; \
    extern const uint8_t const_##file##_end[]; \
    extern const size_t const_##file##_sz;

#define ZakoDefineStrConstant(file) \
    extern const char* const_##file; \
    extern const char* const_##file##_end; \
    extern const size_t const_##file##_sz;

#define ZakoConstant(file) const_##file
#define ZakoConstantSz(file) const_##file##_sz

ZakoDefineConstant(help);

/* Add integrated CAs */


#endif
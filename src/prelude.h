#ifndef ZAKOSIGN_HEADER_PRELUDE_H
#define ZAKOSIGN_HEADER_PRELUDE_H

#define ZAKO_LIBRARY_VERSION_STRING "1.0"
/**
 * Valid version types are:
 *  'stable', 'staging', 'dev'
 */
#define ZAKO_LIBRARY_VERSION_TYPE "staging"

#if __has_include(<unistd.h>)
#define ZAKO_TARGET_LINUX 1
#endif

#if defined(_WIN64)
#define ZAKO_TARGET_NT 1
#endif 

#if defined(__APPLE__)
#define ZAKO_TARGET_APPLE 1
#undef ZAKO_TARGET_LINUX
#endif

#define uint64_t HACK_USE_ONLY
#include <stdint.h>
#undef uint64_t

/**
 * The reason why we hacked uint64_t is because
 * the definition of uint64_t is not consistant across different os.
 * On macOS x64, uint64_t = ull
 * On Linux x64, uint64_t = uli
 * Although they have the same size (64b), but we have to use different formats in printf (%llu vs %lu).
 */
typedef unsigned long long uint64_t;

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define __hide __attribute__((visibility("hidden")))

#include "sys.h"
#include "utils.h"

#endif

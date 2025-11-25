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

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define __hide __attribute__((visibility("hidden")))

#include "sys.h"
#include "utils.h"

#endif

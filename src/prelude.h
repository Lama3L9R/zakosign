#ifndef ZAKOSIGN_HEADER_PRELUDE_H
#define ZAKOSIGN_HEADER_PRELUDE_H

#define ZAKO_LIBRARY_VERSION_STRING "1.0"
/**
 * Valid version types are:
 *  'stable', 'staging', 'dev'
 */
#define ZAKO_LIBRARY_VERSION_TYPE "staging"

#if __has_include(<unistd.h>)
#define ZAKO_TARGET_POSIX 1
#define __hide __attribute__((visibility("hidden")))
#endif

#if defined(_WIN64)
#define ZAKO_TARGET_NT 1
#define __hide
#endif 

#if defined(__APPLE__)
#define ZAKO_TARGET_APPLE 1
#define ZAKO_TARGET_POSIX 1
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sys.h"
#include "utils.h"

#endif

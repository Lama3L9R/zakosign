#ifndef ZAKOSIGN_HEADER_SYS_H
#define ZAKOSIGN_HEADER_SYS_H

#include "prelude.h"

#ifdef ZAKO_TARGET_NT
typedef void* file_handle_t;
#define ZAKO_FHAND_ERROR 0
#endif

#ifdef ZAKO_TARGET_POSIX
typedef int file_handle_t;
#define ZAKO_FHAND_ERROR -1
#endif

#ifdef ZAKO_TARGET_APPLE
typedef int file_handle_t;
#endif

/**
 * Check if given path exist and can be accessed
 */
bool zako_sys_file_exist(char* path);

/**
 * Open file at given path
 */
file_handle_t zako_sys_file_open(char* path);

/**
 * Creates a copy at new of file at path, and then, open the new file
 */
file_handle_t zako_sys_file_opencopy(char* path, char* new, bool overwrite);

/**
 * Append sz bytes of data into file
 */
void zako_sys_file_append_end(file_handle_t file, uint8_t* data, size_t sz);

/**
 * Close an opened file
 */
void zako_sys_file_close(file_handle_t file);

/**
 * Get size of file
 */
size_t zako_sys_file_sz(file_handle_t file);

/**
 * Get size of file at path
 */
size_t zako_sys_file_szatpath(char* path);

/**
 * Map sz bytes of given file into memory (r--)
 */
void* zako_sys_file_map(file_handle_t file, size_t sz);

/**
 * Map sz bytes of given file into memory (rw-)
 */
void* zako_sys_file_map_rw(file_handle_t file, size_t sz);

/**
 * Unmap a mapped file memory
 */
void zako_sys_file_unmap(void* ptr, size_t sz);  


#endif
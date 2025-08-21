#ifndef ZAKOSIGN_HEADER_UTILS_H
#define ZAKOSIGN_HEADER_UTILS_H

#include "prelude.h"

#define ConsoleWrite(...) printf(__VA_ARGS__); printf("\n");
#define ConsoleWriteOK(...) printf("[+] "); printf(__VA_ARGS__); printf("\n");
#define ConsoleWriteFAIL(...) printf("[-] "); printf(__VA_ARGS__); printf("\n");

#define ApplyOffset(ptr, off) (void*)(((size_t) ptr) off)

#define OnFlag(var, fl) if ((var & fl) > 0)
#define OnNotFlag(var, fl) if ((var & fl) == 0)


/**
 * Allocate with malloc but in a safe way.
 */
__hide uint8_t* zako_allocate_safe(size_t len);

__hide void zako_mdupfield(void** buf, size_t len);

#define ZakoAllocateStruct(struct_name) (struct struct_name*) zako_allocate_safe(sizeof(struct struct_name))

__hide bool zako_streq(const char* a, const char* b);

__hide bool zako_strstarts(char* base, char* prefix);

__hide unsigned char* base64_encode(const unsigned char* src, size_t len, size_t* out_len);
__hide unsigned char* base64_decode(const unsigned char* src, size_t len, size_t* out_len);

#endif
#include "sys.h"

#if ZAKO_TARGET_NT
#include <Windows.h>
#include <Shlwapi.h>
#include <fileapi.h>
#include <winbase.h>

bool zako_sys_file_exist(char* path) {
    return PathFileExistsA(path);
}

file_handle_t zako_sys_file_open(char* path) {
    HANDLE handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_APPEND_DATA, NULL);
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        ConsoleWriteFAIL("Failed to open %s because file does not exist!", path);
    }

    return handle;
}

file_handle_t zako_sys_file_opencopy(char* path, char* new, bool overwrite) {
    if (!CopyFileA(path, new, !overwrite)) {
        ConsoleWriteFAIL("Failed to open a copy of %s at %s", path, new);

        return NULL;
    }

    return zako_sys_file_open(new);
}

void zako_sys_file_append_end(file_handle_t file, uint8_t* data, size_t sz) {
    WriteFile(file, data, sz, 0, NULL);
}

void zako_sys_file_close(file_handle_t file) {
    CloseHandle(file);
}

size_t zako_sys_file_sz(file_handle_t file) {
    LARGE_INTEGER li;
    GetFileSizeEx(file, &li);

    if (li.HighPart != 0) {
        ConsoleWriteFAIL("Error: File too big");
        return 0;
    }

    return li.LowPart;
}

size_t zako_sys_file_szatpath(char* path) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    GetFileAttributesExA(path, GetFileExInfoStandard, &data);

    if (data.nFileSizeHigh != 0) {
        ConsoleWriteFAIL("Error: File %s is too big", path);
        return 0;
    } 

    return data.nFileSizeLow;
}

void* zako_sys_file_map(file_handle_t file, size_t sz) {
    HANDLE hMapFile = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    return MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
}

void* zako_sys_file_map_rw(file_handle_t file, size_t sz) {
    HANDLE hMapFile = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, 0, NULL);
    return MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, 0);
}

void zako_sys_file_unmap(void* ptr, size_t sz) {
    UnmapViewOfFile(ptr);

    /* lets leak this for convenient purpose  
    CloseHandle(); */
}

/* https://stackoverflow.com/questions/735126/are-there-alternate-implementations-of-gnu-getline-interface
   Visited at Nov. 24, 2025
*/
/* The original code is public domain -- Will Hartung 4/9/2009 */
/* Modifications, public domain as well, by Antti Haapala, 11/10/2017
   - Switched to getc on 5/23/2019
   - Proper error handling on IO error and wraparound 
     check on buffer extension 3/31/2025 - 4/2/2025
*/
#define MINIMUM_BUFFER_SIZE 128
ssize_t zako_sys_getline(char **lineptr, size_t *n, FILE *stream) {
    size_t pos;
    int c;

    if (lineptr == NULL || stream == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }

    c = getc(stream);
    if (c == EOF) {
        return -1;
    }

    if (*lineptr == NULL) {
        *lineptr = malloc(MINIMUM_BUFFER_SIZE);
        if (*lineptr == NULL) {
            return -1;
        }
        *n = MINIMUM_BUFFER_SIZE;
    }

    pos = 0;
    while(c != EOF) {
        if (pos + 1 >= *n) {
            size_t new_size = *n + (*n >> 2);

            // have some reasonable minimum
            if (new_size < MINIMUM_BUFFER_SIZE) {
                new_size = MINIMUM_BUFFER_SIZE;
            }
            
            // size_t wraparound
            if (new_size <= *n) {
                errno = ENOMEM;
                return -1;
            }

            // Note you might also want to check that PTRDIFF_MAX
            // is not exceeded!

            char *new_ptr = realloc(*lineptr, new_size);
            if (new_ptr == NULL) {
                return -1;
            }
            *n = new_size;
            *lineptr = new_ptr;
        }

        ((unsigned char *)(*lineptr))[pos ++] = c;
        if (c == '\n') {
            break;
        }
        c = getc(stream);
    }

    (*lineptr)[pos] = '\0';
    
    // if an IO error occurred, return -1
    if (c == EOF && !feof(stream)) {
        return -1;
    }

    // otherwise we successfully read until the end-of-file
    // or the delimiter
    return pos;
}

bool zako_sys_gmtime_s(const time_t* timer, struct tm* buf) {
    return gmtime_s(buf, timer) != EINVAL;
}

bool zako_sys_is_file_valid(file_handle_t file) {
    return file != NULL;
}

#endif
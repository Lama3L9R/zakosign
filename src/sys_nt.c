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

#endif
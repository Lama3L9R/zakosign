#include "sys.h"

#ifdef ZAKO_TARGET_APPLE
#include <copyfile.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "syscall.h"

bool zako_sys_file_exist(char* path) {
    return access(path, F_OK) == 0;
}

file_handle_t zako_sys_file_open(char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return -1;
    }

    return fd;
}


file_handle_t zako_sys_file_opencopy(char* path, char* new, bool overwrite) {
    if (access(new, F_OK) == 0) {
        if (overwrite) {
            if (remove(new) == -1) {
                ConsoleWriteFAIL("File %s exists! (Failed to overwrite: %i)", new, errno);
                return -1;
            }
        } else {
            ConsoleWriteFAIL("File %s exists!", new);
            return -1;
        }
    }

    /*
        I know ther is copyfile function defined in "copyfile.h"
        But if I dont use zako_syscall4, it will looks so weired to have a full set
        of manual syscall functions.

        Also using manual syscall won't affect performance, so why not?
        It looks cool, doesn't it?
    */    
    long rtn = zako_syscall4(SYS_copyfile, (long) path, (long) new, 0l, (long) COPYFILE_ALL);

    if (rtn != 0) {
        ConsoleWriteFAIL("Failed to create a copy at %s (%li)", new, rtn);
    }

    int fd_out = open(new, O_CREAT | O_RDWR, 0644);
    if (fd_out == -1) {
        ConsoleWriteFAIL("Failed to open %s", new);
        return -1;
    }

    return fd_out;
}

void zako_sys_file_append_end(file_handle_t file, uint8_t* data, size_t sz) {
    write(file, (void*) data, sz);
}

void zako_sys_file_close(file_handle_t fd) {
    close(fd);
}

size_t zako_sys_file_sz(file_handle_t file) {
    struct stat st;
    fstat(file, &st);

    return (size_t) st.st_size;
}

size_t zako_sys_file_szatpath(char* path) {
    struct stat st;
    stat(path, &st);

    return (size_t) st.st_size;
}

void* zako_sys_file_map(file_handle_t file, size_t sz) {
    return mmap(NULL, sz, PROT_READ, MAP_SHARED, file, 0);
}

void* zako_sys_file_map_rw(file_handle_t file, size_t sz) {
    return mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
}

void zako_sys_file_unmap(void* ptr, size_t sz) {
    munmap(ptr, sz);
}

#endif
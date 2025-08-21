#include "sys.h"

#ifdef ZAKO_TARGET_POSIX
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

    /* Reference: https://man7.org/linux/man-pages/man2/copy_file_range.2.html#EXAMPLES */

    int          fd_in, fd_out;
    off_t        size, ret;
    struct stat  stat;
    
    fd_in = open(path, O_RDONLY);
    if (fd_in == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return -1;
    }
        
    if (fstat(fd_in, &stat) == -1) {
        ConsoleWriteFAIL("Failed to get file stats of %s (%s)", path, strerror(errno));

        close(fd_in);
        return -1;
    }
        
    size = stat.st_size;
        
    fd_out = open(new, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd_out == -1) {
        ConsoleWriteFAIL("Failed to open %s", new);
        return -1;
    }
        
    do {
        /* For some reason, copy_file_range is not defined in unistd...
           For some reason, syscall is not defined in unistd either....

           .... I am very confused ...
           
           In order to not copy from kernel to userspace and vise versa multiple times
           we are going to manually do a syscall. Yay! */
        ret = zako_syscall6(__NR_copy_file_range, fd_in, (long) NULL, fd_out, (long) NULL, size, 0);
        if (ret == -1) {
            ConsoleWriteFAIL("Failed copy %s to %s", path, new);
            return -1;
        }
            
        size -= ret;
    } while (size > 0 && ret > 0);
        
    close(fd_in);

    return fd_out;
}

void zako_sys_file_append_end(file_handle_t file, uint8_t* data, size_t sz) {
    if (lseek(fd, 0, SEEK_END) == -1) {
        return false;
    }

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
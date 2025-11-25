#include "syscall.h"

__hide long zako_syscall0(long n) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number) : "memory");
#endif

    return ret;
}

__hide long zako_syscall1(long n, long a1) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1) : "memory");
#endif

    return ret;
}

__hide long zako_syscall2(long n, long a1, long a2) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    register long arg2 __asm__("x1") = a2;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    register long arg2 __asm__("r1") = a2;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    register long arg2 __asm__("rsi") = a2;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1), "S"(arg2) : "memory");
#endif

    return ret;
}

__hide long zako_syscall3(long n, long a1, long a2, long a3) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    register long arg2 __asm__("x1") = a2;
    register long arg3 __asm__("x2") = a3;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    register long arg2 __asm__("r1") = a2;
    register long arg3 __asm__("r2") = a3;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    register long arg2 __asm__("rsi") = a2;
    register long arg3 __asm__("rdx") = a3;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1), "S"(arg2), "d"(arg3) : "memory");
#endif

    return ret;
}

__hide long zako_syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    register long arg2 __asm__("x1") = a2;
    register long arg3 __asm__("x2") = a3;
    register long arg4 __asm__("x3") = a4;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    register long arg2 __asm__("r1") = a2;
    register long arg3 __asm__("r2") = a3;
    register long arg4 __asm__("r3") = a4;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    register long arg2 __asm__("rsi") = a2;
    register long arg3 __asm__("rdx") = a3;
    register long arg4 __asm__("r10") = a4;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(arg4) : "memory");
#endif

    return ret;
}

__hide long zako_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    register long arg2 __asm__("x1") = a2;
    register long arg3 __asm__("x2") = a3;
    register long arg4 __asm__("x3") = a4;
    register long arg5 __asm__("x4") = a5;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    register long arg2 __asm__("r1") = a2;
    register long arg3 __asm__("r2") = a3;
    register long arg4 __asm__("r3") = a4;
    register long arg5 __asm__("r4") = a5;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    register long arg2 __asm__("rsi") = a2;
    register long arg3 __asm__("rdx") = a3;
    register long arg4 __asm__("r10") = a4;
    register long arg5 __asm__("r8") = a5;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(arg4), "r"(arg5) : "memory");
#endif

    return ret;
}

__hide long zako_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;

#if defined(__aarch64__)
    register long syscall_number __asm__("x8") = n;
    register long arg1 __asm__("x0") = a1;
    register long arg2 __asm__("x1") = a2;
    register long arg3 __asm__("x2") = a3;
    register long arg4 __asm__("x3") = a4;
    register long arg5 __asm__("x4") = a5;
    register long arg6 __asm__("x5") = a6;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6) : "memory");
#elif defined(__arm__)
    register long syscall_number __asm__("r7") = n;
    register long arg1 __asm__("r0") = a1;
    register long arg2 __asm__("r1") = a2;
    register long arg3 __asm__("r2") = a3;
    register long arg4 __asm__("r3") = a4;
    register long arg5 __asm__("r4") = a5;
    register long arg6 __asm__("r5") = a6;
    asm volatile ("svc #0" : "=r"(ret) : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6) : "memory");
#else
    register long syscall_number __asm__("rax") = n;
    register long arg1 __asm__("rdi") = a1;
    register long arg2 __asm__("rsi") = a2;
    register long arg3 __asm__("rdx") = a3;
    register long arg4 __asm__("r10") = a4;
    register long arg5 __asm__("r8") = a5;
    register long arg6 __asm__("r9") = a6;
    asm volatile ("syscall" : "=a"(ret) : "a"(syscall_number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(arg4), "r"(arg5), "r"(arg6) : "memory");
#endif

    return ret;
}
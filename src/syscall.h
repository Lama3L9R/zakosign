#ifndef ZAKOSIGN_HEADER_SYSCALL_H
#define ZAKOSIGN_HEADER_SYSCALL_H

#include "prelude.h"

__hide long zako_syscall0(long n);
__hide long zako_syscall1(long n, long a1);
__hide long zako_syscall2(long n, long a1, long a2);
__hide long zako_syscall3(long n, long a1, long a2, long a3);
__hide long zako_syscall4(long n, long a1, long a2, long a3, long a4);
__hide long zako_syscall5(long n, long a1, long a2, long a3, long a4, long a5);
__hide long zako_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);

#endif
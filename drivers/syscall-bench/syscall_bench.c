/*
 * syscall_bench.c - measure the latency of steps in the system call execution
 */

#include <linux/syscalls.h>

/*
 * syscall_bench - TODO
 */
SYSCALL_DEFINE0(syscall_bench)
{
        return 1;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * x86.c - measure the latency of steps in the system call execution on x86-64
 */

#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm/processor.h>
#include <asm/msr.h>

/*
 * syscall_bench - measure performance counter, write to user space, and return
 */
SYSCALL_DEFINE2(syscall_bench, uint32_t, idx, uint64_t __user *, measurements)
{
	uint32_t eax = 0;
	uint64_t counter;

	asm volatile(
#ifdef CONFIG_SYSCALL_BENCH_SERIAL
		"cpuid;"
#endif
		"movl %2, %%ecx;"
		"rdpmc;"
		"salq $32, %%rdx;"
		"leaq (%%rdx, %%rax), %1;"
#ifdef CONFIG_SYSCALL_BENCH_SERIAL
		"xorl %%eax, %%eax;"
		"cpuid;"
#endif
		: "+&a"(eax), "=r"(counter)
		: "r"(idx)
		: "ebx", "ecx", "edx", "memory");

	if (copy_to_user(&measurements[4], &counter, sizeof(counter)))
		return -EFAULT;
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_bench.h - helpers for system call benchmarking
 */

#ifdef CONFIG_SYSCALL_BENCH

#define SYS_SYSCALL_BENCH 445

#ifndef __ASSEMBLY__

#include <linux/compiler_attributes.h>
#include <linux/compiler_types.h>
#include <linux/uaccess.h>

/*
 * syscall_benchmark - measure cycle count and write the result to user space
 *
 * Returns a negative error number on failure.
 */
static __always_inline int syscall_benchmark(u64 *__user dst)
{
	u64 cycles;
#ifdef CONFIG_SYSCALL_BENCH_SERIAL
	isb();
#endif
	barrier();
	cycles = read_sysreg(pmccntr_el0);
	barrier();
#ifdef CONFIG_SYSCALL_BENCH_SERIAL
	isb();
#endif
	return copy_to_user(dst, &cycles, sizeof(cycles)) ? -EFAULT : 0;
}

#endif /* __ASSEMBLY__ */
#endif /* CONFIG_SYSCALL_BENCH */

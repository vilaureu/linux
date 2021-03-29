// SPDX-License-Identifier: GPL-2.0
/*
 * This header file provides general wrappers and helpers
 * to execute fastcalls.
 *
 * This file is intended for general use when working with fastcalls.
 */

#include <unistd.h>

#define FASTCALL_SYSCALL_NR 442
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define FASTCALL_ADDR ((char *)(0x7fffffffffff & ~(PAGE_SIZE - 1)))

#ifndef __x86_64__
#error "fastcalls can only be used under x86-64"
#endif

/*
 * Execute a fastcall system call.
 *
 * Parameters:
 * TODO
 *
 * Returns -EINVAL when the fastcall does not exist in the fastcall table.
 * All other return values depend on the specific fastcall executed.
 */
long fastcall(void)
{
	return syscall(FASTCALL_SYSCALL_NR);
}

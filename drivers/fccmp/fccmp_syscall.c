// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_syscall.c - new system calls as a comparison to the fastcall mechanism
 */

#include "fccmp_array.h"
#include "fccmp_nt.h"
#include <linux/compiler_types.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE3(fccmp_array, const char __user *, data, unsigned char, index,
		unsigned char, size)
{
	return fccmp_copy_array(data, index, size);
}

SYSCALL_DEFINE2(fccmp_nt, const char __user *, data, unsigned char, index)
{
	return fccmp_copy_array_nt(data, index);
}

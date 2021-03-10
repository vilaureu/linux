// SPDX-License-Identifier: GPL-2.0
/**
 * Syscall that simply returns the long input argument msg
 */
#include <linux/syscalls.h>

SYSCALL_DEFINE1(echo, long, msg)
{
	return msg + 42;
}

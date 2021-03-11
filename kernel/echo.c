// SPDX-License-Identifier: GPL-2.0
/**
 * Syscall that simply returns the long input argument msg
 */
#include <linux/syscalls.h>
#include <vdso/echo.h>

long _vdso_echo_off __attribute__((section(".vvar__vdso_echo_off"), aligned(sizeof(long)))) __visible;

SYSCALL_DEFINE1(echo, long, msg)
{
	return msg + _vdso_echo_off;
}

SYSCALL_DEFINE1(echo_offset, long, off)
{
	_vdso_echo_off = off;
	return 0;
}

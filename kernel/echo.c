// SPDX-License-Identifier: GPL-2.0
/**
 * Syscall that simply returns the long input argument msg
 */
#include <asm-generic/rwonce.h>
#include <linux/syscalls.h>
#include <vdso/echo.h>

long _vdso_echo_off __attribute__((section(".vvar__vdso_echo_off"))) __visible;

SYSCALL_DEFINE1(echo, long, msg)
{
	return msg + READ_ONCE(_vdso_echo_off);
}

SYSCALL_DEFINE1(echo_offset, long, off)
{
	WRITE_ONCE(_vdso_echo_off, off);
	return 0;
}

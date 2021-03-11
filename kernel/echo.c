// SPDX-License-Identifier: GPL-2.0
/**
 * Syscalls to implement offset dependend echo functionality
 */
#include <asm-generic/rwonce.h>
#include <linux/syscalls.h>
#include <vdso/echo.h>

long _vdso_echo_off __attribute__((section(".vvar__vdso_echo_off"))) __visible;

/*
 * The echo systemcalls returns the input msg plus the echo offset
 */
SYSCALL_DEFINE1(echo, long, msg)
{
	return msg + READ_ONCE(_vdso_echo_off);
}

/*
 * Set the echo offset systemwide.
 * This systemcall does not check for any permissions.
 */
SYSCALL_DEFINE1(echo_offset, long, off)
{
	WRITE_ONCE(_vdso_echo_off, off);
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Fast user context implementation of the echo syscall
 */
#include <asm-generic/rwonce.h>

extern long vvar__vdso_echo_off;

notrace long __vdso_echo(long msg)
{
	return msg + READ_ONCE(vvar__vdso_echo_off);
}

long echo(long msg) __attribute__((weak, alias("__vdso_echo")));

// SPDX-License-Identifier: GPL-2.0
/*
 * Fast user context implementation of the echo syscall
 */

extern long vvar__vdso_echo_off;

notrace long __vdso_echo(long msg)
{
	return msg + vvar__vdso_echo_off;
}

long echo(long msg) __attribute__((weak, alias("__vdso_echo")));

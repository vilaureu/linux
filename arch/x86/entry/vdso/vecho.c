// SPDX-License-Identifier: GPL-2.0
/*
 * Fast user context implementation of the echo syscall
 */

notrace long __vdso_echo(long msg)
{
	return msg;
}

long echo(long msg)
	__attribute__((weak, alias("__vdso_echo")));

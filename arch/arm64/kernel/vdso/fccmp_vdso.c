// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_vdso.c - new vDSO functions as a comparison to the fastcall mechanism
 */

#include <linux/fccmp.h>

/*
 * __vdso_fccmp_noop - simply returns 0
 */
long __vdso_fccmp_noop(void)
{
	return 0;
}

/*
 * __vdso_fccmp_copy_array - copy character sequence
 *
 * Copies `size` characters from `from` to `to` at index `index`.
 *
 * `to` is thereby interpreted as an array of 64 byte strings.
 */
long __vdso_fccmp_copy_array(char *to, const char *from, unsigned char index,
			     unsigned long size)
{
	unsigned long tmp;

	to += index * FCCMP_DATA_SIZE;

	asm volatile(""
		     "  ands    xzr, %[size], #7;"
		     "  cset    %[tmp], ne;"
		     "  adds    %[tmp], %[tmp], %[size], lsr #3;"
		     "  b.eq    1f;"
		     "0:"
		     "  ldtr    %[size], [%[from]];"
		     "  str     %[size], [%[to]];"
		     "  add     %[from], %[from], #8;"
		     "  add     %[to], %[to], #8;"
		     "  subs    %[tmp], %[tmp], 1;"
		     "  b.ne    0b;"
		     "1:"
		     : [to] "+r"(to), [from] "+r"(from), [size] "+r"(size),
		       [tmp] "=&r"(tmp)
		     :
		     : "cc", "memory");

	return 0;
}

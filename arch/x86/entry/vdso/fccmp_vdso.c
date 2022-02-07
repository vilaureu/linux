// SPDX-License-Identifier: GPL-2.0

#include <linux/fccmp.h>

/*
 * fccmp_vdso.c - new vDSO functions as a comparison to the fastcall mechanism
 */

/*
 * __vdso_fccmp_noop - simply returns 0
 */
notrace long __vdso_fccmp_noop(void)
{
	return 0;
}

#ifdef CONFIG_X86_64

/*
 * __vdso_fccmp_copy_array - copy character sequence
 *
 * Copies `size` characters from `from` to `to` at index `index`.
 *
 * `to` is thereby interpreted as an array of 64 byte strings.
 */
notrace long __vdso_fccmp_copy_array(char *to, const char *from,
				     unsigned char index, unsigned long size)
{
	to += index * FCCMP_DATA_SIZE;

	asm volatile(""
		     "  movq %2, %%rax;"
		     "  shrq $2, %2;"
		     "  andq $7, %%rax;"
		     "  jz 0f;"
		     "  inc %2;"
		     "0:"
		     "  andq %2, %2;"
		     "  jz 2f;"
		     "1:"
		     "  movq (%1), %%rax;"
		     "  movq %%rax, (%0);"
		     "  leaq 8(%1), %1;"
		     "  leaq 8(%0), %0;"
		     "  decq %2;"
		     "  jnz 1b;"
		     "2:"
		     : "+r"(to), "+r"(from), "+r"(size)
		     :
		     : "%rax", "memory");

	return 0;
}

/*
 * __vdso_fccmp_copy_nt - copy FCCMP_DATA_SIZE characters from `from` to `to` at index `index`.
 *
 * `to` is thereby interpreted as an array of 64 byte strings.
 * AVX2 MUST be available and `to` must be 32 byte aligned.
 */
notrace long __vdso_fccmp_copy_nt(char *to, const char *from,
				  unsigned char index)
{
	to += index * FCCMP_DATA_SIZE;

	/*
	 * Read the written data again.
	 * This stalls the CPU for the non-temporal write to complete.
	 */
	asm volatile(""
		     "vmovdqa (%1), %%ymm0;"
		     "vmovdqa 32(%1), %%ymm1;"
		     "vmovntdq %%ymm0, (%0);"
		     "vmovntdq %%ymm1, 32(%0);"
		     "vmovdqa (%0), %%ymm0;"
		     "vmovdqa 32(%0), %%ymm1;"
		     :
		     : "r"(to), "r"(from)
		     : "memory");

	return 0;
}
#endif /* CONFIG_X86 */

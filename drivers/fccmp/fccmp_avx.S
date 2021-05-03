// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_avx.S - copy data using VMOVNTDQ
 */

#include <linux/linkage.h>

/*
 * fccmp_avx_copy - copy 64 bytes from (%rsi) to (%rdi)
 *
 * The pointers must be 32-byte aligned.
 */
SYM_FUNC_START(fccmp_avx_copy)
	vmovdqa (%rsi), %ymm0
	vmovdqa 32(%rsi), %ymm1
	vmovntdq %ymm0, (%rdi)
	vmovntdq %ymm1, 32(%rdi)

	/*
	 * Read the written data again.
	 * This stalls the CPU for the non-temporal write to complete.
	 */
	vmovdqa (%rsi), %ymm0
	vmovdqa 32(%rsi), %ymm1
	ret
SYM_CODE_END(fccmp_avx_copy)

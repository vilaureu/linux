// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_nt.c - provide a function for copying a char sequence with a non-temporal hint
 */

#include "fccmp_nt.h"
#include "fccmp_array.h"
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/cpufeature.h>
#include <asm/fpu/api.h>

asmlinkage void fccmp_avx_copy(void *to, void *from);

static __ro_after_init DEFINE_STATIC_KEY_FALSE(use_avx2);

/*
 * fccmp_copy_array_nt - copy FCCMP_DATA_SIZE chars from data to the array page at the index.
 *
 * Returns -EBUSY if AVX2 is not available.
 */
int fccmp_copy_array_nt(const char __user *data, unsigned char index)
{
	char __aligned(FCCMP_DATA_SIZE) buffer[FCCMP_DATA_SIZE];
	char *to;

	if (!static_branch_likely(&use_avx2))
		return -EBUSY;

	if (index >= FCCMP_ARRAY_LENGTH)
		return -EINVAL;

	// Copying to a buffer is faster than pinning a page
	if (copy_from_user(buffer, data, FCCMP_DATA_SIZE))
		return -EFAULT;
	to = kmap(fccmp_page) + index * FCCMP_DATA_SIZE;

	kernel_fpu_begin();
	fccmp_avx_copy(to, buffer);
	kernel_fpu_end();

	kunmap(fccmp_page);
	return 0;
}

/*
 * init - check whether AVX2 is available
 */
static int __init init(void)
{
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) &&
	    cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		static_branch_enable(&use_avx2);
	else
		pr_info("fccmp: AVX2 not supported");

	return 0;
}

subsys_initcall(init)

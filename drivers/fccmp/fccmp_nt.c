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
 * data must be aligned to FCCMP_DATA_SIZE.
 */
int fccmp_copy_array_nt(const char __user *data, unsigned char index)
{
	long pages;
	char *to, *from;
	struct page *page;

	if (!static_branch_likely(&use_avx2))
		return -EBUSY;

	if (index >= FCCMP_ARRAY_LENGTH ||
	    (unsigned long)data % FCCMP_DATA_SIZE)
		return -EINVAL;

	pages = pin_user_pages((unsigned long)data, 1, FOLL_TOUCH, &page, NULL);
	if (pages < 0) {
		return pages;
	} else if (pages < 1) {
		// no page pinned, so no unpinning needed
		return -EFAULT;
	}

	from = kmap(page);
	to = kmap(fccmp_page);

	kernel_fpu_begin();
	fccmp_avx_copy(to, from);
	kernel_fpu_end();

	kunmap(fccmp_page);
	kunmap(page);
	unpin_user_pages(&page, 1);
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

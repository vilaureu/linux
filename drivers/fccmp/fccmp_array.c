// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_array.c - functions for copying a character sequence from user space to an array in kernel space
 */

#include "fccmp_array.h"
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <asm-generic/errno-base.h>

struct page *fccmp_page;

/*
 * fccmp_copy_array - copy size characters from data to the array page at the index.
 */
int fccmp_copy_array(const char __user *data, unsigned char index,
		     unsigned char size)
{
	int ret = 0;
	char *to;

	if (index >= FCCMP_ARRAY_LENGTH || size > FCCMP_DATA_SIZE)
		return -EINVAL;

	to = kmap(fccmp_page);
	if (copy_from_user(to + index * FCCMP_DATA_SIZE, data, size))
		ret = -EFAULT;
	kunmap(fccmp_page);

	return ret;
}

/*
 * init - allocate a page to copy user data to
 */
static int __init init(void)
{
	fccmp_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	return fccmp_page ? 0 : -ENOMEM;
}

subsys_initcall(init);

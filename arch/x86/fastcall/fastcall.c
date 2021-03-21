// SPDX-License-Identifier: GPL-2.0
/*
 * The fastcall mechanism allows to register system call handlers 
 * that execute in a minimal kernel environment with reduced overhead.
 */

#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>

/* FASTCALL_ADDR - address of the fastcall jump table in user space */
#define FASTCALL_ADDR 0x7fff00000000 // TODO: eliminate magic number

static const struct vm_special_mapping fastcall_mapping = {
	.name = "[fastcall]",
};

/*
 * setup_fastcall_page - insert a page with fastcall function pointers into user space
 */
int setup_fastcall_page(void)
{
	int ret = 0;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;

	pr_info("fastcall: page setup");

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vma = _install_special_mapping(mm, FASTCALL_ADDR, PAGE_SIZE,
				       VM_READ | VM_MAYREAD, &fastcall_mapping);
	if (IS_ERR(vma)) {
    pr_warn("fastcall: can't install mapping");
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	pr_info("fastcall: mapping installed");

up_fail:
	mmap_write_unlock(mm);
	return ret;
}

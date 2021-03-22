// SPDX-License-Identifier: GPL-2.0
/*
 * The fastcall mechanism allows to register system call handlers 
 * that execute in a minimal kernel environment with reduced overhead.
 */

#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <asm/fastcall.h>

static const struct vm_special_mapping fastcall_mapping = {
	.name = "[fastcall]",
};

/* default_jump_table - fastcall jump table mapped on process creation */
static struct page *default_jump_table;

/*
 * setup_fastcall_page - insert a page with fastcall function pointers into user space
 */
int setup_fastcall_page(void)
{
	int ret = 0;
	struct vm_area_struct *vma;
	vm_fault_t fault;
	struct mm_struct *mm = current->mm;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vma = _install_special_mapping(mm, FASTCALL_ADDR, PAGE_SIZE,
				       VM_READ | VM_MAYREAD, &fastcall_mapping);
	if (IS_ERR(vma)) {
		pr_warn("fastcall: can't install mapping");
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	fault = vmf_insert_page(vma, FASTCALL_ADDR, default_jump_table);
	if (fault != VM_FAULT_NOPAGE) {
		pr_warn("fastcall: can't insert page, error %d", fault);

		if (fault == VM_FAULT_OOM)
			ret = -ENOMEM;
		else
			ret = -EFAULT;
		do_munmap(mm, FASTCALL_ADDR, PAGE_SIZE, NULL);
		goto up_fail;
	}

up_fail:
	mmap_write_unlock(mm);
	return ret;
}

/*
 * fastcall_init - initialize the default fastcall jump table
 */
static __init int fastcall_init(void)
{
	default_jump_table = alloc_page(GFP_USER);
	if (default_jump_table == NULL) {
		pr_warn("fastcall: no memory for default jump table");
		return -ENOMEM;
	}
	// set page to all F for now
	memset(page_address(default_jump_table), 'F', PAGE_SIZE);

	return 0;
}

subsys_initcall(fastcall_init);

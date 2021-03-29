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

/* default_jump_table - fastcall jump table mapped on process creation */
static struct page *default_jump_table;

/*
 * fastcall_mremap - prohibit any remapping of the fastcall pages
 */
static int fastcall_mremap(const struct vm_special_mapping *sm,
			   struct vm_area_struct *new_vma)
{
	return -EINVAL;
}

/*
 * fastcall_may_unmap - prohibit unmapping the fastcall pages
 */
static int fastcall_may_unmap(const struct vm_special_mapping *sm,
			      struct vm_area_struct *vma)
{
	return -EACCES;
}

/*
 * fastcall_fault - every fault to this vma is invalid
 *
 * fastcall pages are all mapped on fastcall registration.
 * This is only called on user access to non-mapped stack pages.
 */
static vm_fault_t fastcall_fault(const struct vm_special_mapping *sm,
				 struct vm_area_struct *vma,
				 struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static const struct vm_special_mapping fastcall_mapping = {
	.name = "[fastcall]",
	.mremap = fastcall_mremap,
	.may_unmap = fastcall_may_unmap,
	.fault = fastcall_fault,
};

/*
 * setup_fastcall_page - insert a page with fastcall function pointers into user space
 *
 * Memory layout of the fastcall pages:
 * 
 * 0xffffffffffffffff +--------------------+
 *                    | kernel space       |
 * 0xffff800000000000 +--------------------+
 *      non-canonical | hole               |
 *     0x7fffffffffff +--------------------+
 *           one page | fastcall table     |
 *      FASTCALL_ADDR +--------------------+
 *   one page per CPU | fastcall stacks    |
 *                    +--------------------+
 *                    | rest of user space |
 *                0x0 +--------------------+
 */
int setup_fastcall_page(void)
{
	int ret = 0;
	struct vm_area_struct *vma;
	unsigned nr_pages = 1 + nr_cpu_ids;
	unsigned long vma_start = FASTCALL_ADDR - nr_cpu_ids * PAGE_SIZE;
	struct mm_struct *mm = current->mm;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vma = _install_special_mapping(mm, vma_start, nr_pages * PAGE_SIZE,
				       VM_READ | VM_MAYREAD, &fastcall_mapping);
	if (IS_ERR(vma)) {
		pr_warn("fastcall: can't install mapping");
		ret = PTR_ERR(vma);
		goto up_fail;
	}

	ret = vm_insert_page(vma, FASTCALL_ADDR, default_jump_table);
	if (ret < 0) {
		pr_warn("fastcall: can't insert page, error %d", ret);
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
	default_jump_table = alloc_page(GFP_KERNEL);
	if (default_jump_table == NULL) {
		pr_warn("fastcall: no memory for default jump table");
		return -ENOMEM;
	}
	// set page to all F for now
	memset(page_address(default_jump_table), 'F', PAGE_SIZE);

	return 0;
}

subsys_initcall(fastcall_init);

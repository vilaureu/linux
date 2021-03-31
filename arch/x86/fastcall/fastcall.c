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
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <asm/fastcall.h>
#include <asm/barrier.h>

#define GFP_FASTCALL (GFP_HIGHUSER | __GFP_ZERO | __GFP_ACCOUNT)
#define NR_ENTRIES                                                             \
	((PAGE_SIZE - sizeof(struct mutex)) / sizeof(struct fastcall_entry))

/*
 * fastcall_entry - a single entry of the fastcall table
 *
 * The entry points to a fastcall function and 
 * supports additional attributes.
 */
struct fastcall_entry {
	void *fn_ptr;
	fastcall_attr attribs;
};

struct fastcall_table {
	struct fastcall_entry entries[NR_ENTRIES];
	struct mutex mutex;
};

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

/*
 * fastcall_mapping - mapping for the fastcall table and stack pages
 */
static const struct vm_special_mapping fastcall_mapping = {
	.name = "[fastcall]",
	.mremap = fastcall_mremap,
	.may_unmap = fastcall_may_unmap,
	.fault = fastcall_fault,
};

/*
 * function_mapping - mapping for the fastcall function code provided by the driver
 */
static const struct vm_special_mapping function_mapping = {
	.name = "[fastcall_function]",
	.mremap = fastcall_mremap,
	.may_unmap = fastcall_may_unmap,
	.fault = fastcall_fault,
};

/*
 * unmappable_mapping - a temporary mapping that allows function pages to be unmapped
 */
static const struct vm_special_mapping unmappable_mapping = {
	.name = "[fastcall_unmap]",
	.mremap = fastcall_mremap,
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

	ret = vm_insert_page(vma, FASTCALL_ADDR, ZERO_PAGE(0));
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
 * create_fastcall_pages - creates and inserts a new fastcall table and new stacks
 *
 * TODO change if fastcall table not created here anymore
 */
static struct page *create_fastcall_pages(struct vm_area_struct *vma,
					  struct page *old)
{
	int err;
	unsigned long start = FASTCALL_ADDR - nr_cpu_ids * PAGE_SIZE;
	unsigned long addr;
	struct page *page;
	struct fastcall_table *table;

	// The stack pages are not mapped yet.
	for (addr = start; addr < FASTCALL_ADDR; addr += PAGE_SIZE) {
		page = alloc_page(GFP_FASTCALL);
		if (!page) {
			zap_page_range(vma, start, addr - start);
			return ERR_PTR(-ENOMEM);
		}
		err = vm_insert_page(vma, addr, page);
		__free_page(page);
		if (err < 0) {
			zap_page_range(vma, start, addr - start);
			return ERR_PTR(err);
		}
	}

	page = alloc_page(GFP_FASTCALL);
	if (!page) {
		zap_page_range(vma, start, nr_cpu_ids * PAGE_SIZE);
		return ERR_PTR(-ENOMEM);
	}

	// TODO Here is a race condition currently in which a table access can fault
	zap_page_range(vma, FASTCALL_ADDR, PAGE_SIZE);
	err = vm_insert_page(vma, FASTCALL_ADDR, page);
	if (err < 0) {
		__free_page(page);
		zap_page_range(vma, start, nr_cpu_ids * PAGE_SIZE);
		return ERR_PTR(err);
	}

	table = kmap(page);
	mutex_init(&table->mutex);
	kunmap(page);
	__free_page(page);

	return page;
}

/*
 * find_fastcall_table - Find the page containing the fastcall of the process.
 *
 * The table is created if it was only the zero page previously.
 * Therefor the mmap lock must be held writable.
 */
static struct page *find_fastcall_table(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct page *page = NULL;

	// Search for the fastcall mapping
	// TODO maybe replace with pin get_user_pages
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma_is_special_mapping(vma, &fastcall_mapping))
			continue;

		// Get the page with the fastcall table
		page = follow_page(vma, FASTCALL_ADDR, 0);
		if (WARN_ON(page == NULL))
			return ERR_PTR(-EFAULT);

		if (WARN_ON(IS_ERR(page)))
			return page;

		if (page == ZERO_PAGE(0)) {
			return create_fastcall_pages(vma, page);
		}

		return page;
	}

	WARN(true, "fastcall: no fastcall table found in process");
	return ERR_PTR(-EFAULT);
}

/*
 * unmap_function - unmap fastcall function text pages at this address
 */
static void unmap_function(unsigned long fn_ptr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start == fn_ptr)
			break;
	}

	if (WARN_ON(!vma))
		return;

	// Make do_munmap possible
	vma->vm_private_data = (void *)&unmappable_mapping;
	WARN_ON(do_munmap(mm, fn_ptr, vma->vm_end - vma->vm_start, NULL));
}

/*
 * install_function_mapping - create and populate a mapping for the function text pages
 *
 * Return the pointer to the first address of the area.
 */
static unsigned long install_function_mapping(struct page **pages,
					      unsigned long num)
{
	unsigned long fn_ptr;
	int err;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long len = num * PAGE_SIZE;

	fn_ptr = get_unmapped_area(NULL, FASTCALL_ADDR, len, 0, 0);
	if (IS_ERR_VALUE(fn_ptr))
		return fn_ptr;

	vma = _install_special_mapping(mm, fn_ptr, len, VM_READ | VM_MAYREAD,
				       &function_mapping);
	if (IS_ERR(vma))
		return (unsigned long)vma;

	err = vm_insert_pages(vma, fn_ptr, pages, &num);
	if (err) {
		unmap_function(fn_ptr);

		return err;
	}

	return fn_ptr;
}

/*
 * register_fastcall - registers a new fastcall into the fastcall table
 *
 * @pages   - List of text pages for the fastcall
 * @num     - Number of pages in the attribute pages
 * @attribs - Additional attributes to put into the fastcall table
 *
 * This creates a new fastcall table and stack if needed.
 * Then the fastcall code is mapped to user space.
 * Finally, the function pointer is inserted into the fastcall table.
 */
int register_fastcall(struct page **pages, unsigned long num,
		      fastcall_attr attribs)
{
	int ret = 0;
	size_t i;
	struct mm_struct *mm = current->mm;
	struct page *page;
	struct fastcall_table *table;
	unsigned long fn_ptr;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	page = find_fastcall_table();
	if (IS_ERR(page)) {
		ret = PTR_ERR(page);
		goto fail_find_table;
	}

	fn_ptr = install_function_mapping(pages, num);
	if (IS_ERR_VALUE(fn_ptr)) {
		ret = (long)fn_ptr;
		goto fail_find_table;
	}

	// No need to get the page as it is pinned already

	BUILD_BUG_ON(sizeof(struct fastcall_table) > PAGE_SIZE);
	table = kmap(page);
	if (mutex_lock_killable(&table->mutex)) {
		ret = -EINTR;
		goto fail_table_lock;
	}

	// Search a free table entry and insert the fn_ptr and attribs there
	for (i = 0; i < NR_ENTRIES; i++) {
		size_t j;
		struct fastcall_entry *entry = &table->entries[i];

		if (entry->fn_ptr)
			continue;

		for (j = 0; j < NR_FC_ATTRIBS; j++) {
			entry->attribs[j] = attribs[j];
		}
		// Guarantee that a fastcall system call sees the attribs above when it reads this fn_ptr
		smp_store_release(&entry->fn_ptr, (void *)fn_ptr);
		ret = i;
		break;
	}

	if (i == NR_ENTRIES)
		ret = -EINVAL; // The fastcall table is full

	mutex_unlock(&table->mutex);
fail_table_lock:
	if (ret < 0)
		unmap_function(fn_ptr);
	kunmap(page);
	// Marking accessed or dirty is not needed because the pages are pinned all the time.
fail_find_table:
	mmap_write_unlock(mm);

	return ret;
}
EXPORT_SYMBOL(register_fastcall);

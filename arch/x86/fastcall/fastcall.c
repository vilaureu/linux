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
#include <linux/slab.h>
#include <asm/fastcall.h>
#include <asm/barrier.h>

#define NR_ENTRIES                                                             \
	((PAGE_SIZE - sizeof(struct mutex)) / sizeof(struct fastcall_entry))

const void fastcall_noop(void);

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
 *
 * TODO mutex_destroy for CONFIG_DEBUG_MUTEXES
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
 *           one page | default functions  |
 *                    +--------------------+
 *   one page per CPU | fastcall stacks    |
 *                    +--------------------+
 *                    | rest of user space |
 *                0x0 +--------------------+
 */
int setup_fastcall_page(void)
{
	int ret = 0;
	size_t i;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct page *page;
	struct fastcall_table *table;

	page = alloc_page(GFP_FASTCALL);
	if (!page)
		return -ENOMEM;

	table = kmap(page);
	mutex_init(&table->mutex);
	for (i = 0; i < NR_ENTRIES; i++)
		table->entries[i].fn_ptr = (void *)fastcall_noop;
	kunmap(page);

	if (mmap_write_lock_killable(mm)) {
		ret = -EINTR;
		goto fail_lock;
	}

	vma = _install_special_mapping(mm, FC_STACK_BOTTOM,
				       NR_FC_PAGES * PAGE_SIZE,
				       VM_READ | VM_MAYREAD, &fastcall_mapping);
	if (WARN_ON(IS_ERR(vma))) {
		ret = PTR_ERR(vma);
		goto fail_install;
	}

	ret = vm_insert_page(vma, FASTCALL_ADDR, page);
	if (WARN_ON(ret < 0)) {
		do_munmap(mm, FC_STACK_TOP, NR_FC_EXTRA_PAGES * PAGE_SIZE,
			  NULL);
	}

fail_install:
	mmap_write_unlock(mm);
	if (ret < 0) {
		table = kmap(page);
		// Destroy mutex for mutex debugging (CONFIG_DEBUG_MUTEXES)
		mutex_destroy(&table->mutex);
		kunmap(page);
	}
fail_lock:
	__free_page(page);

	return ret;
}

/*
 * find_fastcall_vma - find the vma containing the fastcall pages
 */
static struct vm_area_struct *find_fastcall_vma(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma_is_special_mapping(vma, &fastcall_mapping))
			continue;

		return vma;
	}

	// No fastcall mapping was found in the process.
	BUG();
}

/*
 * create_fastcall_stacks - create per-CPU fastcall stacks
 *
 * No operation is performed when the stacks are already created.
 */
static int create_fastcall_stacks(void)
{
	int err = 0;
	struct page **pages;
	unsigned long num = nr_cpu_ids;
	struct vm_area_struct *vma = find_fastcall_vma();
	int i;

	if (!IS_ERR_OR_NULL(follow_page(vma, FC_STACK_BOTTOM, 0)))
		return 0;

	pages = kmalloc(nr_cpu_ids * sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		return -ENOMEM;
	}

	for (i = 0; i < nr_cpu_ids; i++) {
		pages[i] = alloc_page(GFP_FASTCALL);
		if (!pages[i]) {
			err = -ENOMEM;
			goto fail_alloc;
		}
	}

	err = vm_insert_pages(vma, FC_STACK_BOTTOM, pages, &num);
	if (err < 0)
		zap_page_range(vma, FC_STACK_BOTTOM,
			       (nr_cpu_ids - num) * PAGE_SIZE);

fail_alloc:
	for (i--; i >= 0; i--)
		__free_page(pages[i]);
	kfree(pages);

	return err;
}

/*
 * zap_stacks - remove the fastcall stacks from the page table
 *
 * TODO remove
 */
// static void zap_stacks(void)
// {
// 	struct vm_area_struct *vma = find_fastcall_vma();
// 	zap_page_range(vma, FC_STACK_BOTTOM, nr_cpu_ids * PAGE_SIZE);
// }

/*
 * unmap_function - unmap fastcall function text pages at this address
 */
static void unmap_function(unsigned long fn_ptr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start <= fn_ptr && fn_ptr < vma->vm_end)
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

	fn_ptr = get_unmapped_area(NULL, 0, len, 0, 0);
	if (IS_ERR_VALUE(fn_ptr))
		return fn_ptr;

	// Pages need to be executable also in kernel mode
	vma = _install_special_mapping(
		mm, fn_ptr, len, VM_READ | VM_MAYREAD | VM_EXEC | VM_MAYEXEC,
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
 * @off     - Offset of the entry point into the pages
 * @attribs - Additional attributes to put into the fastcall table
 *
 * This creates a new fastcall table and stack if needed.
 * Then the fastcall code is mapped to user space.
 * Finally, the function pointer is inserted into the fastcall table.
 */
int register_fastcall(struct page **pages, unsigned long num, unsigned long off,
		      fastcall_attr attribs)
{
	int ret = 0;
	size_t i;
	struct mm_struct *mm = current->mm;
	struct page *page;
	struct fastcall_table *table;
	unsigned long fn_ptr;

	BUG_ON(num * PAGE_SIZE <= off);

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = pin_user_pages(FASTCALL_ADDR, 1, FOLL_TOUCH, &page, NULL);
	if (ret < 0)
		goto fail_pin_table;

	ret = create_fastcall_stacks();
	if (ret < 0)
		goto fail_create_stacks;

	fn_ptr = install_function_mapping(pages, num);
	if (IS_ERR_VALUE(fn_ptr)) {
		ret = (long)fn_ptr;
		goto fail_install_function;
	}
	fn_ptr += off;

	BUILD_BUG_ON(sizeof(struct fastcall_table) > PAGE_SIZE);
	BUILD_BUG_ON(FC_NR_ENTRIES != NR_ENTRIES);
	BUILD_BUG_ON(sizeof(struct fastcall_entry) != FC_ENTRY_SIZE);
	table = kmap(page);
	if (mutex_lock_killable(&table->mutex)) {
		ret = -EINTR;
		goto fail_table_lock;
	}

	// Search a free table entry and insert the fn_ptr and attribs there
	for (i = 0; i < NR_ENTRIES; i++) {
		size_t j;
		struct fastcall_entry *entry = &table->entries[i];

		if (entry->fn_ptr != fastcall_noop)
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
	// Marking accessed or dirty is not needed because the pages can not be evicted.
fail_install_function:
	unpin_user_page(page);
fail_create_stacks:
	// There is no need to remove the created stacks
fail_pin_table:
	mmap_write_unlock(mm);

	return ret;
}
EXPORT_SYMBOL(register_fastcall);

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
/*
 * SPECIAL_MAPPING - create a special fastcall mapping, 
 *                   which can not be unmapped
 */
#define SPECIAL_MAPPING(NAME)                                                  \
	static const struct vm_special_mapping NAME##_mapping = {              \
		.name = "[fastcall_" #NAME "]",                                \
		.mremap = fastcall_mremap,                                     \
		.may_unmap = fastcall_no_unmap,                                \
		.fault = fastcall_fault,                                       \
	};

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
 * fastcall_no_unmap - prohibit unmapping the fastcall pages
 */
static int fastcall_no_unmap(const struct vm_special_mapping *sm,
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
 * table_mapping - mapping for the fastcall table
 *
 * TODO mutex_destroy for CONFIG_DEBUG_MUTEXES
 */
SPECIAL_MAPPING(table)

/*
 * table_mapping - mapping for the fastcall stacks
 */
SPECIAL_MAPPING(stacks)

/*
 * additional_mapping - mapping for shared or private memory regions
 */
SPECIAL_MAPPING(additional)

/*
 * unmappable_mapping - a temporary mapping that allows function pages to be unmapped
 */
static const struct vm_special_mapping unmappable_mapping = {
	.name = "[fastcall_unmap]",
	.mremap = fastcall_mremap,
	.fault = fastcall_fault,
};

/*
 * vma_set_kernel - remove _PAGE_USER from vma->vm_page_prot
 */
void vma_set_kernel(struct vm_area_struct *vma)
{
	pgprotval_t pgval = pgprot_val(vma->vm_page_prot) & ~(_PAGE_USER);
	WRITE_ONCE(vma->vm_page_prot, __pgprot(pgval));
}

/*
 * find_vma_containing - find a vma containing the address
 *
 * Return NULL if the vma is not found.
 */
static struct vm_area_struct *find_vma_containing(struct mm_struct *mm,
						  unsigned long addr)
{
	struct vm_area_struct *vma = find_vma(mm, addr);

	if (vma && vma->vm_start <= addr)
		return vma;
	else
		return NULL;
}

/*
 * remove_mapping - remove a fastcall function or any additional mapping at this address
 */
static void remove_mapping(unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct vm_special_mapping *sm;

	vma = find_vma_containing(mm, addr);

	if (WARN_ON(!vma))
		return;

	sm = vma->vm_private_data;
	if (sm->may_unmap == fastcall_no_unmap)
		// Make do_munmap possible
		vma->vm_private_data = (void *)&unmappable_mapping;

	WARN_ON(do_munmap(mm, addr, vma->vm_end - vma->vm_start, NULL));
}

/*
 * insert_table - Insert the mapping for the fastcall table.
 */
static int insert_table(struct mm_struct *mm)
{
	int ret = 0;
	size_t i;
	struct vm_area_struct *vma;
	struct page *page;
	struct fastcall_table *table;

	page = alloc_page(GFP_FASTCALL);
	if (!page)
		return -ENOMEM;

	table = kmap(page);
	mutex_init(&table->mutex);
	for (i = 0; i < NR_ENTRIES; i++)
		table->entries[i].fn_ptr = (void *)fastcall_noop;

	vma = _install_special_mapping(mm, FASTCALL_ADDR, PAGE_SIZE,
				       FASTCALL_VM_RO, &table_mapping);
	ret = PTR_ERR(vma);
	if (IS_ERR(vma))
		goto fail_create;

	vma_set_kernel(vma);

	ret = vm_insert_page(vma, FASTCALL_ADDR, page);
	if (WARN_ON(ret < 0))
		goto fail_insert;

	ret = 0;

fail_insert:
fail_create:
	if (ret < 0)
		// Destroy mutex for mutex debugging (CONFIG_DEBUG_MUTEXES)
		mutex_destroy(&table->mutex);
	kunmap(page);
	__free_page(page);

	return ret;
}

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
 *    FC_STACK_BOTTOM +--------------------+
 *                    | rest of user space |
 *                0x0 +--------------------+
 */
int setup_fastcall_page(void)
{
	int ret;
	struct mm_struct *mm = current->mm;

	if (mmap_write_lock_killable(mm))
		return -EINTR;
	ret = insert_table(mm);
	mmap_write_unlock(mm);
	return ret;
}

/*
 * fastcall_dup_table - create a new, empty fastcall table in the child process of a fork
 */
int fastcall_dup_table(struct mm_struct *oldmm, struct mm_struct *mm)
{
	// Do not create table for kernel threads or swapper
	if (!mm || !oldmm || current->pid == 0)
		return 0;

	return insert_table(mm);
}

/*
 * create_stacks - create per-CPU fastcall stacks
 *
 * No operation is performed when the stacks are already created.
 * Note that stacks are shared between forks to save memory.
 */
static int create_stacks(void)
{
	int err;
	struct page **pages;
	unsigned long num = nr_cpu_ids;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma =
		find_vma_containing(current->mm, FC_STACK_BOTTOM);
	int i;

	if (vma)
		return 0;

	vma = _install_special_mapping(mm, FC_STACK_BOTTOM,
				       nr_cpu_ids * PAGE_SIZE,
				       FASTCALL_VM_RW & ~VM_DONTCOPY,
				       &stacks_mapping);
	err = PTR_ERR(vma);
	if (WARN_ON(IS_ERR(vma)))
		goto fail_install;

	vma_set_kernel(vma);

	pages = kmalloc(nr_cpu_ids * sizeof(struct page *), GFP_KERNEL);
	err = -ENOMEM;
	if (!pages)
		goto fail_malloc;

	for (i = 0; i < nr_cpu_ids; i++) {
		pages[i] = alloc_page(GFP_FASTCALL);
		if (!pages[i]) {
			err = -ENOMEM;
			goto fail_alloc;
		}
	}

	err = vm_insert_pages(vma, FC_STACK_BOTTOM, pages, &num);
	if (err < 0)
		goto fail_insert;

	err = 0;

fail_insert:
	// The pages are removed with remove_mapping anyway; no need to zap
fail_alloc:
	for (i--; i >= 0; i--)
		__free_page(pages[i]);
	kfree(pages);
fail_malloc:
	if (err < 0)
		remove_mapping(FC_STACK_BOTTOM);
fail_install:
	return err;
}

/*
 * create_mapping - create and populate a mapping
 *
 * Return a pointer to the first address of the area.
 */
static unsigned long create_mapping(struct page **pages, unsigned long num,
				    unsigned long flags, bool user,
				    const struct vm_special_mapping *spec)
{
	unsigned long addr;
	int err;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long len = num * PAGE_SIZE;

	addr = get_unmapped_area(NULL, 0, len, 0, 0);
	if (IS_ERR_VALUE(addr))
		return addr;

	vma = _install_special_mapping(mm, addr, len, flags, spec);
	if (IS_ERR(vma))
		return (unsigned long)vma;

	if (!user)
		vma_set_kernel(vma);

	err = vm_insert_pages(vma, addr, pages, &num);
	if (err) {
		remove_mapping(addr);
		return err;
	}

	return addr;
}

/*
 * fastcall_function_close - free private vma ressources
 *
 * This is called on process exit and munmap.
 */
static void fastcall_function_close(const struct vm_special_mapping *sm,
				    struct vm_area_struct *vma)
{
	struct fastcall_fn_unmap *fn_unmap = sm->priv;
	if (fn_unmap)
		fn_unmap->ops->free(fn_unmap);
	kfree(sm);
}

/*
 * fastcall_function_unmap - remove the function from the fastcall table and free associated mappings
 */
static int fastcall_function_unmap(const struct vm_special_mapping *sm,
				   struct vm_area_struct *vma)
{
	struct fastcall_fn_unmap *fn_unmap = sm->priv;

	/* Prevent fastcall_function_unmap from beeing called twice when munmap fails later on
	   and the process retries munmap. */
	vma->vm_private_data = (void *)&unmappable_mapping;
	if (fn_unmap)
		fn_unmap->ops->unmap(fn_unmap);
	fastcall_function_close(sm, vma);
	return 0;
}

/*
 * install_function_mapping - create and populate a mapping for the function text pages
 *
 * Return a pointer to the first address of the area.
 */
static unsigned long install_function_mapping(struct page **pages,
					      unsigned long num, struct fastcall_fn_unmap *fn_unmap)
{
	unsigned long addr;
	struct vm_special_mapping *sm;

	sm = kmalloc(sizeof(struct vm_special_mapping), GFP_KERNEL);
	addr = -ENOMEM;
	if (!sm)
		goto fail_alloc;

	sm->name = "[fastcall_function]";
	sm->mremap = fastcall_mremap;
	sm->may_unmap = fastcall_function_unmap;
	sm->close = fastcall_function_close;
	sm->fault = fastcall_fault;
	sm->priv = fn_unmap;

	// Pages need to be executable also in kernel mode
	addr = create_mapping(pages, num, FASTCALL_VM_RX, false, sm);
	if (IS_ERR_VALUE(addr))
		goto fail_create;

fail_create:
	if (IS_ERR_VALUE(addr))
		kfree(sm);
fail_alloc:
	return addr;
}

/*
 * register_fastcall - registers a new fastcall into the fastcall table
 *
 * This creates a new fastcall table and stack if needed.
 * Then the fastcall code is mapped to user space.
 * Finally, the function pointer is inserted into the fastcall table.
 */
int register_fastcall(struct fastcall_reg_args *args)
{
	int ret = 0;
	size_t i;
	struct mm_struct *mm = current->mm;
	struct page *page;
	struct fastcall_table *table;
	unsigned long fn_ptr;

	BUG_ON(args->num * PAGE_SIZE <= args->off);

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = pin_user_pages(FASTCALL_ADDR, 1, FOLL_TOUCH, &page, NULL);
	if (ret < 0)
		goto fail_pin_table;

	ret = create_stacks();
	if (ret < 0)
		goto fail_create_stacks;

	fn_ptr = install_function_mapping(args->pages, args->num, args->fn_unmap);
	if (IS_ERR_VALUE(fn_ptr)) {
		ret = (long)fn_ptr;
		goto fail_install_function;
	}
	args->fn_addr = fn_ptr;
	fn_ptr += args->off;

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
			entry->attribs[j] = args->attribs[j];
		}
		// Guarantee that a fastcall system call sees the attribs above when it reads this fn_ptr
		smp_store_release(&entry->fn_ptr, (void *)fn_ptr);
		ret = 0;
		break;
	}

	if (i >= NR_ENTRIES)
		ret = -EINVAL; // The fastcall table is full

	args->index = i;

	mutex_unlock(&table->mutex);
fail_table_lock:
	if (ret < 0)
		remove_mapping(fn_ptr);
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

/*
 * create_additional_mapping - create and populate an additional mapping
 *
 * @pages - Array of pages, which will fill the mapping
 * @num   - Number of pages in the array
 * @flags - vm_area_struct flags, see FASTCALL_VM_*
 * @user  - Should the pages be marked as user-accessible
 *
 * Return a pointer to the first address of the area.
 * The mapping can be used for shared or private data.
 * Remove the mapping with remove_additional_mapping.
 */
unsigned long create_additional_mapping(struct page **pages, unsigned long num,
					unsigned long flags, bool user)
{
	struct mm_struct *mm = current->mm;
	unsigned long ptr;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	ptr = create_mapping(pages, num, flags, user, &additional_mapping);
	mmap_write_unlock(mm);
	return ptr;
}
EXPORT_SYMBOL(create_additional_mapping);

/*
 * remove_additional_mapping - remove any additional mapping at this address
 */
void remove_additional_mapping(unsigned long ptr)
{
	struct mm_struct *mm = current->mm;

	if (mmap_write_lock_killable(current->mm))
		return;
	remove_mapping(ptr);
	mmap_write_unlock(mm);
}
EXPORT_SYMBOL(remove_additional_mapping);

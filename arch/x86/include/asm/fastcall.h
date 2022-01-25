// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H

#define NR_fastcall 442
#define NR_FC_ATTRIBS 3

#ifdef __KERNEL__

#include <asm/page_types.h>

#ifdef CONFIG_FASTCALL

#if !defined(__ASSEMBLER__) || !defined(CONFIG_X86_5LEVEL)
/* 
 * FASTCALL_ADDR - address of the fastcall jump table in user space
 *
 * The per-CPU fastcall stacks go below this page.
 */
#define FASTCALL_ADDR ((_AC(1, UL) << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)

#define FC_STACK_TOP FASTCALL_ADDR
/*
 * FC_STACK_BOTTOM - virtual address of the first fastcall stack
 */
#define FC_STACK_BOTTOM (FC_STACK_TOP - nr_cpu_ids * PAGE_SIZE)
/*
 * FASTCALL_BOTTOM - first address of the fastcall region
 */
#define FASTCALL_BOTTOM TASK_SIZE_MAX
#endif

#ifdef CONFIG_DEBUG_MUTEXES
// Mutices are slightly larger with debug info
#define FC_NR_ENTRIES 126
#else
#define FC_NR_ENTRIES 127
#endif
#define FC_ENTRY_SIZE ((1 + NR_FC_ATTRIBS) * 8)

#endif /* CONFIG_FASTCALL */

#ifndef __ASSEMBLER__

#include <linux/mm_types.h>

#ifdef CONFIG_FASTCALL

#define GFP_FASTCALL (GFP_HIGHUSER | __GFP_ZERO | __GFP_ACCOUNT)
#define FASTCALL_VM_RO (VM_DONTCOPY | VM_READ | VM_MAYREAD)
#define FASTCALL_VM_RW                                                         \
	(FASTCALL_VM_RO | VM_WRITE | VM_MAYWRITE | VM_SHARED | VM_MAYSHARE)
#define FASTCALL_VM_RX (FASTCALL_VM_RO | VM_EXEC | VM_MAYEXEC)

typedef long fastcall_attr[NR_FC_ATTRIBS];

/*
 * fastcall_fn_ops - callbacks for fastcall_fn_unmap
 *
 * All functions are called at most once per function mapping.
 *
 * @unmap - Called only on explicit deregistration of the function
 * @free  - Called anytime the function mapping is closed (also after unmap)
 */
struct fastcall_fn_ops {
	void (*unmap)(void *priv);
	void (*free)(void *priv);
};

/*
 * fastcall_reg_args - arguments passed in and out for register_fastcall
 *
 * @pages   - Array of text pages for the fastcall
 * @num     - Number of pages in the attribute pages
 * @off     - Offset of the entry point into the pages
 * @attribs - Additional attributes to put into the fastcall table
 * @ops     - Functions called on unmapping or closing of the function mapping
 * @priv    - Private data for the functions in ops
 * @fn_ptr  - Output for the address to the function mapping
 * @module  - The registrar of this fastcall function
 * @index   - Output for the index of the new table entry
 */
struct fastcall_reg_args {
	struct page **pages;
	unsigned long num;
	unsigned long off;
	fastcall_attr attribs;
	const struct fastcall_fn_ops *ops;
	void *priv;
	unsigned long fn_addr;
	struct module *module;
	unsigned index;
};

extern int setup_fastcall_page(void);
extern int register_fastcall(struct fastcall_reg_args *);
extern unsigned long create_additional_mapping(struct page **, unsigned long,
					       unsigned long, bool);
extern void remove_additional_mapping(unsigned long);
extern void fastcall_remove_mapping(unsigned long);

static inline bool in_fastcall_region(unsigned long start, size_t len)
{
	return start >= FASTCALL_BOTTOM && start < FASTCALL_ADDR &&
	       len <= FASTCALL_ADDR - start;
}

#else

static inline int setup_fastcall_page(void)
{
	return 0;
}

#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* __KERNEL__ */
#endif /* _ASM_X86_FASTCALL_H */

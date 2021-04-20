// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H

#include <asm/page_types.h>

#define NR_fastcall 442

#ifdef CONFIG_FASTCALL

/* 
 * FASTCALL_ADDR - address of the fastcall jump table in user space
 *
 * The per-CPU fastcall stacks go below this page.
 */
#define FASTCALL_ADDR (0x7fffffffffff & PAGE_MASK)

#define FC_STACK_TOP FASTCALL_ADDR

/*
 * FC_STACK_BOTTOM - virtual address of the first fastcall stack
 */
#define FC_STACK_BOTTOM (FC_STACK_TOP - nr_cpu_ids * PAGE_SIZE)

#define NR_FC_ATTRIBS 3
#define FC_NR_ENTRIES 127
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

struct fastcall_fn_unmap;
/*
 * fastcall_fn_ops - callbacks for fastcall_fn_unmap
 *
 * All functions are called at most once per function mapping.
 *
 * @unmap - Called only on explicit deregistration of the function
 * @free  - Called anytime the function mapping is closed (also after unmap)
 */
struct fastcall_fn_ops {
	void (*unmap) (const struct fastcall_fn_unmap*);
	void (*free) (const struct fastcall_fn_unmap*);
};

/*
 * fastcall_fn_unmap - struct inserted into vm_special_mapping
 *
 * Allows the registrar of a fastcall function to handle unmapping of additional mappings.
 *
 * @ops  - fastcall_fn_ops. Must not be NULL
 * @priv - Private data of the registrar
 */
struct fastcall_fn_unmap {
	const struct fastcall_fn_ops *ops;
	void *priv;
};

/*
 * fastcall_reg_args - arguments passed in and out for register_fastcall
 *
 * @pages    - Array of text pages for the fastcall
 * @num      - Number of pages in the attribute pages
 * @off      - Offset of the entry point into the pages
 * @attribs  - Additional attributes to put into the fastcall table
 * @fn_unmap - fastcall_fn_unmap. Can be NULL
 * @fn_ptr   - Output for the address to the function mapping
 * @index    - Output for the index of the new table entry
 */
struct fastcall_reg_args {
	struct page **pages;
	unsigned long num;
	unsigned long off;
	fastcall_attr attribs;
	struct fastcall_fn_unmap *fn_unmap;
	unsigned long fn_addr;
	unsigned index;
};

extern int setup_fastcall_page(void);
extern int register_fastcall(struct fastcall_reg_args *);
extern unsigned long create_additional_mapping(struct page **, unsigned long,
					       unsigned long, bool);
extern void remove_additional_mapping(unsigned long);
#else
int setup_fastcall_page(void)
{
	return 0;
}
#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */

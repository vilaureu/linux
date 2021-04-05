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

typedef long fastcall_attr[NR_FC_ATTRIBS];

extern int setup_fastcall_page(void);
extern int register_fastcall(struct page **, unsigned long, unsigned long,
			     fastcall_attr);
#else
int setup_fastcall_page(void)
{
	return 0;
}

#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */

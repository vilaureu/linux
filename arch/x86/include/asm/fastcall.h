// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H

#include <asm/page_types.h>

#define NR_fastcall 442

/* 
 * FASTCALL_ADDR - address of the fastcall jump table in user space
 *
 * The per-CPU fastcall stacks go below this page.
 */
#define FASTCALL_ADDR (0x7fffffffffff & PAGE_MASK)

#ifndef __ASSEMBLER__

#include <linux/mm_types.h>

#ifdef CONFIG_FASTCALL
typedef long fastcall_attr[3];

extern int setup_fastcall_page(void);
extern int register_fastcall(struct page **, unsigned long, fastcall_attr);
#else
int setup_fastcall_page(void)
{
	return 0;
}
#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */

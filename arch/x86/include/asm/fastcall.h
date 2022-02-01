// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H

#define NR_fastcall 442

#ifdef __KERNEL__

#include <asm-generic/fastcall.h>
#include <asm/page_types.h>
#include <asm/pgtable_types.h>

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
 * FASTCALL_MAP_TOP - top of area for regular fastcall mappings
 */
#define FASTCALL_MAP_TOP FC_STACK_BOTTOM

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

#endif /* CONFIG_FASTCALL */

#ifndef __ASSEMBLER__

#ifdef CONFIG_FASTCALL

#define FASTCALL_RND_BITS (__VIRTUAL_MASK_SHIFT - 2)

/*
 * fastcall_kernel_prot - change user page protection to equivalent kernel one
 */
static inline pgprot_t fastcall_kernel_prot(pgprot_t pgprot)
{
	return __pgprot(pgprot_val(pgprot) & ~_PAGE_USER);
}

#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* __KERNEL__ */
#endif /* _ASM_X86_FASTCALL_H */

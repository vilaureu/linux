// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_FASTCALL_H
#define _ASM_FASTCALL_H

#include <asm-generic/fastcall.h>
#include <asm/processor.h>

/*
 * FASTCALL_SVC_IMM - immediate of the svc instruction when calling fastcalls
 */
#define FASTCALL_SVC_IMM 0xFC

/*
 * FASTCALL_ADDR - address of the fastcall jump table in user space
 */
#define FASTCALL_ADDR ((UL(1) << vabits_actual) - PAGE_SIZE)

/*
 * FASTCALL_MAP_TOP - top of area for regular fastcall mappings
 */
#define FASTCALL_MAP_TOP FASTCALL_ADDR

/*
 * FASTCALL_BOTTOM - first address of the fastcall region
 */
#define FASTCALL_BOTTOM TASK_SIZE_64
#define FC_NR_ENTRIES 127

#ifndef __ASSEMBLER__

#include <asm/pgtable-types.h>
#include <asm/pgtable-prot.h>

#define FASTCALL_RND_BITS (vabits_actual - 2)

/*
 * fastcall_kernel_prot - change user page protection to equivalent kernel one
 */
static inline pgprot_t fastcall_kernel_prot(pgprot_t pgprot)
{
	pteval_t pteval = pgprot_val(pgprot);

	pteval &= ~PTE_USER;
	if (!(pteval & PTE_UXN))
		pteval &= ~PTE_PXN;

	pteval |= PTE_UXN;

	return __pgprot(pteval);
}

/*
 * fastcall_write_prot - if PTE_WRITE is set, unset PTE_RDONLY
 */
static inline pgprot_t fastcall_write_prot(pgprot_t pgprot)
{
	pteval_t pteval = pgprot_val(pgprot);

	if (pteval & PTE_WRITE)
		pteval &= ~PTE_RDONLY;

	return __pgprot(pteval);
}

#endif /* !__ASSEMBLER__ */
#endif /* _ASM_FASTCALL_H */

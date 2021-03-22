// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H

#define NR_fastcall 442

/* FASTCALL_ADDR - address of the fastcall jump table in user space */
#define FASTCALL_ADDR 0x7fff00000000 // TODO: eliminate magic number

#ifndef __ASSEMBLER__

#ifdef CONFIG_FASTCALL
extern int setup_fastcall_page(void);
#else
int setup_fastcall_page(void)
{
	return 0;
}
#endif /* CONFIG_FASTCALL */

#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */

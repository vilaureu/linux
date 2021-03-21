// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H
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

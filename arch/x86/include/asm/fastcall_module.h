// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_module.h - common code used in drivers which use the fastcall architecture
 */

#ifndef _FASTCALL_MODULE_H
#define _FASTCALL_MODULE_H

#ifdef __ASSEMBLER__

#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/fastcall.h>
#include <asm/segment.h>

/*
 * Set the stack pointer to the per-CPU stack.
 *
 * The user stack pointer is saved to reg. scratch_reg is clobbered.
 */
.macro SETUP_STACK reg=%rdi, scratch_reg=%rax
	/*
	 * This is save because the user can neither change MSR_TSC_AUX nor the segment limit.
	 *
	 * Additionally, RDPID is save as this is never called coming from KVM.
	 */
	ALTERNATIVE "", "jmp 0f", X86_FEATURE_RDPID
	movq $__CPUNODE_SEG, \reg
	lsl \reg, \reg
	jmp 1f
0:
	rdpid \reg
1:
	andq $VDSO_CPUNODE_MASK, \reg
	imulq $(-PAGE_SIZE), \reg

#ifdef CONFIG_X86_5LEVEL
	ALTERNATIVE "", "jmp 3f", X86_FEATURE_LA57
	movq $((1 << 47) - 4096), \scratch_reg
	jmp 4f
3:
	movq $((1 << 56) - 4096), \scratch_reg
4:
#else
	movq $FC_STACK_TOP, \scratch_reg
#endif

	addq \scratch_reg, \reg
	xchgq %rsp, \reg
.endm

#endif /* __ASSEMBLER__ */

#endif /* _FASTCALL_MODULE_H */

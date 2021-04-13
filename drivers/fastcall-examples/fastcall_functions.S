// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_functions.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm/unwind_hints.h>
#include <asm/segment.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/fastcall.h>

#define SARG0 (1 * 8)
#define ARG1 %rsi

/*
 * Set the stack pointer to the per-CPU stack.
 *
 * The user stack pointer is saved to reg. scratch_reg is clobbered.
 */
.macro SETUP_STACK reg=%rdi, scratch_reg=%rax
	/*
	 * This is save because the user can neither change MSR_TSC_AUX nor the segment limit.
	 *
	 * Additionally, RDPID is save as this is never called comming from KVM.
	 */
	ALTERNATIVE "", "jmp rdpid", X86_FEATURE_RDPID
	movq $__CPUNODE_SEG, \reg
	lsl \reg, \reg
	jmp cpu_number
rdpid:
	rdpid \reg
cpu_number:
	andq $VDSO_CPUNODE_MASK, \reg
	imulq $(-PAGE_SIZE), \reg
	movq $FC_STACK_TOP, \scratch_reg
	addq \scratch_reg, \reg
	xchgq %rsp, \reg
.endm

.text

SYM_INNER_LABEL(fce_functions_start, SYM_L_GLOBAL)

/*
 * fce_noop - sysret with return value 0
 */
SYM_CODE_START(fce_noop)
	UNWIND_HINT_EMPTY
	movq $0, %rax
	sysretq
SYM_CODE_END(fce_noop)

/*
 * fce_stack - sysret with the first argument as return value
 *
 * Tests the stack functionality by writing to and reading from it.
 */
SYM_CODE_START(fce_stack)
	UNWIND_HINT_EMPTY
	SETUP_STACK

	pushq ARG1
	popq %rax

	movq %rdi, %rsp
	sysretq
SYM_CODE_END(fce_stack)

/*
 * fce_stack - sysret with the first argument as return value plus 1
 *
 * Writes to and reads from the address stored in the first entry attribute.
 */
SYM_CODE_START(fce_write_ptr)
	UNWIND_HINT_EMPTY

	movq SARG0(%rax), %rdi
	movq ARG1, (%rdi)
	movq (%rdi), %rax
	addq $1, %rax

	sysretq
SYM_CODE_END(fce_write_ptr)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

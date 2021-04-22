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
#include <asm-generic/errno-base.h>
#include <asm/smap.h>
#include <asm/fastcall.h>

#define SARG0 (1 * 8)
#define SARG1 (2 * 8)
#define ARG1 %rsi
#define ARG2 %rdx
#define DATA_SIZE 64
#define ARRAY_LENGTH (PAGE_SIZE / DATA_SIZE)

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
	xorq %rax, %rax
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
 * fce_write_ptr - sysret with the first argument as return value plus 1
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

/*
 * fce_array - copy data from the shared memroy region
 *
 * The first argument is the index into the array;
 * The second argument is the size of the data in bytes.
 * The data can be up to ARRAY_SIZE charactes long.
 * The data is copied in 8 byte granularity.
 */
SYM_CODE_START(fce_array)
	UNWIND_HINT_EMPTY

	cmpq $ARRAY_LENGTH, ARG1
	jae oob
	cmpq $DATA_SIZE, ARG2
	ja oob

	movq SARG1(%rax), %rdi
	imulq $DATA_SIZE, ARG1
	addq %rdi, ARG1
	movq SARG0(%rax), %rdi

	ASM_STAC
	// Copy %rdx bytes from (%rdi) to (%rsi)
	movq %rdx, %rax
	shrq $3, %rdx
	andq $7, %rax
	jz 0f
	inc %rdx
0:
	andq %rdx, %rdx
	jz end
copy:
	movq (%rdi), %rax
	movq %rax, (%rsi)
	leaq 8(%rdi), %rdi
	leaq 8(%rsi), %rsi
	decq %rdx
	jnz copy
end:
	ASM_CLAC
	xorq %rax, %rax
	sysretq

oob:
	movq $(-EINVAL), %rax
	sysretq
SYM_CODE_END(fce_array)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

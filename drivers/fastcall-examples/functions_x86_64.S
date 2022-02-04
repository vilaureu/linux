// SPDX-License-Identifier: GPL-2.0
/*
 * functions_x86_64.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm/unwind_hints.h>
#include <asm-generic/errno-base.h>
#include <asm/smap.h>
#include <asm/fastcall_module.h>
#include "fastcall_examples.h"

#define SARG0 (1 * 8)
#define SARG1 (2 * 8)
#define ARG1 %rsi
#define ARG2 %rdx

/*
 * Setup code for the source and destination addresses of the array functions.
 */
.macro STATIC_ARRAY_ARGS
	movq SARG1(%rax), %rdi
	imulq $FC_DATA_SIZE, ARG1
	addq %rdi, ARG1
	movq SARG0(%rax), %rdi
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
	FASTCALL_SETUP_STACK

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
 * The data can be up to FC_DATA_SIZE charactes long.
 * The data is copied in 8 byte granularity.
 */
SYM_CODE_START(fce_array)
	UNWIND_HINT_EMPTY

	cmpq $FC_ARRAY_LENGTH, ARG1
	jae inval
	cmpq $FC_DATA_SIZE, ARG2
	ja inval

	STATIC_ARRAY_ARGS

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
SYM_CODE_END(fce_array)

/*
 * fce_array_nt - like fce_array but with non-temporal hint
 *
 * The first argument is the index into the array;
 * FC_DATA_SIZE charactes of data are copied to the array.
 */
SYM_CODE_START(fce_array_nt)
	UNWIND_HINT_EMPTY

	cmpq $FC_ARRAY_LENGTH, ARG1
	jae inval

	STATIC_ARRAY_ARGS

	ASM_STAC

	// Copy FC_DATA_SIZE=64 bytes from (%rdi) to (%rsi)
	vmovdqa (%rdi), %ymm0
	vmovdqa 32(%rdi), %ymm1
	vmovntdq %ymm0, (%rsi)
	vmovntdq %ymm1, 32(%rsi)

	/*
	 * Read the written data again.
	 * This stalls the CPU for the non-temporal write to complete.
	 */
	vmovdqa (%rsi), %ymm0
	vmovdqa 32(%rsi), %ymm1

	ASM_CLAC

	xorq %rax, %rax
	sysretq
SYM_CODE_END(fce_array)

SYM_CODE_START_LOCAL(inval)
	movq $(-EINVAL), %rax
	sysretq
SYM_CODE_END(inval)

/*
 * fce_mwait - wait for a change at a memory address
 *
 * The first static argument specifies the address to monitor at.
 * The first function argument specifies the expected value.
 * This function returns 1 if the value in memory matches the supplied value.
 * It thereby might wait using MWAIT for a change at the memory address.
 * MWAIT will also be interrupted by timer events.
 * If the value does not match until then, the function returns 0.
 * This function clobbers some caller-saved registers.
 */
SYM_CODE_START(fce_mwait)
	UNWIND_HINT_EMPTY
	// Save return address
	movq %rcx, %rdi

	movq SARG0(%rax), %rax

	cmpq %rsi, (%rax)
	je mwait_success

	xorl %ecx, %ecx
	xorl %edx, %edx
	monitor

	// Do not wait if target already matches
	cmpq %rsi, (%rax)
	je mwait_success

	incl %ecx
	movq %rax, %rdx
	xorq %rax, %rax
	mwait

	cmpq %rsi, (%rdx)
	sete %al

mwait_out:
	mov %rdi, %rcx
	sysretq

mwait_success:
	movq $1, %rax
	jmp mwait_out
SYM_CODE_END(fce_mwait)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

// SPDX-License-Identifier: GPL-2.0
/*
 * functions_arm64.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm-generic/errno-base.h>
#include "fastcall_examples.h"

#define SARG0 [x8, #(1 * 8)]
#define SARG1 [x8, #(2 * 8)]
#define SARG2 [x8, #(3 * 8)]

/*
 * Setup code for the source and destination addresses of the array functions.
 *
 * out:
 *   x2: address of shared memory
 *   x3: address of array entry
 */
.macro STATIC_ARRAY_ARGS
	ldp	x2, x3, SARG0

	mov	x9, #FC_DATA_SIZE
	madd	x3, x0, x9, x3
.endm

.text

SYM_INNER_LABEL(fce_functions_start, SYM_L_GLOBAL)

/*
 * fce_noop - eret with return value 0
 */
SYM_CODE_START(fce_noop)
	mov	x0, #0
	eret
SYM_CODE_END(fce_noop)

/*
 * fce_stack - eret with the first argument as return value
 *
 * Tests the stack functionality by writing to and reading from it.
 */
SYM_CODE_START(fce_stack)
	sub	sp, sp, 8

	str	x0, [sp]
	ldr	x0, [sp]

	add	sp, sp, 8
	eret
SYM_CODE_END(fce_stack)

/*
 * fce_write_ptr - eret with the first argument as return value plus 1
 *
 * Writes to and reads from the address stored in the first entry attribute.
 */
SYM_CODE_START(fce_write_ptr)
	// Stack pointer need to be 16-byte aligned on arm64
	str	x0, [sp, #-16]!
	ldr	x0, [sp], #16

	eret
SYM_CODE_END(fce_write_ptr)

/*
 * fce_array - copy data from the shared memory region
 *
 * The first argument is the index into the array;
 * The second argument is the size of the data in bytes.
 * The data can be up to FC_DATA_SIZE characters long.
 * The data is copied in 8 byte granularity.
 */
SYM_CODE_START(fce_array)
	cmp	x0, #FC_ARRAY_LENGTH
	b.cs	inval
	cmp	x1, #FC_DATA_SIZE
	b.hi	inval

	STATIC_ARRAY_ARGS

	ands	xzr, x1, #7
	cset	x0, ne
	adds	x0, x0, x1, lsr #3
	b.eq	1f
0:
	ldtr	x1, [x2]
	str	x1, [x3]
	add	x2, x2, #8
	add	x3, x3, #8
	subs	x0, x0, 1
	b.ne	0b
1:
	mov	x0, #0
	eret
SYM_CODE_END(fce_array)

SYM_CODE_START_LOCAL(inval)
	mov	x0, #-EINVAL
	eret
SYM_CODE_END(inval)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

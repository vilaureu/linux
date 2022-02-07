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
	ldr	x9, SARG0

	str	x0, [x9]
	ldr	x0, [x9]
	add	x0, x0, #1
	eret
SYM_CODE_END(fce_write_ptr)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

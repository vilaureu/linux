// SPDX-License-Identifier: GPL-2.0
/*
 * functions_arm64.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm-generic/errno-base.h>
#include "fastcall_examples.h"

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

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

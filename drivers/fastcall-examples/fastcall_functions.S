// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_functions.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

.text

SYM_INNER_LABEL(fce_functions_start, SYM_L_GLOBAL)

/*
 * fce_noop - sysret with return value 0
 */
SYM_CODE_START(fce_noop)
	UNWIND_HINT_EMPTY
	movq $0, %rax

	ANNOTATE_RETPOLINE_SAFE
	jmpq *%rdi
SYM_CODE_END(fce_noop)

SYM_INNER_LABEL(fce_functions_end, SYM_L_GLOBAL)

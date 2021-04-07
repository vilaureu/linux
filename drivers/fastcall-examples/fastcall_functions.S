// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_functions.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm/smap.h>
#include <asm/page_types.h>

.text
// Align the functions to a page boundary
.align PAGE_SIZE

/*
 * fce_noop - sysret with return value 0
 */
SYM_CODE_START(fce_noop)
	movq $0, %rax
	jmpq *%rdi
SYM_CODE_END(fce_noop)

/*
 * Fill the rest of the page with zeros,
 * such that no other kernel text gets exposed to the user space.
 */
. = PAGE_SIZE

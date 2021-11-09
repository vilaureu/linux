// SPDX-License-Identifier: GPL-2.0
/*
 * functions_wrapper.S - contains the fastcall functions which are jumped to
 *
 * These small assembly functions are only wrappers around the actual fastcall
 * functions. They set a stack up, store and restore registers and move
 * arguments into the right places.
 */

#include <asm/fastcall_module.h>

.text

FASTCALL_ASM_WRAPPER name=eventfc

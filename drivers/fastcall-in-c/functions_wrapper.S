// SPDX-License-Identifier: GPL-2.0
/*
 * functions_wrapper.S - contains the fastcall functions which are jumped to
 *
 * These small assembly functions are only wrappers around the actual fastcall
 * functions. They set a stack up, store and restore registers and move arguments
 * into the right places.
 */

#include <linux/linkage.h>
#include <asm/unwind_hints.h>
#include <asm/smap.h>
#include <asm/fastcall_module.h>

.text

/* function - an example fastcall function wrapper
 *
 * Unfortunately, this function needs an additional register.
 * Hence, arg5 (%r9) is not usable as an argument.
 */
SYM_CODE_START(function)
	UNWIND_HINT_EMPTY
  
  // This clobbers r9 (arg5)
  SETUP_STACK reg=%rdx scratch_reg=%r9

  // Save the stack pointer, flags register and return address
  pushq %rdx
  pushq %r11
  pushq %rcx

  // Move the function arguments into the right position
  movq %rax, %rdi
  movq %r10, %rcx

  // Call the actual fastcall function
  call wrapped_function

  // Restore saved registers
  popq %rcx
  popq %r11
  movq (%rsp), %rsp

  sysretq
SYM_CODE_END(function)

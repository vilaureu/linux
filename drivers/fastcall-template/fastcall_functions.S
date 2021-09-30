// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_functions.S - fastcall function examples
 *
 * This file contains the actual fastcall functions in assembly.
 * They must be between fct_functions_start and fct_functions_end.
 * Additionally, they have to be position independent.
 */

#include <linux/linkage.h>
#include <asm/unwind_hints.h>
#include <asm/smap.h>
#include <asm/fastcall_module.h>

.text

SYM_INNER_LABEL(fct_functions_start, SYM_L_GLOBAL)

/*
 * fct_template - demonstrate the possibilites of fastcall functions
 *
 * Registers in:
 * rax  address of the fastcall table entry of this function
 * rsi  arg1
 * rdx  arg2
 * r10  arg3
 * r8   arg4
 * r9   arg5
 * r11  flags register
 * rcx  return address
 *
 * Return out:
 * rax  return address
 * r11  flags register
 * rcx  return address
 *
 * It should be safe to clobber all caller-saved
 * registers according to the calling convention.
 */
SYM_CODE_START(fct_template)
  // This prevents complains during compilation.
	UNWIND_HINT_EMPTY

  // Setup a per-CPU stack and store old %rsp to %rdx.
  SETUP_STACK reg=%rdx scratch_reg=%rdi
  // Push the old stack pointer to the new stack.
  pushq %rdx

  // Push the first argument.
  pushq %rsi

  // Increment it.
  incq (%rsp)

  // ASM_STAC ... ASM_CLAC are required when accessing shared memory.
  ASM_STAC
  // Load the first static argument (the shared memory).
  movq 8(%rax), %rdi
  // Load the value at this location.
  movq (%rdi), %rdi
  // Add it to our stack value.
  addq %rdi, (%rsp)
  ASM_CLAC

  // Load the second static argument (the private memory).
  movq 16(%rax), %rdi
  // Use the private memory region and store the result in %rax.
  popq %rdx
  movq %rdx, (%rdi)
  incq (%rdi)
  movq (%rdi), %rax

  // Restore user %rsp.
  movq (%rsp), %rsp

  /*
   * We always have to return to user mode.
   * The return value is in %rax.
   */
  sysretq
SYM_CODE_END(fct_template)

SYM_INNER_LABEL(fct_functions_end, SYM_L_GLOBAL)

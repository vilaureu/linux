// SPDX-License-Identifier: GPL-2.0
/* functions.c - contains the actual fastcall function contents
 * 
 * These functions are called by the wrappers in functions_wrapper.S
 * and they should not be exported in the library. Therefore,
 * they are given a hidden visibility.
 */

#include <asm/fastcall_module.h>
#include <asm/smap.h>

// Constant global variable with value zero.
static const long static_increment = 0;
// Constant global variable with a non-zero value.
static const long static_decrement = 5;

/* apply_offsets - test function calls in fastcall images */
noinline static long apply_offsets(long value)
{
	// Test the access to constant variables (in the .rodata section).
	value += *(volatile const long *)&static_increment;
	value -= *(volatile const long *)&static_decrement;
	return value;
}

/* wrapped_function - a small fastcall function which accesses a shared page */
FASTCALL_WRAPPED_FN(function)
{
	long *shared = entry[1];
	// Temporarily disable SMAP for accessing the shared user page.
	stac();
	long value = *shared;
	clac();
	value = apply_offsets(value);
	return value + arg1;
}

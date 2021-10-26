// SPDX-License-Identifier: GPL-2.0
/* functions.c - contains the actual fastcall function contents
 * 
 * These functions are called by the wrappers in functions_wrapper.S
 * and they should not be exported in the library. Therefore,
 * they are given a hidden visibility.
 */

#include <asm/fastcall_module.h>
#include <asm/smap.h>

/* wrapped_function - a small fastcall function which accesses a shared page */
FASTCALL_WRAPPED_FN(function)
{
	long *shared = entry[1];
	// Temporarily disable SMAP for accessing the shared user page.
	stac();
	long value = *shared;
	clac();
	return value + arg1;
}

// SPDX-License-Identifier: GPL-2.0
/* functions.c - contains the actual fastcall function contents
 * 
 * These functions are called by the wrappers in functions_wrapper.S
 * and they should not be exported in the library. Therefore,
 * they are given a hidden visibility.
 */

#include <asm/fastcall.h>
#include <asm/smap.h>

/* wrapped_function - a small fastcall function which accesses a shared page */
long __attribute__((visibility("hidden")))
wrapped_function(void *entry[NR_FC_ATTRIBS + 1], long arg1)
{
	long *shared = entry[1];
	// Temporarily disable SMAP for accessing the shared user page.
	stac();
	long value = *shared;
	clac();
	return value + arg1;
}

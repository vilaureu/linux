// SPDX-License-Identifier: GPL-2.0
/* functions.c - contains the actual fastcall function contents
 *
 * These functions implement the behavior of fastcall-event.
 */

#include <asm/fastcall_module.h>

/* wrapped_eventc - implementation of the eventfc like fastcalls
 *
 * This fastcall function multiplexes the read and write operations 
 */
FASTCALL_WRAPPED_FN(eventfc)
{
	return 0;
}

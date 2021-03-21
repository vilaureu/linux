// SPDX-License-Identifier: GPL-2.0
/*
 * The fastcall mechanism allows to register system call handlers 
 * that execute in a minimal kernel environment with reduced overhead.
 */

#include <linux/printk.h>

/*
 * setup_fastcall_page - insert a page with fastcall function pointers into user space
 */
int setup_fastcall_page(void)
{ 
  pr_info("fastcall: setup page");
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/* functions.h - describes the struct generated in fcc_image.c */

#ifndef _FASTCALL_H
#define _FASTCALL_H

#include <asm/fastcall_module.h>

/* 
 * fcc_image - declaration for the struct defined in fcc_image.c
 *
 * This specifies the properties of the shared library containing the functions
 * and the exported symbols of this library.
 */
extern const struct fcc_image {
	struct fastcall_image image;
	unsigned long sym_function;
} fcc_image;

#endif /* _FASTCALL_H */

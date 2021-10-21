// SPDX-License-Identifier: GPL-2.0
/* functions.h - describes the struct generated in fcc_image.c */

#ifndef _FASTCALL_H
#define _FASTCALL_H

extern const struct fcc_image {
	const void *data;
	unsigned long size;
	unsigned long alt;
	unsigned long alt_len;
	unsigned long sym_function;
} fcc_image;

#endif /* _FASTCALL_H */

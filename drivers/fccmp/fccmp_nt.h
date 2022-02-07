// SPDX-License-Identifier: GPL-2.0

#include <asm-generic/errno-base.h>

#ifdef CONFIG_FCCMP_NT
extern int fccmp_copy_array_nt(const char *, unsigned char);
#else
static inline int fccmp_copy_array_nt(const char *data, unsigned char index)
{
	return -EBUSY;
}
#endif

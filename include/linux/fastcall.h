// SPDX-License-Identifier: GPL-2.0
#ifndef _LINUX_FASTCALL_H
#define _LINUX_FASTCALL_H

#include <linux/types.h>

#ifdef CONFIG_FASTCALL

#include <asm/fastcall.h>

#else /* !CONFIG_FASTCALL */

static inline bool in_fastcall_region(unsigned long start, size_t len)
{
	return false;
}

#endif /* !CONFIG_FASTCALL */

#endif /* _LINUX_FASTCALL_H */
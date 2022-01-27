// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_FASTCALL_H
#define _ASM_FASTCALL_H

#define FASTCALL_SVC_IMM 0xFC

#ifndef __ASSEMBLER__

static inline bool in_fastcall_region(unsigned long start, size_t len)
{
  // TODO
	return false;
}

#endif /* !__ASSEMBLER__ */
#endif /* _ASM_FASTCALL_H */

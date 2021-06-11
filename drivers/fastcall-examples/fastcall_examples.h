// SPDX-License-Identifier: GPL-2.0
#ifndef _FASTCALL_EXAMPLES_H
#define _FASTCALL_EXAMPLES_H

#define FCE_DEVICE_NAME "fastcall-examples"

/*
 * ioctl_args - information returned from the fastcall-examples ioctl handlers
 *
 * @addr  - Start of the function mapping
 * @len   - Length of the function mapping
 * @index - Index of the function in the fastcall table
 */
struct ioctl_args {
	unsigned long addr;
	unsigned long len;
	unsigned index;
};

/*
 * array_args - information returned from the array example ioctl handler
 *
 * @fn_addr     - Start of the function mapping
 * @fn_len      - Length of the function mapping
 * @shared_addr - Address of the shared buffer
 * @index       - Index of the function in the fastcall table
 */
struct array_args {
	unsigned long fn_addr;
	unsigned long fn_len;
	unsigned long shared_addr;
	unsigned index;
};

#define FCE_TYPE 0xDE
#define FCE_IOCTL(cmd) (_IOR(FCE_TYPE, cmd, struct ioctl_args))
#define FCE_ARRAY_LIKE(cmd) ((_IOR(FCE_TYPE, cmd, struct array_args)))
#define FCE_IOCTL_NOOP (FCE_IOCTL(0))
#define FCE_IOCTL_STACK (FCE_IOCTL(1))
#define FCE_IOCTL_PRIV (FCE_IOCTL(2))
#define FCE_IOCTL_ARRAY (FCE_ARRAY_LIKE(3))
#define FCE_IOCTL_NT (FCE_ARRAY_LIKE(4))

#endif /* _FASTCALL_EXAMPLES_H */

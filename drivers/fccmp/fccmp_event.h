// SPDX-License-Identifier: GPL-2.0

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

#define FCCMP_EVENT_DEVICE "fccmp-event"
#define FCCMP_IOCTL_TYPE 0xFC
#define FCCMP_EVENT_IOCTL_ZERO _IO(FCCMP_IOCTL_TYPE, 10)
#define FCCMP_EVENT_IOCTL_SEM _IO(FCCMP_IOCTL_TYPE, 11)

// SPDX-License-Identifier: GPL-2.0
/*
 * application.c - example for calling fastcall function from an application
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define SYS_FASTCALL (442)

// The ioctl definitions are the same as in the kernel code.
#define IOCTL_TYPE (0xDC)
#define IOCTL_TEMPLATE (_IOR(IOCTL_TYPE, 0, struct ioctl_args))
#define DEVICE_PATH ("/dev/fastcall-template")

#define MAGIC (42)

struct ioctl_args {
  unsigned long fn_addr;
  unsigned long fn_len;
  unsigned long shared_addr;
  unsigned index;
};

int main(void) {
  struct ioctl_args args;
  int fd;

  // Open the device to control it via ioctl.
  fd = open(DEVICE_PATH, O_RDONLY);
  if (fd < 0) {
    perror("open failed");
    return 1;
  }

  // Register a new fastcall function.
  if (ioctl(fd, IOCTL_TEMPLATE, &args) < 0) {
    perror("ioctl failed");
    return 1;
  }

  // Use the shared memory area.
  *((unsigned long *)args.shared_addr) = MAGIC;

  // Perform the actual fastcall.
  if (syscall(SYS_FASTCALL, args.index, MAGIC) != 2 * MAGIC + 2) {
    fprintf(stderr, "syscall failed\n");
    return 1;
  }

  // For deregistration unmap the fastcall function memory area.
  if (munmap((void *)args.fn_addr, args.fn_len)) {
    perror("munmap failed");
    return 1;
  }

  // We can also close the file descriptor.
  if (close(fd)) {
    perror("close failed");
    return 1;
  }

  return 0;
}

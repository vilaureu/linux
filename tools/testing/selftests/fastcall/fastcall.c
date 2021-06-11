// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall.c - some simple tests for checking the functionality of fastcall(-examples)
 */

#include "../kselftest_harness.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fastcall_examples.h>

#define MAGIC 42
/*
 * MIN_TABLE_ENTRIES - must be lower than the number of entries in the fastcall table
 */
#define MIN_TABLE_ENTRIES 100
/*
 * MAX_TABLE_ENTRIES - must be larger than the number of entries in the fastcall table
 */
#define MAX_TABLE_ENTRIES 200
#define DEVICE_PATH ("/dev/" FCE_DEVICE_NAME)

/*
 * empty_fastcall_entry - test the default no-operation function in the fastcall table
 */
TEST(empty_fastcall_entry)
{
	int ret = syscall(NR_fastcall, 0);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EINVAL, errno);
}

/*
 * examples_stack - test the fastcall-examples function "stack"
 */
TEST(examples_stack)
{
	struct ioctl_args args;
	int fd, ret;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, FCE_IOCTL_STACK, &args);
	ASSERT_LE(0, ret);

	ret = syscall(NR_fastcall, args.index, MAGIC);
	ASSERT_EQ(MAGIC, ret);

	ret = munmap((void *)args.addr, args.len);
	ASSERT_LE(0, ret);

	ret = close(fd);
	ASSERT_LE(0, ret);
}

/*
 * examples_priv - test the fastcall-examples function "priv"
 */
TEST(examples_priv)
{
	struct ioctl_args args;
	int fd, ret;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, FCE_IOCTL_PRIV, &args);
	ASSERT_LE(0, ret);

	ret = syscall(NR_fastcall, args.index, MAGIC);
	ASSERT_EQ(MAGIC + 1, ret);

	ret = munmap((void *)args.addr, args.len);
	ASSERT_LE(0, ret);

	ret = close(fd);
	ASSERT_LE(0, ret);
}

/*
 * mapping_stable - test that the fastcall function mappings are stable
 *
 * This checks that these mappings can not be passed to munmap, mremap, or mprotect.
 */
TEST(mapping_stable)
{
	struct array_args args;
	int fd, ret;
	void *addr;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, FCE_IOCTL_ARRAY, &args);
	ASSERT_LE(0, ret);

	ret = munmap((void *)args.shared_addr, getpagesize());
	ASSERT_GT(0, ret);

	addr = mremap((void *)args.fn_addr, args.fn_len, args.fn_len,
		      MREMAP_FIXED | MREMAP_MAYMOVE,
		      (void *)args.fn_addr + MAGIC * getpagesize());
	ASSERT_EQ(MAP_FAILED, addr);

	addr = mremap((void *)args.fn_addr, args.fn_len, 2 * args.fn_len, 0);
	ASSERT_EQ(MAP_FAILED, addr);

	ret = mprotect((void *)args.fn_addr, args.fn_len, PROT_NONE);
	ASSERT_GT(0, ret);

	ret = munmap((void *)args.fn_addr, args.fn_len);
	ASSERT_LE(0, ret);

	ret = close(fd);
	ASSERT_LE(0, ret);
}

/*
 * fill_table - test that nothing weird happens when completely filling the fastcall table
 */
TEST(fill_table)
{
	struct ioctl_args args_array[MAX_TABLE_ENTRIES];
	int fd, ret, i;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	for (i = 0; i < MAX_TABLE_ENTRIES; i++) {
		ASSERT_GT(MAX_TABLE_ENTRIES, i + 1);

		ret = ioctl(fd, FCE_IOCTL_NOOP, &args_array[i]);
		if (i < MIN_TABLE_ENTRIES) {
			ASSERT_LE(0, ret);
		} else if (ret < 0) {
			ASSERT_EQ(ENOSPC, errno);
			break;
		}
	}

	for (i--; i >= 0; i--) {
		struct ioctl_args *args = &args_array[i];
		ret = munmap((void *)args->addr, args->len);
		ASSERT_LE(0, ret);
	}

	ret = close(fd);
	ASSERT_LE(0, ret);
}

/*
 * copy_to_user - test that copy_to_user can not write to fastcall mappings
 *
 * This uses the clock_gettime function because it, in turn, uses copy_to_user.
 */
TEST(copy_to_user)
{
	struct ioctl_args args;
	int fd, ret;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, FCE_IOCTL_NOOP, &args);
	ASSERT_LE(0, ret);

	/* prevent calling the vDSO implementation */
	ret = syscall(SYS_clock_gettime, CLOCK_MONOTONIC,
		      (struct timespec *)args.addr);
	ASSERT_GT(0, ret);
	ASSERT_EQ(EFAULT, errno);

	ret = munmap((void *)args.addr, args.len);
	ASSERT_LE(0, ret);

	ret = close(fd);
	ASSERT_LE(0, ret);
}

/*
 * mapping_not_readable - test that fastcall mappings are not readable
 *
 * The pages of these mappings are flaged as super-user-only 
 * and should not be accessible form user mode.
 */
TEST(mapping_not_readable)
{
	struct ioctl_args args;
	int fd, ret, wstatus;
	pid_t pid;

	pid = fork();
	ASSERT_LE(0, pid);

	if (pid == 0) {
		fd = open(DEVICE_PATH, O_RDONLY);
		ASSERT_LE(0, fd);
		ret = ioctl(fd, FCE_IOCTL_NOOP, &args);
		ASSERT_LE(0, ret);

		*((volatile int *)&ret) = *(int *)args.addr;
		exit(0);
	} else {
		pid = waitpid(pid, &wstatus, 0);
		ASSERT_LE(0, pid);
		ASSERT_EQ(1, WIFSIGNALED(wstatus));
	}
}

/*
 * fork_reset - test that fork resets the fastcall table
 */
TEST(fork_reset)
{
	struct ioctl_args args;
	int fd, ret, wstatus;
	pid_t pid;

	fd = open(DEVICE_PATH, O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, FCE_IOCTL_NOOP, &args);
	ASSERT_LE(0, ret);

	pid = fork();
	ASSERT_LE(0, pid);

	ret = syscall(NR_fastcall, args.index);

	if (pid == 0) {
		exit(ret);
	} else {
		ASSERT_EQ(0, ret);

		pid = waitpid(pid, &wstatus, 0);
		ASSERT_LE(0, pid);
		ASSERT_EQ(1, WIFEXITED(wstatus));
		ASSERT_NE(0, WEXITSTATUS(wstatus));
	}

	ret = munmap((void *)args.addr, args.len);
	ASSERT_LE(0, ret);

	ret = close(fd);
	ASSERT_LE(0, ret);
}

TEST_HARNESS_MAIN

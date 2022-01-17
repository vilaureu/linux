// SPDX-License-Identifier: GPL-2.0
/*
 * event.c - tests for checking the functionality of fccmp-event
 */

#include "../kselftest_harness.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fccmp_event.h>

#define DEVICE_PATH ("/dev/" FCCMP_EVENT_DEVICE)
#define MAGIC 42

/*
 * zero_block - test the driver in non-semaphore and blocking mode
 */
TEST(zero_block)
{
	int fd;
	uint64_t buf;

	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_LE(0, fd);

	ASSERT_GT(0, read(fd, &buf, sizeof(buf)));
	ASSERT_EQ(EAGAIN, errno);

	buf = MAGIC;
	ASSERT_EQ(sizeof(buf), write(fd, &buf, sizeof(buf)));

	buf = 0;
	ASSERT_EQ(sizeof(buf), read(fd, &buf, sizeof(buf)));
	ASSERT_EQ(MAGIC, buf);

	ASSERT_GT(0, read(fd, &buf, sizeof(buf)));
	ASSERT_EQ(EAGAIN, errno);

	ASSERT_LE(0, close(fd));
}

TEST_HARNESS_MAIN

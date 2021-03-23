// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include "../kselftest_harness.h"

#define NR_FASTCALL 442
#define FASTCALL_ADDR ((char *)0x7fff00000000)
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)

/*
 * Read the first byte of the fastcall table.
 */
void _read_table(void)
{
	printf("First byte of the fastcall table: 0x%x\n", *FASTCALL_ADDR);
}

/*
 * Read the fastcall table.
 * This must never result in a page fault 
 * as the kernel relies on this page to be present.
 */
TEST(read_table)
{
	_read_table();
}

/*
 * The fastcall table must not be unmapped.
 * munmap should result in an error.
 */
TEST(munmap_table)
{
	int ret = munmap(FASTCALL_ADDR, PAGE_SIZE);
	ASSERT_NE(0, ret);
	_read_table();
}

/*
 * The fastcall table must not be remapped.
 * mremap should result in an error.
 */
TEST(mremap_table)
{
	void *ptr = mremap(FASTCALL_ADDR, PAGE_SIZE, PAGE_SIZE,
			 MREMAP_MAYMOVE | MREMAP_FIXED,
			 FASTCALL_ADDR + PAGE_SIZE);
	ASSERT_EQ(MAP_FAILED, ptr);

	_read_table();
}

TEST_HARNESS_MAIN

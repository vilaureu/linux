// SPDX-License-Identifier: GPL-2.0
/*
 * vdso_test_echo.c: Sample code to test parse_vdso.c and vDSO echo()
 */

#include <stdint.h>
#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/time.h>

#include "../kselftest.h"
#include "parse_vdso.h"

#define MSG ((long) 0x1337)
#define OFF 42

const char *version = "LINUX_2.6";
const char *name = "__vdso_echo";

typedef long (*echo_t)(long);

int main(int argc, char **argv)
{
	unsigned long sysinfo_ehdr;
	unsigned int cpu, node;
	echo_t echo;
	long ret;
	long expected;

	sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
	if (!sysinfo_ehdr) {
		printf("AT_SYSINFO_EHDR is not present!\n");
		return KSFT_SKIP;
	}

	vdso_init_from_sysinfo_ehdr(getauxval(AT_SYSINFO_EHDR));

	echo = (echo_t)vdso_sym(version, name);
	if (!echo) {
		printf("Could not find %s\n", name);
		return KSFT_SKIP;
	}

	ret = syscall(443, 0);
  if (0 != ret) {
		printf("echo_offset failed with code %ld\n", ret);
		return KSFT_FAIL;
	}
	ret = echo(MSG);
	if (MSG != ret) {
		printf("Expected %ld found %ld\n", MSG, ret);
		return KSFT_FAIL;
  }

	ret = syscall(443, OFF);
  if (0 != ret) {
		printf("echo_offset failed with code %ld\n", ret);
		return KSFT_FAIL;
	}
	expected = MSG + OFF;
	ret = echo(MSG);
	if (expected != ret) {
		printf("Expected %ld found %ld\n", expected, ret);
		return KSFT_FAIL;
  }

	return 0;
}

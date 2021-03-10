#include <unistd.h>
#include "../kselftest_harness.h"

#define MSG 0x1337
#define EXPECTED (0x1337 + 42)

TEST(echo_syscall_test)
{
	ASSERT_EQ(EXPECTED, syscall(442, MSG));
}

TEST_HARNESS_MAIN

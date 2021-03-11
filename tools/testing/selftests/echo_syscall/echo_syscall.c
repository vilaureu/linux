#include <unistd.h>
#include "../kselftest_harness.h"

#define MSG 0x1337
#define OFF 42

TEST(echo_syscall_test)
{
	ASSERT_EQ(0, syscall(443, 0));
	ASSERT_EQ(MSG, syscall(442, MSG));
	ASSERT_EQ(0, syscall(443, OFF));
	ASSERT_EQ(MSG + OFF, syscall(442, MSG));
}

TEST_HARNESS_MAIN

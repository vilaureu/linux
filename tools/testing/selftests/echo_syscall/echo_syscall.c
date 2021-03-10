#include <unistd.h>
#include "../kselftest_harness.h"

#define MSG 0x1337

TEST(echo_syscall_test)
{
	ASSERT_EQ(MSG, syscall(442, MSG));
}

TEST_HARNESS_MAIN

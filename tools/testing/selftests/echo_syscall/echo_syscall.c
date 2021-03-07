#include <unistd.h>
#include "../kselftest_harness.h"

#define MSG 0x1337

TEST(echo_syscall_test)
{
	ASSERT_EQ(syscall(442, MSG), MSG);
}

TEST_HARNESS_MAIN

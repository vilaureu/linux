// SPDX-License-Identifier: GPL-2.0
/*
 * functions.c - contains the actual fastcall function contents
 *
 * These functions implement the behavior of fastcall-event.
 */

#include <asm/fastcall_module.h>
#include <asm/mwait.h>

/* 
 * COUNTER_MAX - maximum value of the counter
 *
 * Because system calls use negative return values to indicate errors and
 * read() might return the counter, it cannot be negative.
 */
#define COUNTER_MAX ((unsigned long)LONG_MAX)

/*
 * mwait - wait until monitored address receives a store or interrupt
 */
static __always_inline void mwait(void)
{
	/*
	 * __mwait() does invoke mds_idle_clear_cpu_buffers(), which
	 * does not work here. However, we know that we do not have
	 * to mitigate MDS as checked by the ioctl handler.
	 *
	 * "mwait %eax, %ecx;"
	 */
	asm volatile(".byte 0x0f, 0x01, 0xc9;" ::"a"(0), "c"(1));
}

/*
 * try_read - read the counter without underflow
 *
 * @value - previously read value
 *
 * Returns 0 if the read failed because the counter had become 0.
 */
static unsigned long try_read(unsigned long *counter, unsigned long value,
			      bool semaphore)
{
	if (semaphore) {
		unsigned long prev_value;
		/*
		 * Use CMPXCHG instead of atomic decrement to prevent
		 * underflow. Loop until CMPXCHG succeeds or the counter
		 * reaches 0.
		 */
		do {
			prev_value = value;
			value = arch_cmpxchg(counter, value, value - 1);
		} while (value && value != prev_value);
	} else
		// No worries about underflows here.
		value = arch_xchg(counter, 0);

	return value;
}

/*
 * try_read_checked - read the counter and then invoke try_read()
 */
static unsigned long try_read_checked(unsigned long *counter, bool semaphore)
{
	/*
	 * Allways read the counter to not signal stores with failing XCHGs.
	 * This would wake up other waiting threads.
	 */
	unsigned long value = READ_ONCE(*counter);
	if (!value)
		return value;

	return try_read(counter, value, semaphore);
}

/*
 * read - "read" the counter with the same semantics as in eventfd
 */
static unsigned long read(unsigned long *counter, bool block, bool semaphore)
{
	unsigned long value;

	value = try_read_checked(counter, semaphore);
	if (value)
		return semaphore ? 1 : value;

	if (!block)
		return -EAGAIN;

	/*
	 * Arm the monitor hardware. Loop until we know that we did not miss a
	 * wakeup.
	 */
	for (;;) {
		__monitor(counter, 0, 0);

		value = READ_ONCE(*counter);
		if (!value)
			break;

		value = try_read(counter, value, semaphore);
		if (value)
			return semaphore ? 1 : value;
	}

	mwait();

	// Counter changed from 0 to something; try to read it now.
	value = try_read_checked(counter, semaphore);
	if (value)
		return semaphore ? 1 : value;

	return -EAGAIN;
}

/*
 * try_write - write the counter without exceeding COUNTER_MAX
 *
 * @value - previously read value
 *
 * Returns false if the counter became to large to store the increment.
 */
static bool try_write(unsigned long *counter, unsigned long increment,
		      unsigned long value)
{
	unsigned long prev_value;

	/*
	 * Use CMPXCHG instead of atomic decrement to prevent exceeding
	 * COUNTER_MAX. Loop until CMPXCHG succeeds or the counter would
	 * exceed the maximum.
	 */
	do {
		prev_value = value;
		value = arch_cmpxchg(counter, value, value + increment);
		if (value == prev_value)
			return true;
	} while (value <= COUNTER_MAX - increment);

	return false;
}

/*
 * try_write_checked - read the counter and then invoke try_write()
 */
static bool try_write_checked(unsigned long *counter, unsigned long increment)
{
	unsigned long value = READ_ONCE(*counter);
	if (value > COUNTER_MAX - increment)
		return false;

	return try_write(counter, increment, value);
}

/*
 * write - "write" the counter with the same semantics as in eventfd
 */
static int write(unsigned long *counter, bool block, unsigned long increment)
{
	if (increment == 0)
		return 0;
	else if (increment > COUNTER_MAX)
		return -EINVAL;

	if (try_write_checked(counter, increment))
		return 0;

	if (!block)
		return -EAGAIN;

	/*
	 * Arm the monitor hardware. Loop until we know that we did not miss a
	 * wakeup.
	 */
	for (;;) {
		unsigned long value;
		__monitor(counter, 0, 0);

		value = READ_ONCE(*counter);
		if (value > COUNTER_MAX - increment)
			break;

		if (try_write(counter, increment, value))
			return 0;
	}

	mwait();

	// Counter changed; try to write it now.
	if (try_write_checked(counter, increment))
		return 0;

	return -EAGAIN;
}

/*
 * wrapped_eventc - implementation of the eventfc like fastcalls
 *
 * This fastcall function multiplexes the read and write operations.
 */
FASTCALL_WRAPPED_FN(eventfc)
{
	unsigned long *counter = entry[1];
	bool block = entry[2];
	bool semaphore = entry[3];
	if (arg1 == 0) {
		return read(counter, block, semaphore);
	} else if (arg1 == 1) {
		return write(counter, block, arg2);
	} else {
		return -ENOSYS;
	}
}

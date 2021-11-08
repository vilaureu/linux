// SPDX-License-Identifier: GPL-2.0
/* functions.c - contains the actual fastcall function contents
 *
 * These functions implement the behavior of fastcall-event.
 */

#include <asm/fastcall_module.h>
#include <asm/mwait.h>

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
		value = arch_xchg(counter, 0);

	return value;
}

noinline static unsigned long try_read_checked(unsigned long *counter,
					       bool semaphore)
{
	/*
	 * Allways read the counter to not signal stores with failing XCHGs.
	 * This would wake up other waiting threads.
	 */
	unsigned long value = *counter; //READ_ONCE(*counter);
	if (!value)
		return value;

	return try_read(counter, value, semaphore);
}

noinline static unsigned long read(unsigned long *counter, bool block,
				   bool semaphore)
{
	unsigned long value;

	value = try_read_checked(counter, semaphore);
	if (value)
		return value;

	if (block) {
		/*
		 * Arm the monitor hardware. Loop until we know that we did not
		 * miss a wakeup.
		 */
		for (;;) {
			__monitor(counter, 0, 0);

			value = READ_ONCE(*counter);
			if (!value)
				break;

			value = try_read(counter, value, semaphore);
			if (value)
				return value;
		}

		/*
		 * __mwait() does invoke mds_idle_clear_cpu_buffers(), which
		 * does not work here. However, we know that we do not have
		 * to mitigate MDS as checked by the ioctl handler.
		 *
		 * "mwait %eax, %ecx;"
		 */
		asm volatile(".byte 0x0f, 0x01, 0xc9;" ::"a"(0), "c"(1));

		// Counter changed from 0 to something; try to read it now.
		value = try_read_checked(counter, semaphore);
		if (value)
			return value;
	}

	return -EAGAIN;
}

static unsigned long write(unsigned long *counter, bool block)
{
	return -EAGAIN;
}

/* wrapped_eventc - implementation of the eventfc like fastcalls
 *
 * This fastcall function multiplexes the read and write operations 
 */
FASTCALL_WRAPPED_FN(eventfc)
{
	unsigned long *counter = entry[1];
	bool block = entry[2];
	bool semaphore = entry[3];
	if (arg1 == 0) {
		return read(counter, block, semaphore);
	} else if (arg1 == 1) {
		return write(counter, block);
	} else {
		return -ENOSYS;
	}
}

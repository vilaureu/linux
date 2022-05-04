/*
 * syscall_bench.c - measure the latency of steps in the system call execution
 */

#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm/processor.h>
#include <asm/msr.h>

/*
 * syscall_bench - measure performance counter, write to user space, and return
 */
SYSCALL_DEFINE2(syscall_bench, uint32_t, idx, uint64_t __user *, measurements)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long long counter;

	cpuid(0, &eax, &ebx, &ecx, &edx);
	counter = native_read_pmc(idx);
	cpuid(0, &eax, &ebx, &ecx, &edx);

	if (copy_to_user(&measurements[4], &counter, sizeof(counter)))
		return -EFAULT;
	return 0;
}

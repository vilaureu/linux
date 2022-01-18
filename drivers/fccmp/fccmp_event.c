// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_event.c - eventfd-like interface based on mwait
 */

#include "fccmp_event.h"

#include <linux/irqflags.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/compiler_types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/mwait.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/fcntl.h>
#include <asm-generic/rwonce.h>

MODULE_DESCRIPTION("eventfd-like interface based on mwait.");
MODULE_LICENSE("GPL");

#define COUNTER_MAX (~1UL)
#define mwait()                                                                \
	do {                                                                   \
		__mwait(0, 1);                                                 \
	} while (0);

/*
 * ctx - hold the context of an event file descriptor
 */
struct ctx {
	uint64_t counter;
	bool semaphore;
};

static dev_t dev;
static struct cdev *cdev;
static struct class *class;
static struct device *device;

/*
 * open - allocate and initialize internal state
 */
static int open(struct inode *inode, struct file *file)
{
	struct ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	file->private_data = ctx;
	return 0;
}

/*
 * release - free the allocated state
 */
static int release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

/*
 * ioctl - react to ioctl invocations
 *
 * These change the semaphore semantics of the eventfd-like counter.
 */
static long ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	struct ctx *ctx = file->private_data;

	if (!(file->f_mode & FMODE_WRITE))
		return -EPERM;

	switch (cmd) {
	case FCCMP_EVENT_IOCTL_ZERO:
		WRITE_ONCE(ctx->semaphore, false);
		break;
	case FCCMP_EVENT_IOCTL_SEM:
		WRITE_ONCE(ctx->semaphore, true);
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

/*
 * try_read - read the counter without underflow
 *
 * @value - previously read value
 *
 * Returns 0 if the read failed because the counter had become 0.
 */
static uint64_t try_read(uint64_t *counter, uint64_t value, bool semaphore)
{
	if (semaphore) {
		uint64_t prev_value;
		/*
                 * Use CMPXCHG instead of atomic decrement to prevent
                 * underflow. Loop until CMPXCHG succeeds or the counter
                 * reaches 0.
                 */
		do {
			prev_value = value;
			value = cmpxchg(counter, value, value - 1);
		} while (value && value != prev_value);
	} else
		// No worries about underflows here.
		value = xchg(counter, 0);

	return value;
}

/*
 * try_read_checked - read the counter and then invoke try_read()
 */
static uint64_t try_read_checked(uint64_t *counter, bool semaphore)
{
	/*
         * Allways read the counter to not signal stores with failing XCHGs.
         * This would wake up other waiting threads.
         */
	uint64_t value = READ_ONCE(*counter);
	if (!value)
		return value;

	return try_read(counter, value, semaphore);
}

/*
 * read - "read" the counter with the same semantics as in eventfd
 */
static ssize_t read(struct file *file, char __user *buf, size_t count,
		    loff_t *off)
{
	struct ctx *ctx = file->private_data;
	uint64_t *counter = &ctx->counter;
	bool semaphore = READ_ONCE(ctx->semaphore);
	bool block = !(file->f_flags & O_NONBLOCK);
	uint64_t value;

	value = try_read_checked(counter, semaphore);
	if (value)
		goto copy;
	else if (!block)
		return -EAGAIN;

	local_irq_disable();

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
		if (value) {
			local_irq_enable();
			goto copy;
		}
	}

	mwait();
	local_irq_enable();

	// Counter changed from 0 to something; try to read it now.
	value = try_read_checked(counter, semaphore);
	if (value)
		goto copy;

	return -EAGAIN;

copy:
	if (semaphore)
		value = 1;

	if (copy_to_user(buf, &value, sizeof(value)))
		return -EFAULT;

	return sizeof(*counter);
}

/*
 * try_write - write the counter without exceeding COUNTER_MAX
 *
 * @value - previously read value
 *
 * Returns false if the counter became to large to store the increment.
 */
static bool try_write(uint64_t *counter, uint64_t increment, uint64_t value)
{
	uint64_t prev_value;

	/*
	 * Use CMPXCHG instead of atomic decrement to prevent exceeding
	 * COUNTER_MAX. Loop until CMPXCHG succeeds or the counter would
	 * exceed the maximum.
	 */
	do {
		prev_value = value;
		value = cmpxchg(counter, value, value + increment);
		if (value == prev_value)
			return true;
	} while (value <= COUNTER_MAX - increment);

	return false;
}

/*
 * try_write_checked - read the counter and then invoke try_write()
 */
static bool try_write_checked(uint64_t *counter, uint64_t increment)
{
	uint64_t value = READ_ONCE(*counter);
	if (value > COUNTER_MAX - increment)
		return false;

	return try_write(counter, increment, value);
}

/*
 * write - "write" the counter with the same semantics as in eventfd
 */
static ssize_t write(struct file *file, const char __user *buf, size_t count,
		     loff_t *off)
{
	struct ctx *ctx = file->private_data;
	uint64_t *counter = &ctx->counter;
	bool block = !(file->f_flags & O_NONBLOCK);
	uint64_t increment = 0;

	if (count < sizeof(*counter) || *off)
		return -EINVAL;

	if (copy_from_user(&increment, buf, sizeof(increment)))
		return -EFAULT;

	if (increment == 0)
		return sizeof(*counter);
	else if (increment > COUNTER_MAX)
		return -EINVAL;

	if (try_write_checked(counter, increment))
		return sizeof(*counter);
	else if (!block)
		return -EAGAIN;

	local_irq_disable();

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

		if (try_write(counter, increment, value)) {
			local_irq_enable();
			return sizeof(*counter);
		}
	}

	mwait();
	local_irq_enable();

	// Counter changed; try to write it now.
	if (try_write_checked(counter, increment))
		return sizeof(*counter);

	return -EAGAIN;
}

/*
 * fccmp_init - initialize this module
 *
 * Add a "fccmp-event" character device.
 */
static int __init fccmp_init(void)
{
	int result;
	static struct file_operations fops = {
		.owner = THIS_MODULE,
		.open = open,
		.release = release,
		.unlocked_ioctl = ioctl,
		.write = write,
		.read = read,
	};

	// Check for MONITOR/MWAIT in the same way as kvm_can_mwait_in_guest().
	if (!boot_cpu_has(X86_FEATURE_MWAIT) ||
	    boot_cpu_has_bug(X86_BUG_MONITOR) ||
	    !boot_cpu_has(X86_FEATURE_ARAT)) {
		pr_warn("fccmp_event: mwait not supported\n");
		return -ENODEV;
	}

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, FCCMP_EVENT_DEVICE);
	if (result < 0) {
		pr_warn("fccmp_event: can't allocate chrdev region\n");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("fccmp_event: can't allocate struct cdev\n");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("fccmp_event: can't add character device\n");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, FCCMP_EVENT_DEVICE);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fccmp_event: can't create class\n");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, FCCMP_EVENT_DEVICE);
	if (IS_ERR_VALUE(device)) {
		pr_warn("fccmp_event: can't create device\n");
		result = PTR_ERR(device);
		goto fail_device_create;
	}

	return 0;

	// Error handing
fail_device_create:
	class_destroy(class);
fail_class_create:
fail_cdev_add:
	cdev_del(cdev);
fail_cdev_alloc:
	unregister_chrdev_region(dev, 1);
fail_chrdev:
	return result;
}

static void __exit fccmp_exit(void)
{
	device_destroy(class, dev);
	class_destroy(class);
	cdev_del(cdev);
	unregister_chrdev_region(dev, 1);
}

module_init(fccmp_init);
module_exit(fccmp_exit);

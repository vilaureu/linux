// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_event.c - eventfd-like interface based on mwait
 */

#include "fccmp_event.h"

#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/compiler_types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>

MODULE_DESCRIPTION("eventfd-like interface based on mwait.");
MODULE_LICENSE("GPL");

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
	switch (cmd) {
	}

	return -ENOIOCTLCMD;
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
	};

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, FCCMP_EVENT_DEVICE);
	if (result < 0) {
		pr_warn("fccmp-event: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("fccmp-event: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("fccmp-event: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, FCCMP_EVENT_DEVICE);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fccmp-event: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, FCCMP_EVENT_DEVICE);
	if (IS_ERR_VALUE(device)) {
		pr_warn("fccmp-event: can't create device");
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

// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_event.c - eventfd-like interface based on mwait
 */

#include <linux/module.h>
#include <linux/compiler_types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <asm-generic/errno-base.h>

MODULE_DESCRIPTION("eventfd-like interface based on mwait.");
MODULE_LICENSE("GPL");

#define DEVICE_NAME "fccmp-event"
#define IOCTL_TYPE 0xFC
#define IOCTL_ZERO _IO(IOCTL_TYPE, 10)
#define IOCTL_SEM _IO(IOCTL_TYPE, 11)

static dev_t dev;
static struct cdev *cdev;
static struct class *class;
static struct device *device;

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
		.unlocked_ioctl = ioctl,
	};

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
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
	class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fccmp-event: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, DEVICE_NAME);
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

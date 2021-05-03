// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_ioctl.c - character device driver for comparing ioctl functions with the fastcall mechanism
 */

#include "fccmp_array.h"
#include "fccmp_nt.h"
#include <linux/module.h>
#include <linux/compiler_types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <asm-generic/errno-base.h>

MODULE_DESCRIPTION(
	"A character device driver for comparing ioctl functions with the fastcall mechanism.");
MODULE_LICENSE("GPL");

struct array_args {
	const char __user *data;
	unsigned char index;
	unsigned char size;
};

struct array_nt_args {
	const char __user *data;
	unsigned char index;
};

#define DEVICE_NAME "fccmp"
#define IOCTL_TYPE 0xFC
#define IOCTL_NOOP _IO(IOCTL_TYPE, 0)
#define IOCTL_ARRAY _IOW(IOCTL_TYPE, 1, struct array_args)
#define IOCTL_NT _IOW(IOCTL_TYPE, 2, struct array_nt_args)

static dev_t dev;
static struct cdev *cdev;
static struct class *class;
static struct device *device;

static int copy_array(struct file *file, unsigned long args)
{
	struct array_args ioctl_args;

	if (!(file->f_mode & FMODE_WRITE))
		return -EACCES;

	if (copy_from_user(&ioctl_args, (void *)args,
			   sizeof(struct array_args)))
		return -EFAULT;

	return fccmp_copy_array(ioctl_args.data, ioctl_args.index,
				ioctl_args.size);
}

static int copy_array_nt(struct file *file, unsigned long args)
{
	struct array_nt_args ioctl_args;

	if (!(file->f_mode & FMODE_WRITE))
		return -EACCES;

	if (copy_from_user(&ioctl_args, (void *)args,
			   sizeof(struct array_nt_args)))
		return -EFAULT;

	return fccmp_copy_array_nt(ioctl_args.data, ioctl_args.index);
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	switch (cmd) {
	case IOCTL_NOOP:
		return 0;
	case IOCTL_ARRAY:
		return copy_array(file, args);
	case IOCTL_NT:
		return copy_array_nt(file, args);
	}

	return -ENOIOCTLCMD;
}

/*
 * fccmp_init - initialize this module
 *
 * Add a "fccmp" character device.
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
		pr_warn("fccmp: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("fccmp: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("fccmp: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fccmp: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, DEVICE_NAME);
	if (IS_ERR_VALUE(device)) {
		pr_warn("fccmp: can't create device");
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

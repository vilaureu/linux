// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_examples.c - an example device driver which adds some fastcalls for testing and benchmarking
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/fastcall.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(
	"An example device driver which adds some fastcalls for testing and benchmarking.");

#define FCE_DEVICE_NAME "fastcall-examples"

static dev_t fce_dev;
static struct cdev *fce_cdev;
static struct class *fce_class;
static struct device *fce_device;

/*
 * fce_open() - open the device
 * TODO: remove if it stays empty
 */
static int fce_open(struct inode *inode, struct file *file)
{
	// TODO decide if only device should only be opened writable
	// if (!(file->f_mode & FMODE_WRITE)) {
	// 	return -EACCES;
	// }

	return 0;
}

/*
 * fce_ioctl() - register the example fastcall specified by cmd
 */
static long fce_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -EINVAL;
	struct page *pages[] = { ZERO_PAGE(0) };
	fastcall_attr attribs = { 0, 0, 0 };

	switch (cmd) {
	case 0:
		return register_fastcall(pages, 1, attribs);
	}

	return ret;
}

/*
 * fce_init() - initialize this module
 * 
 * Add one "fastcall-examples" character device.
 */
static int __init fce_init(void)
{
	int result;
	// TODO implement close to unregister fastcalls
	static struct file_operations fops = { .owner = THIS_MODULE,
					       .open = fce_open,
					       .unlocked_ioctl = fce_ioctl };

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&fce_dev, 0, 1, FCE_DEVICE_NAME);
	if (result < 0) {
		pr_warn("fce: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	fce_cdev = cdev_alloc();
	if (fce_cdev == NULL) {
		pr_warn("fce: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	fce_cdev->owner = THIS_MODULE;
	fce_cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(fce_cdev, fce_dev, 1);
	if (result < 0) {
		pr_warn("fce: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	fce_class = class_create(THIS_MODULE, FCE_DEVICE_NAME);
	if (IS_ERR_VALUE(fce_class)) {
		pr_warn("fce: can't create class");
		result = PTR_ERR(fce_class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	fce_device =
		device_create(fce_class, NULL, fce_dev, NULL, FCE_DEVICE_NAME);
	if (IS_ERR_VALUE(fce_device)) {
		pr_warn("fce: can't create device");
		result = PTR_ERR(fce_device);
		goto fail_device_create;
	}

	return 0;

	// Error handing
fail_device_create:
	class_destroy(fce_class);
fail_class_create:
fail_cdev_add:
	cdev_del(fce_cdev);
fail_cdev_alloc:
	unregister_chrdev_region(fce_dev, 1);
fail_chrdev:
	return result;
}

static void __exit fce_exit(void)
{
	device_destroy(fce_class, fce_dev);
	class_destroy(fce_class);
	cdev_del(fce_cdev);
	unregister_chrdev_region(fce_dev, 1);
}

module_init(fce_init);
module_exit(fce_exit);

// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_driver.c - an example device driver which adds some fastcalls for testing and benchmarking
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/minmax.h>
#include <asm/fastcall.h>
#include <asm/pgtable.h>

MODULE_DESCRIPTION(
	"An example device driver which adds some fastcalls for testing and benchmarking.");

#define FCE_DEVICE_NAME "fastcall-examples"

/*
 * Function labels from fastcall_functions.S.
 */
const void fce_functions_start(void);
const void fce_noop(void);
const void fce_stack(void);
const void fce_functions_end(void);

/*
 * FCE_FUNCTIONS_SIZE - size of the fastcall function text segment in bytes
 */
#define FCE_FUNCTIONS_SIZE                                                     \
	((unsigned long)(fce_functions_end - fce_functions_start))
#define NR_FCE_PAGES ((FCE_FUNCTIONS_SIZE - 1) / PAGE_SIZE + 1)

#define FCE_IOCTL_NOOP 0
#define FCE_IOCTL_STACK 1

static dev_t fce_dev;
static struct cdev *fce_cdev;
static struct class *fce_class;
static struct device *fce_device;
static struct page *fce_pages[1];

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
 * function_offset - return the offset of the function into the containing page
 */
static unsigned long function_offset(const void (*fn)(void))
{
	return fn - fce_functions_start;
}

/*
 * fce_ioctl() - register the example fastcall specified by cmd
 */
static long fce_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -EINVAL;
	fastcall_attr attribs = { 0, 0, 0 };

	switch (cmd) {
	case FCE_IOCTL_NOOP:
		return register_fastcall(fce_pages, NR_FCE_PAGES, function_offset(fce_noop),
					 attribs);
	case FCE_IOCTL_STACK:
		return register_fastcall(fce_pages, NR_FCE_PAGES, function_offset(fce_stack),
					 attribs);
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
	int result, page_id;
	size_t count;
	void *addr;
	// TODO implement close to unregister fastcalls
	static struct file_operations fops = { .owner = THIS_MODULE,
					       .open = fce_open,
					       .unlocked_ioctl = fce_ioctl };

	// Allocate pages for example function and copy them
	BUG_ON(NR_FCE_PAGES != sizeof(fce_pages) / sizeof(struct page *));
	for (page_id = 0; page_id < NR_FCE_PAGES; page_id++) {
		fce_pages[page_id] = alloc_page(GFP_FASTCALL);
		if (!fce_pages[page_id]) {
			pr_warn("fce: can't allocate function page");
			result = -ENOMEM;
			goto fail_page_alloc;
		}
		addr = kmap(fce_pages[page_id]);
		count = min(FCE_FUNCTIONS_SIZE - page_id * PAGE_SIZE,
			    PAGE_SIZE);
		memcpy(addr, fce_functions_start, count);
		kunmap(fce_pages[page_id]);
	}

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
fail_page_alloc:
	for (page_id--; page_id >= 0; page_id--)
		__free_page(fce_pages[page_id]);

	return result;
}

static void __exit fce_exit(void)
{
	unsigned page_id;

	device_destroy(fce_class, fce_dev);
	class_destroy(fce_class);
	cdev_del(fce_cdev);
	unregister_chrdev_region(fce_dev, 1);

	for (page_id = 0; page_id < NR_FCE_PAGES; page_id++)
		__free_page(fce_pages[page_id]);
}

module_init(fce_init);
module_exit(fce_exit);

MODULE_LICENSE("GPL");

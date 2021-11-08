// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_driver.c - registers fastcall functions for eventfc
 *
 * This driver provides fastcalls which allow applications to wait for
 * events triggered by other applications using the MWAIT instruction.
 * They can be used to create an interface similar to eventfd.
 */

#include <asm-generic/fcntl.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/fastcall.h>

#include "functions.h"

MODULE_DESCRIPTION("Fastcalls for an event wait mechanism similar to eventfd.");

#define DEVICE_NAME "fastcall-event"
#define IOCTL_TYPE 0xC2
#define IOCTL_CMD(nr) _IOR(IOCTL_TYPE, nr, struct ioctl_args)
#define IOCTL_ZERO IOCTL_CMD(0)
#define IOCTL_SEM IOCTL_CMD(1)
#define FUNCTION_PAGES ((eventfc_image.image.size - 1) / PAGE_SIZE + 1)

/*
 * ioctl_args - information returned from the ioctl handler
 *
 * @fn_addr     - start of the function mapping
 * @fn_len      - length of the function mapping
 * @index       - index of the function in the fastcall table
 */
struct ioctl_args {
	unsigned long fn_addr;
	unsigned long fn_len;
	unsigned index;
};

static struct page **function_pages;
static dev_t dev;
static struct cdev *cdev;
static struct class *class;
static struct device *device;

static void additional_unmap(void *priv)
{
	fastcall_remove_mapping((unsigned long)priv);
}

static void additional_free(void *priv)
{
	/*
	 * priv is a direct pointer to the counter mapping.
	 * Therefore, nothing needs to be freed here.
	 */
}

/*
 * ioctl_handler - registers the fastcall function
 *
 * This function maps the function image to user space and adds a coresonding
 * entry to the fastcall table.
 *
 * Returns a negative error number, a 0 on success or
 * a 1 if the registration succeeded but the copy operation failed.
 *
 * @semaphore - same semantics as EFD_SEMAPHORE
 */
static long ioctl_handler(unsigned long args, struct page *counter_page,
			  bool block, bool semaphore)
{
	unsigned long counter_addr;
	long ret;
	struct ioctl_args *ioctl_args;
	static struct fastcall_fn_ops fn_ops = {
		.unmap = additional_unmap,
		.free = additional_free,
	};
	struct fastcall_reg_args reg_args = {
		.pages = function_pages,
		.num = FUNCTION_PAGES,
		.off = eventfc_image.sym_eventfc,
		.module = THIS_MODULE,
		.ops = &fn_ops,
	};

	/*
   * This maps the page into the address space.
   * The last parameter makes the mapping accessable from user mode.
   */
	counter_addr = create_additional_mapping(&counter_page, 1,
						 FASTCALL_VM_RW, true);
	ret = (long)counter_addr;
	if (IS_ERR_VALUE(counter_addr))
		goto fail_shared_create;

	reg_args.priv = (void *)counter_addr;
	reg_args.attribs[0] = counter_addr;
	reg_args.attribs[1] = block;
	reg_args.attribs[2] = semaphore;

	/*
   * Allocate zeroed memory area for the return structure,
   * which is copied to user space.
   */
	ioctl_args = kzalloc(sizeof(struct ioctl_args), GFP_KERNEL);
	ret = -ENOMEM;
	if (!ioctl_args)
		goto fail_args_alloc;

	/*
   * Register the fastcall function. This makes the function live immediately.
   * Therefore, this function can not really fail afterwards.
   */
	ret = register_fastcall(&reg_args);
	if (ret < 0)
		goto fail_register;

	ioctl_args->fn_addr = reg_args.fn_addr;
	ioctl_args->fn_len = reg_args.num * PAGE_SIZE;
	ioctl_args->index = reg_args.index;

	/*
   * At this point we have no possibility to easily, safely revert our steps.
   * Hence, we return with the alternative "success" value of 1.
   */
	ret = 1;
	if (copy_to_user((void *)args, ioctl_args, sizeof(struct ioctl_args)))
		goto fail_copy;

	ret = 0;

fail_copy:
fail_register:
	kfree(ioctl_args);
fail_args_alloc:
	if (ret < 0)
		remove_additional_mapping(counter_addr);
fail_shared_create:
	return ret;
}

/*
 * ioctl() - register the fastcall functions as specified by cmd and args
 */
static long ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -ENOIOCTLCMD;
	struct page *counter_page = file->private_data;
	bool block = file->f_flags ^ O_NONBLOCK;

	/*
	 * Check for MONITOR/MWAIT in the same way as kvm_can_mwait_in_guest().
	 * For simplicity, we do not enable eventfd for CPUs with only the MSBDS bug.
	 * Hence, we do not have to mitigate MDS when going idle.
	 * Mitigating MDS when going idle does not make sense for CPUs with more MDS
	 * bugs, see update_mds_branch_idle().
	 */
	if (!boot_cpu_has(X86_FEATURE_MWAIT) ||
	    boot_cpu_has_bug(X86_BUG_MONITOR) ||
	    !boot_cpu_has(X86_FEATURE_ARAT) ||
	    boot_cpu_has_bug(X86_BUG_MSBDS_ONLY))
		return -ENOIOCTLCMD;

	if (cmd == IOCTL_ZERO) {
		ret = ioctl_handler(args, counter_page, block, false);
	} else if (cmd == IOCTL_SEM) {
		ret = ioctl_handler(args, counter_page, block, true);
	}

	return ret == 1 ? -EFAULT : ret;
}

static int open(struct inode *i, struct file *file)
{
	struct page *counter_page = alloc_page(GFP_FASTCALL);
	if (!counter_page)
		return -ENOMEM;
	file->private_data = counter_page;

	return 0;
}

static int release(struct inode *i, struct file *file)
{
	__free_page(file->private_data);
	return 0;
}

/*
 * fastcall_init() - initialize this module
 *
 * This function prepares the pages with the fastcall functions
 * and registers a new device for interacting with the
 * applications.
 */
static int __init fastcall_init(void)
{
	int result;
	static struct file_operations fops = {
		.owner = THIS_MODULE,
		.open = open,
		.release = release,
		.unlocked_ioctl = ioctl,
	};

	// Copy the image of fastcall functions and apply alternatives
	function_pages = fastcall_prepare_image(&eventfc_image.image);
	if (!function_pages) {
		pr_warn("eventfc: can't prepare functions image");
		result = -ENOMEM;
		goto fail_image;
	}

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
	if (result < 0) {
		pr_warn("eventfc: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("eventfc: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("eventfc: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR_VALUE(class)) {
		pr_warn("eventfc: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, DEVICE_NAME);
	if (IS_ERR_VALUE(device)) {
		pr_warn("eventfc: can't create device");
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
	fastcall_free_image(function_pages, FUNCTION_PAGES);
fail_image:
	return result;
}

static void __exit fastcall_exit(void)
{
	device_destroy(class, dev);
	class_destroy(class);
	cdev_del(cdev);
	unregister_chrdev_region(dev, 1);
	fastcall_free_image(function_pages, FUNCTION_PAGES);
}

module_init(fastcall_init);
module_exit(fastcall_exit);

MODULE_LICENSE("GPL");

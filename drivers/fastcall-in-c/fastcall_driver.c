// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_driver.c - registers fastcall functions written in C
 *
 * This driver enables applications to register fastcall functions
 * written in C for their address space.
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/fastcall.h>
#include "functions.h"

MODULE_DESCRIPTION("An example for writing fastcall functions in C.");

#define DEVICE_NAME "fastcall-in-c"
#define IOCTL_TYPE 0xC1
#define IOCTL_CMD _IOR(IOCTL_TYPE, 0, struct ioctl_args)
#define FUNCTION_PAGES ((fcc_image.size - 1) / PAGE_SIZE + 1)

/*
 * ioctl_args - information returned from the ioctl handler
 *
 * @fn_addr     - Start of the function mapping
 * @fn_len      - Length of the function mapping
 * @shared_addr - Address of the shared buffer
 * @index       - Index of the function in the fastcall table
 */
struct ioctl_args {
	unsigned long fn_addr;
	unsigned long fn_len;
	unsigned long shared_addr;
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
	 * priv is a direct pointer to the shared mapping.
	 * Therefore, nothing needs to be freed here.
	 */
}

/*
 * ioctl_handler - registers a fastcall function
 *
 * The function requires the reg_args parameter to have .pages
 * .num and .off already set. The address of the shared memory area
 * is saved into .attribs[0]. The rest of this array might be used otherwise.
 *
 * Returns a negative error number, a 0 on success or
 * a 1 if the registration succeeded but the copy operation failed.
 */
static long ioctl_handler(struct fastcall_reg_args reg_args, unsigned long args)
{
	unsigned long shared_addr;
	struct page *shared_page;
	long ret;
	struct ioctl_args *ioctl_args;
	static struct fastcall_fn_ops fn_ops = {
		.unmap = additional_unmap,
		.free = additional_free,
	};

	reg_args.module = THIS_MODULE;

	// This creates a new page for sharing between application and fastcall.
	shared_page = alloc_page(GFP_FASTCALL);
	ret = -ENOMEM;
	if (!shared_page)
		goto fail_shared_alloc;

	/*
   * This maps the page into the address space.
   * The last parameter makes the mapping accessable from user mode.
   */
	shared_addr = create_additional_mapping(&shared_page, 1, FASTCALL_VM_RW,
						true);
	ret = (long)shared_addr;
	if (IS_ERR_VALUE(shared_addr))
		goto fail_shared_create;

	reg_args.ops = &fn_ops;
	reg_args.priv = (void *)shared_addr;
	reg_args.attribs[0] = shared_addr;

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
	ioctl_args->shared_addr = shared_addr;
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
		remove_additional_mapping(shared_addr);
fail_shared_create:
	__free_page(shared_page);
fail_shared_alloc:
	return ret;
}

/*
 * ioctl() - register the fastcall functions as specified by cmd and args
 */
static long ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -ENOIOCTLCMD;

	if (cmd == IOCTL_CMD) {
		struct fastcall_reg_args reg_args = {
			.pages = function_pages,
			.num = FUNCTION_PAGES,
			.off = fcc_image.sym_function,
		};
		ret = ioctl_handler(reg_args, args);
	}

	return ret == 1 ? -EFAULT : ret;
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
	int result, page_alloc, page_copy;
	size_t count;
	void *addr, *alt_start;
	static struct file_operations fops = {
		.owner = THIS_MODULE,
		.unlocked_ioctl = ioctl,
	};

	// Allocate array for holding the page pointers
	function_pages = kmalloc_array(FUNCTION_PAGES, sizeof(struct page *),
				       GFP_KERNEL);
	if (!function_pages) {
		pr_warn("fcc: can't allocate page array");
		result = -ENOMEM;
		goto fail_pages;
	}

	/*
	 * Allocate pages for the fastcall functions image
	 * and copy the contents to there.
	 */
	for (page_alloc = 0; page_alloc < FUNCTION_PAGES; page_alloc++) {
		function_pages[page_alloc] = alloc_page(GFP_FASTCALL);
		if (!function_pages[page_alloc]) {
			pr_warn("fcc: can't allocate function page");
			result = -ENOMEM;
			goto fail_page_alloc;
		}
	}

	addr = vmap(function_pages, FUNCTION_PAGES, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		pr_warn("fcc: can't map function pages");
		result = -ENOMEM;
		goto fail_vmap;
	}

	for (page_copy = 0; page_copy < FUNCTION_PAGES; page_copy++) {
		size_t offset = page_copy * PAGE_SIZE;
		count = min(fcc_image.size - offset, PAGE_SIZE);
		memcpy(addr + offset, fcc_image.data + offset, count);
	}

	alt_start = addr + fcc_image.alt;
	apply_alternatives(alt_start, alt_start + fcc_image.alt_len);
	vunmap(addr);

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
	if (result < 0) {
		pr_warn("fcc: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("fcc: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("fcc: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fcc: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, DEVICE_NAME);
	if (IS_ERR_VALUE(device)) {
		pr_warn("fcc: can't create device");
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
fail_vmap:
fail_page_alloc:
	for (page_alloc--; page_alloc >= 0; page_alloc--)
		__free_page(function_pages[page_alloc]);
	kfree(function_pages);
fail_pages:
	return result;
}

static void __exit fastcall_exit(void)
{
	unsigned page_id;

	device_destroy(class, dev);
	class_destroy(class);
	cdev_del(cdev);
	unregister_chrdev_region(dev, 1);

	for (page_id = 0; page_id < FUNCTION_PAGES; page_id++)
		__free_page(function_pages[page_id]);
	kfree(function_pages);
}

module_init(fastcall_init);
module_exit(fastcall_exit);

MODULE_LICENSE("GPL");

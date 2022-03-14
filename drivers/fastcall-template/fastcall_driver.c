// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_driver.c - this file contains the code for registering a fastcall
                       through an ioctl interface
 *
 * The ioctl requests are handled by the ioctl function in this file.
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/fastcall_module.h>

MODULE_DESCRIPTION("A template for fastcall-based drivers.");

/*
 * Function labels from fastcall_functions.S .
 */
void fct_functions_start(void);
void fct_template(void);
void fct_functions_end(void);

/*
 * FUNCTION_SIZE - size of the fastcall function text segment in bytes
 */
#define FUNCTION_SIZE ((unsigned long)(fct_functions_end - fct_functions_start))
/*
 * FUNCTION_PAGES - number of pages the fastcall function segment would span
 */
#define FUNCTION_PAGES ((FUNCTION_SIZE - 1) / PAGE_SIZE + 1)
#define DEVICE_NAME ("fastcall-template")
/*
 * IOCTL_TYPE - identifier for the ioctl handler of this module
 *
 * The ioctl type differentiates this interface from others which might
 * handle requests for the same file descriptor.
 */
#define IOCTL_TYPE (0xDC)
// For more ioctl handlers increment the nr parameter (0 here).
#define IOCTL_TEMPLATE (_IOR(IOCTL_TYPE, 0, struct ioctl_args))

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

/*
 * function_pages - pages containing the copied fastcall functions
 *
 * Unfortunately, the length must a literal but it is checked with a
 * BUG_ON during runtime to equal FUNCTION_PAGES.
 */
static struct page *function_pages[1];
static dev_t dev;
static struct cdev *cdev;
static struct class *class;
static struct device *device;

/*
 * template_unmap - remove any additional mappings
 *
 * This function uses the private data in the vm_area_struct
 * to remove the two additional mappings from user space.
 */
static void template_unmap(void *priv)
{
	unsigned long(*mappings)[2] = priv;
	fastcall_remove_mapping((*mappings)[0]);
	fastcall_remove_mapping((*mappings)[1]);
}

/*
 * template_free - free the priv element
 *
 * This function is called only after template_unmap.
 */
static void template_free(void *priv)
{
	kfree(priv);
}

/*
 * template_handler - handle the user request to register
 *                    the template fastcall function
 *
 * This function creates a shared and a private memory mapping
 * for the fastcall function. Then it registers the actual
 * fastcall function. Finally, it copies a struct with
 * retrun information back to user space.
 *
 * Returns a negative error number, a 0 on success or
 * a 1 if the registration succeeded but the copy operation failed.
 *
 * In the last case, the user program has to locate the function mapping itself,
 * if it wants to deregister the function.
 */
static long template_handler(unsigned long args)
{
	unsigned long shared_addr, private_addr;
	struct page *shared_page, *private_page;
	unsigned long(*priv)[2];
	long ret;
	struct ioctl_args *ioctl_args;
	struct fastcall_reg_args reg_args = {
		.pages = function_pages,
		.num = FUNCTION_PAGES,
		.off = fct_template - fct_functions_start,
		.module = THIS_MODULE,
	};
	static struct fastcall_fn_ops template_fn_ops = {
		.unmap = template_unmap,
		.free = template_free,
	};

	/*
	 * This stores the addresses of the shared and private memory regions
	 * into the vm_area_struct.
	 * This allows us to free the memory on deregistration.
	 */
	priv = kmalloc(sizeof(unsigned long[2]), GFP_KERNEL);
	ret = -ENOMEM;
	if (!priv)
		goto fail_malloc;

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

	// This creates a new page private to the fastcall.
	private_page = alloc_page(GFP_FASTCALL);
	ret = -ENOMEM;
	if (!private_page)
		goto fail_private_alloc;

	private_addr = create_additional_mapping(&private_page, 1,
						 FASTCALL_VM_RW, false);
	ret = (long)private_addr;
	if (IS_ERR_VALUE(private_addr))
		goto fail_private_create;

	(*priv)[0] = shared_addr;
	(*priv)[1] = private_addr;
	/*
	 * The ops handle the unmapping of our additional mappings and
	 * the freeing of the priv array itself.
	 * If you do not need any additional memory areas,
	 * .ops and .priv can be set to NULL.
	 */
	reg_args.ops = &template_fn_ops;
	reg_args.priv = priv;
	// These are the attributes inserted into the fastcall table.
	reg_args.attribs[0] = shared_addr;
	reg_args.attribs[1] = private_addr;

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
	ioctl_args->fn_len = FUNCTION_PAGES * PAGE_SIZE;
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
		remove_additional_mapping(private_addr);
fail_private_create:
	__free_page(private_page);
fail_private_alloc:
	if (ret < 0)
		remove_additional_mapping(shared_addr);
fail_shared_create:
	__free_page(shared_page);
fail_shared_alloc:
	if (ret < 0)
		kfree(priv);
fail_malloc:
	return ret;
}

/*
 * ioctl() - register the fastcall functions as specified by cmd and args
 */
static long ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -ENOIOCTLCMD;

	if (cmd == IOCTL_TEMPLATE)
		ret = template_handler(args);

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
	int result, page_id;
	size_t count;
	void *addr;
	static struct file_operations fops = {
		.owner = THIS_MODULE,
		.unlocked_ioctl = ioctl,
	};

	// Allocate pages for all fastcall functions and
	// copy their text segments to the new pages.
	BUG_ON(FUNCTION_PAGES !=
	       sizeof(function_pages) / sizeof(struct page *));
	for (page_id = 0; page_id < FUNCTION_PAGES; page_id++) {
		function_pages[page_id] = alloc_page(GFP_FASTCALL);
		if (!function_pages[page_id]) {
			pr_warn("fct: can't allocate function page");
			result = -ENOMEM;
			goto fail_page_alloc;
		}
		addr = kmap(function_pages[page_id]);
		// Do not copy past fct_functions_end
		count = min(FUNCTION_SIZE - page_id * PAGE_SIZE, PAGE_SIZE);
		memcpy(addr, fct_functions_start + page_id * PAGE_SIZE, count);
		kunmap(function_pages[page_id]);
	}

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
	if (result < 0) {
		pr_warn("fct: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	cdev = cdev_alloc();
	if (cdev == NULL) {
		pr_warn("fct: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	cdev->owner = THIS_MODULE;
	cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(cdev, dev, 1);
	if (result < 0) {
		pr_warn("fct: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR_VALUE(class)) {
		pr_warn("fct: can't create class");
		result = PTR_ERR(class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	device = device_create(class, NULL, dev, NULL, DEVICE_NAME);
	if (IS_ERR_VALUE(device)) {
		pr_warn("fct: can't create device");
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
fail_page_alloc:
	for (page_id--; page_id >= 0; page_id--)
		__free_page(function_pages[page_id]);

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
}

module_init(fastcall_init);
module_exit(fastcall_exit);

MODULE_LICENSE("GPL");

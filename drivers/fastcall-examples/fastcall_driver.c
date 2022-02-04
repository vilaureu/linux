// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_driver.c - an example device driver which adds some fastcalls for testing and benchmarking
 */

#include <linux/module.h>
#include <linux/fastcall.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/cpufeature.h>
#include "fastcall_examples.h"

MODULE_DESCRIPTION(
	"An example device driver which adds some fastcalls for testing and benchmarking.");

/*
 * Function labels from fastcall_functions.S.
 */
const void fce_functions_start(void);
const void fce_noop(void);
const void fce_stack(void);
const void fce_write_ptr(void);
const void fce_functions_end(void);
const void fce_array(void);
const void fce_array_nt(void);
const void fce_mwait(void);

/*
 * FCE_FUNCTIONS_SIZE - size of the fastcall function text segment in bytes
 */
#define FCE_FUNCTIONS_SIZE                                                     \
	((unsigned long)(fce_functions_end - fce_functions_start))
#define NR_FCE_PAGES ((FCE_FUNCTIONS_SIZE - 1) / PAGE_SIZE + 1)

static dev_t fce_dev;
static struct cdev *fce_cdev;
static struct class *fce_class;
static struct device *fce_device;
static struct page *fce_pages[1];

/*
 * register_and_copy - registers a fastcall function and copies the ioctl_args to user space
 *
 * Return negative error number, 0 on success and
 * 1 if the registration succeeded and the copy operation failed.
 *
 * In the last case, the user program has to locate the function mapping itself afterwards,
 * if it wants to deregister the function.
 */
static int register_and_copy(struct fastcall_reg_args reg_args,
			     unsigned long args)
{
	int ret;
	struct ioctl_args *io_args;

	// Use zeroed memory to prevent information leaks.
	io_args = kzalloc(sizeof(struct ioctl_args), GFP_KERNEL);
	ret = -ENOMEM;
	if (!io_args)
		goto fail_alloc;

	ret = register_fastcall(&reg_args);
	if (ret < 0)
		goto fail_register;

	io_args->addr = reg_args.fn_addr;
	io_args->len = NR_FCE_PAGES * PAGE_SIZE;
	io_args->index = reg_args.index;

	ret = 1;
	if (copy_to_user((void *)args, io_args, sizeof(struct ioctl_args)))
		goto fail_copy;

	ret = 0;

fail_copy:
	// Do not undo the registration. This could result in race conditions with other memory mappings.
fail_register:
	kfree(io_args);
fail_alloc:
	return ret;
}

/*
 * function_offset - return the offset of the function into the containing page
 */
static unsigned long function_offset(const void (*fn)(void))
{
	return fn - fce_functions_start;
}

/*
 * args_for - return fastcall_reg_args for this function
 *
 * pages, num and off are filled in.
 */
static struct fastcall_reg_args args_for(const void (*fn)(void))
{
	return (struct fastcall_reg_args){
		.pages = fce_pages,
		.num = NR_FCE_PAGES,
		.off = function_offset(fn),
		.module = THIS_MODULE,
	};
}

static void single_unmap(void *priv)
{
	fastcall_remove_mapping((unsigned long)priv);
}

static void single_free(void *priv)
{
	// priv stores the address directly, nothing to free here
}

/*
 * single_fn_ops - frees a single mapping stored in the
 *                 (struct fastcall_reg_args)->priv pointer.
 */
static const struct fastcall_fn_ops single_fn_ops = {
	.unmap = single_unmap,
	.free = single_free,
};

#ifdef CONFIG_X86_64 /* TODO: implement for arm64 */

/*
 * private_example - example for the use of private memory regions for a fastcall
 */
static long private_example(unsigned long args)
{
	unsigned long addr;
	struct page *page;
	long ret = -ENOMEM;
	struct fastcall_reg_args reg_args = args_for(fce_write_ptr);

	page = alloc_page(GFP_FASTCALL);
	if (!page)
		goto fail_alloc;

	addr = create_additional_mapping(&page, 1, FASTCALL_VM_RW, false);
	ret = (long)addr;
	if (IS_ERR_VALUE(addr))
		goto fail_create;

	reg_args.ops = &single_fn_ops;
	reg_args.priv = (void *)addr;
	reg_args.attribs[0] = addr;
	ret = register_and_copy(reg_args, args);

	if (ret < 0)
		remove_additional_mapping(addr);
fail_create:
	__free_page(page);
fail_alloc:
	return ret;
}

#endif /* CONFIG_X86_64 */

static void array_unmap(void *priv)
{
	unsigned long(*mappings)[2] = priv;
	fastcall_remove_mapping((*mappings)[0]);
	fastcall_remove_mapping((*mappings)[1]);
}

static void array_free(void *priv)
{
	kfree(priv);
}

static const struct fastcall_fn_ops array_fn_ops = {
	.unmap = array_unmap,
	.free = array_free,
};

/*
 * array_example - example for copying data with a shared buffer
 *
 * Data is copies from the shared buffer to an array of chararcter arrays.
 */
static long array_example(unsigned long args, const void (*fn)(void))
{
	unsigned long shared_addr, array_addr;
	struct page *shared_page, *array_page;
	unsigned long(*priv)[2];
	long ret;
	struct fastcall_reg_args reg_args = args_for(fn);
	struct array_args *array_args;

	priv = kmalloc(sizeof(unsigned long[2]), GFP_KERNEL);
	ret = -ENOMEM;
	if (!priv)
		goto fail_malloc;

	shared_page = alloc_page(GFP_FASTCALL);
	ret = -ENOMEM;
	if (!shared_page)
		goto fail_shared_alloc;

	shared_addr = create_additional_mapping(&shared_page, 1, FASTCALL_VM_RW,
						true);
	ret = (long)shared_addr;
	if (IS_ERR_VALUE(shared_addr))
		goto fail_shared_create;

	array_page = alloc_page(GFP_FASTCALL);
	ret = -ENOMEM;
	if (!array_page)
		goto fail_array_alloc;

	array_addr = create_additional_mapping(&array_page, 1, FASTCALL_VM_RW,
					       false);
	ret = (long)array_addr;
	if (IS_ERR_VALUE(array_addr))
		goto fail_array_create;

	(*priv)[0] = shared_addr;
	(*priv)[1] = array_addr;
	reg_args.ops = &array_fn_ops;
	reg_args.priv = priv;
	reg_args.attribs[0] = shared_addr;
	reg_args.attribs[1] = array_addr;

	array_args = kzalloc(sizeof(struct array_args), GFP_KERNEL);
	ret = -ENOMEM;
	if (!array_args)
		goto fail_args_alloc;

	ret = register_fastcall(&reg_args);
	if (ret < 0)
		goto fail_register;

	array_args->fn_addr = reg_args.fn_addr;
	array_args->fn_len = NR_FCE_PAGES * PAGE_SIZE;
	array_args->shared_addr = shared_addr;
	array_args->index = reg_args.index;

	ret = 1;
	if (copy_to_user((void *)args, array_args, sizeof(struct array_args)))
		goto fail_copy;

	ret = 0;

fail_copy:
fail_register:
	kfree(array_args);
fail_args_alloc:
	if (ret < 0)
		remove_additional_mapping(array_addr);
fail_array_create:
	__free_page(array_page);
fail_array_alloc:
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

#ifdef CONFIG_X86_64
/*
 * mwait_example - wait for a memory change using MWAIT
 *
 * This fastcall function shares a memory page with the application.
 * It will listen for changes at the beginning of this page upon calling.
 */
static long mwait_example(unsigned long args)
{
	unsigned long shared_addr;
	struct page *shared_page;
	long ret;
	struct fastcall_reg_args reg_args = args_for(fce_mwait);
	mwait_args_struct *mwait_args;

	shared_page = alloc_page(GFP_FASTCALL);
	ret = -ENOMEM;
	if (!shared_page)
		goto fail_shared_alloc;

	shared_addr = create_additional_mapping(&shared_page, 1, FASTCALL_VM_RW,
						false);
	ret = (long)shared_addr;
	if (IS_ERR_VALUE(shared_addr))
		goto fail_shared_create;

	reg_args.ops = &single_fn_ops;
	reg_args.priv = (void *)shared_addr;
	reg_args.attribs[0] = shared_addr;

	mwait_args = kzalloc(sizeof(mwait_args_struct), GFP_KERNEL);
	ret = -ENOMEM;
	if (!mwait_args)
		goto fail_args_alloc;

	ret = register_fastcall(&reg_args);
	if (ret < 0)
		goto fail_register;

	mwait_args->fn_addr = reg_args.fn_addr;
	mwait_args->fn_len = NR_FCE_PAGES * PAGE_SIZE;
	mwait_args->shared_addr = shared_addr;
	mwait_args->index = reg_args.index;

	ret = 1;
	if (copy_to_user((void *)args, mwait_args, sizeof(mwait_args_struct)))
		goto fail_copy;

	ret = 0;

fail_copy:
fail_register:
	kfree(mwait_args);
fail_args_alloc:
	if (ret < 0)
		remove_additional_mapping(shared_addr);
fail_shared_create:
	__free_page(shared_page);
fail_shared_alloc:
	return ret;
}
#endif /* CONFIG_X86_64 */

/*
 * fce_ioctl() - register the example fastcall specified by cmd
 */
static long fce_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -ENOIOCTLCMD;
	struct fastcall_reg_args reg_args;

	switch (cmd) {
	case FCE_IOCTL_NOOP:
		reg_args = args_for(fce_noop);
		ret = register_and_copy(reg_args, args);
		break;
#ifdef CONFIG_X86_64 /* TODO: implement for arm64 */
	case FCE_IOCTL_STACK:
		reg_args = args_for(fce_stack);
		ret = register_and_copy(reg_args, args);
		break;
	case FCE_IOCTL_PRIV:
		ret = private_example(args);
		break;
	case FCE_IOCTL_ARRAY:
		ret = array_example(args, fce_array);
		break;
#ifdef CONFIG_X86_64
	case FCE_IOCTL_NT:
		if (boot_cpu_has(X86_FEATURE_AVX2) &&
		    boot_cpu_has(X86_FEATURE_AVX))
			ret = array_example(args, fce_array_nt);
		break;
	case FCE_IOCTL_MWAIT:
		// Same check as in kvm_can_mwait_in_guest()
		if (boot_cpu_has(X86_FEATURE_MWAIT) &&
		    !boot_cpu_has_bug(X86_BUG_MONITOR) &&
		    boot_cpu_has(X86_FEATURE_ARAT))
			ret = mwait_example(args);
		break;
#elif CONFIG_ARM64
	case FCE_IOCTL_NT:
		ret = array_example(args, fce_array_nt);
		break;
#endif
#endif /* CONFIG_X86_64 */
	}

	return ret == 1 ? -EFAULT : ret;
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
	static struct file_operations fops = {
		.owner = THIS_MODULE,
		.unlocked_ioctl = fce_ioctl,
	};

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
		memcpy(addr, fce_functions_start + page_id * PAGE_SIZE, count);
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

// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_module.h - common code used in drivers which use the fastcall architecture
 */

#ifndef _FASTCALL_MODULE_H
#define _FASTCALL_MODULE_H

#ifdef __ASSEMBLER__

#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/fastcall.h>
#include <asm/segment.h>

/*
 * Set the stack pointer to the per-CPU stack.
 *
 * The user stack pointer is saved to reg. scratch_reg is clobbered.
 */
.macro FASTCALL_SETUP_STACK reg=%rdi, scratch_reg=%rax
	/*
	 * This is save because the user can neither change MSR_TSC_AUX nor the segment limit.
	 *
	 * Additionally, RDPID is save as this is never called coming from KVM.
	 */
	ALTERNATIVE "", "jmp 0f", X86_FEATURE_RDPID
	movq $__CPUNODE_SEG, \reg
	lsl \reg, \reg
	jmp 1f
0:
	rdpid \reg
1:
	andq $VDSO_CPUNODE_MASK, \reg
	imulq $(-PAGE_SIZE), \reg

#ifdef CONFIG_X86_5LEVEL
	ALTERNATIVE "", "jmp 3f", X86_FEATURE_LA57
	movq $((1 << 47) - 4096), \scratch_reg
	jmp 4f
3:
	movq $((1 << 56) - 4096), \scratch_reg
4:
#else
	movq $FC_STACK_TOP, \scratch_reg
#endif

	addq \scratch_reg, \reg
	xchgq %rsp, \reg
.endm

/*
 * Create a wrapper for fastcall functions in C in ASM.
 *
 * This is the function to which the fastcall entry will jump to.
 * It sets up the stack, saves important registers and then
 * calls the wrapped function of the name wrapped_<name>.
 * This clobbers %r9 (system call argument five).
 */
.macro FASTCALL_ASM_WRAPPER name
	SYM_CODE_START(\name)
		UNWIND_HINT_EMPTY

		// This clobbers %r9 (arg5)
		FASTCALL_SETUP_STACK reg=%rdx scratch_reg=%r9

		// Save the stack pointer, flags register and return address
		pushq %rdx
		pushq %r11
		pushq %rcx

		// Move the function arguments into the right position
		movq %rax, %rdi
		movq %r10, %rcx

		// Call the actual fastcall function
		call wrapped_\name

		// Restore saved registers
		popq %rcx
		popq %r11
		movq (%rsp), %rsp

		sysretq
	SYM_CODE_END(\name)
.endm

#else /* !__ASSEMBLER__ */

#include <asm/fastcall.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/*
 * Macro for the head of wrapped fastcall functions in C.
 *
 * The first parameter is an array of pointers "entry"
 * which corresponds to the fastcall table entry.
 * The other parameters are the system call arguments one
 * through four.
 */
#define FASTCALL_WRAPPED_FN(name)                                              \
	long __attribute__((visibility("hidden")))                             \
	wrapped_##name(void *entry[NR_FC_ATTRIBS + 1], long arg1, long arg2,   \
		       long arg3, long arg4)

/*
 * fastcall_image - common data for all fastcall-in-c image structs.
 */
struct fastcall_image {
	// Contents of the shared library (image).
	const void *data;
	// Size of the image.
	unsigned long size;
	// Location of the .altinstructions section.
	unsigned long alt;
	// Length of this section.
	unsigned long alt_len;
};

/*
 * fastcall_prepare_image - return an array containing the prepared image
 *
 * This function copys the image data to fresh pages and applies
 * alternatives on them.
 *
 * Free the returned struct with fastcall_free_image on success.
 * Retruns NULL when not enough memory is available.
 */
static inline struct page **
fastcall_prepare_image(const struct fastcall_image *image)
{
	struct page **function_pages;
	int page_alloc, page_copy;
	size_t count, nr_pages = (image->size - 1) / PAGE_SIZE + 1;
	void *addr, *alt_start;

	BUG_ON(image->size == 0);

	// Allocate array for holding the page pointers
	function_pages =
		kmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!function_pages)
		goto fail_pages;

	// Allocate pages for the fastcall functions image.
	for (page_alloc = 0; page_alloc < nr_pages; page_alloc++) {
		function_pages[page_alloc] = alloc_page(GFP_FASTCALL);
		if (!function_pages[page_alloc]) {
			goto fail_page_alloc;
		}
	}

	// Map the pages continuously.
	addr = vmap(function_pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!addr)
		goto fail_vmap;

	// Copy the image contents.
	for (page_copy = 0; page_copy < nr_pages; page_copy++) {
		size_t offset = page_copy * PAGE_SIZE;
		count = min(image->size - offset, PAGE_SIZE);
		memcpy(addr + offset, image->data + offset, count);
	}

	// Apply alternatives to the copied image.
	alt_start = addr + image->alt;
	apply_alternatives(alt_start, alt_start + image->alt_len);
	vunmap(addr);

	return function_pages;

fail_vmap:
fail_page_alloc:
	for (page_alloc--; page_alloc >= 0; page_alloc--)
		__free_page(function_pages[page_alloc]);
	kfree(function_pages);
fail_pages:
	return NULL;
}

/*
 * fastcall_free_image - frees the pages and the array of pages itself
 */
static inline void fastcall_free_image(struct page **function_pages,
				       size_t nr_pages)
{
	unsigned page_id;
	if (!function_pages)
		return;

	for (page_id = 0; page_id < nr_pages; page_id++)
		__free_page(function_pages[page_id]);
	kfree(function_pages);
}

#endif /* !__ASSEMBLER__ */
#endif /* _FASTCALL_MODULE_H */

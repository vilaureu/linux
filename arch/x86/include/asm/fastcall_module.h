// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_module.h - common code used in drivers which use the fastcall architecture
 */

#ifndef _FASTCALL_MODULE_H
#define _FASTCALL_MODULE_H

#define SYSCALL_PARAMS_SIZE (7 * 8)

#ifdef __ASSEMBLER__

#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/fastcall.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>
#include <linux/errno.h>
#include <asm/nospec-branch.h>

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
 * Define syscall_entry symbol where the address of the system call entry
 * will be stored.
 */
.macro FASTCALL_DEFINE_SYS_ENTRY
	.section .rodata
	.global syscall_entry
	syscall_entry:
	.quad 0
.endm

/*
 * Restore saved registers in FASTCALL_ASM_WRAPPER
 */
.macro RESTORE_REGISTERS
	popq %rcx
	popq %r11
	movq (%rsp), %rsp
.endm

/*
 * Create a wrapper for fastcall functions in C in ASM.
 *
 * This is the function to which the fastcall entry will jump to.
 * It sets up the stack, saves important registers and then
 * calls the wrapped function of the name wrapped_<name>.
 * This clobbers %r9 (system call argument five).
 */
.macro FASTCALL_ASM_WRAPPER name syscall_fallback
	SYM_CODE_START(\name)
	UNWIND_HINT_EMPTY

	// This clobbers %r9 (arg5)
	FASTCALL_SETUP_STACK reg=%rdi scratch_reg=%r9

	// Save the stack pointer, flags register and return address
	pushq %rdi
	pushq %r11
	pushq %rcx

	.if (\syscall_fallback - 0)
		subq $SYSCALL_PARAMS_SIZE, %rsp
		movq %rsp, %r9
	.endif

	// Move the function arguments into the right position
	movq %rax, %rdi
	movq %r10, %rcx

	// Call the actual fastcall function
	call wrapped_\name

	.if (\syscall_fallback - 0)
		cmpw $-ERESTARTSYS, %ax
		jne 0f

		popq %rax
		popq %rdi
		popq %rsi
		popq %rdx
		popq %r10
		popq %r8
		popq %r9

		RESTORE_REGISTERS

		ANNOTATE_RETPOLINE_SAFE
		jmpq *syscall_entry(%rip)

		0:
		addq $SYSCALL_PARAMS_SIZE, %rsp
	.endif

	RESTORE_REGISTERS

	sysretq
	SYM_CODE_END(\name)
.endm

#else /* !__ASSEMBLER__ */

#include <asm/fastcall.h>
#include <asm/proto.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/*
 * FASTCALL_WRAPPED_FN - macro for the head of wrapped fastcall functions in C
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

struct syscall_params {
	unsigned long syscall_nr;
	long arg0, arg1, arg2, arg3, arg4, arg5;
};

/*
 * FASTCALL_WRAPPED_SYS - wrapped function with syscall parameter struct
 *
 * The function can store system call parameters in the syscall_params struct
 * and then return with -ERESTARTSYS to trigger a system call.
 */
#define FASTCALL_WRAPPED_SYS(name)                                             \
	long __attribute__((visibility("hidden")))                             \
	wrapped_##name(void *entry[NR_FC_ATTRIBS + 1], long arg1, long arg2,   \
		       long arg3, long arg4,                                   \
		       struct syscall_params *syscall_params)

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
	/*
	 * Address to store the syscall_entry in.
	 *
	 * ULONG_MAX if there is no such symbol in the library.
	 */
	unsigned long syscall_entry;
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

	// Store address of entry_SYSCALL_64 at syscall_entry
	if (image->syscall_entry != ULONG_MAX) {
		unsigned long syscall_entry;
		unsigned long *syscall_entry_addr;

		rdmsrl(MSR_LSTAR, syscall_entry);
		syscall_entry_addr = addr + image->syscall_entry;
		*syscall_entry_addr = syscall_entry;
	}
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

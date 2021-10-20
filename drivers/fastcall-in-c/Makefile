# SPDX-License-Identifier: GPL-2.0

include $(srctree)/lib/fastcall/Makefile

# The fastcall functions written in C are put in a separately compiled
# shared library.
image_objs := functions.o functions_wrapper.o
image_lib := functions.so
image_as_c := fcc_image.c
image := $(image_as_c:%.c=%.o)

# Sanitizer runtimes are unavailable and cannot be linked here.
KASAN_SANITIZE_functions.o := n
UBSAN_SANITIZE_functions.o := n
KCSAN_SANITIZE_functions.o := n
OBJECT_FILES_NON_STANDARD_functions.o	:= y

ftargets := $(image_as_c) $(image_lib) $(image_objs)
targets += $(ftargets)

obj-$(CONFIG_FASTCALL_IN_C)	+= fastcall_in_c.o
# These files are directly linked into the kernel
fastcall_in_c-y	+= fastcall_driver.o $(image)

# This script translates the library into a source file
$(obj)/$(image_as_c): $(obj)/$(image_lib) $(FATSCALL2C_SCRIPT) FORCE
	$(call if_changed,fastcall2c)

# This creates a separate shared library for the fastcall functions
$(obj)/$(image_lib): KBUILD_LDFLAGS := $(FASTCALL_LDFLAGS)
$(obj)/$(image_lib): $(foreach F,$(image_objs),$(obj)/$F)
	$(call if_changed,ld)

$(obj)/functions.o: KBUILD_CFLAGS := $(FASTCALL_CFLAGS)

clean-files += $(ftargets)

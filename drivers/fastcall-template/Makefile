# SPDX-License-Identifier: GPL-2.0

# fastcall_template.o is the resulting object file
# for the module ...
obj-$(CONFIG_FASTCALL_TEMPLATE)	+= fastcall_template.o
# ... it contains these other object files,
# the user-facing fastcall_driver.c and the
# fastcall_functions.S for the actual fastcall functions.
fastcall_template-y	+= fastcall_driver.o fastcall_functions.o

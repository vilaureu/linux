# SPDX-License-Identifier: GPL-2.0

# Compile and linkage flags for fastcall functions written in C
FASTCALL_CFLAGS := -fPIC -O2 -fno-stack-protector $(filter -W%,$(KBUILD_CFLAGS))
FASTCALL_LDFLAGS := -nostdlib -shared -fPIC -Bsymbolic

FATSCALL2C_SCRIPT := $(srctree)/scripts/fastcall2c.py

# This script translates a fastcall function library into a C source file
quiet_cmd_fastcall2c = FC2C    $@
      cmd_fastcall2c = $(PYTHON3) $(FATSCALL2C_SCRIPT) $< $@

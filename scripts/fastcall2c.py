#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2
"""This script converts a shared library with fastcall functions to a C file.

Usage: fastcall2c.py <SOURCE> <DESTINATION>

The destination contains the library as a large array and a struct
describing the library.
The struct needs to be declared in a header file "<source base name>.h"
and the instantiation in the destination looks as follows:
    const struct <destination base name> <destination base name> = {
    .data = <pointer to the large array>,
    .size = <size of the array>,
    .sym_<symbol> = <offset of this exported symbol>,
    [...]
    };

This script is compatible with Python >= 3.6.15.
"""

import sys
from sys import stderr
import os
from os import stat
from subprocess import run, PIPE
import re

BYTES_PER_LINE = 10
PAGE_SIZE = 2**12
NM_REGEX = re.compile("([0-9a-f]{16}) T (.+)")


def main():
    if len(sys.argv) != 3:
        print("Usage: fastcall2c.py <SOURCE> <DESTINATION>", file=stderr)
        exit(1)

    # The name of the header file depends on the source.
    header = basename_root(sys.argv[1]) + ".h"
    # The name of the struct depends on the destination.
    struct = basename_root(sys.argv[2])
    size = stat(sys.argv[1]).st_size
    with open(sys.argv[2], "w") as dst:
        write_destination(dst, header, struct, size)


def write_destination(dst, header, struct, size):
    """Write the C file similar to the vDSO image."""
    dst.write(("/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n"
               "#include <linux/cache.h>\n"
               "#include <linux/linkage.h>\n"
               "#include <asm/page_types.h>\n"
               f'#include "{header}"\n\n'
               f"static const unsigned char raw_data[{size}] __ro_after_init = {{\n"))
    src_bytes = read_source()
    for line in src_bytes:
        dst.write("\t")
        dst.write(", ".join(f"0x{byte:02x}" for byte in line))
        dst.write(",\n")
    dst.write("};\n\n")
    dst.write(f"const struct {struct} {struct} = {{\n")
    dst.write("\t.data = raw_data,\n")
    dst.write(f"\t.size = {size},\n")
    symbols = sorted(source_symbols(), key=lambda s: s[1])
    for (name, address) in symbols:
        address = hex(address)
        dst.write(f"\t.sym_{name} = {address},\n")
    dst.write("};\n")


def read_source():
    """Return tuples of bytes in an iterator."""
    with open(sys.argv[1], "rb") as src:
        while True:
            src_bytes = src.read(BYTES_PER_LINE)
            if not src_bytes:
                break
            yield src_bytes


def source_symbols():
    """Utilize nm to find the symbol offsets in the library."""
    process = run(["nm", "--format=bsd", "--",  sys.argv[1]],
                  stdout=PIPE, encoding='ascii')
    for line in process.stdout.split("\n"):
        match = NM_REGEX.match(line)
        if not match:
            continue

        address = match.group(1)
        yield match.group(2), int(address, 16)


def basename_root(path):
    return os.path.splitext(os.path.basename(path))[0]


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2
"""This script converts a shared library with fastcall functions to a C file.

Usage: fastcall2c.py <SOURCE> <DESTINATION>

The destination contains the library as a large array and a struct
describing the library.
The struct needs to be declared in a header file "<source base name>.h"
and the instantiation in the destination looks as follows:

  const struct <destination base name> <destination base name> = {
    .image = {
        .data = <pointer to the large array>,
        .size = <size of the array>,
        .alt = <offset of .altinstructions>
        .alt_len = <length of .altinstructions>
    },
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
ALT_REGEX = re.compile(
    r"\.altinstructions\s+([0-9A-Fa-f]+)(?:\s+[0-9A-Fa-f]+){2}\s+([0-9A-Fa-f]+)\s+")
EXPORTED_FN_REGEX = re.compile(r"([0-9A-Fa-f]{16}) T (.+)")
UNDEF_SYM_REGEX = re.compile(r"U (.+)")


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
               f'#include "{header}"\n\n'
               f"static const unsigned char raw_data[{size}] = {{\n"))
    src_bytes = read_source()
    for line in src_bytes:
        dst.write("\t")
        dst.write(", ".join(f"0x{byte:02x}" for byte in line))
        dst.write(",\n")
    dst.write("};\n\n")

    dst.write(f"const struct {struct} {struct} = {{\n")
    dst.write("\t.image = {\n")
    dst.write("\t\t.data = raw_data,\n")
    dst.write(f"\t\t.size = {size},\n")

    (alt, alt_len) = alt_sec()
    dst.write(f"\t\t.alt = {hex(alt)},\n")
    dst.write(f"\t\t.alt_len = {alt_len},\n")
    dst.write("\t},\n")

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


def alt_sec():
    """Utilize objdump to get start and length of the .altinstructions section.

    This also checks that the library does not contain .data or .bss sections.
    """
    process = run(["objdump", "--section-headers", "--", sys.argv[1]],
                  stdout=PIPE, encoding='ascii')

    if ".data" in process.stdout or ".bss" in process.stdout:
        print("the library must not contain a .bss or .data section", file=stderr)
        exit(1)

    match = ALT_REGEX.search(process.stdout)
    if not match:
        print("no .alitinstructions section found", file=stderr)
        exit(1)

    return int(match.group(2), 16), int(match.group(1), 16)


def source_symbols():
    """Utilize nm to find the symbol offsets in the library.

    This also checks that the library does not use any undefined symbols which
    a dynamic loader should resolve.
    """
    process = run(["nm", "--format=bsd", "--", sys.argv[1]],
                  stdout=PIPE, encoding='ascii')
    for line in process.stdout.split("\n"):
        line = line.strip()
        match = EXPORTED_FN_REGEX.match(line)
        if match:
            address = match.group(1)
            yield match.group(2), int(address, 16)

        match = UNDEF_SYM_REGEX.match(line)
        if match:
            print(f"undefined symbol '{match.group(1)}' found", file=stderr)
            exit(1)


def basename_root(path):
    return os.path.splitext(os.path.basename(path))[0]


if __name__ == "__main__":
    main()

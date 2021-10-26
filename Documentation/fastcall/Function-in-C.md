# Fastcall Functions in C

This document describes how fastcall functions can be written in C
and how the compilation process in the background works.
An example project can be found in `drivers/fastcall-in-c`

## Make Process

The overall process is inspired by the vDSO.
The idea is to create a shared library which contains the
fastcall functions and can be mapped to the address space
of the application as a whole.
The library itself consists of an ASM file, which contains
the entry points for the fastcall functions.
They set up the stack and preserve important registers.
Afterwards they call the actual fastcall functions, which are
written in C and are contained in accompanying C files.
After linking the library, it is converted into a C array and
a corresponding struct describing the library image and
exported fastcall functions.
This C file is then linked into the kernel (module).

## Features

- Fastcall function can be written in C
- Constant global variables can be used (.rodata section)

## Limitations

- Non-constant global variables can not be used
- Static function variables can not be used either

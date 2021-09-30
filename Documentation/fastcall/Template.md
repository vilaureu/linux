<!-- SPDX-License-Identifier: GPL-2.0 -->

# Fastcall Driver Template

This file documents the module at `drivers/fastcall-template`

## Introduction

This module demonstrates how to use the _fastcall_ architecture
to write own fastcall functions and also functions as a template
for new fastcall drivers.
Fastcall functions are added through drivers which can also be
loaded as a module.

These drivers must implement the following things:

1. Create a _character device_ for interacting with applications.
2. Provide the text segments of _fastcall functions_.
3. Register fastcall function on application requests
   using the fastcall architecture of the kernel.

Applications can register a fastcall function to their address space
using _ioctl_ system calls to the character device.
Afterwards, they can use the new _fastcall system call_ to
execute the fastcall function in their address space.
Deregistration is performed via unmapping the function.

## Overview

This template consists of following files:

| File                   | Description                           |
| ---------------------- | ------------------------------------- |
| `fastcall_driver.c`    | setup + ioctl hander for registration |
| `fastcall_functions.S` | actual fastcall functions             |
| `Kconfig`              | configuration entry for this driver   |
| `Makefile`             | Makefile for this driver              |
| `../Kconfig`           | includes `./Kconfig`                  |
| `../Makefile`          | includes `./Makefile`                 |

## Getting Started

- Copy `fastcall_driver.c`, `fastcall_functions.S`, `Kconfig` and
  `Makefile` to the desired location.
- Modify `../Kconfig` and `../Makefile` to include the new files.
- Create your fastcall functions in `fastcall_functions.S`.
- Implement ioctl handlers for your functions in `fastcall_driver.c`.
- Create an application. You might want to have a look at the
  `application.c` file in this directory.

<!-- SPDX-License-Identifier: GPL-2.0 -->

# Fastcall Architecture

The _fastcall_ architecture aims at providing a complement to system calls.
It allows application to perform low-latency privileged function calls.

## Implementation

Fastcalls are currently implemented as a shortcut into the regular system call
handling.
The idea is to branch off from the system call handler in the kernel as early
as possible and then to execute the privileged functionality without much
overhead.

The memory is layout as follows:

```
/---------------------------------\
| Kernel Space                    |
|=================================|
| Fastcall Space                  |
| (in fact part of user space)    |
| /-------------------------------|
| | Fastcall Table                |
| |-------------------------------|
| | Per-CPU Stacks                |
| | (x86-only)                    |
| |-------------------------------|
| | Memory Mappings for Fastcalls |
| | (data and text segments)      |
| \-------------------------------|
|---------------------------------|
| Regular User Space              |
\---------------------------------/
```

## Setting Up a Fastcall

User-space processes apply for fastcall functions through kernel modules.
Such a module inserts the required text and data segments for a function into
a specific portion of the user space: the _fastcall space_.
These mappings are then protected from malicious manipulations by the
application (e.g. through munmap, mremap, read, write, etc.).
Afterwards, the pointer to the fastcall function is inserted into the _fastcall
table_, which makes the fastcall available to the application.
Finally, the module returns the index into the fastcall table to the
application.

## Invoking A Fastcall

For invoking a fastcall, the application uses the hardware-provided system call
instruction.
A fastcall invocation is identified as such early in the system call handler of
the kernel.
For x86, a specific system call number is used.
For ARM, a specific immediate for `svc` is used.
The application also provides the index into the fastcall table and additional
arguments via the system call interface.
After indexing the table in kernel mode, the fastcall function is executed.
Afterwards, the fastcall function returns to user mode.

During the whole fastcall execution, interrupts are kept disabled.
This allows to use per-CPU stacks under x86, which is necessary because the
normal kernel stacks are protected by KPTI and need `swapgs` for being located.
On ARM, the regular kernel stacks are used.

## FAQ

### How do fastcalls handle multithreading?

Fastcalls themselves are not interruptable.
As such, they can safely use spin locks for mutual exclusion when required.
On x86, this also allows them to use per-CPU stacks without danger of
corruption.

The fastcall implementation itself only requires special care when manipulating
the fastcall table.
This is solved by acquire-release semantics.

### Can fastcall find out which thread they are executed on?

Fastcalls can currently not find out their own thread identification number.
This would require locating more current thread information in the kernel
address space.

### Do fastcalls allow to intercept/replace regular system calls?

Fastcalls are designed as an addition to system calls.
There is currently no interposition implemented.
If fastcall should be executed instead of a libc/system call, `LD_PRELOAD` might
present an alternative for realizing the interposition in user space.

### Can fastcalls share memory between processes?

Yes, the fastcall space consists of virtual memory areas which can reference
physical pages.
Hence, memory areas in two processes can simply reference the same physical
pages when sharing of data is needed.
This is all realized in the registration procedure of the specific fastcall
kernel module (_fastcall provider_).

### Which CPU instruction can fastcalls use?

Fastcalls can generally use all CPU instructions which the kernel can also use.
This should include nearly all instruction which user space uses.
More specifically, also FPU instruction should work without problem as lazy FPU
switching is no longer used in the Linux kernel (for x86 at least).
It should be noted, that accessing user-accessible pages requires dealing with
_SMAP_ which can be quickly done with the `stac` and `clac` instructions.

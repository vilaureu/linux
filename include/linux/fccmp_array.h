// SPDX-License-Identifier: GPL-2.0

#define FCCMP_DATA_SIZE 64
#define FCCMP_ARRAY_LENGTH (PAGE_SIZE / FCCMP_DATA_SIZE)

int fccmp_copy_array(const char *, unsigned char, unsigned char);

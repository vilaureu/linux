// SPDX-License-Identifier: GPL-2.0
/*
 * fccmp_vdso.c - new vDSO functions as a comparison to the fastcall mechanism
 */

/*
 * __vdso_fccmp_noop - simply returns 0
 */
notrace long __vdso_fccmp_noop(void)
{
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * arm64.c - measure the latency of steps in the system call execution on arm64
 */

#include <asm/sysreg.h>
#include <asm/syscall_bench.h>

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/perf_event.h>
#include <linux/smp.h>
#include <linux/syscalls.h>

/* setup_sysregs - configure cycle counter for user reads */
static void setup_sysregs(void *info)
{
	// Configure performance counters and enable them.
	sysreg_clear_set(pmcr_el0, ARMV8_PMU_PMCR_D | ARMV8_PMU_PMCR_DP,
			 ARMV8_PMU_PMCR_E | ARMV8_PMU_PMCR_C |
				 ARMV8_PMU_PMCR_LC);
	// Set pmccntr_el0 enable bit.
	sysreg_clear_set(pmcntenset_el0, 0, 1U << 31);
	// Configure pmccntr_el0 incrementing.
	sysreg_clear_set(pmccfiltr_el0,
			 ARMV8_PMU_EXCLUDE_EL0 | ARMV8_PMU_EXCLUDE_EL1 |
				 ARMV8_PMU_INCLUDE_EL2,
			 0);
	// Enable user access to counters.
	sysreg_clear_set(pmuserenr_el0, ARMV8_PMU_USERENR_MASK,
			 ARMV8_PMU_USERENR_CR);
}

/* syscall_bench_init - initialize cycle counter on all cpus */
static int __init syscall_bench_init(void)
{
	u64 pmcr, pmcntenset, pmccfiltr, pmuserenr;

	if (perf_num_counters() < 1) {
		pr_warn("syscall_bench: performance counters not supported\n");
		return 0;
	}

	on_each_cpu(setup_sysregs, NULL, true);

	pmcr = read_sysreg(pmcr_el0);
	pmcntenset = read_sysreg(pmcntenset_el0);
	pmccfiltr = read_sysreg(pmccfiltr_el0);
	pmuserenr = read_sysreg(pmuserenr_el0);
	pr_info("syscall_bench: pmcr=0x%llx, pmcntenset_el0=0x%llx, "
		"pmccfiltr=0x%llx, pmuserenr=0x%llx\n",
		pmcr, pmcntenset, pmccfiltr, pmuserenr);

	return 0;
}

// Must be executed after armv8_pmu_driver_init.
late_initcall(syscall_bench_init);

/*
 * syscall_bench - measure performance counter, write to user space, and return
 */
SYSCALL_DEFINE1(syscall_bench, uint64_t __user *, measurements)
{
	return syscall_benchmark(&measurements[5]);
}

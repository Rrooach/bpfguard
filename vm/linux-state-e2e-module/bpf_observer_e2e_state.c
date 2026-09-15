// SPDX-License-Identifier: GPL-2.0-only

/*
 * Empty, test-only module used to give the module endpoint-state confirmer a
 * deterministic positive S0/S1 difference in a disposable VM.
 */

#include <linux/init.h>
#include <linux/module.h>

static int __init bpf_observer_e2e_state_init(void)
{
	return 0;
}

static void __exit bpf_observer_e2e_state_exit(void)
{
}

module_init(bpf_observer_e2e_state_init);
module_exit(bpf_observer_e2e_state_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BPF State Observer disposable E2E state marker");

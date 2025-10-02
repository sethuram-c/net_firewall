// SPDX-License-Identifier: GPL-2.0
/* NETFW Phase 2: a minimal loadable kernel module (no filtering yet). */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static int __init netfw_hello_init(void)
{
	pr_info("netfw_hello: module loaded; no packets are filtered\n");
	return 0;
}

static void __exit netfw_hello_exit(void)
{
	pr_info("netfw_hello: module unloaded\n");
}

module_init(netfw_hello_init);
module_exit(netfw_hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NETFW learning project");
MODULE_DESCRIPTION("Phase 2 minimal Linux kernel module");
MODULE_VERSION("0.2");

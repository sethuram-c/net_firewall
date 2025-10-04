// SPDX-License-Identifier: GPL-2.0
/* Phase 4: learn kernel heap allocation and failure-safe cleanup. */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#define NETFW_MESSAGE_SIZE 128

static char *netfw_message;

static int __init netfw_hello_init(void)
{
	/* GFP_KERNEL is suitable for this process-context initialization. */
	netfw_message = kmalloc(NETFW_MESSAGE_SIZE, GFP_KERNEL);
	if (!netfw_message) {
		pr_err("netfw_hello: kmalloc failed\n");
		return -ENOMEM;
	}

	strscpy(netfw_message, "allocated kernel memory safely", NETFW_MESSAGE_SIZE);
	pr_info("netfw_hello: %s; no packets filtered\n", netfw_message);
	return 0;
}

static void __exit netfw_hello_exit(void)
{
	kfree(netfw_message);
	netfw_message = NULL;
	pr_info("netfw_hello: memory released; module unloaded\n");
}

module_init(netfw_hello_init);
module_exit(netfw_hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NETFW learning project");
MODULE_DESCRIPTION("Phase 4 kernel allocation and cleanup demo");
MODULE_VERSION("0.4");

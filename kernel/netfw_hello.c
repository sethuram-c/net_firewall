// SPDX-License-Identifier: GPL-2.0
/* Phase 5: acquire resources in order; release them in reverse order. */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#define NETFW_MESSAGE_SIZE 128
#define NETFW_LABEL_SIZE 32

static char *netfw_message;
static char *netfw_label;
/* 0: normal, 1: fail before first allocation, 2: fail after first. */
static int fail_step;
module_param(fail_step, int, 0444);
MODULE_PARM_DESC(fail_step, "Demo only: force init failure at step 1 or 2");

static int __init netfw_hello_init(void)
{
    int err = -ENOMEM;

    /* All startup paths begin with empty ownership. */
    netfw_message = NULL;
    netfw_label = NULL;

    if (fail_step == 1) {
        pr_warn("netfw_hello: injected failure before first allocation\n");
        return -ENOMEM;
    }

    netfw_message = kmalloc(NETFW_MESSAGE_SIZE, GFP_KERNEL);
    if (!netfw_message) {
        pr_err("netfw_hello: kmalloc failed for message\n");
        return -ENOMEM;
    }
    strscpy(netfw_message, "allocated kernel memory safely", NETFW_MESSAGE_SIZE);

    if (fail_step == 2) {
        pr_warn("netfw_hello: injected failure after first allocation\n");
        goto err_free_message;
    }

    netfw_label = kmalloc(NETFW_LABEL_SIZE, GFP_KERNEL);
    if (!netfw_label) {
        pr_err("netfw_hello: kmalloc failed for label\n");
        goto err_free_message;
    }
    strscpy(netfw_label, "phase5", NETFW_LABEL_SIZE);
    pr_info("netfw_hello: %s; label=%s; no packets filtered\n",
            netfw_message, netfw_label);
    return 0;

err_free_message:
    kfree(netfw_message);
    netfw_message = NULL;
    return err;
}

static void __exit netfw_hello_exit(void)
{
    kfree(netfw_label);
    netfw_label = NULL;
    kfree(netfw_message);
    netfw_message = NULL;
    pr_info("netfw_hello: memory released; module unloaded\n");
}

module_init(netfw_hello_init);
module_exit(netfw_hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NETFW learning project");
MODULE_DESCRIPTION("Phase 5 multi-resource initialization and unwind demo");
MODULE_VERSION("0.5");

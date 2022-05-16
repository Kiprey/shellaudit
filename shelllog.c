#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");

#define DRIVERNAME "shelllog"
#define LOG(x...) \
    printk("shelllog: " x)

static int __init shelllog_init(void)
{
    LOG("mod start\n");
    return 0;
}

static void __exit shelllog_exit(void)
{
    LOG("mod exit\n");
}

module_init(shelllog_init);
module_exit(shelllog_exit);
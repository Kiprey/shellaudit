#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>


MODULE_LICENSE("Dual BSD/GPL");

#define DRIVERNAME "shelllog"
#define LOG(x...) \
    pr_info("shelllog: " x)

#define ERR(x...) \
    pr_err("shelllog: " x)

// linux/fs/exec.c
// linux/arch/x86/include/asm/ptrace.h:59

static struct kprobe kp_execve, kp_execveat;

static int __kprobes log_execve(struct kprobe *p, struct pt_regs *regs) {
    // LOG("execve path: %s", (char*)regs->di);
    // TODO

    return 0;
}

static int __kprobes log_execveat(struct kprobe *p, struct pt_regs *regs) {
    // TODO

    return 0;
}

static int do_register_kprobe(struct kprobe* kp, char* symbol_name, void* handler) {
    int ret;

    kp->symbol_name = symbol_name;
    kp->pre_handler = handler;

    ret = register_kprobe(kp);
    if (ret < 0) {
        ERR("do_register_kprobe: failed to register for symbol %s, returning %d\n", symbol_name, ret);
        return ret;
    }

    LOG("Planted krpobe for symbol %s at %p\n", symbol_name, kp->addr);

    return ret;
}

static int __init shelllog_init(void)
{
    int status;

    LOG("mod start\n");

    status  = do_register_kprobe(&kp_execve, "__x64_sys_execve", log_execve);
    if (status < 0) 
        return -ENOMEM;

    status = do_register_kprobe(&kp_execveat, "__x64_sys_execveat", log_execveat);
    if (status < 0) {
        // cleaning initial krpobe
        unregister_kprobe(&kp_execve);
        return -ENOMEM;
    }
    
    return 0;
}

static void __exit shelllog_exit(void)
{
    LOG("mod exit\n");
    unregister_kprobe(&kp_execve);
    unregister_kprobe(&kp_execveat);
}

module_init(shelllog_init);
module_exit(shelllog_exit);
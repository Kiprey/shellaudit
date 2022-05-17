#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>
#include <linux/skbuff.h>
#include <linux/selinux_netlink.h>
#include <net/net_namespace.h>
#include <net/netlink.h>


MODULE_LICENSE("Dual BSD/GPL");

#define DRIVERNAME "shelllog"
#define NETLINK_PROTOCOL 30
#define USER_PORT 100

#define LOG(x...) \
    pr_info("shelllog: " x)

#define ERR(x...) \
    pr_err("shelllog: " x)

#define assert(expr) \
    if (unlikely(!(expr))) {				\
        ERR("Assertion failed! %s,%s,%s,line=%d\n",	\
                #expr, __FILE__, __func__, __LINE__);	\
    }

// linux/fs/exec.c
// linux/arch/x86/include/asm/ptrace.h:59

// 用于探测的探针
static struct kprobe kp_execveat;

// 用于将用户通过 netlink 发送来的数据输出的处理例程
static void netlink_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    char *umsg = NULL;

    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        umsg = NLMSG_DATA(nlh);
        if(umsg) // 如何处理要根据实际的数据结构来定义
        {
            print_hex_dump(
                KERN_INFO, "raw data: ", DUMP_PREFIX_OFFSET, 
                16, 1, umsg, nlh->nlmsg_len, true);
        }
    }
}

// 与用户层通信的 socket
struct sock *nlsk = NULL;
// netlink 全局配置
struct netlink_kernel_cfg cfg = { 
    .input = netlink_rcv_msg, /* set recv callback */
};

// 向用户层发送数据
int netlink_send_msg(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;
 
    int ret;
 
    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        ERR("netlink alloc failure\n");
        return -1;
    }
 
    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, 0, len, 0);
    if(nlh == NULL)
    {
        ERR("nlmsg_put failure\n");
        // nlmsg_free(nl_skb);
        return -1;
    }
 
    /* 拷贝数据发送 */
    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = nlmsg_unicast(nlsk, nl_skb, 100);
 
    return ret;
}

// 复制字符串指针
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)
#define MAX_ARG_STRINGS 0x7FFFFFFF
int copy_strings(const char __user *const __user * userp, char*** buf) {
    const char __user *p;
    int nr = 0, len = 0, copylen = 0;
    char **newbuf;

    // 获取长度
    for (;;) {
        if (get_user(p, userp + nr))
            return -EFAULT;

        if (!p)
            break;

        if (nr >= MAX_ARG_STRINGS)
            return -E2BIG;
        ++nr;
    }
    
    // 分配内存
    newbuf = (char **)kmalloc(nr + 1, GFP_KERNEL);
    newbuf[nr] = NULL;

    // 复制参数
    for(int i = 0; i < nr; i++) {
        if (get_user(p, userp + i))
            return -EFAULT;
        len = strnlen_user(p, MAX_ARG_STRLEN);
        newbuf[i] = kmalloc(len + 1, GFP_KERNEL);
        copylen = strncpy_from_user(newbuf[i], p, len + 1);
        assert(copylen <= len);
    }

    *buf = newbuf;
    return nr;
}

void free_strings(char** ptrs, int size) {
    for(int i = 0; i < size; i++) {
        kfree(ptrs[i]);
    }
    kfree(ptrs);
}

// 进行挂钩处理

// extern long __x64_##sym(const struct pt_regs *)
static int __kprobes log_execve(struct kprobe *p, struct pt_regs *regs) {
    char *kfilename;
    long len, copylen;

    struct pt_regs* execve_regs;
    const char __user *filename;
    const char __user *const __user * argv;
    const char __user *const __user *  env;

    char** kargv, ** kenv;
    int kargc, kenvc;
    
    execve_regs = (struct pt_regs*)regs->di;

    // 获取路径
    filename = (char*) execve_regs->di;
    len = strnlen_user(filename, PATH_MAX);
    kfilename = kmalloc(len + 1, GFP_KERNEL);
    copylen = strncpy_from_user(kfilename, filename, len + 1);
    assert(copylen <= len);

    LOG("execve path: %s\n", kfilename);

    // 获取参数
    argv = (const char __user *const __user *) execve_regs->si;
    kargc = copy_strings(argv, &kargv);
    if(kargc < 0)
        return kargc;

    LOG("arguments: \n");
    for(int i = 0; i < kargc; i++)
        LOG("\targv%d: %s\n", i, kargv[i]);

    // 获取环境变量
    env =  (const char __user *const __user *) execve_regs->dx;
    kenvc = copy_strings(env, &kenv);
    if(kenvc < 0)
        return kenvc;

    LOG("environments: \n");
    for(int i = 0; i < kenvc; i++)
        LOG("\tenv%d: %s\n", i, kenv[i]);
    
    // TODO 发送信息

    // 回收资源
    kfree(kfilename);   
    free_strings(kargv, kargc);
    free_strings(kenv, kenvc);

    return 0;
}

// 插入 kprobe
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

    /* create netlink socket */
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_PROTOCOL, &cfg);
    if(nlsk == NULL)
    {   
        ERR("netlink_kernel_create error !\n");
        return -1; 
    } 

    status  = do_register_kprobe(&kp_execveat, "__x64_sys_execve", log_execve);
    if (status < 0) 
        return -1;

    return 0;
}

static void __exit shelllog_exit(void)
{
    LOG("mod exit\n");
    unregister_kprobe(&kp_execveat);
}

module_init(shelllog_init);
module_exit(shelllog_exit);
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

// 进行挂钩处理
static int __kprobes log_execveat(struct kprobe *p, struct pt_regs *regs) {
    /*
    int fd = regs->di;
    struct filename * filename = regs->si;
    struct user_arg_ptr argv = regs->dx;
	struct user_arg_ptr envp = regs->cx;
    int flags = regs->r8;

    const char __user *const __user *__argv = argv.,
	const char __user *const __user *__envp

    LOG("execve path: %px\n", (char*)regs->di);
    print_hex_dump(
        KERN_INFO, "execve path: ", DUMP_PREFIX_OFFSET, 
        16, 1, (char*)regs->di, 0x30, true);
    */

    // TODO
    char str[0x20] = "execveat triggered.";
    netlink_send_msg(str, strlen(str) + 1);

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

    status  = do_register_kprobe(&kp_execveat, "do_execveat_common", log_execveat);
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
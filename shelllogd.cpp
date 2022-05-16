#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
// #include "nlohmann/json.hpp"
using namespace std;

#define NO_ERROR 0
#define ERROR 1
#define WARNING 2
// #define TEST
#define DAEMON

#define NETLINK_PROTOCOL 30
/*

    // create netlink socket
    nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_PROTOCOL, &cfg);
    if(nlsk == NULL)
    {
        printk("netlink_kernel_create error !\n");
        return -1;
    }
    printk("test_netlink_init\n");
*/
#define MSG_LEN 8192

#define ERR_EXIT(m)         \
    do                      \
    {                       \
        perror(m);          \
        exit(EXIT_FAILURE); \
    } while (0);

string log_file = "/var/log/shellaudit.log"; // will append log in this file

void creat_daemon(void);

typedef struct _user_msg
{
    struct nlmsghdr hdr;
    char msg[MSG_LEN];
} user_msg;
string get_time()
{
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
void log(string &&msg, int level = NO_ERROR)
{
    switch (level)
    {
    case NO_ERROR:
        msg = get_time() + " [INFO]: " + msg + "\n";
        break;
    case WARNING:
        msg = get_time() + " [WARNING]: " + msg + "\n";
        break;
    case ERROR:
        msg = get_time() + " [ERROR]: " + msg + "\n";
        break;
    default:
        msg = get_time() + " [INFO]: " + msg + "\n";
        break;
    }

    printf("%s", msg.c_str());
    int fd = open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1)
        ERR_EXIT("open user.log error");
    write(fd, msg.c_str(), msg.size());
    close(fd);
}

void start_work(int _protocol = NETLINK_PROTOCOL, unsigned int _saddr_nl_pid = 100)
{
    int skfd;
    skfd = socket(AF_NETLINK, SOCK_RAW, _protocol);
    if (skfd == -1)
    {
        log("create socket error", ERROR);
        return;
    }
    struct sockaddr_nl saddr, daddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = _saddr_nl_pid;
    saddr.nl_groups = 0;
    if (bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        log("bind() error", ERROR);
        close(skfd);
        return;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;

    int ret;

    const char *msg = "hello world";
    nlmsghdr *nlh = (nlmsghdr *)malloc(NLMSG_SPACE(MSG_LEN));
    nlh->nlmsg_len = NLMSG_SPACE(MSG_LEN);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid;
#ifdef TEST
    memcpy(NLMSG_DATA(nlh), msg, strlen(msg));
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (sockaddr *)&daddr, sizeof(sockaddr_nl));
    if (!ret)
    {
        log("sendto error", ERROR);
        free(nlh);
        close(skfd);
        return;
    }
    log("send: " + string(msg));
#endif

    socklen_t len;
    user_msg u_info;

    while (true)
    {
        memset(&u_info, 0, sizeof(u_info));
        len = sizeof(struct sockaddr_nl);
        ret = recvfrom(skfd, &u_info, sizeof(user_msg), 0, (struct sockaddr *)&daddr, &len);
        if (!ret)
        {
            perror("recv form kernel error\n");
            free(nlh);
            close(skfd);
            return;
        }
#ifdef TEST
        log("recv: " + string(u_info.msg));
        break;
#else
        log(string(u_info.msg));
#endif
    }
    free(nlh);
    close(skfd);
}

int main(int argc, char **argv)
{
#ifdef DAEMON
    if (daemon(0, 0) == -1)
        ERR_EXIT("daemon error");
    start_work();
#else
    start_work();
#endif
    return 0;
}
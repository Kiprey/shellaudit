# shellaudit

## 简介

- 该工具用于记录 Linux execve 系统调用情况，以便于进行 shell 执行审计。
- 信息系统安全课设

## 背景

- Linux 系统现行的安全审计机制是在应用程序级实现的，它是通过独立于操作系统的审计程序 syslogd 来记录用户登陆和相关操作的信息的。
- 用户执行 shell 程序记录通常位于 `~/.bash_history` 路径下。当用户通过 shell 执行了一些命令后，其执行情况将被记录在该文件中：
  
    ```bash
    $ cat ~/.bash_history | tail -n 5                                    
    id
    ls
    git status
    rm -r libs/2.34-0ubuntu3_amd64/
    ./download 2.34-0ubuntu3_amd64
    ```

  但这种记录相当的简陋，没有记录下时间戳信息，也没有记录下执行环境......。同时， 日志文件`~/.bash_history` 还可被入侵者恶意删除，以抹去供给痕迹。

由于系统实现安全审计功能的是应用程序，因而入侵者取得一定的权限后有可能绕过 syslogd，而使其入侵操作不被记录，甚
至抹掉所有的审计信息和入侵记录。

因此，该工具用于记录日常 shell 执行程序时的情况，以便于后续进行分析。

## 概述

该工具主要由两部分构成：Linux 内核驱动 **shelllog.ko** 与守护进程 **shelllogd**。

### 1. shelllog.ko

1. 在 load 时自动使用 kprob 探针劫持 execve 相关函数。 
2. 当有控制流执行 SYS_execve 时，自动获取其 
    1. path
    2. 参数
    3. 环境变量
    4. 调用者信息
    5. 父进程链
   并将该信息通过 netlink 传给守护进程。若不存在守护进程，则不发送任何信息。
3. 在 unload 时自动解除探针。

### 2. shelllogd

守护进程将获取到的这些信息，以合理的方式组织成一条日志，并将该日志保存在 `/var/log/shelllog` 中。

注意，该日志文件属主必须是 root，以防止被恶意用户删除。通常用 root 权限启动的守护进程，创建文件的属主将默认为 root，因此这点应该无需担心。

改进点：直接将日志信息保存在日志中，可能会使得日志文件急剧增大。因此可以模仿 syslogd 的设计，当当前写入的日志文件大小达到某个阈值后，将该文件压缩为 `.tar.gz` 压缩包，以降低占用空间。该改进点可在设计上暂时忽略。

## 构建过程

### 1. 内核编译与构建

参照 [Linux 内核编译过程](https://kiprey.github.io/2021/10/kernel_pwn_introduction/#%E4%BA%8C%E3%80%81%E7%8E%AF%E5%A2%83%E9%85%8D%E7%BD%AE)，进行 Linux 配置。

注意点：
  1. busybox-1.34.1 源码文件夹路径必须在 Linux 源码文件夹中
  2. 将解压后的 Linux 源码文件夹，符号链接至项目根路径下的 **linux 软连接**

> 如果一切配置正常，则命令 `ls linux/busybox-1.34.1` 将会正常输出。

### 2. 运行

根据自己机器上的条件，修改并运行 `sudo ./run.sh` 命令以启动脚本，自动运行编译命令，并将编译后的二进制文件打包进内核的文件系统中，并自动启动 QEMU 内核和 GDB 调试器。

在 qemu 中，运行 `whoami` 命令查看当前是否为 root 用户，如果不是则需要修改 init 脚本（见上面的博文）
之后运行 `insmod shelllog.ko` 安装内核驱动，并手动启动 shelllogd 守护进程。
> 这一步可以直接添加进 init 脚本中做到开机自启，无需每次启动时都需要手动运行。

生成的日志如下所示：

```bash
2022-05-31 11:41:40 [INFO]: ===============================
execve path: /bin/cttyhack
arguments: 
    argv0: /bin/cttyhack
    argv1: setuidgid
    argv2: 0
    argv3: /bin/sh
environments: 
    env0: SHLVL=1
    env1: HOME=/
    env2: TERM=linux
    env3: PWD=/
pid: 80
uid: 0, gid: 0, suid: 0, sgid: 0,euid: 0, egid: 0, fsuid: 0, fsgid: 0
pwd: /
root: /
Process Tree:           
    1: setsid(80)
    2: init(1)
    3: swapper/0(0)

```

可以运行 `rmmod shelllog` 以卸载驱动程序。

若需要强制关闭嵌入在终端的 QEMU，则先按下 ctrl + a，**松手** 再按下 x 即可关闭 QEMU。

## 参考

[1] 须文波,王斌,冯斌.Linux审计功能的分析和扩展[J].现代计算机(专业版),2003(09):22-24.

> PDF 原文附件已同步至仓库根目录下。
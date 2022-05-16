#! /bin/bash

# 判断当前权限是否为 root，需要高权限以执行 gef-remote --qemu-mode
user=$(env | grep "^USER" | cut -d "=" -f 2)
if [ "$user" != "root"  ]
  then
    echo "请使用 root 权限执行"
    exit
fi

# 编译程序
# shelllogd 源码编译命令，注意使用静态编译
g++ ./shelllogd.cpp -o ./shelllogd -static
# 编译驱动
make
# 复制文件至 rootfs
cp ./shelllogd shelllog.ko linux/busybox-1.34.1/_install

# 构建 rootfs
pushd linux/busybox-1.34.1/_install
find . | cpio -o --format=newc > ../../rootfs.img
popd

gnome-terminal -e 'gdb -x mygdbinit'

# 启动 qemu
qemu-system-x86_64 \
	-kernel ./linux/arch/x86/boot/bzImage \
	-initrd ./linux/rootfs.img \
    -append "nokaslr" \
    -m 2G \
    -s  \
    -S \
    -nographic -append "console=ttyS0"

    # -s ： 等价于 -gdb tcp::1234， 指定 qemu 的调试链接
    # -S ：指定 qemu 启动后立即挂起

    # -nographic                # 关闭 QEMU 图形界面
	# -append "console=ttyS0"   # 和 -nographic 一起使用，启动的界面就变成了当前终端
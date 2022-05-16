# 指定声称哪些 内核模块
obj-m += shelllog.o

# 指定内核项目路径
KDIR=linux/

all:
	# -C 参数指定进入内核项目路径
	# -M 指定驱动源码的环境，使 Makefile 在构建模块之前返回到 驱动源码 目录，并在该目录中生成驱动模块
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
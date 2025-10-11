---
title: Linux内核调试
published: 2025-03-20
description: '本文介绍了Linux内核调试的基本流程，包括源码获取、内核编译、文件系统镜像加载、QEMU启动以及GDB调试。通过关闭内核地址随机化（KASLR）和开启调试信息，确保内核可调试性。文章详细描述了如何使用syzkaller生成文件系统镜像，并通过QEMU启动虚拟机进行调试。最后，通过GDB远程连接到虚拟机内核，完成断点设置和调试操作'
image: ''
tags: [内核调试]
category: '技术'
draft: false 
lang: ''
---

# 源码获取

首先拖源码与补丁

```shell
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.4.1.tar.gz
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/patch-4.4.1.xz
tar zxvf linux-4.4.1.tar.gz 
xz -d patch-4.4.1.xz | patch -p1							# 这里没有输出代表执行成功
```

# 内核编译

```shell
cd linux-4.4.1
make x86_64_defconfig		   # 加载默认config
make menuconfig		# 自定义config
```

要进行打断点调试，需要关闭系统的随机化和开启调试信息：

```
Processor type and features  ---> 
    [ ] Build a relocatable kernel                                               
        [ ]  Randomize the address of the kernel image (KASLR) (NEW) 


Kernel hacking  --->
    Compile-time checks and compiler options  --->  
        [*] Compile the kernel with debug info                                                                  
        [ ]   Reduce debugging information                                                                      
        [ ]   Produce split debuginfo in .dwo files                                                             
        [*]   Generate dwarf4 debuginfo                                         
        [*]   Provide GDB scripts for kernel debugging
```

之后进行编译

```shell
make -j32
```

如果遇到编译错误`cc1: error: code model kernel does not support PIC mode`，则在MakeFile中的KBUILD_CFLAGS选项中加入`-fno-pie`

之后在进行make即可。

# 加载文件系统镜像

这里可以使用`syzkaller`的生成脚本

```shell
cd linux-4.4.1
sudo apt-get install debootstrap
wget https://github.com/google/syzkaller/blob/master/tools/create-image.sh -O create-image.sh	# 这里我得到的是一个html页面，最终笔者自行访问页面复制了相关的代码。
chmod +x create-image.sh
./create-image.sh				# 这里会在当前目录生成 stretch.img
```

# 启动qemu

这里的`-nographic`以及`-s`一定要加，执行命令后会启动生成的linux系统，并得到一个shell，这里可以不指定-net参数，默认会有一个NAT的网络，可以访问外网。

```shell
cd linux-4.4.1 &&
sudo qemu-system-x86_64 \
	-s \
    -kernel ./arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial"\
    -drive file=./bullseye.img,format=raw \
    -nographic
    -pidfile vm.pid \
    2>&1 | tee vm.log
```

# gdb调试

```shell
cd linux-4.4.1
gdb vmlinux
gef➤  target remote:1234		# 连接到远程调试接口
# 后面就可以正常进行调试了
```

![QQ_1742479786343](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250320221154962.png)


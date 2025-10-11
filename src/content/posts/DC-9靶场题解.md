---
title: DC-9靶场题解
published: 2025-07-04
description: '本文内容为DC-9靶场题解，DC-9 是一个包含真实漏洞场景的靶场，模拟了企业级环境中常见的安全防护机制（如敲门服务）与漏洞，适合用于渗透测试实战演练与提权技巧学习。'
image: ''
tags: [渗透测试]
category: '技术'
draft: false 
lang: ''
---
## 信息收集

确定靶机地址，查看网段地址：

![图片 1](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804000251523.png)

利用nmap扫描：

![图片 2](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001530649.png)

排除发现192.168.159.1为windows服务，192.168.159.254为wmnet 1网卡地址

所以靶机地址为192.168.159.153

### 探测主机开放端口及对应服务

发现目标主机只开放了80端口，是web服务

![图片 3](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001533507.png)

访问靶机网站

![图片 4](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001538653.png)

### 探测网站目录结构

利用dirsearch扫描网站

![图片 5](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001542715.png)

扫描出来的 url 路径，接下来去就需要自己去一一查看。这次查看之后没有发现有用的数据。所以只能去网站看看有没有利用的点。

## 字典收集，尝试登录

打开网站发现网站记录大量”员工“的名字、邮件、手机号等敏感信息，然后也找到登录提交页面，登录次数没有进行限制，尝试利用邮箱、手机号、名字制作用户名和密码字典，然后使用 burpsuite 进行爆破测试。

![图片 6](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001547384.png)

Burp抓包，并发送到爆破模块

![图片 7](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001551567.png)

设置攻击类型和攻击位置

![图片 8](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001556003.png)

开始攻击，结果显示没有攻击成功

![图片 9](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001600436.png)

## sql注入

在网站这个地方发现有查询用户姓名和姓氏的功能，带有一个参数 search，推断可能存在sql注入点， 接下来使用sqlmap进行验证。

![图片 10](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001624452.png)

查询所有数据库

![图片 11](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001627226.png)

![图片 12](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001832511.png)

得到三个数据库名

查询指定数据库中所有表

![图片 13](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001834826.png)

得到一个表UserDetails

查询表中的数据

![图片 14](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001837110.png)

![图片 15](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001839020.png)

继续查询另一个数据库中的内容

![图片 16](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001842069.png)

看出该密码为MD5加密，在https://www.somd5.com/网站解密得transorbital1

![图片 17](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001844068.png)

利用该内容成功以管理员身份登录

![图片 18](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001848259.png)

## 本地文件包含利用

一般获取 web 网站的账号密码登录成功之后，首先查询系统提供的功能是否存在文件上传利用点或远程代码执行漏洞获取 webshell。但这次没有发现相关利用点，但找到了一个本地文件包含利用点。

![图片 19](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001852029.png)

![图片 20](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909579.png)

![图片 21](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909580.png)

通过文件包含的利用点，查看系统主机上的敏感文件内容，最终发现一个文/etc/knockd.conf 文件，发现通过顺序访问指定端口就能打开主机 ssh 22 端口。

![图片 22](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909581.png)

检验端口是否开启,发现 22 端口成功开放

![图片 23](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909582.png)

## SSH暴力登录

利用直接 sqlmap --dump 拖库拿到的明文账号和密码设置字典进行 ssh 强制登录，这里使用的到的工具是 hyder, hyder 支持多种协议的登录爆破。SSHH 文本就是 用户名：密码 这样的格式自己创建一个密码本 TXT 文本。

设置的字典内容为：

![图片 24](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909583.png)

拿到ssh账户之后，依次登录这些用户进行提权尝试和敏感数据找寻。经过尝试之后，发现这三个账户都不能提权为 root 用户

![图片 25](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909584.png)

![图片 26](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909585.png)

![图片 27](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909586.png)

![图片 28](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909587.png)

在 janitor 家目录发现一个密码备份文件，将对应的密码加入到之前的账号密码字典中，尝试暴力出其它账户。

![图片 29](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909588.png)

![图片 30](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909589.png)

制作username爆破文件

![图片 31](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909590.png)

制作密码爆破文件，加入新的密码

![图片 32](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909591.png)

发现新爆破出另一个账号

![图片 33](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909592.png)

进行ssh登录，成功登录：

![图片 34](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909593.png)

查看权限：

![图片 35](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909594.png)

进入提示的文件夹，尝试执行test文件

![图片 36](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909595.png)

提示需要test.py

![图片 37](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909596.png)

发现test.py文件

![图片 38](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909597.png)

查看代码内容，意思是将第一个文件的内容写入第二个文件中

![图片 39](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909598.png)

所以我们可以创建一个文件写入我们自己登录的账户信息

先使用 openssl 工具生成一个密码的 hash 值：

```shell
openssl passwd -1 -salt demon 123456
```

![图片 40](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909599.png)

将我们的登录信息写入到 tmp 目录下的 demon

![图片 41](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909600.png)

再利用 test 将/tmp/demon 的内容写入到/etc/passwd

![图片 42](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909601.png)

切换用户到我们创建的 demon 用户，执行 whoami 查看当前权限，是 root，提权成功

![图片 43](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909602.png)

打开交互模式：

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
```

![图片 44](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909603.png)

成功在根目录下找到flag

![图片 45](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250804001909604.png)
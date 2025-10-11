---
title: UOS 20 配置LNMP
published: 2025-08-03
description: '本文介绍了在UOS 20下配置LNMP的基本方法，包括Nginx，Maria数据库，PHP等的安装配置。'
image: ''
tags: [UOS]
category: '技术'
draft: false 
lang: ''
---


## 安装配置nginx

```shell
sudo apt update
sudo apt install nginx
```

编辑nginx配置

首先删除/etc/nginx/sites-enabled中的默认配置文件default

新建test.conf文件，内容如下

```shell
# 定义 HTTP 服务器块
server {
    # 监听 80 端口（HTTP 默认端口）
    listen 80;
    
    # 设置网站根目录路径
    root /var/www/html;
    
    # 设置服务器名称，_ 表示匹配所有域名
    server_name _;
    
    # 字符集设置
    #charset koi8-r;
    
    # 访问日志路径设置
    #access_log /var/log/nginx/log/host.access.log main;
    
    # 定义 location 块，匹配所有请求
    location / {
        # 指定默认索引文件查找顺序
        index index.php index.html index.htm;
    }
    
    # 自定义 404 错误页面
    #error_page 404 /404.html;
    
    # 定义 50x 系列错误页面
    error_page 500 502 503 504 /50x.html;
    
    # 精确匹配 50x.html 请求
    location = /50x.html {
        # 设置错误页面的根目录
        root /var/www/html;
    }
    
    # 处理 PHP 脚本的 location 块
    # 使用正则表达式匹配所有 .php 结尾的请求
    location ~ \.php$ {
        # 将 PHP 请求转发到 FastCGI 服务器（通常是 PHP-FPM）
        fastcgi_pass 127.0.0.1:9000;
        
        # 设置 FastCGI 默认索引文件
        fastcgi_index index.php;
        
        # 设置 FastCGI 参数，指定脚本文件路径
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        
        # 包含 FastCGI 通用参数配置文件
        include fastcgi_params;
    }
}
```

启动并设置开机自启

```shell
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## CGI与Fast CGI

![](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250712152215821.png)

CGI (Common Gateway Interface) 是一种在Web 服务器和外部程序之间传递数据的标准协议，它允许服务器与外部程序进行交互，从而生成动态网页内容。简单来说，CGI 就像一个中间人，负责将用户在网页上提交的数据传递给服务器端的程序，然后将程序处理后的结果返回给用户。﻿

FastCGI 是一种让交互程序(如网站应用程序) 与Web 服务器通信的协议，它是 CGI 的一个改进版本。FastCGI 通过减少每次请求都需要重新启动程序的开销，从而显著提高性能和可扩展性。简单来说，FastCGI 允许Web 服务器与动态脚本语言(如PHP) 之间更高效地通信，从而可以同时处理更多的Web 请求。﻿

### 两者对比  

### **传统 CGI 的问题**

- **每次请求都启动新进程**：用户每次访问动态页面Web 服务器会启动一个新的 PHP 解释器进程来处理请求，处理完立即关闭。  
- **高开销**：频繁的进程创建和销毁会消耗大量 CPU 和内存，导致 **并发能力差**。
- **依赖本地进程**：CGI 通常通过 **本地 Shell 或管道（pipe）** 与 Web 服务器通信，无法跨机器部署。  
- **性能瓶颈**：如果 PHP 脚本较复杂，Web 服务器会被阻塞，影响整体性能。 
- **环境变量传递**：CGI 依赖 **环境变量（如 `QUERY_STRING`）** 传递请求参数，数据量有限，且解析复杂。  
- **无状态**：每次请求都是独立的，无法共享上下文（如数据库连接池）。  
- **与 Web 服务器同权限**：CGI 进程通常以 Web 服务器（如 `www-data`）身份运行，存在安全风险（如 PHP 漏洞影响整个服务器）。

### **FastCGI 的改进**

- **进程池**：FastCGI 预先启动一组 **长期运行** 的 Worker 进程（如 PHP-FPM），处理完请求后 **不退出**，而是等待下一个请求。  
- **复用进程**：多个 HTTP 请求可以 **复用同一个 FastCGI 进程**，避免了反复创建和销毁进程的开销。  
- **基于 TCP/IP 或 Unix Socket**：FastCGI 进程可以运行在 **独立服务器** 上，通过 **网络协议** 与 Web 服务器通信（如 Nginx → PHP-FPM）。  
- **非阻塞通信**：Web 服务器可以异步发送请求，不阻塞自身运行。  
- **二进制协议**：FastCGI 使用 **结构化二进制数据** 传输请求（比文本解析更快）。   
- **持久化上下文**：FastCGI 进程可以 **保持状态**（如数据库连接复用）。  
- **独立进程**：FastCGI 进程（如 PHP-FPM）可以以 **低权限用户** 运行，减少攻击面。  
- **资源隔离**：Web 服务器和 FastCGI 进程可以部署在不同的沙盒或容器中。  

## 安装数据库管理系统

安装mariadb数据库（mysql的社区版本）

```shell
sudo apt install mariadb-server mariadb-client #安装
sudo systemctl start mariadb  #启动
sudo systemctl enable mariadb #设置开机自启动
```

## 安装PHP

```shell
sudo apt install php7.3 php7.3-bcmath php7.3-cli php7.3-common php7.3-curl php7.3-fpm php7.3-gd php7.3-gmp php-imagick php7.3-intl php7.3-json php7.3-mbstring php7.3-mysql php-pear php7.3-xml php7.3-xmlrpc php7.3-zip php7.3-imap -y
sudo systemctl start php7.3-fpm
systemctl enable php7.3-fpm
sudo apt purge `dpkg -l | grep php8.1| awk '{print $2}' |tr "\n" " "`
```

修改nginx配置以支持php

修改fastcgi_pass内容为：

```shell
fastcgi_pass   unix:/var/run/php/php7.4-fpm.sock; #将 PHP 请求转发到 PHP-FPM 的 Unix Socket 文件（通常由 PHP-FPM 生成），实现高效本地进程间通信（IPC）。
```

* `fastcgi_pass` 是 Nginx 中用于 **将 PHP/Python 等动态请求转发给 FastCGI 服务器（如 PHP-FPM）** 的核心指令，决定了动态内容如何被处理。

重启nginx服务

```shell
sudo systemctl restart nginx
```

访问服务器IP地址，成功响应

![image-20250712153936199](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250712153937749.png)
---
title: Upload-Lab 题解
published: 2025-08-03
description: '本文内容为Upload-Lab靶场的部分题解，重点记录了文件上传攻击的常见手段'
image: ''
tags: [文件上传攻击]
category: '总结'
draft: false 
lang: ''
---

## Pass-01

上传.jpg文件的shell文件，抓包修改后缀名为php

![图片 2](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717140654683.png)

![img](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717140710579.jpg)

## Pass-02

分析代码，可以看到，后端PHP代码只对content-type进行了检查

使用bp抓包，修改上传的PHP的content-type为image/png等允许的格式

## Pass-03

分析代码，进行黑名单验证，但是黑名单不全，可以使用php3、php5、phtml等等绕过（需更改服务器配置文件）

## Pass-04

.htaccess可以帮我们实现包括：文件夹密码保护、用户自动重定向、自定义错误页面、改变你的文件扩展名、封禁特定IP地址的用户、只允许特定IP地址的用户、禁止目录列表，以及使用其他文件作为index文件等一些功能

文件内容如下，意思为该文件用php来解析。先上传该.htaccess文件

```
<FilesMatch "1.png">
SetHandler application/x-httpd-php
</FilesMatch>
```

在文件内写入php脚本，上传后访问该文件即可

## Pass-05

创建一个.user.ini文件并把它上传

```
auto_prepend_file = 5.jpg
```

.user.ini文件里的意思是：所有的php文件都自动包含5.jpg文件。

将.user.ini上传至服务器，将shell文件名改为5.jpg。上传该文件。再根据提示访问上传目录下的readme.php，即可将1.gif内的内容脚本正常执行。

## Pass-06

使用大小写1.pHP绕过

![图片 8](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142118330.png)

## Pass-07

使用空格绕过`1.php `

![图片 10](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717144010449.png)

## Pass-08

使用1.php.绕过

![图片 12](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142203813.png)

## Pass-09

用`::$DATA`绕过

![图片 14](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142318007.png)

## Pass-10

使用`1.php. .`可以成功绕过

![图片 16](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142314307.png)

## Pass-11

双写绕过

![图片 18](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142310998.png)

## Pass-12

用到了%00截断，00截断使用环境必须是php5.3版本以下、关闭magic_quotes_gpc函数，0x00是字符串结尾标志，那么就可以绕过后缀限制，a.php%00.jpg，输出就是a.php，%00.jpg就会被截断

![图片 20](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142353352.png)

## Pass-13

同上一题，但Post方法需要在消息体中进行十六进制编码

![图片 22](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142428329.png)

## Pass-14

制作图片马

以二进制形式打开图片，在文件结尾加上一句话木马

![图片 25](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717142453511.png)

之后访问http://upload.local/include.php?file=upload/6520250716152328.jpg即可

## Pass-15

同14

## Pass-16

同14

## Pass-17

这一关对上传图片进行了判断了后缀名、content-type，以及利用imagecreatefromgif判断是否为gif图片，最后再做了一次二次渲染，但是后端二次渲染需要找到渲染后的图片里面没有发生变化的Hex地方，添加一句话木马。

二次渲染：后端重写文件内容

制作方法：上传正常的GIF图片下载回显的图片，用010Editor编辑器进行对比两个GIF图片内容，找到相同的地方（指的是上传前和上传后，两张图片的部分Hex仍然保持不变的位置）并插入PHP一句话，上传带有PHP一句话木马的GIF图片

参考：https://wwe.lanzoui.com/iFSwwn53jaf

## Pass-18

抓包，重复发送该文件，服务器删除该文件会有延迟。在服务器还未删除时，运行该php文件，实现写入shell。

![图片 30](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717143204844.png)

![图片 31](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717143207299.png)

设置重复访问该文件（burp设置同上）

![图片 32](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717143214359.png)

即可成功写入shell

![图片 34](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250717143216053.png)
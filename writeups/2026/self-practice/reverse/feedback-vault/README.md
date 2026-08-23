# Feedback Vault

> 比赛：`self-practice`
>
> 分类：`reverse`
>
> 难度：`medium`
>
> 完成日期：`2026-08-21`

## 题目信息

题目是一个 Windows x64 控制台程序。程序读取一行输入，先检查长度和 `flag{...}` 外形，再执行 29 轮带反馈状态的字节校验。

静态观察到程序由 MinGW/GCC 编译，关键字符串可见，没有壳或反调试。主要难点不是单个运算，而是：

- 输入字节不按自然顺序处理；
- 三个变换函数通过函数指针表间接调用；
- Ghidra 初始函数签名存在多处宽度误判；
- 每轮产生的新状态会影响下一轮。

仓库不包含题目二进制、调试转储或最终 flag。

## 初步观察

运行错误输入时可以看到两类失败信息：

```text
Signal rejected.
Feedback mismatch.
```

这提示程序至少分为外层格式检查和内层算法校验。通过成功、失败字符串的 XREF 定位到 `FUN_1400015ff`。该函数负责输入、格式检查、核心校验调用和成功/失败输出，因此将其识别并重命名为源码层面的 `main`。

需要注意：它不是 PE Header 中的入口地址，而是 C Runtime 初始化后调用的用户主函数。

## 外层格式检查

整理 `main` 后可得到三个约束：

```c
strlen(input) == 0x1d;          // 29
memcmp(input, "flag{", 5) == 0;
input[28] == '}';
```

Ghidra 最初把栈缓冲区拆成 `char input[28]` 和相邻的 `local_6c`。结尾判断中的 `local_6c` 实际对应第 29 个字符 `input[28]`，不是另一个独立语义变量。

## 核心校验循环

核心函数 `FUN_140001550` 返回布尔值，可结合调用位置重命名为 `verify_flag`。整理后的循环骨架如下：

```c
state = 0xa7;
mismatch_acc = 0;

for (i = 0; i < 29; i++) {
    input_byte = input[(i * 8 + 5) % 29];
    output_byte = run_pipeline(input_byte, i, state);
    mismatch_acc |= output_byte ^ target_table[i];
    state = update_state(state, input_byte, output_byte, i);
}

return state == 0x62 && mismatch_acc == 0;
```

输入索引公式为：

```c
source_index = (i * 8 + 5) % 29;
```

前几轮索引是 `5, 13, 21, 0, ...`，说明程序按一个置换顺序访问全部 29 个输入字节。

`mismatch_acc` 使用 OR 累积每轮的 XOR 差异：一旦某轮不匹配，差异位不会被后续匹配轮清除。因此 `mismatch_acc == 0` 等价于全部输出字节均与目标表一致。

## 函数指针流水线

`run_pipeline` 的原始反编译包含：

```c
value = (*(code *)(&PTR_FUN_140003000)[j])(value, i, state);
```

x64 指针宽度为 8 字节。检查 `.data` 段后确认函数表：

```text
0x140003000 -> FUN_14000144e
0x140003008 -> FUN_140001486
0x140003010 -> FUN_1400014bf
```

因此间接调用循环可以手工展开为：

```c
value = stage1_xor_mix(value, i, state);
value = stage2_rotate_left(value, i, state);
value = stage3_add_round(value, i, state);
return value;
```

每一阶段处理的是上一阶段的返回值，而不是分别处理同一个原始输入字节。

## 第一阶段：异或混合

Ghidra 最初错误地显示四字节返回值并产生 `CONCAT31`。根据调用方的一字节输入与返回值，将签名修正为：

```c
byte stage1_xor_mix(byte value, ulonglong i, byte state);
```

修正后公式为：

```c
return state ^ value ^ stage1_table[(i * 3 + 2) % 11];
```

把 `DAT_1400040a0` 定义为 `byte[11]` 后，Ghidra 不再显示多余的 `&`。表内容为：

```text
2d 91 47 b8 53 0e c6 7a 15 e3 69
```

## 第二阶段：循环左移

第二阶段的轮次表达式包含：

```text
0xcccccccccccccccd
128 位乘法
SUB161
& 0xfc
```

这是编译器对常数除法的优化。`0xcccccccccccccccd` 是除以 5 的魔数；在本题 `i = 0..28` 的范围内，复杂项等价于：

```c
4 * (i / 5);
```

因此完整位数表达式可以化简为：

```c
i - 5 * (i / 5) + 1
= i % 5 + 1;
```

辅助函数在修正为 `byte (byte value, byte shift)` 后变为：

```c
byte rol8(byte value, byte shift)
{
    return value << (shift & 7) |
           value >> (8 - (shift & 7));
}
```

所以第二阶段是：

```c
return rol8(value, i % 5 + 1);
```

## 第三阶段：轮次加法

修正第三阶段的一字节签名后，Ghidra 显示：

```c
return (char)i * '\v' + '!' + value;
```

字符常量 `\v = 0x0b = 11`，`'!' = 0x21 = 33`，因此：

```c
return (byte)(value + i * 11 + 33);
```

返回类型是 `byte`，溢出按模 256 回绕。

## 状态反馈

状态更新函数同样存在 `int/uint` 宽度误判。根据调用位置将签名修正为：

```c
byte update_state(byte state,
                  byte input_byte,
                  byte output_byte,
                  int i);
```

另一个旋转辅助函数是 8 位循环右移：

```c
byte ror8(byte value, byte shift)
{
    return value >> (shift & 7) |
           value << (8 - (shift & 7));
}
```

最终状态公式为：

```c
return ror8(output_byte, 1) ^
       (rol8(state, 1) + input_byte + i * 7 + 19);
```

由于下一轮的第一阶段使用新状态，不能独立恢复所有输入字节，必须按照轮次顺序逆解并同步更新状态。

## 目标表

`target_table` 是 `byte[29]`：

```text
4a 8e f1 99 f0 e1 bb 2d 3a 8a 3f 21 7a 9d 6d
89 c9 36 7e d8 db 4c d6 6d 1e 81 be 75 b4
```

## 逆解步骤

第 `i` 轮已知目标输出：

```c
v3 = target_table[i];
```

逆三阶段的顺序与正向相反：

```c
v2 = (byte)(v3 - i * 11 - 33);
v1 = ror8(v2, i % 5 + 1);
input_byte = v1 ^ state ^ stage1_table[(i * 3 + 2) % 11];
```

将恢复的字节放回原位置，再更新状态：

```c
source_index = (i * 8 + 5) % 29;
input[source_index] = input_byte;
state = update_state(state, input_byte, v3, i);
```

完成 29 轮后检查：

```c
state == 0x62
```

并将恢复结果交给原程序验证。实际运行进入 `Access granted.` 分支，说明静态恢复的算法与逆解顺序正确。公开版本不记录最终 flag。

## 踩坑与失败尝试

### 把 `fgets` 返回指针当成输入内容

`fgets(input, size, stdin)` 将字符写入 `input`，返回值只是成功时指向该缓冲区的指针。应区分保存数据的数组和用于检查读取是否成功的指针变量。

### 只按类型映射函数参数

分析 `run_pipeline(input_byte, i, state)` 时，曾因第一、第三参数都是字节而交换二者。正确方法是先按参数位置映射，再用 Windows x64 的 `RCX`、`RDX`、`R8` 寄存器和类型交叉验证。

### 把反编译器类型当成事实

多个函数最初被识别为 `void`、`int` 或 `undefined8`，产生 `CONCAT31`、`CONCAT71` 等噪声。调用方和被调函数必须相互校验；修正字节宽度后，真实算法会明显简化。

### 混淆循环左移和循环右移

逆第二阶段时，正向 `rol8` 必须使用 `ror8` 撤销。判断方向时应明确哪一端移出的位绕回另一端，而不是只看普通移位结果。

### 被魔数公式拖住

实战中不必从头证明魔数。先把“大常量 + 宽乘 + 取高位 + 移位/掩码”标记为常数除法候选，再结合附近的 `/ 5` 和边界试值确认。

## 关键结论

- 函数签名修正是清除反编译噪声的关键步骤。
- 函数指针表要按表项地址和指针宽度恢复真实调用顺序。
- 字节变换均可逆，但滚动状态使各轮产生前后依赖。
- 逆解流水线必须反向撤销各阶段，轮次本身仍按正向顺序推进。
- 最终结果必须回到原程序动态验证，不能只依赖脚本输出。

## 复盘

以后遇到类似题目，可以优先按以下顺序处理：

1. 从成功与失败字符串定位核心函数；
2. 用调用点修正参数、返回值和字节宽度；
3. 把函数指针调用改写成可读的阶段流水线；
4. 将常量数据定义成正确大小的数组；
5. 区分单轮输出比较与跨轮状态更新；
6. 写正向公式后，再按相反顺序构造逆运算；
7. 使用原程序验证完整输入和最终状态。


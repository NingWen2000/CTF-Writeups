# CTF Writeups

这里记录 CTF 题目的完整解题过程，重点保留分析思路、证据、踩坑和可复现步骤，而不只是最终答案。

## 内容索引

按比赛、方向与题目浏览：[Writeups 索引](writeups/README.md)

## 目录约定

```text
writeups/<year>/<event>/<category>/<challenge>/
├── README.md
└── assets/
```

每篇 WP 使用 Markdown 编写；图片放入对应题目的 `assets/` 目录。题目附件、可执行文件、压缩包、调试转储、凭据和比赛期间不宜公开的内容不会纳入仓库。

## 分类建议

- `reverse`：逆向工程
- `pwn`：二进制利用
- `web`：Web 安全
- `crypto`：密码学
- `misc`：杂项
- `forensics`：取证

## 发布原则

- 先验证，再下结论。
- 区分静态分析推测与动态调试事实。
- 保留失败尝试及其原因，方便复盘。
- 活跃比赛期间不公开 Flag 或受限材料。
- 所有内容在发布前进行脱敏检查。


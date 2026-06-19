# Handoff Prompt for Remote Claude Code Session

Copy the text below as the prompt for the next Claude Code session on the remote server (`secondst@pve-research.tail0f6352.ts.net`).

---

## Prompt

你在 `/home/secondst/Code/lancet_advanced` 目录下工作。这是 Lancet 工具的代码库——一个基于 Intel PIN 的 DBI（动态二进制插桩）工具，通过 ownership 模型检测堆漏洞。

### 当前任务

继续构建 `dataset/` 目录。模板 case `CVE-2024-4323_fluentbit` 已经完成，你的任务是按照模板和 `dataset/README.md` 的规范，创建剩余的 case。

**优先级**（从 Tier 1 开始）：

Tier 1（深度分析，有完整 exploit chain）：
1. `CVE-2019-11932_whatsapp` — 源在 `tests/llm_generated/exp_whatsapp_CVE-2019-11932/`
2. `CVE-2020-9273_proftpd` — 源在 `tests/llm_generated/exp_proftpd_CVE-2020-9273/`
3. `CVE-2025-49844_redis` — 源在 `tests/llm_generated/exp_redis_CVE-2025-49844/`
4. `CVE-2021-3156_sudo` — 源在 `tests/llm_generated/exp_sudo_CVE-2021-3156/`
5. `CPV15_nginx` — 源在 `tests/cpv15_standalone/`，需要 `-struct_layout cpv15.structs`，nginx binary 在 `/home/seondst/Desktop/Code/heapkiller/testcases/CPV15/challenge-004-nginx-source/objs/nginx`（如果不在本机，需要从本地传过来或跳过）

Tier 2（有 binary + Lancet output）：
6. `CVE-2024-6387_openssh` — 源在 `tests/llm_generated/exp_openssh_CVE-2024-6387/`
7. `CVE-2026-32746_telnetd`
8. `CVE-2024-12084_rsync`
9. `CVE-2025-3277_sqlite`

Tier 3（FFmpeg 批量，结构相同）：
10-18. `CVE-2026-392{10-18}_ffmpeg`

### 每个 case 的操作步骤

1. `mkdir -p dataset/<CVE>_<target>/{src,bin,poc,exp,lancet}`
2. 从 `tests/llm_generated/exp_<name>/` 复制 binary、exploit、PoC
3. 复制并调整 `run_lancet.sh`（改 binary 路径，加特殊参数如 `-targetlib`）
4. 运行 `bash run_lancet.sh` 生成 `lancet/raw.log`
5. 写 `analysis.md`：
   - 读 raw.log，用 `grep -oP '\[[^\]]+\]' lancet/raw.log | sort | uniq -c | sort -rn` 统计检测类型
   - 对 HIJACK、PIVOT、CROSSBOUNDARY 等关键行，用 `addr2line -e bin/<binary> -f <offset>` 定位函数
   - 对应到 exploit 的每个 phase（参考 `docs/REALWORLD_ANALYSIS.md` 中的 exploit chain 分析）
   - 精炼简短，每个关键检测行 1-2 句话解释
6. 写 `metadata.json`（detection 统计数字从 raw.log 提取）
7. 验证：`run_lancet.sh` 能跑、analysis 中引用的 log 行在 raw.log 中存在

### 关键参考文件

- `dataset/README.md` — 完整的目录规范、使用说明、开发经验、PIN 陷阱
- `dataset/CVE-2024-4323_fluentbit/` — 已完成的模板 case
- `docs/REALWORLD_ANALYSIS.md` — 29 个 exploit case 的检测数据 + 5 个深度 exploit chain 分析
- `tests/llm_generated/EXPLOIT_CHAIN_ANALYSIS.md` — ProFTPD/WhatsApp/FluentBit/Redis/sudo 的 exploit ↔ Lancet 对应

### 环境

- PIN: `~/Code/pin-4.2/pin`
- Lancet: `obj-intel64/lancet.so`（已编译好）
- 构建: `make -j4`（如果需要重新编译）
- addr2line: 直接可用
- Python + pyelftools: 已安装（用于 `tools/extract_structs.py`）

### 注意事项

- `lancet/raw.log` 中的 `lancet_output.log` 可能已经存在于源目录（之前跑过），可以直接复制，也可以重新跑
- analysis.md 要精炼——每个关键检测行 1-2 句解释，不要写长段落
- FFmpeg cases 结构完全相同（同一个 ffmpeg binary + 不同 PoC），可以批量处理
- 如果某个 binary 跑不了（缺库、crash），在 metadata.json 标记 `"status": "SKIP"` 并注明原因
- 不需要全部做完，做到 Tier 2 即可，Tier 3/4 留给后续 session

---

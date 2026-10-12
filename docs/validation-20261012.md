# 2026-10-12 首版验证记录

验证对象为四个局部参考条件、16 个原子义务的候选核查实现。映射仍为草案；本记录不代表全 SOP 符合或真实任务验收。

## 内核

- Python 3.12：`python -m unittest discover -s tests -v`，33 项通过。
- 独立进程：`python -I scripts/verify.py` 从其他工作目录执行离线样例，单 JSON 输出正常。
- 离线样例结果：三个候选满足、一个运行条件未核查，整体未核查，`formal_closed=false`。候选由测试显式提供，不是模型语义准确率结果。
- 覆盖了引用和行号伪造、原子义务遗漏、父子结果冲突、失败优先、版本不匹配、无完整 diff、采集范围不完整、越界输入、JSON 重复字段、畸形模型输出、模型未配置/失败及秘密脱敏。
- wheel 构建核对了冻结规则与原文快照随包包含；运行时无第三方依赖。

## 集成

Server/Web 适配分别在各自仓库的 `codex/sop-verification-mvp` 分支。集成检查记录随对应变更提交，内核离线通过不能替代 API 权限、浏览器或实际部署验证。

Server：最新完整 lib 82 项通过、8 项忽略；`cargo check --tests` 通过。另执行了实际 Python worker 的跨仓库离线烟测（1 项通过）。Web：21 项 unit、8 项 Chrome fixtures、typecheck、lint、design check 与 production build 通过。

## 一次真实模型请求

在用户明确授权后，仅在内存中读取既有 DeepSeek 密钥，向官方 API 发送 `examples/model-request.json` 的合成材料一次；没有发送私人 Trace，也没有复制配置文件或提交密钥。

- Provider：`deepseek-flash`，`invoked=true`、`request_count=1`、`status=completed`。
- 三个静态条件保留候选满足；运行条件 `FIX05.C04` 使用了不受信的证据类型，程序拒绝其正向判断，保存 `unverified` 和 `unsupported_evidence_kind`。
- 整体 `analysis_complete=false`，`formal_closed=false`；按 Server 契约本轮状态为 `failed`，表示分析未完整。API 返回完成不等于核查完整、修复成功或正式验收。
- 保留了 12 个有效原子义务；本轮不宣称全部 16 项成功分析。独立复核了保留的 26 个证据引用及当前 SOP 引文，行号、原文、摘要和定位一致。

真实返回报告仅保存在被忽略的本地 `reports/`。未验证私有任务全链路、PostgreSQL 集成、容器构建、人工复核或生产部署。

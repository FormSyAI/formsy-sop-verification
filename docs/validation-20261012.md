# 2026-10-12 首版验证记录

验证对象为四个局部参考条件、16 个原子义务的候选核查实现。映射仍为草案；本记录不代表全 SOP 符合或真实任务验收。

## 内核

- Python 3.12：`python -m unittest discover -s tests -v`，33 项通过。
- 独立进程：`python -I scripts/verify.py` 从其他工作目录执行离线样例，单 JSON 输出正常。
- 离线样例结果：三个候选满足、一个运行条件未核查，整体未核查，`formal_closed=false`。候选由测试显式提供，不是模型语义准确率结果。
- 覆盖了引用和行号伪造、原子义务遗漏、父子结果冲突、失败优先、版本不匹配、无完整 diff、采集范围不完整、越界输入、JSON 重复字段、畸形模型输出、模型未配置/失败及秘密脱敏。
- wheel 构建核对了冻结规则与原文快照随包包含；运行时无第三方依赖。

## 集成

Server/Web 适配位于隔离的本地 `codex/sop-verification-mvp` 工作树。现有仓库推送返回 403，未创建远端分支或 PR；新仓库的 `integration/` 保存了可选补丁。已用临时 Git index 验证两份补丁可应用到记录的基线。内核离线通过不能替代 API 权限、浏览器或实际部署验证。

Server：最新完整 lib 82 项通过、8 项忽略；`cargo check --tests` 通过。另执行了实际 Python worker 的跨仓库离线烟测（1 项通过）。Web：21 项 unit、8 项 Chrome fixtures、typecheck、lint、design check 与 production build 通过。

## 独立本地页面

`scripts/serve.py` 与 `web/` 在本仓库内运行，不依赖旧 Server/Web 的上传权限。启动仅绑定 `127.0.0.1`，无前端安装或构建步骤，默认回放随仓库保存的合成报告。当前演示进程移除了模型密钥环境变量，`model_configured=false`。

完整 Python 测试 42 项通过，其中 9 项覆盖真实 loopback HTTP：示例配对、无自动模型请求、显式模式和密钥门禁、离线实际内核调用、每轮私有文件保存、Host/Origin、输入限制、畸形协议和静态目录边界。页面 JavaScript 语法检查通过。

独立页面的无头 Chrome 烟测通过 15 项检查：默认回放且无 POST、未配置模型门禁、原子项展开、LF 原文与规范定位、无效导入保留旧报告、真实离线 worker 往返、历史固定材料、HTTP 失败保留历史、模型模式去除离线候选（仅浏览器 mock）、恶意引文与错误指针、长来源阅读窗口、窄屏布局及无 JS/CSP 错误。没有新增模型调用。主界面截图为 `docs/images/workbench.png`。

本地页面的来源由使用者提供，历史切换只使用当轮原始输入；它不能替代 FormSy 的项目授权、可信采集与正式报告库。

## 一次真实模型请求

在用户明确授权后，仅在内存中读取既有 DeepSeek 密钥，向官方 API 发送 `examples/model-request.json` 的合成材料一次；没有发送私人 Trace，也没有复制配置文件或提交密钥。

- Provider：`deepseek-flash`，`invoked=true`、`request_count=1`、`status=completed`。
- 三个静态条件保留候选满足；运行条件 `FIX05.C04` 使用了不受信的证据类型，程序拒绝其正向判断，保存 `unverified` 和 `unsupported_evidence_kind`。
- 整体 `analysis_complete=false`，`formal_closed=false`；按 Server 契约本轮状态为 `failed`，表示分析未完整。API 返回完成不等于核查完整、修复成功或正式验收。
- 保留了 12 个有效原子义务；本轮不宣称全部 16 项成功分析。独立复核了保留的 26 个证据引用及当前 SOP 引文，行号、原文、摘要和定位一致。

此次合成返回已另存为 `examples/synthetic-live-report.json`，用于无需密钥、无需再次调用模型的可复现页面演示。它只含本仓库虚构任务的材料引用，不是私人 Trace 或旧审计历史。真实任务报告仍应保存在被忽略的 `reports/`。

未验证私有任务全链路、PostgreSQL 集成、容器构建、人工复核或生产部署。

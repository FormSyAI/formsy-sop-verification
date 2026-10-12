# formsy-sop-verification

FormSy 的任务级 SOP 核查工具：独立本地页面与 Python 内核读取固定版本的规范和选定执行记录，生成可追溯的候选结论，保留证据不足、分析失败及未覆盖范围。

本项目由三部分协作：本仓库负责核查内核；`formsy-server` 负责项目权限、取证和不可变报告；`formsy-web` 在任务的“验证”阶段提供核查入口。既有 TaskCheck 与 Finish Gate 承接人工检查，候选报告不会自动完成任务。

当前独立页面统一提供 **完整条件审计**，复用 TraceAuditWeb r11 的需求提取、适用性选择、逐条件及原子义务核查、反证和引用复核；默认规则由 `FormSyAI/formsy-sop` 统一维护。原 4 项 worker/API 保留兼容，页面不再提供快速核查入口。

原 4 项 Server/Web 集成已合并到各自 `main`，并保留[对应补丁与合并版本](integration/README.md)；本轮完整审计和自定义 SOP 接口运行在本仓库本地服务，共享 FormSy 服务尚未部署。

管理员可按[接入步骤](docs/server-connection.md)部署已合并版本、配置模型并完成真实任务验收。当前缺少部署主机的发布通道；GitHub 合并已完成。

## 先看效果

需要 Python 3.10 或更高版本，无需安装前端依赖：

```sh
python3 -I scripts/serve.py
```

打开 `http://127.0.0.1:8769`。页面默认选择 DeepSeek，可用“DeepSeek API”按钮读取本地服务配置，密钥不会返回浏览器。该按钮不会调用模型或验证账户余额；实际额度与连接以审计请求返回为准。DeepSeek 未配置或本轮请求因认证、额度、连接等问题中断时，才显示本地结构检查备用入口，不会自动补跑审计。

可导入 TraceAudit 原生请求或已保存的 2.1 报告。完整报告保留概览、任务与要求、验收点映射、SOP 选择与完整核查、基础修复检查、具体问题及证据材料。上传和本地检查不调用模型；新模型审计须载入材料、确认发送，再点击“使用 DeepSeek 开始审计”。

默认库含 33 条规则、144 个条件、184 个原子义务；每轮冻结规则源版本、内容摘要及原文。自定义规则沿用原工具的 JSON 格式，可上传数组或含 `rules` 的对象，最多 8 条；逐条保留版本、判定条件、所需证据、复检和关闭要求。自定义规则数独立计算，不套用默认库的 144 条数量。完整入口与来源配置见[完整审计说明](docs/full-audit.md)。

合成示例只提供请求材料，不自动运行模型或业务代码。完整入口接受原生请求，不直接导入旧 4 项 worker 请求。模型模式需要启动进程已有 `DEEPSEEK_API_KEY`，且点击前页面会说明材料发送至 DeepSeek。工具不读取任何 `.env` 文件。每轮新结果保存在被忽略的 `reports/local/`，请勿提交真实材料。

本地上传材料由使用者提供；独立页面不证明其已经 FormSy 权限系统认证或由可信采集器冻结。完整平台取证需部署已合并的集成。

[查看工作台截图](docs/images/workbench.png)

## 兼容的 4 项 worker 范围

- 一个明确任务及其绑定的会话、轮次；可明确选择完整目标 Commit。
- 四个局部关联参考条件：基准证据、要求与实质改动的对应、测试设计证据、执行证据完整性。
- 冻结当前六章 SOP 原文、版本和摘要，以及参考条件、映射修订和证据身份。
- 逐字引用、行号和原子义务检查；满足、不满足、未核查、不适用分开保留。
- DeepSeek 语义候选与程序验证后结果分开，正式关闭始终为否。
- 每轮追加保存；补证或换版重新核查，不覆盖旧报告。

四个参考条件不等于六章全文或完整审计库全部已覆盖。完整审计库在另一入口执行，不会把旧报告重标为 144 项审计。当前快速映射是待复核的局部参考关系，不能自动增加任务义务。没有目标版本和完整 diff 的改动覆盖、没有受信执行适配的运行结果均保留未核查。

## 本地开发

需要 Python 3.10 或更高版本，内核仅使用标准库。离线测试不会读取本机 env 文件、调用模型或执行材料中的代码：

```sh
python3 -m unittest discover -s tests -v

# 打包引擎的上游合成回归
PYTHONPATH=src python3 -m unittest discover \
  -s src/formsy_sop_verification/trace_audit/tests -t src -q
```

源码 worker 通过标准输入接收一个 JSON 请求，通过标准输出返回一个 JSON 报告：

```sh
python3 -I scripts/verify.py < examples/offline-request.json
```

精确输入输出、引用格式和模式见[worker 契约](docs/worker-contract.md)。输入最多 2 MiB、400 份证据、32 万字符；超限明确拒绝。

## 模型与部署

原 4 项集成的部署基线：Server `345d833a3933ba6193993f0913782989e51a1523`（[PR #25](https://github.com/FormSyAI/formsy-server/pull/25)），Web `ff020f76e32275b1d4bd7449e3cad286ae6d92d4`（[PR #6](https://github.com/FormSyAI/formsy-web/pull/6)），worker `2328953cd9eefec02c6c09df7fbb9f3aaf6395e8`。本轮主站 UI 与只读预览更新见 [PR #7](https://github.com/FormSyAI/formsy-web/pull/7)；完整审计与自定义 SOP 接口尚未接入共享服务。

沿用 TraceAuditWeb 的 DeepSeek 适配，默认模型为 `deepseek-flash`。只有 `mode=model` 才尝试模型请求；`mode=offline` 仅验证显式提供的测试候选。API 格式参考 [DeepSeek 官方文档](https://api-docs.deepseek.com/api/create-chat-completion/)。

worker 从进程环境读取 `DEEPSEEK_API_KEY` 和可选的 `DEEPSEEK_MODEL`。不要提交密钥、复制既有 `.env.local`、上传私人审计历史或把真实 Trace 放进测试样例。

Server 部署时显式设置以下字段；路径必须指向部署机器上的可信文件：

```text
FORMSY_SOP_VERIFICATION_PYTHON=<Python解释器绝对路径>
FORMSY_SOP_VERIFICATION_WORKER=<本仓库>/scripts/verify.py
FORMSY_SOP_VERIFICATION_API_KEY_REF=env://DEEPSEEK_API_KEY
FORMSY_SOP_VERIFICATION_MODEL=deepseek-flash
```

密钥由部署环境提供。worker 不自动读取当前工作目录或其他仓库的配置。Server 使用固定解释器和脚本启动隔离子进程，不执行来源或模型返回的命令。

快速 worker 采用有界的单次请求。完整审计使用本地异步作业，SOP 阶段最多 64 次、全流程最多 80 次模型请求（含有界恢复）；模型失败保留明确失败状态，不自动重跑整轮，不推断业务通过。停止查看进度不会取消后台作业，进程重启后需要导入磁盘上保留的报告回放。接入正式 FormSy 任务页需部署匹配的 Server/Web 变更；独立本地页面可以单独运行。

部署前备份数据库并核对 SQLx `0025` 无冲突，保留原 Compose project、配置文件、卷、OAuth 和密钥，不执行 `down -v`。迁移后不含 `0025` 的旧 Server 镜像会报 `VersionMissing(25)`，不能直接回滚；停用 worker 或恢复完整备份的步骤见[管理员说明](docs/server-connection.md#5-停用与回滚)。

## 证据和验证

原始来源定位、内容摘要、SOP pin、映射版本、候选标签和验证错误随报告保留。首次核查是按所选规范回溯评价，不能证明目标会话执行前已采用该规范。

原内核与规则的复用来源在包内 `profiles/provenance.json`；部署与最小验收见[集成说明](docs/integration.md)。离线契约测试、模拟模型联调、真实模型核查、人工认可和生产部署分别记录。

# formsy-sop-verification

FormSy 的任务级 SOP 核查内核：读取固定版本的项目规范和选定执行记录，生成可追溯的候选结论，保留证据不足、分析失败及未覆盖范围。

本项目由三部分协作：本仓库负责核查内核；`formsy-server` 负责项目权限、取证和不可变报告；`formsy-web` 在任务的“验证”阶段提供核查入口。既有 TaskCheck 与 Finish Gate 承接人工检查，候选报告不会自动完成任务。

## 首版范围

- 一个明确任务及其绑定的会话、轮次；可明确选择完整目标 Commit。
- 四个局部关联参考条件：基准证据、要求与实质改动的对应、测试设计证据、执行证据完整性。
- 冻结当前六章 SOP 原文、版本和摘要，以及参考条件、映射修订和证据身份。
- 逐字引用、行号和原子义务检查；满足、不满足、未核查、不适用分开保留。
- DeepSeek 语义候选与程序验证后结果分开，正式关闭始终为否。
- 每轮追加保存；补证或换版重新核查，不覆盖旧报告。

四个参考条件不等于六章全文或旧审计库 33 条规则、144 个条件全部已覆盖。当前映射是待复核的局部参考关系，不能自动增加任务义务。没有目标版本和完整 diff 的改动覆盖、没有受信执行适配的运行结果均保留未核查。

## 本地开发

需要 Python 3.10 或更高版本，内核仅使用标准库。离线测试不会读取本机 env 文件、调用模型或执行材料中的代码：

```sh
python3 -m unittest discover -s tests -v
```

源码 worker 通过标准输入接收一个 JSON 请求，通过标准输出返回一个 JSON 报告：

```sh
python3 -I scripts/verify.py < examples/offline-request.json
```

精确输入输出、引用格式和模式见[worker 契约](docs/worker-contract.md)。输入最多 2 MiB、400 份证据、32 万字符；超限明确拒绝。

## 模型与部署

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

当前首版采用有界的单次请求；模型失败保留明确失败状态，不推断业务通过。同步部署的反向代理应允许请求完成并返回结果。使用前需同时部署匹配的 Server/Web 集成变更。

## 证据和验证

原始来源定位、内容摘要、SOP pin、映射版本、候选标签和验证错误随报告保留。首次核查是按所选规范回溯评价，不能证明目标会话执行前已采用该规范。

原内核与规则的复用来源在包内 `profiles/provenance.json`；部署与最小验收见[集成说明](docs/integration.md)。离线契约测试、模拟模型联调、真实模型核查、人工认可和生产部署分别记录。

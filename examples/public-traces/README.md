# 公开 Trace 演示输入

这里提供四份公开、完整的单任务执行轨迹，以及该次审阅所用的代码和版本材料。每份 `input.json` 都逐字节复制自已冻结的审计输入，SHA-256 保存在 [catalog.json](catalog.json)。加载示例只读取输入；点击开始审计后才会发起模型调用。源码、工具命令和历史日志都是审阅材料，加载时不会执行其中的业务代码或命令。

| 示例 | 输入 | 出处与版本说明 | 请求消息 / 原生记录 | 材料 |
| --- | --- | --- | --- | --- |
| Melevir/cognitive_complexity：递归复杂度 | [input.json](Melevir__cognitive_complexity-15/input.json) | [source.json](Melevir__cognitive_complexity-15/source.json) | 30 / 31 | 22 |
| akolar/ogn-lib：解析器注册 | [input.json](akolar__ogn-lib-18/input.json) | [source.json](akolar__ogn-lib-18/source.json) | 22 / 23 | 25 |
| DCC-Lab/RayTracing：折射率边界 | [input.json](DCC-Lab__RayTracing-273/input.json) | [source.json](DCC-Lab__RayTracing-273/source.json) | 40 / 41 | 13 |
| tobymao/sqlglot：SQL MAP 转换 | [input.json](tobymao__sqlglot-2063/input.json) | [source.json](tobymao__sqlglot-2063/source.json) | 16 / 17 | 17 |

原生记录来自 Nebius 发布的 [SWE-agent-trajectories](https://huggingface.co/datasets/nebius/SWE-agent-trajectories)，任务原文与元信息来自 [SWE-bench-extra](https://huggingface.co/datasets/nebius/SWE-bench-extra)。两份数据集均声明 CC BY 4.0；原仓库代码分别保留 MIT 许可。许可证全文、数据集许可卡快照、核查日期和内容摘要见 [licenses/](licenses/) 与 [license-sources.json](license-sources.json)。本目录各部分的许可分别适用，不能将整个输入统一解释为 MIT。

原有输入适配将原生 system/user 包装保存为 context，将后续 ai/user 映射为 assistant/tool，并加入任务需求、所列完整源码与派生目标版本。112 条原生消息载荷均与保留的公开数据集原生记录逐字核对；本次打包没有改动这些冻结输入。完整 Trace 不代表完整仓库：DCC 与 SQLGlot 只附所列源码，缺失文件范围保留在输入的 provenance 中。

`source.json` 分别记录公开 base commit、由原 Agent 补丁重建的 target commit、数据集行号、生成模型与日期字段。派生 target SHA 标识本地重建的版本，不是上游发布的提交。`task_created_at_as_recorded` 是数据集记录的任务日期，不能代替 Trace 运行日期；许可快照 revision 是本次许可核查所用版本，不能冒充当初下载数据的 revision。

Melevir/cognitive_complexity 的精确 base 在 `setup.py` 中声明 MIT，当时没有独立 LICENSE 文件；这里保留当前官方仓库的同作者 MIT 全文 notice，并在出处中明确区分。其余三个仓库的 MIT 全文直接取自各自精确 base commit。

上游轨迹生成：**Built with Llama**。四份所选记录由 SWE-agent Llama 生成器产生；数据集发布者要求遵守 Llama 3.1 输出相关条款，因此这里保留其 [许可证](licenses/LLAMA-3.1-LICENSE.txt)、[使用政策](licenses/LLAMA-3.1-USE-POLICY.md)和 [notice](licenses/NOTICE-LLAMA-3.1.txt)。本目录提供文字记录，不提供模型权重或模型代码，也不训练或发布新模型。数据集和代码作者未被声明为本工具的认可方。

目录只提供输入、出处和许可材料，不预置通过报告。输入中原有的历史 evaluator 文本属于公开数据集材料，不是本工具本轮运行的回执、验收或正式关闭证明。公开作者信息和原测试样例中的联系人字段保留原样；本地账号、服务配置、私有项目镜像和旧审计模型响应没有纳入示例目录。

网页使用的参考 SOP 是本地演示审计规约，不表示这些仓库发布、采用或认可了该 SOP。完整审计结束、业务验证、人审和正式关闭仍是分别记录的结果。

# 完整 SOP 审计入口与规则来源

原 4 条件 worker、`scripts/verify.py` 及其 Server/Web 契约保持独立。本入口调用冻结的
TraceAuditWeb r11 衍生内核，采用 r12 规则解释：需求提取与独立支持检查 → 初次分析 → 反证复核 → 程序边界 →
规则选择 → 逐条件及原子义务核查 → 主张/范围/引用与失败复核 → 候选矩阵汇总。
打包冻结内核及本地修复模块；默认规则从独立 `FormSyAI/formsy-sop` 的已校验本地 checkout 读取，
也可上传原生规则 JSON。没有复制旧数据目录、模型响应、凭据、截图或私有 Trace。

页面统一展示完整审计，保留原七个报告章节，默认选择 DeepSeek。
“DeepSeek API”按钮仅读取本地进程配置，不额外调用模型、展示密钥或确认账户余额。
未配置或本轮模型请求因认证/额度/连接失败时显示本地结构检查备用入口，不自动补跑。
引用/分析校验失败不代表模型服务不可用；旧报告回放也不会改变当前 API 状态。

## 默认规则与自定义 SOP

默认发布位置为 `FormSyAI/formsy-sop/audit/traceaudit-r12`，固定 Git commit
`8a57dcf33658844f6852fb144c3943ab4a3fed4d`，发布摘要为
`f749e17f38821844b3c5322f3b295bae25c37f1011d91887e608a84c6202ef08`。
判定口径 `interpretation_revision=1.9.1` 与机器契约结构 `1.9` 分别冻结；33 条规则、144 个条件、184 个原子义务保持不变。
r12 澄清有效需求与旧断言、单任务外部依据复用及凭据对象/版本边界。新解释只用于新轮次，r11 原报告仍按各自冻结来源展示。
不在运行时联网拉取，不自动更新 checkout。
开发机默认位置是本仓库同级 `formsy-sop/audit/traceaudit-r12`；独立安装时须配置绝对路径：

```bash
export FORMSY_SOP_RULES_ROOT=/absolute/formsy-sop/audit/traceaudit-r12
# 通常无需设置：代码已固定上述发布 commit。管理员显式升级才更改此 pin。
export FORMSY_SOP_RULES_COMMIT=8a57dcf33658844f6852fb144c3943ab4a3fed4d
python3 -I scripts/audit_full.py --catalog
```

规则 checkout 的 HEAD 必须停在上述提交；可用独立 Git worktree 固定它，不能直接用已前进到其他提交的开发分支。

运行机器需有 Git。读取检查 `release.json` 的逐文件字节数、SHA256、库内路径和非符号链接，
核对实际 Git HEAD 与固定 commit、每份采用文件的已提交 blob；Git replace 对象被禁用。
再从校验过的原字节重建目录并编译，与发布的 `compiled-catalog.json` 及完整原子合同摘要比较。
默认发布为 33 规则 / 144 条件 / 184 原子义务；默认 pinned 选择不能删减这些条件。
缺失、未提交、错误版本、字节漂移或合同不兼容会明确标记默认规则不可用，**不回退打包旧规则**。
仓库字节与版本身份不代表这些参考规范已在某个 FormSy 项目发布或历史生效。

自定义 SOP 沿用旧审计页面的 `rules-file` JSON：文件可为规则数组或 `{ "rules": [...] }`；
HTTP 发送形式固定为后者，完整审计请求将该数组放入顶层 `rules`。
复用上游静态 normalization / `uploaded_catalog`，按满足条件、所需证据及复检/关闭要求生成条件与原子合同，
**不调用 LLM 编译**。保留 1–8 条规则上限，最多 512 条条件、2048 个原子项，输入不超过 2 MiB；
`criterion` 等字段仍遵循上游单项长度限制。上传规则数量动态，不宣称已覆盖默认 144 条件。
不接受用户路径、URL 或 `rules_root`；自定义 `rules` 与 pinned 默认库互斥。
自定义请求自包含冻结规则，默认库未安装时也能校验或运行，不查询最新默认源。

```json
{"rules":[{"id":"TEAM:ZERO","title":"保留零值","version":"team-1",
"criterion":"保留显式零值；空值使用默认值","required_evidence":["源码及断言"],
"recheck":"变更后重查原反例","closure_policy":"需要人工复核"}]}
```

`rule_sources.default_catalog(selection=None)` 与 `validate_upload({"rules": [...]})`
都返回 `{rules, catalog, summary}`。`catalog` 保留逐条件完整原子合同；`summary` 提供
`source`、`rule_count`、`condition_count`、`atomic_item_count`、文档版本及数量限制。
报告顶层 `rule_source` 固定本轮源身份：默认带 repository/path/git_commit/release/catalog/contract 摘要及 interpretation_revision；
上传带原输入包与归一后 catalog/contract 摘要。后续读取报告不以最新规则替换冻结版本。

本地 HTTP 接口均不访问共享 FormSy 服务端：

| 接口 | 用途 |
| --- | --- |
| `GET /api/sop-library` | 默认库可用性、数量、来源版本；默认缺失返回 200 且 `default_available=false` |
| `GET /api/sop-template` | 下载原生规则 JSON 示例，不调用模型 |
| `POST /api/sop-uploads` | 同源 `{rules:[...]}` 离线验证冻结，201 返回 `{id,summary,rules,model_invoked:false,created_at}` |
| `GET /api/sop-uploads/{id}` | 读取本进程已验证上传记录；未找到为 404 |
| `GET /api/full-demo-catalog` | 列出固定目录中通过路径和原文件 SHA 校验的公开示例元信息，不调用模型 |
| `GET /api/full-demo/{id}` | 按允许列表读取完整公开输入；来源与许可证见 `examples/public-traces/` |
| `POST /api/full-audits` | 显式 `{mode:"model",request:{...}}` 启动，202 返回新 job 及 `supersedes`；成功接收后请求停止旧作业 |
| `GET /api/full-audits/active` | 返回本进程最新活动作业的安全元信息，不返回原材料或猜测 Trace 身份 |
| `GET /api/full-audits/{id}` | 读取 queued/running/cancelling/cancelled/completed/failed 与已有报告，不调用模型 |

上传原文及冻结 catalog 只追加到忽略目录 `reports/local/sop-uploads/`（文件 600）；
上传验证不发送材料至模型。模型未配置时审计 POST 为 503；无效输入为固定 422 JSON。
所有 POST 要求本地页面同源 Origin，服务只绑定 `127.0.0.1`，不启用 CORS。
job `completed` 只说明流程返回，仍须看 `sop_coverage.analysis_complete`、未核查项与失败记录。
新输入先校验、保存并启动后台线程，成功后才请求旧任务退出；无效输入或启动失败不会停止旧任务。
同进程只有一个审计 runner 执行，新任务等待旧调用真正退出；连续提交以最后成功接收的任务为准。
取消保留旧输入、已接收的脱敏响应、停止请求和停止阶段，不生成通过结论；响应或停止记录保存失败明确记为存储失败。
取消为协作式：读取 SSE 数据时检查停止信号，阻塞中的连接或读取可能仍需等待 180 秒 socket 超时。
关闭页面或停止查看进度不会取消后台作业，也不能保证服务商已停止计算或收费。
当前 job 为本地单进程内存索引；退出进程不会自动重启或恢复作业，旧磁盘报告可导入回放，没有整轮墙钟期限。
页面的“当前审计对象”只展示所载入输入中的身份、仓库、Commit 与原文；原输入没有 Trace ID 时明确显示未提供。
选择公开示例仅执行 GET，每次更换材料或规则均清除发送确认，须再次显式确认后提交。

完整入口可显式设置 `DEEPSEEK_THINKING=enabled`，采用 `high` 推理强度及 32768 输出 token 上限。
默认仍为 `disabled`（10000 输出 token）；非法配置在请求前拒绝，不自动换模式或重试。
实际配置写入逐次 provider request 和报告 `model_snapshot.request_settings`；超时仍为 180 秒，
截断、无效 JSON、引用及版本门槛保持不变。推理模式是待实测的执行配置，不代表结论已获验证。
参数依据 [DeepSeek 官方推理模式说明](https://api-docs.deepseek.com/guides/thinking_mode/)；
只读配置接口公开模式名称，不返回密钥，原四条件入口不受此开关影响。

## Python 接口

```python
from formsy_sop_verification.full_audit import (
    catalog_summary, prepare_full, run_full_audit,
)

inventory = catalog_summary()  # 33 规则 / 144 条件 / 184 原子义务
package = prepare_full(payload)  # 冻结显式输入与已校验规则源，不调用模型

# 只有用户明确选择将这些材料发给 DeepSeek 后才调用。
report = run_full_audit(
    payload,
    directory="/private/path/new-empty-attempt",
    max_sop_calls=64,
    max_total_calls=80,
    stage_callback=lambda stage: print(stage),
    # 可选 threading.Event；设置后协作退出并保留已有记录。
    cancellation_event=None,
)
```

函数同步执行；本地 HTTP 层负责异步 job，不应在默认页面加载、上传或 GET 时调用。
`stage_callback` 接收阶段字符串，不能执行材料中的命令，也不能发起额外模型调用。
默认环境型 DeepSeek client 使用 `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL` / `DEEPSEEK_BASE_URL`，不读取任何
`.env`、`.env.local`、旧 AuditService 历史或 `.trusted-runners.json`。
预算最多为 SOP 阶段 64 次、全流程合计 80 次；网络 socket 操作超时为 180 秒、请求上限 4 MiB、响应上限 1 MiB。
推理模式使用 SSE；180 秒是等待 socket 数据的超时，不是整轮或单请求的墙钟期限。
SSE 传输上限为 16 MiB，拼接的回答与推理文本共用 1 MiB 上限；须完整帧、`[DONE]`、`finish_reason=stop` 及严格 JSON 校验后才采用回答。
流式附件保留原接收摘要和字节数，事件文本经解码、跨片段凭据遮蔽后规范化留存；未知或截断事件用明确占位记录，不保存可能可恢复的凭据片段。
全部阶段及其恢复共用总预算；仅允许官方 DeepSeek 和腾讯云 TokenHub 的已校验 HTTPS 端点，
禁 HTTP 重定向，每个预算单位至多发送一次 HTTP 请求。
认证/余额/网络错误不当作格式错误自动重试；输出协议错误沿用原有有界恢复逻辑。

腾讯云通道使用 `DEEPSEEK_BASE_URL=https://tokenhub.tencentmaas.com/v1`，默认模型为
`deepseek/deepseek-flash`；也可通过 `DEEPSEEK_MODEL` 显式选择已授权模型。
配置、逐次 provider request 与报告保存实际 `provider` 和完整 `provider_endpoint`，网页发送说明随之更新；
旧报告仍显示该报告生成时的服务商。基址不能包含凭据、查询参数、端口或未允许路径。
调用参数依据 [腾讯云 DeepSeek 指南](https://cloud.tencent.com/document/product/1823/132248)。
连通及小 JSON 探测成功只证明对应请求可用，完整审计和语义正确性仍需分别验收。

`directory` 必须为空；目录权限设为 700，文件为 600。请求、各阶段响应和失败记录保留在本轮目录，
已有目录不覆盖。私有材料应放在被忽略的 `reports/local/`，不能放到 `web/`、`public/` 或提交 Git。
调用方需把异常转为固定错误码，不能把异常全文或 traceback 直接返回浏览器。

每次调用使用唯一的 `stage.call-NNN` 文件名，保留脱敏 provider request、原始 provider envelope / 不可解析文本、
`finish_reason`、接收字节摘要及截断标记，再写通过解析的 candidate response。
坏 JSON 或不完整结束仍留原响应，不会仅记录一个错误码或覆盖先前失败。
所有 JSON 模式请求显式提示输出严格 JSON 对象，避免个别提取阶段缺少 JSON 指令；HTTP 错误仍保留且不自动重新提交。

原生参考规范的引用若坐标、任务和版本有效，但只有助手/工具陈述或没有支持确定结论的证据，
保留模型原判断并转为 `未核查 / evidence_missing`；错误引文、跨任务或错误目标版本仍属校验失败。
“不适用”独立复核遇到输出截断时保留原失败，拆成更小批次继续核查，每批仍携带完整证据上下文，
共用上述调用预算。单项仍截断或预算耗尽时明确记录复核未完成，不能以“未核查”掩盖程序失败。
逐项校验失败时保留有效结果，仅将无效子项连同字段错误反馈重试一次；每批独立保存校验结果，
重试成功也保留首次失败。适用性观察的 `acceptance_ids` 只能选择本任务的验收点 ID，不能填任务 ID；
没有关联验收点时用空数组，程序不代替模型改写错误 ID。
需求复核将测试交付与行为示例分别核查：`test_delivery` 必须由明确交付请求支持；
把用户报告的期望计算或兼容条件归为测试交付会触发有界重新提取，原候选不会静默改写或删除。
网页逐项失败记录显示对应条件、子项、阶段和类别，便于从最终报告定位保存的失败附件。
原生 FIX02 的反向任务依据子项还需与目标版本改动清单一致：仍有用途未覆盖或未解析的改动时，
保留原“满足”候选并将该子项转为未核查；未关联本身不构成业务失败，也不抵消其它已确认失败。
完整原生规则路径中的 FIX02/FIX03 自由失败候选，还须通过对应固定子义务的同范围反证复核。
原模型理由与引用单独保留；程序回执绑定任务、目标版本、原候选和输入摘要，模型不能自报该回执。
仅更小修法、分派路径变化或未说明改动目的不足以确认违约；复核证据不足保留未核查，不提升为满足。
已有验收反例、原生条件失败及受信执行失败仍独立保留；复核失败或预算耗尽明确标记分析未完成。
该门槛不改变没有对应原生子义务的旧 2.0 入口与 4 条件契约；原始 findings 仍是未独立复核的模型候选，不能借检查项回执自动认证。
TC14 对每个确定的声明比较候选另做完整命题范围复核，防止只证明事实部分就放行整句推断。
原命题和第一次比较均保留；范围复核失败或达到固定批次上限仍记录分析未完成。
范围复核的多项输出截断时有界二分，保留完整证据、原命题及首次失败；单项仍截断、HTTP 失败或共享预算耗尽不会自动重发，也不算恢复完成。
原生 TC14.C01 的满足候选还须独立覆盖当前任务的原用户和助手采用记录，分别核定每项实际依据
自己的版本、来源日期、位置和适用性。代码 SHA 不能证明外部规范版本或日期；同路径、同版本标签
不能将不同材料拼成同一来源。合法引用但证明不足时保留原候选与有效属性，结果为未核查；
坏引用、错误任务或源码版本仍记录分析失败。本复核沿用既有调用预算，不追加自动补跑。
逐来源采用记录已校验引用且明确关联同一依据时，程序可将这些引用汇总到 `effective_adoption_refs`，
保留模型的原 `adoption_refs` 与汇总来源记录；不重新搜证、选择引用或补写采用分类。
引用汇总只证明引用及关联结构闭合，不认证采用语义、来源真实性或缺失的版本与日期属性。

## 独立请求格式

完整入口接受 TraceAudit 原生格式，不接受 4 条件 worker request，也不把其六章 SOP 自动提升为
144 条件规范。HTTP 层在外层要求显式 `mode`；以下原生对象自身不含 `mode`。

```json
{
  "title": "合成代码修复示例",
  "trace": {
    "messages": [
      {"role": "user", "content": "保留显式零值。"},
      {"role": "assistant", "content": "已修改默认值处理，仍需验证。"}
    ]
  },
  "commits": [{
    "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "parent": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "repository": "synthetic/example",
    "diff": "--- a/limit.py\n+++ b/limit.py\n@@ -1 +1 @@\n-return value or 25\n+return 25 if value is None else value\n"
  }],
  "materials": [{
    "kind": "source",
    "name": "limit.py",
    "path": "limit.py",
    "version_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "content": "return 25 if value is None else value\n"
  }],
  "audit_context": {"profile": "code_fix"},
  "sop_selection": {"mode": "auto"}
}
```

`trace.messages[].role` 为 `user|assistant|tool`。`materials[].kind` 为
`source|test_log|run_record|context`；工具日志和上传 run_record 始终是不受信线索。
请求上限 2 MiB，材料总长度 320000 字符，不静默截断。
`audit_context.profile` 为 `code_fix|full_sop`；使用默认规则时 `code_fix` 仍保留 144 条矩阵，治理条件可延期，
延期属于未核定范围，不能当“不适用”或“通过”。自定义规则矩阵数量以本轮冻结 catalog 为准。

## CLI

```bash
python3 -I scripts/audit_full.py --catalog
python3 -I scripts/audit_full.py --request /private/path/full-request.json

# 显式发送材料；默认命令只有 prepare，不调用模型。
python3 -I scripts/audit_full.py --request /private/path/full-request.json \
  --run --output-dir /private/path/new-empty-attempt
```

默认输出 `prepare_only` 以及输入摘要/规则数量，不输出材料正文。实际运行输出完整候选报告。
CLI 错误退出 2，只给固定错误 JSON；完整失败证据保留在私有 attempt 目录。

## 报告与证据读取

报告采用原 `schema_version: "2.1"`，保留 `tasks`、`acceptance_checks`、`checks`、`findings`、
`sop_condition_checks`、`sop_documents`、`sop_rules`、`sop_coverage` 与 `original_sop`。
四态为“满足 / 不满足 / 未核查 / 不适用”；`matrix_complete` 只说明条件行齐备，
`analysis_complete` 说明模型分析是否完成，二者都不等于语义正确、业务成功或正式关闭。

条件及原子项引用 `{evidence_id,start_line,end_line,quote}` 查 `report.evidence[].id`；规范引用
`{document_id,start_line,end_line,quote}` 查 `report.sop_documents[].id`。
完整引擎保留上游 Python `splitlines(keepends=True)` 行坐标，不能混用 4 条件 worker 的 LF-only 口径。
来源 `original_sha256s` 保留上传原文摘要集合（多个原文可能脱敏归一为同一证据 ID），唯一时也提供
`original_sha256`。原 `sha256` 对应上游归一后的分析来源；`display_sha256` 对应页面返回文本，
`display_redacted` 标记上传原文与展示是否因脱敏不同，不能拿原文摘要宣称脱敏展示内容完全相同。
不要用模型自报定位信息发起任意 URL 或本地文件读取。

所有报告强制 `review_state=model_candidate`、`human_review=not_reviewed`、`formal_closed=false`、
`source_authenticated=false`、`business_tests_executed=false`。
adapter 不执行业务代码，不验证私人 runner 签名，不写 TaskCheck、启用知识、完成 Task 或部署。
通过注入 fake client 的测试结果标为 `model_snapshot.execution_mode=offline_fake`，
`model_invoked=false`，不能把这些阶段请求计数当作实际 DeepSeek 调用。
`api_request_count` 只计实际 HTTP 发送，fake 为 0；`stage_call_count` 另外记录流程调用数。

## 来源、回归与残余

`src/formsy_sop_verification/trace_audit/provenance.json` 列出逐文件上游及打包后 SHA256 和改动。
最初的打包适配包括包内导入、禁旧 dotenv 读取、artifact 写入追加当前环境 key 脱敏，
以及将来源路径改为本仓库快照位置。此后另有引用 selector、版本与范围绑定、原始模型理由的
未核实标注、输出字段合同及有界恢复修复；逐文件改动和字节身份以 provenance 为准。
这些修复与离线回归通过不能证明全部语义错误已消除，完整运行后仍须核对结论与对应版本原文。
复制的 13 个上游 synthetic 测试模块覆盖 350 项离线回归；新增 adapter 测试另计。
上游公开资料的 109 程序/1018 回归是 r11 的交付记录，不能称为本接入重新执行的测试数。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_full_audit.py' -v
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_rule_sources.py' -v
PYTHONPATH=src python3 -m unittest discover \
  -s src/formsy_sop_verification/trace_audit/tests -t src -q
```

r11 已修复需求摘要语气/事实支持恢复、整文件否定范围门、合法 Q-ID 诊断和有界引用恢复路径，
仍有 TC14 提取失败/属性与路径范围误判、SEC06 首次合法引用旁的错误理由、TC13 漏述 True 测试、
FIX03/FIX04 引用恢复及 TC04/TC05 双侧合同复核失败。报告 `integration.known_limitations` 保留这些边界。
本接入另以明确授权的公开 Lexicon 完整 Trace 与冻结相关源码执行了一轮 DeepSeek 审计：
40 次实际 HTTP 请求，144 条矩阵记录齐备，6 满足 / 5 不满足 / 133 未核查。
5 条分析/引用校验失败记录导致 `analysis_complete=false`，不是网络请求失败；没有自动重跑整轮。
人工抽查仍发现 FIX04 对已有 True 输入测试的理由表述失真，因此不能宣称误判已全部解决。
原始请求、响应、失败记录与人工抽查只保存在本机忽略目录，没有提交到 GitHub；
这些候选结果不代表业务测试执行成功、完整语义审计通过或人工验收完成。

## 原四条件入口的凭据与引用身份

原 `/api/verify` 与 CLI 在模型请求、报告返回及新记录保存前遮蔽字典键、文本和已识别凭据字段。
只使用当前进程及注入 client 的密钥，不读取凭据文件或扫描旧记录。来源原文与脱敏文本分别保存摘要，重复脱敏保持占位符稳定。

已校验的项目、任务、SOP pin、来源 ID/版本及 SourceRef 身份字段保留原值，例如 `password:foo`、`authorization:review`。
该例外只用于明确的四条件输入/报告边界；任意嵌套 SOP 内容和名为 `source_index` 的普通数据没有豁免。
身份字段含当前密钥或通用 sk 密钥时，在调用模型前返回 `credential_in_evidence_identity`，不改写身份来制造有效引用。
Manual URL 保留合法命名空间路径，但拒绝 userinfo、解码后的凭据 query 或明确凭据赋值，不重写原 URL。

新记录的 `input_sha256` / `report_sha256` 对应传给存储的原结构 JSON 序列化，
`stored_input_sha256` / `stored_report_sha256` 对应实际保存的脱敏对象；`input_storage_redacted` / `report_storage_redacted` 说明差异。
这些不是原始 HTTP 字节摘要。HTTP 顶层结构保持不变，只返回脱敏显示副本；保留 SOP digest 不认证显示副本等于原 SOP。
旧记录不回写。完整审计继续使用自己的字段脱敏规则，包括原生授权事实；其请求、响应映射与规则 pin 不受此四条件修复改变。

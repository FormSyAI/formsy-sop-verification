# 完整 SOP 审计入口与规则来源

原 4 条件 worker、`scripts/verify.py` 及其 Server/Web 契约保持独立。本入口调用冻结的
TraceAuditWeb r11 引擎：需求提取与独立支持检查 → 初次分析 → 反证复核 → 程序边界 →
规则选择 → 逐条件及原子义务核查 → 主张/范围/引用与失败复核 → 候选矩阵汇总。
打包 16 个执行模块；默认规则从独立 `FormSyAI/formsy-sop` 的已校验本地 checkout 读取，
也可上传原生规则 JSON。没有复制旧数据目录、模型响应、凭据、截图或私有 Trace。

页面统一展示完整审计，保留原七个报告章节，默认选择 DeepSeek。
“DeepSeek API”按钮仅读取本地进程配置，不额外调用模型、展示密钥或确认账户余额。
未配置或本轮模型请求因认证/额度/连接失败时显示本地结构检查备用入口，不自动补跑。
引用/分析校验失败不代表模型服务不可用；旧报告回放也不会改变当前 API 状态。

## 默认规则与自定义 SOP

默认发布位置为 `FormSyAI/formsy-sop/audit/traceaudit-r11`，固定 Git commit
`617385cb54995287abeca8ccb5cb407b1e246994`。不在运行时联网拉取，不自动更新 checkout。
开发机默认位置是本仓库同级 `formsy-sop/audit/traceaudit-r11`；独立安装时须配置绝对路径：

```bash
export FORMSY_SOP_RULES_ROOT=/absolute/formsy-sop/audit/traceaudit-r11
# 通常无需设置：代码已固定上述发布 commit。管理员显式升级才更改此 pin。
export FORMSY_SOP_RULES_COMMIT=617385cb54995287abeca8ccb5cb407b1e246994
python3 -I scripts/audit_full.py --catalog
```

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
报告顶层 `rule_source` 固定本轮源身份：默认带 repository/path/git_commit/release/catalog/contract 摘要；
上传带原输入包与归一后 catalog/contract 摘要。后续读取报告不以最新规则替换冻结版本。

本地 HTTP 接口均不访问共享 FormSy 服务端：

| 接口 | 用途 |
| --- | --- |
| `GET /api/sop-library` | 默认库可用性、数量、来源版本；默认缺失返回 200 且 `default_available=false` |
| `GET /api/sop-template` | 下载原生规则 JSON 示例，不调用模型 |
| `POST /api/sop-uploads` | 同源 `{rules:[...]}` 离线验证冻结，201 返回 `{id,summary,rules,model_invoked:false,created_at}` |
| `GET /api/sop-uploads/{id}` | 读取本进程已验证上传记录；未找到为 404 |
| `POST /api/full-audits` | 显式 `{mode:"model",request:{...}}` 启动，202 返回 job；单 full job 忙时 429 |
| `GET /api/full-audits/{id}` | 读取 queued/running/completed/failed 与已有报告，不调用模型 |

上传原文及冻结 catalog 只追加到忽略目录 `reports/local/sop-uploads/`（文件 600）；
上传验证不发送材料至模型。模型未配置时审计 POST 为 503；无效输入为固定 422 JSON。
所有 POST 要求本地页面同源 Origin，服务只绑定 `127.0.0.1`，不启用 CORS。
job `completed` 只说明流程返回，仍须看 `sop_coverage.analysis_complete`、未核查项与失败记录。
当前 job 为本地单进程内存索引；退出进程不会自动重启或恢复作业，没有取消与整轮墙钟期限。

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
)
```

函数同步执行；本地 HTTP 层负责异步 job，不应在默认页面加载、上传或 GET 时调用。
`stage_callback` 接收阶段字符串，不能执行材料中的命令，也不能发起额外模型调用。
默认环境型 DeepSeek client 只使用 `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL`，不读取任何
`.env`、`.env.local`、旧 AuditService 历史或 `.trusted-runners.json`。
预算最多为 SOP 阶段 64 次、全流程合计 80 次；网络 socket 操作超时为 180 秒、请求上限 4 MiB、响应上限 1 MiB。
全部阶段及其恢复共用总预算；固定官方端点，禁 HTTP 重定向，每个预算单位至多发送一次 HTTP 请求。
认证/余额/网络错误不当作格式错误自动重试；输出协议错误沿用原有有界恢复逻辑。

`directory` 必须为空；目录权限设为 700，文件为 600。请求、各阶段响应和失败记录保留在本轮目录，
已有目录不覆盖。私有材料应放在被忽略的 `reports/local/`，不能放到 `web/`、`public/` 或提交 Git。
调用方需把异常转为固定错误码，不能把异常全文或 traceback 直接返回浏览器。

每次调用使用唯一的 `stage.call-NNN` 文件名，保留脱敏 provider request、原始 provider envelope / 不可解析文本、
`finish_reason`、接收字节摘要及截断标记，再写通过解析的 candidate response。
坏 JSON 或不完整结束仍留原响应，不会仅记录一个错误码或覆盖先前失败。

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
改动仅为包内导入适配、禁旧 dotenv 读取、artifact 写入追加当前环境 key 脱敏，
以及将来源路径改为本仓库快照位置，避免依赖开发机的绝对目录。
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

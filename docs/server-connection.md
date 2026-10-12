# 服务端接入：管理员交接说明

目前可运行的是本地核查工作台；共享 FormSy 尚未部署本次集成。[Server #25](https://github.com/FormSyAI/formsy-server/pull/25) 和 [Web #6](https://github.com/FormSyAI/formsy-web/pull/6) 已合并到各自 `main`，管理员只需部署下列固定版本及完整 worker 并验收。当前尚未配置部署主机的发布通道，GitHub 合并已完成。Entire 上传或本机模型 key 不会自动发布服务端改动。

接通后的流程：用户登录 FormSy → 打开任务的“验证”页 → 确认当前生效 SOP 版本及可选目标 Commit → 显式发起核查 → Server 按当前权限读取任务绑定的 Trace → 调用核查程序与 DeepSeek → 保存并展示候选报告。现有人工检查和任务完成流程不自动改变。

## 已确认的现状

2026-10-12 对当前网页地址 `http://192.168.1.9:3002` 做了不带凭据的只读连通性检查：

- `/api/v1/auth/me` 返回 `401 authentication_required`：API 可达，但独立工作台没有 FormSy 登录授权。
- 向 `/mcp/knowledge` 发送协议初始化请求，返回 `405` 和前端 HTML：这个网页地址尚未提供可用的 MCP 入口。这不能证明实际后端没有 MCP；管理员可确认真实 API 地址及代理规则。

当前 FormSy CLI 的授权范围也不能直接枚举并读取完整 Trace。推荐先部署已有的任务页集成，复用 FormSy 登录、项目权限及完整取证逻辑。现有 MCP 读取还缺少完整的来源枚举与长工具输出覆盖，单独转发路由不足以达到本项目的完整核查要求。

## 管理员需要准备

- 部署机器的发布通道，以及现有部署配置和数据库的操作权限；Server/Web 合入已完成。
- 一个测试项目、已发布且有效的 SOP 版本，以及具有明确 `source_bindings` 的任务。只有 `session_ids` 不代表选定了核查范围。
- 用户能读取选定项目和 GitHub 来源，并能编辑该任务：项目 owner/maintainer，或仍具 developer 角色的任务创建者。项目应已同步可读的 Conversation/Trace 内容；只有 Commit 元数据不足以核查执行过程。
- 部署环境通过既有 secret 渠道提供 DeepSeek key。本机工作台进程中的 key 不会自动同步到服务器，也不需要提交到 GitHub。

## 1. 固定已合并的部署版本

在原部署 checkout 或构建流水线中取下列正式合并提交，核对实际构建 SHA。两个 PR 已合入，不再重复应用补丁。

| 仓库 | 正式合并提交 | PR |
| --- | --- | --- |
| formsy-server | `345d833a3933ba6193993f0913782989e51a1523` | [Server #25](https://github.com/FormSyAI/formsy-server/pull/25) |
| formsy-web | `ff020f76e32275b1d4bd7449e3cad286ae6d92d4` | [Web #6](https://github.com/FormSyAI/formsy-web/pull/6) |

完整 worker 固定为 `2328953cd9eefec02c6c09df7fbb9f3aaf6395e8`。本仓库的 [`integration/`](../integration/README.md) 仅保留对应补丁及基线用于交接存档，不包含旧仓库 Git 历史。

补丁 SHA-256：

```text
formsy-server.patch  1058d6ef4744a956732aad2d85bf1a034066d93c45f62dc9d7688cc3121f1922
formsy-web.patch     5584a0a73eec22940c2e9b048e8277d67277fd8ac5a2345af510a9963817e79b
```

## 2. 部署完整核查仓库与模型配置

使用有权限的部署身份将 [FormSyAI/formsy-sop-verification](https://github.com/FormSyAI/formsy-sop-verification) 完整放到部署机器，例如 `/opt/formsy-sop-verification`。已联调的 worker 版本为 `2328953cd9eefec02c6c09df7fbb9f3aaf6395e8`；请固定该版本并记录实际部署 SHA。不能只复制 `scripts/verify.py`，还需要 `src/` 和冻结的 profile。

非容器部署需要 Python 3.10 以上，并在 Server 的运行环境配置：

```text
FORMSY_SOP_VERIFICATION_PYTHON=/usr/bin/python3
FORMSY_SOP_VERIFICATION_WORKER=/opt/formsy-sop-verification/scripts/verify.py
FORMSY_SOP_VERIFICATION_API_KEY_REF=env://DEEPSEEK_API_KEY
FORMSY_SOP_VERIFICATION_MODEL=deepseek-flash
```

`DEEPSEEK_API_KEY` 由既有 secret 渠道注入 Server 进程。若部署环境已有用于 DeepSeek 的 `FORMSY_KNOWLEDGE_MODEL_API_KEY`，可以显式改用 `env://FORMSY_KNOWLEDGE_MODEL_API_KEY`。服务端只向隔离 worker 传递模型所需配置，不复制 `.env.local`。

若沿用 Server 仓库的 Compose，另设 `FORMSY_SOP_VERIFICATION_REPO` 为宿主机完整 worker checkout 的绝对路径。已合并的 `compose.sop-verification.yaml` 会只读挂载该目录，并设置容器内的 Python/worker 路径；基础 Compose 会传入模型配置和 key。保留原 Compose project 名、配置文件及顺序、卷、数据库、OAuth、key 和其他生产配置；不执行 `docker compose down -v`。

## 3. 在测试环境构建、迁移并发布

先记录当前 Server/Web 镜像和 SHA，按现有备份流程取得数据库与关联对象存储的一致性备份，明确恢复点。升级前查询部署数据库的 SQLx 迁移记录（以下为 PostgreSQL）：

```sql
SELECT version, description, success, encode(checksum, 'hex') AS checksum
FROM _sqlx_migrations
WHERE version >= 25
ORDER BY version;
```

首次升级应无 `0025`。若已存在，确认它确为本次 `sop_verification_reports` 迁移且 checksum 一致；发现同号其他迁移、失败记录或不一致时先停止发布并排查。Server 启动会执行新增的 `0025_sop_verification_reports.sql`，无需手工创建报告表。该迁移会影响旧镜像回滚，见第 5 节。

沿用仓库 Compose 时，在原部署上下文加入 override；下面命令还需保留原部署使用的 project 名和其他配置文件：

```sh
docker compose -f compose.yaml -f compose.sop-verification.yaml config --quiet
docker compose -f compose.yaml -f compose.sop-verification.yaml up -d --build api
```

`config --quiet` 仅检查配置，不打印展开后的 secret。同时按现有流程构建并发布上述 Web 合并版本。API 镜像已加入 Python；其他自建镜像需确认解释器版本和 worker 路径。

现有同源 `/api` 代理应继续转发到更新后的 Server，并保留登录 Cookie、CSRF 和 GitHub 来源权限。Web 合并版本已将 Nginx 代理超时设为 150 秒；使用其他代理时也应允许至少 150 秒。worker 上限为 120 秒，Web 请求为 180 秒。无需开放本机的 `8769` 端口，也无需关闭认证。

报告接口为：

```text
POST /api/v1/projects/{project}/tasks/{task}/sop-verifications
GET  /api/v1/projects/{project}/tasks/{task}/sop-verifications
GET  /api/v1/projects/{project}/tasks/{task}/sop-verifications/{id}
```

POST 使用现有浏览器登录和 CSRF，正文示例为 `{"sop_version":1}`；可选 `target_commit` 必须是该项目的完整 40 位 SHA。

## 4. 用一个真实任务验收

1. 登录 FormSy，在测试任务绑定少量可读 Trace，确认原 Conversation、工具调用和 Trace 可打开；确认页面显示的当前生效 SOP 版本。
2. 在任务“验证”页确认材料将发送至 DeepSeek，再点击发起核查。核对报告中的 SOP pin、来源、逐字引文与原文一致。
3. 补充材料后再核查一次，确认出现两轮报告且旧轮次未被覆盖。确认人工检查及任务完成状态没有自动变化。
4. 在测试环境检查无权限拒绝、模型失败提示、缺证据保留未核查，以及超大范围明确拒绝。若选择 Commit，确认完整 diff 能读取；普通测试文本不视为可信执行回执。

POST 成功追加报告返回 `201`；其中也可能保存 `status: failed` 的失败轮次，必须查看报告状态、`analysis_complete` 和 `analysis_errors`，不能只凭 HTTP 状态或模型调用完成认定分析成功。模型候选不等于人工通过。常见接入问题：`503` 检查 worker/key 配置、进程启动或管道故障，`502` 检查 worker 契约或崩溃，`504` 检查超时，`413` 缩小来源范围，`409` 检查目标 diff 完整性或分析期间变化的输入。通过当前权限检查后，才能读取报告正文。

请回传实际 Server/Web/worker SHA、部署 URL、测试项目与任务 ID，以及上述验收结果。无需回传 key、Cookie 或私人 Trace 正文。

## 5. 停用与回滚

执行 `0025` 后，直接运行不含该迁移的旧 Server 镜像会触发 SQLx `VersionMissing(25)`，不能把换回旧镜像当作可用回滚。

- 最小停用：保留本次新版 Server 和数据库，将 `FORMSY_SOP_VERIFICATION_PYTHON`、`FORMSY_SOP_VERIFICATION_WORKER` 置空并按原发布流程重启 API。若使用核查专用 Compose override，需从发布命令中移除 `compose.sop-verification.yaml`，避免它重新设置这两项路径；原有其他 Compose 文件、project、卷、OAuth 和 key 均保留。核查触发返回明确的 `503`，现有人工检查和任务流程继续可用；需要时可单独回退 Web。
- 全量回滚：先停写，再恢复升级前数据库及关联对象存储的一致性备份，并发布与备份匹配的旧 Server/Web。升级后产生的写入可能丢失，需管理员评估恢复范围。不要手工删除迁移记录或报告表来绕过版本检查，也不要执行 `down -v`。

## 已验证与待验证

已执行本地 worker 42 项离线测试；Server 82 项 lib 测试通过、8 项忽略，`cargo check --tests` 及实际 worker 离线联调通过，Knowledge 约束合同 8 项通过、1 项 PostgreSQL 忽略；Web 21 项单元测试、8 个不同的聚焦 Chrome 场景、typecheck、lint、tokens/design、构建及 route-entrypoints 通过。Web 当前 e2e 共 11 项，本轮未全量重跑。两个补丁已核对可应用到 [integration/README.md](../integration/README.md) 所列原基线。

PostgreSQL 迁移、容器构建、共享环境部署和真实 FormSy Trace 的端到端核查尚未验证。四个参考条件仍是局部映射；完整读取已选来源不代表所有现实过程均被记录。部署前的检查和部署后的真实验收不能互相替代。

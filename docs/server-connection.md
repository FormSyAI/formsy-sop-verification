# 服务端接入：管理员交接说明

目前可运行的是本地核查工作台；共享 FormSy 尚未部署本次集成。Server/Web 集成已提交草稿 PR：[Server #25](https://github.com/FormSyAI/formsy-server/pull/25)、[Web #6](https://github.com/FormSyAI/formsy-web/pull/6)。管理员需要审阅、合入并部署两端改动及本仓库的核查程序。仅授予 GitHub 仓库权限、完成 Entire 上传或在本机配置模型 key，都不会自动完成服务端接入。

接通后的流程：用户登录 FormSy → 打开任务的“验证”页 → 确认当前生效 SOP 版本及可选目标 Commit → 显式发起核查 → Server 按当前权限读取任务绑定的 Trace → 调用核查程序与 DeepSeek → 保存并展示候选报告。现有人工检查和任务完成流程不自动改变。

## 已确认的现状

2026-10-12 对当前网页地址 `http://192.168.1.9:3002` 做了不带凭据的只读连通性检查：

- `/api/v1/auth/me` 返回 `401 authentication_required`：API 可达，但独立工作台没有 FormSy 登录授权。
- 向 `/mcp/knowledge` 发送协议初始化请求，返回 `405` 和前端 HTML：这个网页地址尚未提供可用的 MCP 入口。这不能证明实际后端没有 MCP；管理员可确认真实 API 地址及代理规则。

当前 FormSy CLI 的授权范围也不能直接枚举并读取完整 Trace。推荐先部署已有的任务页集成，复用 FormSy 登录、项目权限及完整取证逻辑。现有 MCP 读取还缺少完整的来源枚举与长工具输出覆盖，单独转发路由不足以达到本项目的完整核查要求。

## 管理员需要准备

- Server/Web 仓库的合入及部署权限，以及部署机器、现有配置和数据库的操作权限；申请人的旧仓库上传权限不是部署前提。
- 一个测试项目、已发布且有效的 SOP 版本，以及具有明确 `source_bindings` 的任务。只有 `session_ids` 不代表选定了核查范围。
- 用户能读取选定项目和 GitHub 来源，并能编辑该任务：项目 owner/maintainer，或仍具 developer 角色的任务创建者。项目应已同步可读的 Conversation/Trace 内容；只有 Commit 元数据不足以核查执行过程。
- 部署环境通过既有 secret 渠道提供 DeepSeek key。本机工作台进程中的 key 不会自动同步到服务器，也不需要提交到 GitHub。

## 1. 审阅并合入两个 PR

优先审阅上述 Server/Web PR，核对匹配版本后按团队流程合入。若需要用补丁交接，也可按下面步骤操作；PR 已合入后不再重复应用补丁。

补丁位于本仓库的 [`integration/`](../integration/README.md)，只包含本次改动，不包含旧仓库 Git 历史。

| 仓库 | 补丁 | 已验证可应用的基线 |
| --- | --- | --- |
| formsy-server | [formsy-server.patch](../integration/formsy-server.patch) | `479b80a8eba09ddfc26e7f258bfad4edab8f01aa` |
| formsy-web | [formsy-web.patch](../integration/formsy-web.patch) | `032b05b63b5c71b178c69605adff9f3fb675b307` |

请在各仓库的集成分支上先检查，再应用。例如在 Server checkout 内：

```sh
git switch -c codex/sop-verification-integration
git apply --check /opt/formsy-sop-verification/integration/formsy-server.patch
git apply /opt/formsy-sop-verification/integration/formsy-server.patch
```

Web 同样执行，补丁文件换成 `formsy-web.patch`。若当前部署代码已偏离基线，先复核冲突及关联接口，不使用强制应用。维护者按团队流程审阅、提交并合入。

补丁 SHA-256：

```text
formsy-server.patch  1058d6ef4744a956732aad2d85bf1a034066d93c45f62dc9d7688cc3121f1922
formsy-web.patch     e6b2be1905be12e19174d3fcb5aca9957821c91b33f2e135bc4e46ff31d82b21
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

若沿用 Server 仓库的 Compose，另设 `FORMSY_SOP_VERIFICATION_REPO` 为宿主机完整 worker checkout 的绝对路径。补丁提供的 `compose.sop-verification.yaml` 会只读挂载该目录，并设置容器内的 Python/worker 路径；基础 Compose 会传入模型配置和 key。保留现有数据库、OAuth、卷、Compose project 名及其他生产配置。

## 3. 在测试环境构建、迁移并发布

先备份数据库。Server 启动会执行新增的 `0025_sop_verification_reports.sql`，无需手工创建报告表。

沿用仓库 Compose 时，在原部署上下文加入 override；下面命令还需保留原部署使用的 project 名和其他配置文件：

```sh
docker compose -f compose.yaml -f compose.sop-verification.yaml config --quiet
docker compose -f compose.yaml -f compose.sop-verification.yaml up -d --build api
```

`config --quiet` 仅检查配置，不打印展开后的 secret。同时按现有流程构建并发布匹配的 Web 补丁。补丁中的 API 镜像已加入 Python；其他自建镜像需确认解释器版本和 worker 路径。

现有同源 `/api` 代理应继续转发到更新后的 Server，并保留登录 Cookie、CSRF 和 GitHub 来源权限。反向代理响应超时建议至少 150 秒；worker 上限为 120 秒，Web 为 180 秒。无需开放本机的 `8769` 端口，也无需关闭认证。

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

## 已验证与待验证

已执行本地 worker 42 项离线测试；Server 82 项 lib 测试通过、8 项忽略，`cargo check --tests` 及实际 worker 离线联调通过，Knowledge 约束合同 8 项通过、1 项 PostgreSQL 忽略；Web 21 项单元测试、8 个不同的聚焦 Chrome 场景、typecheck、lint、tokens/design、构建及 route-entrypoints 通过。Web 当前 e2e 共 11 项，本轮未全量重跑。两个补丁已核对可应用到表中基线。

PostgreSQL 迁移、容器构建、共享环境部署和真实 FormSy Trace 的端到端核查尚未验证。四个参考条件仍是局部映射；完整读取已选来源不代表所有现实过程均被记录。部署前的检查和部署后的真实验收不能互相替代。

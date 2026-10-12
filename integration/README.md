# 已合并的 FormSy 集成与补丁

新仓库可独立运行核查内核与本地页面。[Server #25](https://github.com/FormSyAI/formsy-server/pull/25) 和 [Web #6](https://github.com/FormSyAI/formsy-web/pull/6) 已合并到各自 `main`；此目录保存对应集成补丁。共享服务尚未部署，当前尚无已配置的部署主机发布通道。

管理员可直接按[接入步骤](../docs/server-connection.md)部署已合并版本并验收，无需再次合入或应用补丁。

| 补丁 | 已核对基线 | 正式合并提交 | 已合并 PR |
| --- | --- | --- | --- |
| `formsy-server.patch` | `479b80a8eba09ddfc26e7f258bfad4edab8f01aa` | `345d833a3933ba6193993f0913782989e51a1523` | [Server #25](https://github.com/FormSyAI/formsy-server/pull/25) |
| `formsy-web.patch` | `032b05b63b5c71b178c69605adff9f3fb675b307` | `ff020f76e32275b1d4bd7449e3cad286ae6d92d4` | [Web #6](https://github.com/FormSyAI/formsy-web/pull/6) |

请部署上述正式合并版本。补丁仅作交接存档，只包含本次改动，没有导入旧仓库的 Git 历史；已合入 PR 的 checkout 不再重复应用补丁。补丁对应的功能提交为 Server `800f08ee8f714be1e5d84fd142718b8169871bfa` 和 Web `5e1713ac2fa64c0f750a90b62532dca5f4095823`。

补丁 SHA-256：

```text
formsy-server.patch  1058d6ef4744a956732aad2d85bf1a034066d93c45f62dc9d7688cc3121f1922
formsy-web.patch     5584a0a73eec22940c2e9b048e8277d67277fd8ac5a2345af510a9963817e79b
```

Server 补丁包含报告表迁移、受权限控制的取证与 worker 调用、不可变报告 API、部署设置及测试。Web 补丁在任务验证页提供候选条件、原子项、历史轮次、来源定位和分析错误展示。两端都不自动写人工检查或完成任务。

部署时固定完整 worker 仓库到 `2328953cd9eefec02c6c09df7fbb9f3aaf6395e8`（包括 `src/` 和冻结 profile），使用 Python 3.10 以上及既有 secret 渠道注入的 DeepSeek 密钥。Server 的 `docs/sop-verification-mvp.md` 说明只读挂载、迁移、权限、超时和输入限制。部署前备份数据库，核对 SQLx `0025` 无冲突、同源 Cookie/CSRF 与 GitHub 来源权限；保留原 Compose project、文件、卷、OAuth 和 key，不执行 `down -v`。

执行 `0025` 后不能直接回退不含该迁移的旧 Server 镜像，SQLx 会报 `VersionMissing(25)`。优先停用 worker、保留新版 Server，必要时回退 Web；全量回滚需停写并恢复升级前的一致性备份，可能丢失升级后写入。具体步骤见[管理员说明](../docs/server-connection.md#5-停用与回滚)。

已执行的检查：Server 最新完整 lib 82 项通过、8 项忽略，`cargo check --tests` 通过，实际 Python worker 离线烟测通过，Knowledge 约束合同 8 项通过、1 项 PostgreSQL 忽略；Web 21 项 unit、8 个不同的聚焦 Chrome 场景、typecheck、lint、tokens/design check、production build 和 route-entrypoints 通过。Web 当前 e2e 共 11 项，本轮未全量重跑。PostgreSQL、容器构建和生产部署尚未验证。

# 可选的 FormSy 集成补丁

新仓库可独立运行核查内核与本地页面。Server/Web 集成分支已推送并创建草稿 PR；此目录保存与送审提交对应的补丁。尚未合并或部署共享服务。

维护者可直接按[管理员接入步骤](../docs/server-connection.md)完成审阅、部署和验收。

| 补丁 | 已核对基线 | 集成提交 | 草稿 PR |
| --- | --- | --- | --- |
| `formsy-server.patch` | `479b80a8eba09ddfc26e7f258bfad4edab8f01aa` | `800f08ee8f714be1e5d84fd142718b8169871bfa` | [Server #25](https://github.com/FormSyAI/formsy-server/pull/25) |
| `formsy-web.patch` | `032b05b63b5c71b178c69605adff9f3fb675b307` | `caa743f4756e7de70fdfcd69e3118a754dc2054f` | [Web #6](https://github.com/FormSyAI/formsy-web/pull/6) |

请优先审阅上述 PR。补丁来自隔离工作树，只包含本次改动，没有导入旧仓库的 Git 历史；若采用补丁方式，应用到上述基线前先用 `git apply --check <补丁绝对路径>` 检查，基线变化时需重新复核。已合入 PR 后不再重复应用补丁。

Server 补丁包含报告表迁移、受权限控制的取证与 worker 调用、不可变报告 API、部署设置及测试。Web 补丁在任务验证页提供候选条件、原子项、历史轮次、来源定位和分析错误展示。两端都不自动写人工检查或完成任务。

部署时需要完整的本 worker 仓库（包括 `src/` 和冻结 profile），Python 3.10 以上，以及既有 secret 渠道注入的 DeepSeek 密钥。Server 补丁中的 `docs/sop-verification-mvp.md` 说明只读挂载、迁移、权限、超时和输入限制。部署前应备份数据库，核对同源 Cookie/CSRF 与 GitHub 来源权限。

已执行的检查：Server 最新完整 lib 82 项通过、8 项忽略，`cargo check --tests` 通过，实际 Python worker 离线烟测通过，Knowledge 约束合同 8 项通过、1 项 PostgreSQL 忽略；Web 21 项 unit、8 个不同的聚焦 Chrome 场景、typecheck、lint、tokens/design check、production build 和 route-entrypoints 通过。Web 当前 e2e 共 11 项，本轮未全量重跑。PostgreSQL、容器构建和生产部署尚未验证。

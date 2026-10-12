# 可选的 FormSy 集成补丁

新仓库可独立运行核查内核与本地页面。此目录仅保存以后接入 FormSy 的适配改动；当前凭据无法推送既有 Server/Web 仓库，未创建远端集成分支或 PR，也没有部署共享服务。

| 补丁 | 已核对基线 | 本地实现提交 |
| --- | --- | --- |
| `formsy-server.patch` | `479b80a8eba09ddfc26e7f258bfad4edab8f01aa` | `85d07969e47f0385c066d3101072e0a30e915ce7` |
| `formsy-web.patch` | `032b05b63b5c71b178c69605adff9f3fb675b307` | `5b231e7f3c8dcfe0d50ebd60c8a7980e2a1084ef` |

补丁来自隔离工作树，只包含本次改动，没有导入旧仓库的 Git 历史。应用到上述基线前先用 `git apply --check <补丁绝对路径>` 检查；基线变化时需重新复核。

Server 补丁包含报告表迁移、受权限控制的取证与 worker 调用、不可变报告 API、部署设置及测试。Web 补丁在任务验证页提供候选条件、原子项、历史轮次、来源定位和分析错误展示。两端都不自动写人工检查或完成任务。

部署时需要完整的本 worker 仓库（包括 `src/` 和冻结 profile），Python 3.10 以上，以及既有 secret 渠道注入的 DeepSeek 密钥。Server 补丁中的 `docs/sop-verification-mvp.md` 说明只读挂载、迁移、权限、超时和输入限制。部署前应备份数据库，核对同源 Cookie/CSRF 与 GitHub 来源权限。

已执行的检查：Server 最新完整 lib 82 项通过、8 项忽略，`cargo check --tests` 通过，实际 Python worker 离线烟测通过；Web 21 项 unit、8 项 Chrome fixtures、typecheck、lint、design check 和 production build 通过。PostgreSQL、容器构建和生产部署尚未验证。

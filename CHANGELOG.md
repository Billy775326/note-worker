# 更新日志

## [Unreleased]

### Added

- 新增记事本单项 API：列表及关键词搜索、分页、详情、新建、部分修改和删除。接口位于现有私人入口下，继续使用登录 Cookie，保留小说和其他笔记数据。
- 提供接口调用文档和内存 KV 回归测试；沿用现有数据格式，不需要迁移。

### Security

- PATCH、DELETE 与现有 POST 一样校验同源 Origin 和 `X-Requested-With` 请求头。

### Changed

- 补充 README 的接口入口、Linux 服务器更新步骤和发布验证边界；同步已有 Tab/Esc 编辑键盘行为到远端开发源码，保持现有使用流程。

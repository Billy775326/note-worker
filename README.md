# Note Cloudflare Worker

## 控制台直接修改 Secrets

在 Cloudflare → Workers & Pages → note → Settings → Variables and Secrets 中，以 Secret 类型添加或编辑，保存并部署后生效：

| 名称（区分大小写） | 用途 |
| --- | --- |
| `login` | 私人入口后缀，例如 `my-notes` 对应 `/my-notes`。支持 3～128 位英文字母、数字、下划线和连字符，可包含首尾斜杠，不支持多级路径；不要填完整域名。 |
| `PASSWORD_SALT` | 密码盐，至少 16 个字符。保留现有随机值即可。 |
| `SESSION_SECRET` | 会话密钥，至少 32 个字符。修改后所有会话失效。 |
| `PASSWORD_HASH` | 登录密码的加盐 MD5 哈希（32 位十六进制），唯一的密码配置。重新生成方式见下文「改密码」。 |

首页及错误入口只返回独立静态展示页，不读取 KV、不包含私人入口、笔记、登录表单或编辑器脚本。私人 API 也位于 `/<login>/api/...`，仍需登录鉴权。`login` 无效或未设置时关闭私人入口。修改入口或有效密码会使旧会话失效，需要用新地址重新登录。

**改密码 = 生成新的加盐哈希。** 最简单是重新运行 `./setup-secrets.ps1`：会同时更换盐、`SESSION_SECRET` 和哈希（旧会话全部失效，KV 数据不受影响），再运行 `npx wrangler deploy --secrets-file secrets.json`。只想替换哈希时，在 PowerShell 计算后覆盖 `PASSWORD_HASH` Secret：

```powershell
$salt = '粘贴现有 PASSWORD_SALT'; $pwd = Read-Host '新密码'
[BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("${salt}:${pwd}"))).Replace('-','').ToLowerInvariant()
```

明文密码从不保存；Cloudflare 控制台查看不到已保存的 Secret 原文，但可以覆盖修改。

`worker.js` 是完整的单文件 Worker，保留原笔记、小说和采集页面。无需前端构建。

界面采用暖纸、松影和陶土三套主题（新会话默认松影夜色，主题下拉列表同样跟随配色）；记事本默认「对照」模式并随输入实时刷新预览，版型默认宽版，可切窄版/标准；提供标题/正文搜索、内容摘要、作品选中状态和当前正文字数统计；手机端使用抽屉式作品列表。更新界面使用 `npx wrangler deploy --keep-vars`，无需重新上传密码 Secrets。

记事本支持 Markdown 标题、加粗、引用、列表、任务清单、代码块、链接和 GFM 表格。工具栏可切换编辑、对照和预览，点击「＋ 表格」指定 1～12 列、1～50 行，在 Markdown 源码中填写单元格。阅读模式同样渲染 Markdown，支持导出原始 `.md` 文件；沉浸阅读开启时自动跟随当前主题配色，也可手动切换纸张/护眼/夜间。内容仍以原文保存，预览不会修改数据；单元格里的竖线可写作 `\|`。外部图片和任意 HTML 样式不在本次支持范围内。

顶部「历史」列出云端自动留存的最近 10 份快照：自动保存约 10 分钟合并一份，手动保存与回滚前强制留存，快照总量超约 15 MiB 时自动淘汰最旧。选择版本一键回滚；回滚前当前内容会先强制留存一份，可再次回滚撤销。

渲染采用 [Marked](https://marked.js.org/) 和 DOMPurify，经过标签/属性过滤及链接协议限制。依赖已内嵌到 `worker.js`，运行不依赖 CDN；修改 `markdown-browser.js` 或升级依赖后执行 `npm run build:markdown` 重新嵌入，再测试发布。

登录由 `/api/login` 在后端验证 `MD5(UTF8(PASSWORD_SALT + ':' + password))` 并与 `PASSWORD_HASH` 比较；不读取任何明文密码配置。盐为随机 32 字节十六进制字符串；密码原文不写入源码、本地文件或浏览器存储。MD5 加盐抗离线破解能力弱，面向公网长期使用建议迁移 PBKDF2/Argon2。

## 部署

1. 在本目录运行 `npm install --save-dev wrangler`，再运行 `npx wrangler login` 登录 Cloudflare。
2. 修改 `wrangler.jsonc` 的 `name` 为目标 Worker 名称，将 KV ID 占位符替换为原有 KV namespace ID。必须使用原来的 KV 才能继续读取已有数据；键名仍为 `user_creative_data`。新项目可运行 `npx wrangler kv namespace create CLOUD_EDITOR_KV` 创建 KV。
3. 在 PowerShell 运行 `./setup-secrets.ps1`，按隐藏输入提示设置密码。脚本生成 `.dev.vars` 和 `secrets.json`，均已加入忽略列表。
4. 如使用小说采集，在 `PROXY_ALLOWED_HOSTS` 填入可信的公网目标域名，用逗号分隔。域名精确匹配，重定向域名也必须列入；留空禁用网络采集，离线 HTML 采集仍可用。只添加自己信任、不会解析到私有地址的域名。
5. 检查登录限流的 `namespace_id` 在账号内是否已被其他应用使用，需要隔离时改为另一个正整数字符串。默认每个 IP、每个 Cloudflare 节点每分钟最多 5 次登录，属于分布式近似限流。
6. 执行 `npm test`，然后运行 `npx wrangler deploy --secrets-file secrets.json`，一并发布代码和 Secrets。当前锁定的 Wrangler 版本支持此参数，避免代码先上线、Secrets 尚未配置的间隔。
7. 打开部署输出的 HTTPS 地址验证登录、保存、刷新恢复和退出。未登录访问 `/api/get-data` 或 `/api/proxy` 应返回 401。

也可以在 Cloudflare 控制台粘贴 `worker.js`，但仍需配置 KV、三个 Secrets、LOGIN_RATE_LIMITER 限流绑定和可选的域名变量；CLI 配置更容易复现。

## 会话与数据

- 会话采用 HMAC-SHA256 签名 Cookie，`HttpOnly; Secure; SameSite=Strict`，有效期 8 小时。页面自动删除旧版 localStorage 明文密码。需 HTTPS；普通 HTTP 的 Cookie 行为不作为生产支持范围。
- 退出会先保存成功，再清除浏览器 Cookie。无状态会话不能单独撤销已被复制的令牌；更换 `SESSION_SECRET` 或密码盐/哈希后所有旧会话失效。
- 后端检查写请求 Origin 和自定义请求头、JSON 类型、数据结构及最大 20 MiB 请求体；`GET /api/history` 与 `GET /api/history-item?ts=` 读取历史快照，同样要求登录。代理要求登录，限制域名、重定向、15 秒超时和 5 MiB 响应体，不转发用户 Cookie。
- 修复列表、目录、阅读内容的 HTML 注入。加载失败时禁止写入默认空数据；会话过期后重新登录保留当前页面的未保存编辑。
- 沿用原有 KV 全量保存模型：多标签页/多人同时编辑仍可能覆盖，KV 跨地区读取有传播延迟；本次没有实现协同编辑和冲突合并。历史快照存放在第二个键 `user_creative_history`，每次保存多一次 KV 读/写。
- `npm test` 使用 Node 和模拟 KV/限流/代理运行；Node 不支持 Workers 的 MD5 WebCrypto 扩展，测试仅对此调用用 Node OpenSSL 替代。上线后仍需真实环境验证。

官方文档：[Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)、[Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)、[KV bindings](https://developers.cloudflare.com/kv/concepts/kv-bindings/)、[Rate limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)。

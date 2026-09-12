# Note Cloudflare Worker

云端笔记 / 小说编辑器：单文件 Cloudflare Worker。会话登录、Markdown 对照模式、沉浸阅读、版本历史回滚、域名白名单采集代理。

## 目录结构

```text
note-worker/
├── worker.js                 # 完整单文件 Worker（后端 + 内嵌前端），可直接粘贴到 Cloudflare 控制台
├── src/
│   └── markdown-browser.js   # Markdown 渲染源码（marked + DOMPurify 封装）
├── scripts/
│   ├── build-markdown.mjs    # 把 src/markdown-browser.js 打包并内嵌进 worker.js
│   └── setup-secrets.ps1     # 交互式生成 Secrets（密码哈希 / 盐 / 会话密钥）
├── test/
│   └── worker.test.mjs       # 自动化测试（npm test）
├── wrangler.jsonc            # KV、登录限流等部署配置
└── .gitignore                # 已排除 secrets.json / .dev.vars，密钥不入库
```

## 入口与密码：两个关键字段

| 你想要 | 用哪个配置 | 说明 |
| --- | --- | --- |
| **进入登录页面**（决定网址） | Secret `login` | 填 `my-notes` → 登录页就是 `https://<Worker名>.<账户子域>.workers.dev/my-notes`。只填后缀路径，不要带域名；3～128 位英文字母、数字、下划线、连字符。 |
| **输入密码登录**（验证依据） | Secret `PASSWORD_SALT` + `PASSWORD_HASH` | 登录页密码框输入的密码，由后端计算 `MD5(盐 + ':' + 输入的密码)` 并与 `PASSWORD_HASH` 比对，一致才发会话 Cookie。明文密码不保存在任何地方。 |

一句话：`login` 决定**在哪个网址登录**，`PASSWORD_HASH` 决定**输入什么密码能登录**。

其余配置：

| 名称 | 类型 | 作用 |
| --- | --- | --- |
| `SESSION_SECRET` | Secret | 会话 Cookie 的签名密钥（≥32 字符）；更换后所有登录状态失效 |
| `PROXY_ALLOWED_HOSTS` | 普通变量 | 采集代理的域名白名单，逗号分隔；留空禁用网络采集 |

首页与错误入口只返回独立静态展示页，不读取 KV、不包含私人入口、登录表单或编辑器脚本；私人 API 位于 `/<login>/api/...`，同样要求登录。`login` 无效或未设置时关闭私人入口。

## 日常操作

**改密码**：重新运行 `./scripts/setup-secrets.ps1`（同时更换盐、`SESSION_SECRET` 和哈希，旧会话全部失效，KV 数据不受影响），再运行 `npx wrangler deploy --secrets-file secrets.json`。只想替换哈希时，在 PowerShell 里计算后覆盖 `PASSWORD_HASH` Secret：

```powershell
$salt = '粘贴现有 PASSWORD_SALT'; $pwd = Read-Host '新密码'
[BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("${salt}:${pwd}"))).Replace('-','').ToLowerInvariant()
```

明文密码从不保存；控制台查看不到 Secret 原文，但可以覆盖修改。

**改入口**：修改 `login` Secret 即可。旧地址立即关闭，旧会话全部失效，需用新地址重新登录。

**更新界面代码**：改完 `worker.js` 后运行 `npx wrangler deploy --keep-vars`，无需重新上传 Secrets；手动部署则重新粘贴整份 `worker.js`。

**升级 Markdown 依赖**：修改 `src/markdown-browser.js` 或升级依赖后执行 `npm run build:markdown` 重新内嵌进 `worker.js`，再测试发布。渲染采用 [Marked](https://marked.js.org/) + DOMPurify（标签/属性过滤、链接协议限制），运行不依赖 CDN。

## 功能特性

- **编辑器**：暖纸 / 松影 / 陶土三套主题（新会话默认松影夜色，主题下拉列表同样跟随配色）；记事本默认「对照」模式并随输入实时刷新预览；版型默认宽版，可切窄版/标准；标题/正文搜索、内容摘要、字数统计；手机端抽屉式作品列表。
- **Markdown**：标题、加粗、引用、列表、任务清单、代码块、链接和 GFM 表格（「＋ 表格」指定 1～12 列、1～50 行，在源码中填写单元格，竖线写作 `\|`）；支持导出原始 `.md`。预览是只读渲染，不改动保存的原文；外部图片与任意 HTML 样式不支持。
- **沉浸阅读**：开启时自动跟随当前主题配色（暖纸→纸张、松影→夜间、陶土→护眼），也可手动切换纸张/护眼/夜间；阅读模式同样渲染 Markdown。
- **版本历史**：顶部「历史」列出云端自动留存的最近 10 份快照——自动保存约 10 分钟合并一份，手动保存与回滚前强制留存，总量超约 15 MiB 自动淘汰最旧；一键回滚，回滚前当前内容先强制留存一份，可再次回滚撤销。

## 部署

### 方式一：命令行（wrangler，推荐）

1. 本目录运行 `npm install --save-dev wrangler`，再运行 `npx wrangler login` 登录 Cloudflare。
2. 修改 `wrangler.jsonc` 的 `name` 为目标 Worker 名称，将 KV ID 替换为目标 namespace ID。**升级已有项目必须使用原来的 KV 才能读到已有数据**（数据键 `user_creative_data`）；新项目运行 `npx wrangler kv namespace create CLOUD_EDITOR_KV`。
3. PowerShell 运行 `./scripts/setup-secrets.ps1`，按隐藏输入提示设置密码，生成 `.dev.vars` 和 `secrets.json`（均在忽略列表中，不会提交）。
4. 如使用小说采集，在 `PROXY_ALLOWED_HOSTS` 填入可信公网域名（逗号分隔、精确匹配，重定向域名也要列入）；留空禁用网络采集，离线 HTML 采集仍可用。
5. 检查限流 `namespace_id` 未被账号内其他应用占用，需要隔离时改用其他正整数；默认每 IP、每 Cloudflare 节点每分钟最多 5 次登录。
6. `npm test` 通过后运行 `npx wrangler deploy --secrets-file secrets.json`，代码与 Secrets 一并发布，避免「代码先上线、Secrets 未配置」的间隔。
7. 打开部署输出的 `https://<地址>/<login>` 验证登录、保存、刷新恢复、历史回滚；未登录请求 `/<login>/api/get-data` 应返回 401。

### 方式二：手动（Cloudflare 控制台）

1. **创建 Worker 并粘贴代码**：Workers & Pages → Create → Create Worker，名称如 `note`；进入在线编辑器，清空模板代码，粘贴 `worker.js` 全部内容，Deploy。
2. **创建 KV**：Storage & Databases → KV → Create namespace，名称任意（如 `note-data`）。升级旧项目必须选择原来的 namespace。
3. **绑定 KV**：Worker → Settings → Bindings → Add → KV namespace，变量名称填 `CLOUD_EDITOR_KV`，选择上一步的 namespace。
4. **绑定登录限流**：同页 Add → Rate limiting，变量名称 `LOGIN_RATE_LIMITER`，namespace ID 填账号内未占用的正整数（如 `1001`），限制 5 次 / 60 秒。若绑定列表没有 Rate limiting 类型，该绑定只能通过命令行方式完成（`wrangler.jsonc` 已配置）。
5. **添加 Secrets**：Settings → Variables and Secrets → Add，类型选 Secret，逐个添加（生成随机十六进制的命令见表格下方）：

   | 名称 | 填写内容 | 对应作用 |
   | --- | --- | --- |
   | `login` | 入口后缀，如 `my-notes` | **登录页网址**：`https://…/<login>` |
   | `PASSWORD_SALT` | 64 位随机十六进制（生成命令见下） | 密码验证的盐 |
   | `PASSWORD_HASH` | 用上面的盐按「改密码」公式计算，32 位十六进制 | **登录页要输入的密码**对应的哈希 |
   | `SESSION_SECRET` | 生成命令同样适用，取 64 位 | 会话签名，更换后全部会话失效 |

   ```powershell
   # 生成 64 位随机十六进制（PASSWORD_SALT / SESSION_SECRET 都用它）
   (1..64 | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) -join ''
   ```

6. **添加普通变量（可选）**：同页 Add，类型 Text，名称 `PROXY_ALLOWED_HOSTS`，值为逗号分隔的可信采集域名；不用采集可跳过。
7. **验证**：打开 `https://<Worker 名称>.<账户子域>.workers.dev/<login>`，依次验证登录、保存、刷新恢复、历史回滚；未登录请求 `/<login>/api/get-data` 应返回 401。

以后更新：在线编辑器里重新粘贴新的 `worker.js` 保存即可，Secrets 和绑定不受影响。

## 会话与数据

- **会话**：HMAC-SHA256 签名 Cookie，`HttpOnly; Secure; SameSite=Strict`，有效期 8 小时，需 HTTPS。无状态会话无法单独吊销已复制的令牌；更换 `SESSION_SECRET` 或密码盐/哈希后所有旧会话失效。退出先保存再清除 Cookie。
- **数据**：KV 键 `user_creative_data` 全量保存，多标签页/多人并发编辑仍可能互相覆盖，KV 有跨区传播延迟；未实现协同编辑与冲突合并。历史快照存于第二个键 `user_creative_history`，每次保存多一次 KV 读/写。
- **后端防护**：写请求校验 Origin、自定义请求头、JSON 类型、数据结构及 20 MiB 上限；`GET /api/history` 与 `GET /api/history-item?ts=` 同样要求登录；代理限制域名白名单、逐跳重定向复查、15 秒超时、5 MiB 响应体，不转发用户 Cookie。
- **登录验证**：完全在后端完成，不读取任何明文密码配置；MD5 加盐抗离线破解能力弱，面向公网长期使用建议迁移 PBKDF2/Argon2。
- **测试**：`npm test` 在 Node 中以模拟 KV/限流/代理运行；Node 不支持 Workers 的 MD5 WebCrypto 扩展，测试内以 OpenSSL 等价替代；上线后仍需真实环境验证。

官方文档：[Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)、[Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)、[KV bindings](https://developers.cloudflare.com/kv/concepts/kv-bindings/)、[Rate limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)。

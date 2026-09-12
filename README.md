# note · 云端笔记与小说编辑器

单文件 Cloudflare Worker：无前端构建、无数据库、无外部依赖，一个 `worker.js` 加一个 KV 即可运行。

## 功能特性

- **双栏编辑器**：笔记 / 小说（多卷多章）两种类型；记事本默认「对照」模式，编辑与预览并排、随输入实时刷新；标题/正文搜索、字数统计；手机端抽屉式作品列表。
- **Markdown**：标题、加粗、引用、列表、任务清单、代码块、链接、GFM 表格（1～12 列 × 1～50 行）；导出 `.md`。预览只读渲染，不改动保存的原文；不支持外部图片与任意 HTML。
- **沉浸阅读**：自动跟随当前主题配色（暖纸→纸张、松影→夜间、陶土→护眼），也可手动切换纸张/护眼/夜间。
- **版本历史**：云端自动留存最近 10 份快照，一键回滚；回滚前当前内容先强制留存，可再回滚撤销。
- **安全基线**：私人入口 + HMAC 会话 + 登录限流 + CSRF/SSRF 防护 + DOMPurify 过滤，详情见[架构与安全](#架构与安全)。

## 两个关键字段：入口与密码

部署后怎么打开、用什么登录，由这两个配置决定：

| 你想要 | 用哪个配置 | 说明 |
| --- | --- | --- |
| **进入登录页面**（决定网址） | Secret `login` | 填 `my-notes` → 登录页就是 `https://<Worker名>.<账户子域>.workers.dev/my-notes`。只填后缀路径，不要带域名；3～128 位英文字母、数字、下划线、连字符。 |
| **输入密码登录**（验证依据） | Secret `PASSWORD_HASH`（+ `PASSWORD_SALT`） | 两种填法任选：① 按「改密码」公式算出 32 位十六进制加盐 MD5（推荐）；② **直接填密码原文**，后端登录时现算加盐 MD5 比对（原文仅存于 Cloudflare Secrets）。 |

一句话：`login` 决定**在哪个网址登录**，`PASSWORD_HASH` 决定**输入什么密码能登录**。

其余配置：

| 名称 | 类型 | 作用 |
| --- | --- | --- |
| `PASSWORD_SALT` | Secret | 密码验证的盐，任意非空字符串（建议 64 位随机十六进制） |
| `SESSION_SECRET` | Secret | 会话 Cookie 签名密钥，任意非空字符串（建议 64 位随机十六进制）；更换后所有登录状态失效 |
| `PROXY_ALLOWED_HOSTS` | 普通变量 | 采集代理的域名白名单，逗号分隔、精确匹配；留空禁用网络采集 |

三个 Secret 字段（`PASSWORD_SALT` / `PASSWORD_HASH` / `SESSION_SECRET`）都**无格式强制、兼容明文**，首尾空格和换行自动忽略；但短盐/短密钥会降低防破解强度，正式使用建议随机长值。`login` 无效或未设置时关闭私人入口。

## 部署

### 方式一：命令行（wrangler，推荐）

1. 本目录运行 `npm install --save-dev wrangler`，再运行 `npx wrangler login` 登录 Cloudflare。
2. 修改 `wrangler.jsonc` 的 `name` 为目标 Worker 名称，将 KV ID 替换为目标 namespace ID。**升级已有项目必须使用原来的 KV 才能读到已有数据**（数据键 `user_creative_data`）；新项目运行 `npx wrangler kv namespace create CLOUD_EDITOR_KV`。
3. PowerShell 运行 `./scripts/setup-secrets.ps1`，按隐藏输入提示设置密码，生成 `.dev.vars` 和 `secrets.json`（均在忽略列表中，不会提交）。
4. 如使用小说采集，在 `PROXY_ALLOWED_HOSTS` 填入可信公网域名（重定向域名也要列入）；留空禁用网络采集，离线 HTML 采集仍可用。
5. 检查限流 `namespace_id` 未被账号内其他应用占用；默认每 IP、每 Cloudflare 节点每分钟最多 5 次登录。
6. `npm test` 通过后运行 `npx wrangler deploy --secrets-file secrets.json`，代码与 Secrets 一并发布。
7. 打开部署输出的 `https://<地址>/<login>` 验证：登录、保存、刷新恢复、历史回滚；未登录请求 `/<login>/api/get-data` 应返回 401。

### 方式二：手动（Cloudflare 控制台）

1. **创建 Worker 并粘贴代码**：Workers & Pages → Create → Create Worker，名称如 `note`；在线编辑器清空模板，粘贴 `worker.js` 全部内容，Deploy。
2. **创建 KV**：Storage & Databases → KV → Create namespace（如 `note-data`）。升级旧项目必须选择原来的 namespace。
3. **绑定 KV**：Worker → Settings → Bindings → Add → KV namespace，变量名称填 `CLOUD_EDITOR_KV`，选择上一步的 namespace。
4. **绑定登录限流（必需）**：同页 Add → Rate limiting，变量名称 `LOGIN_RATE_LIMITER`，namespace ID 填账号内未占用的正整数（如 `1001`），限制 5 次 / 60 秒。**跳过将无法登录**；若绑定列表没有 Rate limiting 类型，只能用命令行方式。
5. **添加 Secrets**：Settings → Variables and Secrets → Add，类型选 Secret：

   | 名称 | 填写内容 | 对应作用 |
   | --- | --- | --- |
   | `login` | 入口后缀，如 `my-notes` | **登录页网址**：`https://…/<login>` |
   | `PASSWORD_SALT` | 任意非空字符串，建议随机十六进制（生成命令见下） | 密码验证的盐 |
   | `PASSWORD_HASH` | **直接填登录密码原文**，或按「日常操作 → 改密码」公式计算哈希 | **登录页要输入的密码** |
   | `SESSION_SECRET` | 任意非空字符串，建议随机十六进制 | 会话签名，更换后全部会话失效 |

   ```powershell
   # 生成 64 位随机十六进制（PASSWORD_SALT / SESSION_SECRET 都用它）
   (1..64 | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) -join ''
   ```

6. **添加普通变量（可选）**：同页 Add，类型 Text，名称 `PROXY_ALLOWED_HOSTS`，值为逗号分隔的可信采集域名。
7. **验证**：打开 `https://<Worker 名称>.<账户子域>.workers.dev/<login>`，依次验证登录、保存、刷新恢复、历史回滚。

以后更新：在线编辑器里重新粘贴新的 `worker.js` 保存即可，Secrets 和绑定不受影响。

> 登录时若提示「服务配置不完整，缺少：…」，冒号后面就是要补的清单——逐项到 Settings → Bindings / Variables and Secrets 里补齐即可，补完立即生效，无需重新部署。

## 日常操作

**改密码**——三种做法任选：

1. 最简单：把新密码原文直接填入 `PASSWORD_HASH` Secret，立即生效（原文会保存在 Cloudflare Secrets 中）。
2. 更严谨：PowerShell 计算加盐哈希后覆盖 `PASSWORD_HASH`（明文不落任何存储）：

   ```powershell
   $salt = '粘贴现有 PASSWORD_SALT'; $pwd = Read-Host '新密码'
   [BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("${salt}:${pwd}"))).Replace('-','').ToLowerInvariant()
   ```

3. 最彻底：重新运行 `./scripts/setup-secrets.ps1`，同时更换盐、`SESSION_SECRET` 和哈希（KV 数据不受影响），再 `npx wrangler deploy --secrets-file secrets.json`。

以上操作都会使旧会话失效，需重新登录。

**改入口**：修改 `login` Secret。旧地址立即关闭，需用新地址重新登录。

**更新界面代码**：`npx wrangler deploy --keep-vars`，无需重新上传 Secrets；手动部署则重新粘贴 `worker.js`。

**升级 Markdown 依赖**：修改 `src/markdown-browser.js` 或升级依赖后执行 `npm run build:markdown` 重新内嵌进 `worker.js`。渲染采用 [Marked](https://marked.js.org/) + DOMPurify（标签/属性过滤、链接协议限制），运行不依赖 CDN。

## 本地开发与测试

```bash
npm install              # 安装 wrangler、esbuild、marked、dompurify
npm run dev              # 本地启动（读取 .dev.vars 中的 Secrets，KV/限流为本地模拟）
npm test                 # 16 项自动化测试
npm run build:markdown   # 重新内嵌 Markdown 渲染器
npm run deploy           # 等价于 npx wrangler deploy
```

`npm test` 在 Node 中以模拟 KV/限流/代理运行全部路由与安全断言；Node 不支持 Workers 的 MD5 WebCrypto 扩展，测试内以 OpenSSL 等价替代。上线后仍需真实环境验证。

## 架构与安全

### 目录结构

```text
note-worker/
├── worker.js                 # 完整单文件 Worker（后端 + 内嵌前端），可直接粘贴到控制台
├── src/
│   └── markdown-browser.js   # Markdown 渲染源码（marked + DOMPurify 封装）
├── scripts/
│   ├── build-markdown.mjs    # 打包 src/markdown-browser.js 并内嵌进 worker.js
│   └── setup-secrets.ps1     # 交互式生成 Secrets（哈希 / 盐 / 会话密钥）
├── test/
│   └── worker.test.mjs       # 自动化测试
├── wrangler.jsonc            # KV、登录限流绑定等部署配置
└── .gitignore                # 已排除 secrets.json / .dev.vars，密钥不入库
```

### 私有 API 一览（均位于 `/<login>` 前缀下，除登录外都要求有效会话）

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/api/login` | POST | 登录，限流 5 次/分钟/IP，成功签发 8 小时会话 Cookie |
| `/api/logout` | POST | 退出并清除 Cookie |
| `/api/session` | GET | 会话有效性检查 |
| `/api/get-data` | GET | 读取全部笔记与小说（KV 键 `user_creative_data`） |
| `/api/save-data` | POST | 全量保存；内容有变化时自动留存历史快照 |
| `/api/history` | GET | 历史快照列表（最多 10 份，约 10 分钟合并，总量 15 MiB 内） |
| `/api/history-item?ts=` | GET | 读取指定快照，用于回滚 |
| `/api/proxy?url=` | GET | 白名单采集代理：逐跳重定向复查、15 秒超时、5 MiB 上限、不转发 Cookie |

### 安全说明

- **会话**：HMAC-SHA256 签名 Cookie，`HttpOnly; Secure; SameSite=Strict`，8 小时，需 HTTPS。签名密钥由 `SESSION_SECRET`、盐、密码、入口路径共同派生，更换任一项即全量失效；无状态会话无法单独吊销已复制的令牌。
- **写请求防护**：校验 Origin、自定义请求头、JSON 类型、数据结构及 20 MiB 上限；加载失败时禁止写入默认空数据。
- **页面隔离**：首页与错误入口只返回静态展示页，不读 KV、不含私人入口与编辑器脚本。
- **已知取舍**：MD5 加盐抗离线破解能力弱，公网长期使用建议迁移 PBKDF2/Argon2；KV 全量保存模型下多标签页并发编辑可能互相覆盖，未实现协同编辑。

官方文档：[Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)、[Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)、[KV bindings](https://developers.cloudflare.com/kv/concepts/kv-bindings/)、[Rate limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)。

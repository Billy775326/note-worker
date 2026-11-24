# 记事本增删查改 API

本接口操作随手记（`notes`），不提供小说、卷、章节的单项增删改。旧版整库接口继续保留，数据仍存储于现有 `CLOUD_EDITOR_KV`，无需迁移。

以下地址和密码均为示例。若 `login` Secret 是 `my-notes`，API 前缀为 `https://notes.example/my-notes/api`。URL 后缀不是密码，所有笔记接口仍要求登录 Cookie；未登录返回 401。

## 登录与请求头

先请求 `POST /<login>/api/login`，JSON 内容为 `{"password":"你的密码"}`。登录成功后使用响应中的 HttpOnly Cookie；现有会话有效期为 8 小时。

所有写请求（POST、PATCH、DELETE）必须携带：

```http
Origin: https://notes.example
X-Requested-With: note-editor
```

有 JSON 请求体时还需 `Content-Type: application/json`。同源页面可直接使用现有 `apiFetch`；脚本客户端需显式发送上面的头并维护 Cookie。接口不新增 Bearer Token 或跨域 CORS 支持。

## 接口列表

| 方法 | 路径（相对于 API 前缀） | 成功响应 |
| --- | --- | --- |
| GET | `/notes?q=关键词&offset=0&limit=50` | 200：`{notes, total, offset, limit}` |
| GET | `/notes/{id}` | 200：`{note}` |
| POST | `/notes` | 201：`{note}`，并返回 `Location` |
| PATCH | `/notes/{id}` | 200：`{note}` |
| DELETE | `/notes/{id}` | 200：`{success:true, id}` |

列表包含笔记正文，按现有存储顺序返回；`q` 对标题和正文进行不区分大小写的子串匹配，不解析 Markdown。`offset` 是非负安全整数，默认 0；`limit` 是 1～200 的整数，默认 50。`total` 是过滤后的总数，越界页返回空列表。

### 新建与修改

```json
{
  "title": "项目计划",
  "content": "# 本周计划\n\n| 事项 | 状态 |\n| --- | --- |\n| 整理笔记 | 进行中 |",
  "pinned": false
}
```

- 新建必须提供非空字符串 `title`，会去掉首尾空白；`content` 默认空字符串，`pinned` 默认 false。
- PATCH 至少提供一个字段，只更新所提供的字段。`content` 可设为空字符串，`pinned` 必须是布尔值。
- 两种请求均只接受 `title`、`content`、`pinned`，未知字段会报错。
- 新建时后端生成 UUID、`createdAt`、`updatedAt`；修改时保留原 ID、创建时间及其他元数据，更新 `updatedAt`。时间为 UTC Unix 毫秒数。
- Markdown 作为原文保存，接口不渲染 HTML。已有笔记的额外字段仍会保留并随详情返回。
- 删除立即移除指定笔记，再次操作该 ID 返回 404。沿用现有的有限历史快照机制（尽力保存、按时间合并），不保证每次 API 操作都生成独立版本，也不承诺删除必可恢复。

## 同源页面调用示例

在已登录的记事本页面中，`apiFetch` 会自动补全私人入口和必要的写请求头：

```javascript
async function result(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

const created = await result(await apiFetch('/api/notes', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ title: '项目计划', content: '# 本周计划' })
}));
const id = encodeURIComponent(created.note.id);

const list = await result(await apiFetch('/api/notes?q=' + encodeURIComponent('计划')));
const detail = await result(await apiFetch('/api/notes/' + id));

await result(await apiFetch('/api/notes/' + id, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: '# 已更新的计划', pinned: true })
}));

await result(await apiFetch('/api/notes/' + id, { method: 'DELETE' }));
```

该示例包含真实写入与删除动作，仅对测试笔记执行。当前页面仍使用自己的内存副本和整库自动保存，API 不会自动刷新该副本。不要同时运行此示例和页面编辑；调用后需在无待保存编辑时刷新页面。

## 错误及边界

错误响应为 `{"error":"说明"}`。

| 状态码 | 说明 |
| --- | --- |
| 400 | JSON、字段或分页参数无效 |
| 401 | 未登录、Cookie 无效或过期 |
| 403 | 写请求缺少来源/自定义头，或来源不符 |
| 404 | 入口、路径、ID 不存在；重复删除也返回 404 |
| 405 | 已识别路径不支持该方法，响应包含 `Allow` |
| 413 | 请求体或操作后整库 JSON 的 UTF-8 大小超过 20 MiB |
| 415 | JSON 请求未使用正确 Content-Type |
| 429 | 登录尝试触发已有频率限制 |
| 500 | 存储内容损坏或 KV 读写失败 |
| 503 | Worker 现有必需配置缺失 |

ID 允许 1～128 位字母、数字、下划线和连字符。不支持尾随斜杠或多级 ID。无效存储数据不会被本接口自动清空重建。不存在的 KV 数据键视为首次使用，可创建空库。

**并发限制：**这些操作仍是 KV 整库的读取—修改—写入，无事务锁、条件更新或幂等键。多个请求或打开的编辑器同时保存可能丢失更新，跨节点读取也可能存在传播延迟；请串行操作并避免与旧整库保存混用。新建请求若响应丢失，不应直接重发，以免重复创建。需要强一致协作时应另行迁移存储方案。

## 开发验证

需要 Node.js 20+，无需安装第三方包。在项目根目录运行：

```bash
node --check worker.js
node test/notes-api.mjs
```

测试使用虚构环境和内存 KV，覆盖完整 CRUD、搜索分页、会话鉴权、写入来源、非法字段、损坏数据、历史保留及体积限制。它不访问 Cloudflare，不代表线上 KV 并发或真实登录部署验证。

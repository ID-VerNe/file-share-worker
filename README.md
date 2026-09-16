# Cloudflare R2 Share - 私人文件分享与管理系统

基于 **Cloudflare Workers**、**Cloudflare R2** 和 **Cloudflare D1** 构建的轻量级、高安全性私人文件存储与分享系统。

专为"个人偶尔分享文件"的场景设计。通过高度定制的安全策略（Cloudflare Access + HMAC 动态签名），在彻底杜绝 R2 存储桶被公网恶意刷流量的同时，保留了极简的直连下载体验。

---

## 技术栈

| 层级 | 技术 |
|------|------|
| 计算层 | Cloudflare Workers (JavaScript / V8 Isolate) |
| 存储层 | Cloudflare R2 Object Storage |
| 元数据层 | Cloudflare D1 (SQLite) |
| 安全认证 | Cloudflare Access (Zero Trust) 邮箱验证 + HMAC-SHA256 动态签名 |
| 定时任务 | Cron Trigger（每 30 分钟清理过期文件） |
| 前端界面 | 原生 HTML5 + CSS3 + Vanilla JS（内置渲染，零外部依赖） |

---

## 核心特性

1. **动态签名保护：** 每个分享链接均根据文件名、过期时间、文件版本盐值和一次性标记动态生成 HMAC-SHA256 签名，防止横向越权访问。
2. **链接时效性：** 支持设置链接有效期（默认 24 小时，最长 30 天），过期自动失效。
3. **一次性链接（One-Time Link）：** 支持生成仅可访问一次的下载链接，首次完整下载后自动吊销，适合发送敏感文件。
4. **下载次数限制：** 上传时可设置最大下载次数，达到上限后链接自动失效。计数按"完整下载"计：流式播放器的 Range 请求不消耗额度，只有覆盖到文件末字节的下载（200 全量或末段 206）才 +1。
5. **链接吊销（Revoke）：** 支持一键吊销某个文件的所有已签发链接，通过更新文件元数据中的版本盐值使旧签名立即失效，无需删除文件。
6. **链接作废（Invalidate）：** 支持将文件标记为"待删除"状态，立即失效所有链接，并在下次 Cron 触发时自动从 R2 中物理删除。
7. **多密钥轮转支持：** 签名支持 `kid`（Key ID）参数，可在 `AUTH_SECRET` 中以 JSON 形式配置多个密钥，实现平滑密钥轮换。
8. **大文件分片上传：** 突破 Cloudflare Workers 免费版 100MB 请求体限制，前端使用 40MB 自动切片并发流式上传，单文件最大支持 8GB。
9. **存储配额管理：** 可配置总存储上限（默认 10GB），上传前自动校验，超限拒绝上传。
10. **文件类型白名单：** 仅允许上传指定扩展名的文件类型，防止恶意文件上传。
11. **完美中文支持：** 严格遵循 RFC 5987 标准（`filename*=UTF-8''`），彻底解决下载时中文文件名乱码问题。
12. **原子下载计数：** 基于 D1 数据库的 `RETURNING` 子句实现原子化的下载次数递增，仅在完整下载时计数，精确控制下载限额。
13. **元数据自愈（Self-Healing）：** 当文件存在于 R2 但 D1 元数据记录缺失时，自动从 R2 的 Custom Metadata 重建 D1 记录，保证系统一致性。
14. **惰性清理（Lazy Cleanup）：** 访问过期文件时即时删除并返回失效页面，Cron 定时任务做兜底批量清理。
15. **美观的失效页面：** 链接过期或达到下载上限时，返回友好的中文/双语失效提示页面。
16. **CORS 跨域支持：** 完整处理 `OPTIONS` 预检请求并全局注入 CORS 头，允许从其他域名安全调用 API 或下载资源。
17. **深度防探测机制：** 统一签名错误与资源不存在时的返回行为（模糊处理），避免攻击者通过响应差异进行文件枚举探测。
18. **安全响应头：** 自动注入 `X-Robots-Tag: noindex, nofollow` 防止搜索引擎索引、`X-Content-Type-Options: nosniff` 防止 MIME 嗅探、`Cache-Control: no-store` 强制禁用缓存以确保下载计数准确。
19. **结构化日志：** 支持 Cloudflare Analytics Engine，所有操作记录结构化日志，邮箱自动脱敏。

---

## D1 数据库

系统使用 Cloudflare D1（基于 SQLite）存储文件元数据，实现精确的下载计数、链接状态追踪和自动清理。

### 建表语句

请在 Cloudflare Dashboard 或通过 Wrangler 执行以下 SQL：

```sql
CREATE TABLE IF NOT EXISTS files (
  file_key       TEXT PRIMARY KEY,       -- 文件名（R2 Object Key）
  original_name  TEXT NOT NULL,           -- 原始文件名
  expire_at      INTEGER NOT NULL,        -- 过期时间戳（Unix 秒）
  max_downloads  INTEGER DEFAULT 999999,  -- 最大下载次数
  download_count INTEGER DEFAULT 0,       -- 当前下载次数
  version_salt   TEXT NOT NULL,           -- 版本盐值（用于签名和吊销）
  is_one_time    INTEGER DEFAULT 0,       -- 是否一次性链接
  status         TEXT DEFAULT 'active',   -- active / pending_delete / deleted (expired 仅在请求处理时作为内存瞬态，不落库)
  created_at     INTEGER NOT NULL,        -- 创建时间戳
  delete_after   INTEGER                  -- 待删除时间戳（pending_delete 状态用）
);

CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_expire ON files(expire_at);
```

> 额外建一个 `meta` 表维护 `used_bytes` 配额计数器（见 `migrations/0002_create_meta_table.sql`），后台打开与上传检查只读单行，不再每次全桶 `list`：

```sql
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT OR IGNORE INTO meta (k, v) VALUES ('used_bytes', '0');
```

---

## 系统架构与请求路由

```mermaid
flowchart TD
    User(["用户 / 浏览器"]) -->|HTTPS Request| CF_Edge["Cloudflare 边缘节点"]
    CF_Edge -->|/_admin/* 路径| ZeroTrust{"Cloudflare Access"}
    ZeroTrust -->|未登录| Login["重定向至邮箱登录页"]
    ZeroTrust -->|已登录| Worker

    CF_Edge -->|其他路径| Worker["Cloudflare Worker"]

    Worker --> Route{"路由解析"}

    Route -->|/_admin| AdminModule["src/admin.js<br/>Dashboard + 管理 API<br/>+ 分片上传"]
    Route -->|GET /*| VerifyFlow{"D1 查询文件状态"}

    VerifyFlow -->|文件不存在/非活跃| SelfHeal{"R2 自愈检查"}
    SelfHeal -->|R2 有元数据| Rebuild["重建 D1 记录"]
    SelfHeal -->|R2 也无| ExpiredPage["返回失效页面"]

    Rebuild --> CryptoModule["src/crypto.js<br/>HMAC 签名校验"]
    VerifyFlow -->|活跃且未过期| CryptoModule

    CryptoModule -->|校验失败 / 过期| 403["403 Forbidden / 失效页面"]
    CryptoModule -->|校验成功| CountFlow{"原子下载计数"}
    
    CountFlow -->|达上限 / 一次性| AutoRevoke["自动吊销 + 待删除标记"]
    CountFlow -->|正常| BucketModule["src/bucket.js<br/>从 R2 读取文件流"]

    AdminModule --> R2[("R2 Storage Bucket")]
    AdminModule --> D1[("D1 Database")]
    BucketModule --> R2
    CountFlow --> D1
    VerifyFlow --> D1

    subgraph Cron["Cron Trigger (每30分钟)"]
        Cleanup["查询过期/pending_delete 记录"] --> BatchDelete["批量删除 R2 + D1"]
    end
```

### 路由说明

| 路径 | 方法 | 认证方式 | 说明 |
|------|------|----------|------|
| `/_admin` | GET | Cloudflare Access | 管理后台 Dashboard |
| `/_admin/api/sign` | GET | Cloudflare Access | 生成文件分享签名链接 |
| `/_admin/api/revoke` | POST | Cloudflare Access | 吊销文件所有已签发链接 |
| `/_admin/api/invalidate` | POST | Cloudflare Access | 作废链接并标记待删除 |
| `/_admin/api/delete/*` | DELETE | Cloudflare Access | 物理删除文件 |
| `/_admin/api/reconcile` | POST | Cloudflare Access | 全桶扫描校准 used_bytes 配额计数器 |
| `/_admin/api/multipart/start` | GET | Cloudflare Access | 初始化分片上传 |
| `/_admin/api/multipart/upload` | PUT | Cloudflare Access | 上传分片 |
| `/_admin/api/multipart/complete` | POST | Cloudflare Access | 完成分片上传 |
| `/_admin/api/multipart/abort` | DELETE | Cloudflare Access | 中止分片上传 |
| `/{filename}?s=&e=&k=&ot=` | GET | HMAC 签名 | 公开下载文件 |

### 公开下载 URL 参数

| 参数 | 必填 | 说明 |
|------|------|------|
| `s` | 是 | HMAC-SHA256 签名值 |
| `e` | 是 | 过期时间戳（Unix 秒） |
| `k` | 否 | 密钥 ID，默认 `v1` |
| `ot` | 否 | 是否为一次性链接，`1` 表示启用 |

---

## 目录结构

```
file-share-worker/
├── src/
│   ├── index.js      # 主入口，路由分发、安全检查、CORS 处理、Cron 定时任务
│   ├── crypto.js     # HMAC-SHA256 签名生成、校验及恒定时间比较
│   ├── admin.js      # 管理后台 Dashboard、分片上传及所有管理 API
│   ├── bucket.js     # R2 存储桶操作抽象层（文件读取、Range 支持）
│   └── logger.js     # 结构化日志及 Analytics Engine 上报
├── public/
│   └── favicon.png   # 站点图标
├── test/
│   └── index.spec.js # Vitest 单元测试
├── wrangler.jsonc    # Wrangler 配置文件
├── vitest.config.js  # Vitest 配置
└── package.json
```

---

## 快速开始

### 前置条件

- Node.js 18+
- pnpm
- Cloudflare 账号
- 已创建 R2 存储桶
- 已创建 D1 数据库

### 1. 克隆并安装依赖

```bash
pnpm install
```

### 2. 配置 R2 存储桶与 D1 数据库

编辑 `wrangler.jsonc`，将 `r2_buckets[0].bucket_name` 和 `d1_databases[0].database_id` 修改为你的实际值：

```jsonc
"r2_buckets": [
  {
    "binding": "BUCKET",
    "bucket_name": "你的存储桶名称"
  }
],
"d1_databases": [
  {
    "binding": "file_share_db",
    "database_name": "file-share-db",
    "database_id": "你的 D1 数据库 ID"
  }
]
```

### 3. 初始化 D1 数据库表

```bash
npx wrangler d1 execute file-share-db --file=./schema.sql
```

或者直接执行 SQL：

```bash
npx wrangler d1 execute file-share-db --command="CREATE TABLE IF NOT EXISTS files (file_key TEXT PRIMARY KEY, original_name TEXT NOT NULL, expire_at INTEGER NOT NULL, max_downloads INTEGER DEFAULT 999999, download_count INTEGER DEFAULT 0, version_salt TEXT NOT NULL, is_one_time INTEGER DEFAULT 0, status TEXT DEFAULT 'active', created_at INTEGER NOT NULL, delete_after INTEGER); CREATE INDEX IF NOT EXISTS idx_files_status ON files(status); CREATE INDEX IF NOT EXISTS idx_files_expire ON files(expire_at);"
```

### 4. 配置密钥

```bash
# 设置 HMAC 签名密钥（生产环境必填）
npx wrangler secret put AUTH_SECRET
```

输入一个随机长字符串作为 HMAC 签名密钥。建议使用以下命令生成：

```bash
openssl rand -base64 32
```

### 5. 配置管理员邮箱与 Access 验证

```bash
# 设置管理员邮箱列表，多个邮箱用逗号分隔
npx wrangler secret put ADMIN_EMAILS
# 设置 Cloudflare Access 团队域名（形如 https://<team>.cloudflareaccess.com）
npx wrangler secret put TEAM_DOMAIN
# 设置 Access 应用 Audience Tag（Zero Trust -> Access -> Applications -> 你的应用 -> Additional settings -> Application Audience (AUD) Tag）
npx wrangler secret put POLICY_AUD
```

输入格式：`admin@example.com,admin2@example.com`

### 6. 本地开发

```bash
pnpm run dev
```

### 7. 部署

```bash
pnpm run deploy
```

---

## 环境变量

| 变量名 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `AUTH_SECRET` | Secret | 生产环境必填 | - | HMAC 签名密钥。支持两种格式：<br>• 纯字符串：作为 `kid=v1` 的密钥<br>• JSON 对象：`{"v1":"密钥1","v2":"密钥2"}` 支持多密钥轮转 |
| `ADMIN_EMAILS` | Secret | 是 | - | 管理员邮箱列表，支持多个邮箱用逗号分隔（如 `a@b.com,c@d.com`） |
| `TEAM_DOMAIN` | Secret | 是 | - | Cloudflare Access 团队域名，形如 `https://<team>.cloudflareaccess.com`，用于验证 `CF-Access-JWT-Assertion` |
| `POLICY_AUD` | Secret | 是 | - | Cloudflare Access 应用的 Audience Tag，用于 JWT `aud` 校验 |
| `TOTAL_QUOTA_GB` | Var | 否 | `10` | 存储总配额（GB），超出后拒绝上传 |

---

## 生产环境部署检查清单

### 1. Cloudflare Access 配置

在 Cloudflare Zero Trust 控制台为 `/_admin*` 路径创建 Access Application：

1. 进入 Zero Trust Dashboard → Access → Applications
2. 创建 Self-hosted 应用，Application Domain 填写你的自定义域名
3. Path 设置为 `/_admin*`
4. 在 Policy 中配置仅允许管理员邮箱访问
5. 复制该应用的 Application Audience (AUD) Tag，填入 `POLICY_AUD` secret

**重要：每个 shard 域名都要单独配置 Access。** 分片上传走 `SHARD_DOMAINS` 里的一组域名，这些是不同于主域的另一组域名，Worker 在它们上同样靠 Access 鉴权。如果任一 shard 域名没有自己的 Access 策略，该域名上的 `/_admin*` 就不会经过 Access，鉴权依赖就会崩塌。为每个 shard 域名重复上面的 1-5 步。

### 2. 管理员邮箱与 JWT 验证

管理员邮箱通过 secret `ADMIN_EMAILS` 管理。生产环境下，Worker 用 `TEAM_DOMAIN`+`POLICY_AUD` 验证 `CF-Access-JWT-Assertion` 的 RS256 签名与 `aud`/`iss`/`exp`，从验证后的 JWT 取 `email` 比对白名单——不再裸信 `CF-Access-Authenticated-User-Email` 头（该头在未过 Access 的域名上可被伪造）。

```bash
npx wrangler secret put ADMIN_EMAILS    # 输入: user1@example.com,user2@example.com
npx wrangler secret put TEAM_DOMAIN    # 输入: https://<team>.cloudflareaccess.com
npx wrangler secret put POLICY_AUD     # 输入: <Access app AUD tag>
```

### 3. 自定义域名绑定

在 Worker → Settings → Domains 中绑定自定义域名。建议在 `wrangler.jsonc` 中保持 `"workers_dev": false` 以禁用 `.workers.dev` 直接访问。

### 4. R2 生命周期规则（重要）

必须在 R2 存储桶上配置生命周期规则：

- **自动中止未完成的分片上传：** 设置 N 天（建议 1 天）后自动中止，防止上传失败产生孤儿分片，造成隐性存储费用。
- **自动清理过期文件：** 根据需要设置过期删除规则，节省存储空间。

### 5. Analytics Engine（可选）

系统已内置结构化日志。如需在 Cloudflare Dashboard 查看操作统计：

1. 在 Cloudflare Dashboard 创建 Analytics Engine 数据集
2. 取消 `wrangler.jsonc` 中 `analytics_engine_datasets` 配置的注释，填写正确的 `dataset` 名称
3. 重新部署

### 6. 安全加固

- 系统已内置分片上传失败自动中止（Abort）逻辑
- 签名校验采用恒定时间比较，防止时序攻击
- 签名错误与资源不存在统一返回 403，防止信息泄露
- 生产环境自动阻止 `.workers.dev` 域名直接访问
- **防索引保护**：自动注入 `X-Robots-Tag: noindex, nofollow` 响应头，防止搜索引擎抓取已签发的链接
- **缓存控制**：强制 `Cache-Control: no-store, no-cache, must-revalidate`，确保每次下载都经过计数校验
- **失效页面**：链接过期或达上限时展示友好的中文/双语提示页面，不暴露任何技术细节

---

## 速率限制与滥用防护 (Rate Limiting)

由于下载链接是公开的（仅受签名保护），为了防止链接泄露后的恶意刷流，建议在 Cloudflare Dashboard 中配置 **WAF 速率限制规则**。

### 配置步骤

1. 登录 Cloudflare 控制台 → **安全性 (Security)** → **WAF** → **速率限制规则 (Rate Limiting Rules)**。
2. 创建规则：
   - **名称**: `Limit R2 Downloads`
   - **匹配条件**:
     - `URI 路径` 不等于 `/_admin*`（排除管理后台）
     - `URI 路径` 不等于 `/favicon.png`
   - **速率设置**:
     - **请求频率**: 建议 `100` 次请求 / `1 分钟`（按 IP 统计）。
     - **操作**: `阻止 (Block)` 或 `JS 挑战`。
3. 针对管理员 API 的额外保护：
   - 创建规则针对路径 `/_admin/api/sign`。
   - 限制频率（如 `10` 次请求 / `10 秒`），防止签名接口被盗用后高频暴力调用。

---

## 允许上传的文件类型

默认白名单（可在 `src/admin.js` 中修改 `ALLOWED_EXTENSIONS` 数组）：

| 分类 | 扩展名 |
|------|--------|
| 图片 | `jpg` `jpeg` `png` `gif` `webp` |
| 视频 | `mp4` `mov` `avi` |
| 音频 | `mp3` `wav` |
| 文档 | `pdf` `doc` `docx` `xls` `xlsx` `ppt` `pptx` `txt` `md` `json` |
| 压缩包 | `zip` `rar` `7z` `gz` `tar` |

---

## 开发者指南

```bash
# 安装依赖
pnpm install

# 本地开发
pnpm run dev

# 运行测试
pnpm run test

# 部署到 Cloudflare
pnpm run deploy

# 生成 TypeScript 类型（修改 wrangler.jsonc 后执行）
npx wrangler types
```

---

## API 参考

### 生成签名链接

```
GET /_admin/api/sign?key={文件名}&exp={过期时间戳}&k={密钥ID}&ot={是否一次性}
```

**参数说明：**

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `key` | 是 | - | 文件名 |
| `exp` | 否 | 当前时间 + 24 小时 | 过期时间戳（Unix 秒），最长不超过当前时间 + 30 天 |
| `k` | 否 | `v1` | 密钥 ID |
| `ot` | 否 | `0` | 是否生成一次性链接，`1` 启用 |

**响应示例：**

```json
{
  "key": "example.pdf",
  "exp": 1717776000,
  "signature": "abc123...",
  "kid": "v1",
  "ot": "0",
  "url": "https://your-domain.com/example.pdf?s=abc123...&e=1717776000&k=v1"
}
```

### 吊销链接

```
POST /_admin/api/revoke?key={文件名}
```

使指定文件的所有已签发链接立即失效。通过更新 D1 记录中的版本盐值（`version_salt`）实现，使旧签名立即失效，无需删除文件。注意：版本盐值只存于 D1，不回写 R2 Custom Metadata。

### 作废链接

```
POST /_admin/api/invalidate?key={文件名}
```

将文件标记为 `pending_delete` 状态，立即失效所有链接，更新版本盐值，并设置 10 分钟后由 Cron 任务执行物理删除。

### 删除文件

```
DELETE /_admin/api/delete/{文件名}
```

直接从 R2 和 D1 中物理删除文件。

### 分片上传流程

1. **初始化上传：** `GET /_admin/api/multipart/start?key={文件名}&size={文件大小}&max={最大下载次数}`
2. **上传分片：** `PUT /_admin/api/multipart/upload?key={文件名}&uploadId={ID}&partNumber={N}`
3. **完成上传：** `POST /_admin/api/multipart/complete?key={文件名}&uploadId={ID}` — Body 为 `[{partNumber, etag}, ...]`
4. **中止上传：** `DELETE /_admin/api/multipart/abort?key={文件名}&uploadId={ID}`

---

## 常见问题

### 如何实现密钥轮转？

在 `AUTH_SECRET` 中使用 JSON 格式配置多个密钥：

```json
{"v1":"旧密钥","v2":"新密钥"}
```

新签发的链接将使用 `kid=v2`，旧链接仍可通过 `v1` 验证。轮转完成后，移除旧密钥并重新部署即可。

### 如何吊销某个文件的分享链接？

在管理后台点击文件对应的 "Revoke Links" 按钮，系统会更新 D1 记录中的版本盐值，使所有旧签名立即失效（不回写 R2 Custom Metadata）。也可以调用 API：

```
POST /_admin/api/revoke?key={文件名}
```

### 如何作废（Invalidate）文件？

作废比吊销更彻底：它将文件标记为 `pending_delete`，链接立即失效，并在下次 Cron 触发时自动物理删除。点击管理后台的 "Invalidate" 按钮或调用：

```
POST /_admin/api/invalidate?key={文件名}
```

### 什么是一次性链接（One-Time Link）？

一次性链接在首次完整下载（覆盖到文件末字节的 200 或 206 请求）后会自动吊销，确保链接只能被使用一次。在管理后台点击 "One-Time Link" 按钮即可生成。技术原理：sign 接口在 `ot=1` 时把 D1 的 `is_one_time=1`；首次完整下载时计数 +1 达到上限，触发自动吊销（轮换版本盐值）。流式播放器的 Range 请求不消耗额度，只有完整下载才计数。

### 上传失败怎么办？

前端会在上传失败时自动调用 Abort API 清理已上传的分片。同时，R2 生命周期规则会兜底清理超时的未完成分片上传，确保不会产生额外费用。

### 如何修改链接默认有效期？

默认有效期为 24 小时。修改 `src/admin.js` 中 `handleAdminRequest` 函数里的默认值：

```javascript
let exp = requestedExp || (now + 24 * 60 * 60); // 将 24 * 60 * 60 改为你需要的秒数
```

### 下载时中文文件名乱码怎么办？

系统已内置 RFC 5987 标准处理，正常情况下不会出现乱码。如果仍有问题，请检查浏览器是否支持 `filename*=UTF-8''` 编码格式。

### 元数据不同步怎么办？

系统内置了自愈（Self-Healing）机制：当文件存在于 R2 但 D1 记录缺失时，Worker 会自动从 R2 的 Custom Metadata 中读取版本盐值、过期时间等信息，重建 D1 记录。一般情况下无需手动干预。

### 如何查看操作日志？

系统内置结构化日志输出，可在 Cloudflare Dashboard → Workers → 你的 Worker → Logs 中查看实时日志。如果配置了 Analytics Engine，还可以在 Analytics 页面查看聚合统计数据。

---

## 许可证

MIT

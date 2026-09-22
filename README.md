# Capability Token API

基于 **Python / FastAPI / SQLite** 的能力令牌（Capability Token）服务，为文件下载等
HTTP 操作签发**短期 HMAC 签名令牌**，并在使用时进行严格验证。无需任何第三方账号或外部
依赖（不需要 Redis、JWT 服务、对象存储账号等），单个 SQLite 文件即完整运行。

- 🔐 **HMAC-SHA256 签名**，令牌自包含、可离线验证（多用途令牌无状态）
- 🔑 **密钥环 + 无中断轮换**：`CAPABILITY_KEYRING` 接收有序 `kid:secret` 列表，首项签发、
  全体验签；令牌在受签名保护的负载中携带 `kid`，验签时按 `kid` **精确选键**（绝不遍历试签），
  未知 kid 返回 `401 unknown_key`；保留旧键即可继续验证未过期旧令牌，移除旧键立即拒绝；
  旧版无 kid 令牌只能用 `CAPABILITY_LEGACY_SECRET` 校验
- 🔗 **绑定 HTTP 方法与规范化路径**：令牌不能被挪用到其它动词或路径
- ⏱️ **短期有效**：签发时指定 TTL，服务端强制上限，过期即失效
- 🔁 **可选一次性 nonce**：成功使用后原子写入 SQLite，重放请求被拒绝
  （`BEGIN IMMEDIATE` + 主键唯一约束，并发请求只有一个能成功）
- 🚫 **主体级撤销**：管理员可按 `subject` 设置撤销截止时间，`iat` 不晚于截止时间的
  令牌一律 401；撤销判断与 nonce 消费在**同一个 SQLite 事务**中完成，被撤销的令牌
  不会消耗 nonce，且支持一键恢复
- 🚀 启动时自动初始化数据库，监听 **8000** 端口
- 🐳 提供 `Dockerfile` 与 `docker-compose.yml`，开箱即用

---

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── config.py        # 环境变量配置
│   ├── db.py            # SQLite：nonce 原子消费、主体撤销记录与过期清理
│   ├── tokens.py        # 令牌签发 / 解析 / 验证（HMAC 核心）
│   ├── schemas.py       # Pydantic 请求/响应模型
│   └── main.py          # FastAPI 路由与启动生命周期
├── files/               # 受保护的示例下载目录（compose 只读挂载）
│   └── hello.txt
├── tests/
│   └── test_api.py      # 48 个端到端测试（无需网络/容器）
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env          # 按需修改 CAPABILITY_KEYRING
docker compose up --build
```

服务在 `http://localhost:8000` 启动，交互式文档位于
`http://localhost:8000/docs`。

### 方式二：本地运行

```bash
pip install -r requirements.txt
export CAPABILITY_KEYRING="dev:$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# 或：python -m app.main
```

> 未设置 `CAPABILITY_KEYRING` 与 `CAPABILITY_SECRET` 时，服务会在启动时生成
> **进程内随机密钥**（kid=`ephemeral`），重启后所有旧令牌失效（日志会有 WARNING）。
> 开发可用，生产请务必通过密钥环固定密钥。

### 健康检查

```bash
curl http://localhost:8000/health
# {"status":"ok","time":1727000000}
```

## 使用流程

### 1. 签发令牌

```bash
curl -X POST http://localhost:8000/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "path": "/files/hello.txt",
    "ttl_seconds": 120,
    "one_time": true,
    "subject": "alice"
  }'
```

响应：

```json
{
  "token": "eyJraWQi...（base64url(payload).base64url(hmac)）",
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "kid": "2026-09",
  "method": "GET",
  "path": "/files/hello.txt",
  "issued_at": 1727000000,
  "expires_at": 1727000120,
  "expires_in": 120,
  "one_time": true,
  "subject": "alice"
}
```

请求字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `method` | 是 | 令牌绑定的 HTTP 方法（规范为大写），如 `GET`、`POST`、`DELETE` |
| `path` | 是 | 令牌绑定的路径，必须以 `/` 开头，如 `/files/hello.txt` |
| `ttl_seconds` | 否 | 有效期秒数；缺省用 `CAPABILITY_DEFAULT_TTL`，并被 `CAPABILITY_MAX_TTL` 截断 |
| `one_time` | 否 | `true` 表示一次性令牌，首次成功使用即失效 |
| `subject` | 否 | 令牌归属主体（如用户 ID），会写入签名负载 |
| `extra` | 否 | 任意额外 JSON 声明（同样受签名保护，篡改即签名失败） |

### 2. 使用令牌访问受保护资源（文件下载）

支持三种携带方式（任选其一）：

```bash
# 查询参数
curl -i "http://localhost:8000/files/hello.txt?token=<TOKEN>"

# Authorization 头（Bearer 或 Capability 方案均可）
curl -i -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/files/hello.txt

# 自定义头
curl -i -H "X-Capability-Token: <TOKEN>" \
  http://localhost:8000/files/hello.txt
```

一次性令牌**第一次成功下载返回 200**，再次使用返回：

```json
HTTP/1.1 401 Unauthorized
{"error":"nonce_replayed","detail":"one-time token has already been used"}
```

### 3. 独立验证令牌（不访问资源）

适合网关 / 其它服务在转发前做校验：

```bash
curl -X POST http://localhost:8000/tokens/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "<TOKEN>",
    "method": "GET",
    "path": "/files/hello.txt",
    "consume": true
  }'
```

- `consume: true`（默认）：若为一次性令牌且验证通过，会**真正消费 nonce**。
- `consume: false`：只做"演练"（dry run），不消费一次性令牌，可用于预检。

成功响应：

```json
{
  "valid": true,
  "kid": "2026-09",
  "method": "GET",
  "path": "/files/hello.txt",
  "expires_at": 1727000120,
  "expires_in": 97,
  "one_time": true,
  "consumed": true,
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "subject": "alice",
  "extra": {}
}
```

旧版无 kid 令牌验证成功时 `kid` 为 `null`。

### 4. 主体级撤销（管理员接口）

当某个用户（`subject`）的令牌泄露或需要强制下线时，无需轮换签名密钥，按主体撤销即可。
接口由 `CAPABILITY_ADMIN_KEY` 保护（请求头 `X-Admin-Key`）；**未配置该变量时接口整体
返回 503 `admin_key_not_configured`（fail closed）**，不会裸奔。

```bash
# 撤销：alice 在截止时间（含）之前签发的所有令牌立即失效；
# 省略 cutoff 时默认为当前时间
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "cutoff": 1727000000}'
# {"subject":"alice","revoked":true,"restored":false,"cutoff":1727000000,
#  "created_at":1727000001,"updated_at":1727000001}

# 之后 alice 的旧令牌验证返回（nonce 不会被消耗）：
# HTTP/1.1 401 Unauthorized
# {"error":"subject_revoked","detail":"subject 'alice' is revoked ..."}

# 查看当前全部撤销记录
curl http://localhost:8000/tokens/revocations \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY"
# {"revocations":[{"subject":"alice","cutoff":1727000000,...}],"count":1}

# 恢复：解除对 alice 的撤销（截止时间之后签发的令牌本就不受影响）
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "restore": true}'
# {"subject":"alice","revoked":false,"restored":true,...}
```

要点：

- 判定依据是令牌负载中的 `iat`（签发时间）：`iat <= cutoff` 即拒绝，与令牌剩余
  有效期无关；`iat > cutoff` 的令牌（撤销后新签发的）不受影响；
- 撤销记录持久化在 SQLite（`subject_revocations` 表），重启后仍然有效；
- 当 `cutoff + CAPABILITY_MAX_TTL <= now` 时，该记录能命中的令牌必然已全部过期，
  后台清理任务（每 10 分钟，启动时也会执行一次）会自动将其删除，表不会无限增长；
- 撤销对多用途令牌（`one=false`）同样生效——它们原本完全无状态，撤销是唯一的
  服务端状态依赖；不带 `subject` 的令牌不参与撤销，依旧完全无状态。

Docker Compose 场景下把 `CAPABILITY_ADMIN_KEY` 写进 `.env`（见 `.env.example`），
然后在宿主机直接执行上面的 curl 即可（compose 默认映射 `8000:8000`）。

## 无中断密钥轮换（CAPABILITY_KEYRING）

密钥环是一个**有序**的 `kid:secret` 列表（逗号分隔，冒号按**第一个**切分，所以 secret
本身可以包含冒号，但不能包含逗号）：

```bash
CAPABILITY_KEYRING="2026-09:Zk9-new-secret,2026-06:f1A-old-secret"
```

- **首项是当前签发密钥**：新令牌一律用第一项签名，并在受签名保护的负载中写入
  `"kid": "2026-09"`（签发响应与验签响应也会回显 `kid`）；
- **验签按 kid 精确选键**：服务端只对负载声明的那一个键计算一次 HMAC，
  **从不遍历整个密钥环试签**。kid 不在环中（旧键已移除）直接返回
  `401 unknown_key`，不会做任何签名比较；
- **轮换 = 前置新键、滞后移除旧键**，全程无需停服，也不会使未过期的旧令牌失效：

```bash
# 1) 准备新密钥
NEW=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')
OLD=$(从现有配置中取出旧 secret)

# 2) 把新键放在第一项，旧键保留在后面，滚动重启所有实例
#    .env:
CAPABILITY_KEYRING="2026-09:${NEW},2026-06:${OLD}"
docker compose up -d

# 此刻：新令牌由 2026-09 签发；2026-06 的未过期旧令牌继续验签通过

# 3) 等待至少 CAPABILITY_MAX_TTL（默认 3600 秒），保证旧键签署的令牌全部过期

# 4) 从环中移除旧键，再次滚动重启；此后旧键令牌一律 401 unknown_key
CAPABILITY_KEYRING="2026-09:${NEW}"
```

**旧版令牌（无 kid）兼容**：升级前签发的令牌负载里没有 `kid`。它们只能用
`CAPABILITY_LEGACY_SECRET` 校验，**绝不会被拿去逐个试环中的密钥**：

```bash
CAPABILITY_KEYRING="2026-09:${NEW},2026-06:${OLD}"
CAPABILITY_LEGACY_SECRET="${VERY_OLD_CAPABILITY_SECRET}"
```

不配置 `CAPABILITY_LEGACY_SECRET` 时，无 kid 令牌一律 `401 unknown_key`（fail closed）。
注意把环中某个键误填成 legacy secret 也不会"碰巧"验证成功——两条路径完全独立。

**启动时配置校验（fail fast）**：以下情况直接拒绝启动，避免带错配置上线：

- `CAPABILITY_KEYRING` 与 `CAPABILITY_SECRET` 同时设置（两种模式互斥）；
- kid 重复、kid 为空、secret 为空、条目格式不是 `kid:secret`；
- 密钥环为空（`CAPABILITY_KEYRING=" , "` 之类）。

**从单密钥模式迁移**：继续使用 `CAPABILITY_SECRET` 也能启动（新令牌以固定
kid `default` 签发，同一 secret 自动兼作 legacy 验签键，旧令牌无感）。但正式轮换时
请切换到 `CAPABILITY_KEYRING`；两种模式不能同时启用。

## 验证规则（核心）

`verify_token` 按以下顺序检查，任何一步失败立即返回稳定错误码：

1. **结构**：令牌必须为 `<base64url(payload)>.<base64url(signature)>`，payload 是 JSON 对象；
2. **选键**：负载含 `kid` 时，按 kid 在密钥环中**精确取一个** HMAC 密钥（不遍历、不回退），
   kid 未知返回 `401 unknown_key`；负载不含 `kid`（升级前旧令牌）时，只允许使用
   `CAPABILITY_LEGACY_SECRET`，未配置则返回 `401 unknown_key`；
3. **签名**：用所选的唯一一个密钥计算 `HMAC-SHA256(secret, payload)`，与令牌附带签名用
   `hmac.compare_digest` 常量时间比较，防止时序攻击；
4. **负载声明**：版本号 `v=1`，`kid`（若存在）为非空字符串，`m`/`p`/`jti` 为非空字符串，
   `iat`/`exp` 为整数且 `iat <= exp`，`one` 为布尔；
5. **过期时间**：当前时间 `>= exp` 即拒绝（`expired`）；
6. **方法绑定**：令牌方法 ≠ 请求方法返回 `403 method_mismatch`；
7. **路径绑定**：令牌路径 ≠ 规范化后的请求路径返回 `403 path_mismatch`；
8. **主体撤销 + 一次性 nonce**：在**同一个 `BEGIN IMMEDIATE` 事务**中先查
   `subject_revocations`（`iat <= cutoff` 则返回 `401 subject_revoked`，且不消耗
   nonce），再在需要时原子写入 `consumed_nonces`（已存在则返回 `nonce_replayed`）。
   撤销与验证并发竞争时由事务串行化裁决：要么验证先提交（nonce 已消费、撤销后至），
   要么撤销先生效（验证被拒、nonce 保留），绝不出现"被撤销却烧掉 nonce"的中间态。

### 路径规范化

签发与验证使用同一套规则（`app/tokens.py::canonical_path`），保证双方对路径的理解一致：

- 折叠重复斜杠（包括前导 `//`）；
- 解析 `.` / `..` 段；
- 去掉根路径以外的结尾 `/`。

因此 `/files/hello.txt` 与 `//files/./hello.txt/` 视为同一绑定。受保护下载端点还会在
文件系统层做 `Path.resolve()` 边界检查，杜绝目录穿越。

### 错误码

| `error` | HTTP 状态码 | 含义 |
| --- | --- | --- |
| `malformed` | 401 | 令牌格式/base64/JSON 错误 |
| `unknown_key` | 401 | 负载中的 `kid` 不在密钥环（旧键已移除），或无 kid 令牌但未配置 `CAPABILITY_LEGACY_SECRET` |
| `bad_signature` | 401 | HMAC 签名不匹配（令牌被篡改或密钥不同） |
| `bad_payload` | 401 | 负载声明类型/版本非法 |
| `expired` | 401 | 令牌已过期 |
| `nonce_replayed` | 401 | 一次性令牌被重复使用 |
| `subject_revoked` | 401 | 主体已被撤销（`iat` 不晚于撤销截止时间） |
| `method_mismatch` | 403 | HTTP 方法与绑定不一致 |
| `path_mismatch` | 403 | 路径与绑定不一致 |
| `unauthorized` | 401 | 缺少或错误的 `X-Issuer-Key` / `X-Admin-Key` |
| `admin_key_not_configured` | 503 | 未配置 `CAPABILITY_ADMIN_KEY`，管理接口未启用 |
| `validation_error` | 422 | 请求体未通过 Pydantic 校验 |

## 令牌格式

```
<base64url(payload_json)>.<base64url(hmac_sha256(secret, payload_json))>
```

负载（键按字典序排序的紧凑 JSON，全部纳入签名）：

```json
{
  "v": 1,
  "kid": "2026-09",
  "m": "GET",
  "p": "/files/hello.txt",
  "iat": 1727000000,
  "exp": 1727000120,
  "jti": "z1w6w4XPKcDQ2mkotgWgng",
  "one": true,
  "sub": "alice",
  "ext": {}
}
```

- `kid` 是签名密钥的标识，和方法/路径一样受签名保护：篡改 `kid` 会直接 `bad_signature`，
  无法把令牌"换标"成另一个键；升级前签发的旧令牌没有该字段，只能走 legacy 通道；
- 多用途令牌（`one=false`）**完全无状态**：只靠签名和过期即可验证，数据库不记录任何东西；
- 一次性令牌只在服务端记住一个不透明 nonce（`jti`），不存储令牌或负载内容。

## 一次性 nonce 的原子性（防重放）

`app/db.py` 使用 SQLite：

```sql
CREATE TABLE consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE subject_revocations (
    subject    TEXT PRIMARY KEY,
    cutoff     INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
```

消费逻辑在一个 `BEGIN IMMEDIATE` 事务中执行
`INSERT OR IGNORE`，以 `rowcount == 1` 判定是否为首次使用。数据库级主键唯一约束会把
并发竞争串行化：**N 个并发重放恰好 1 个成功，其余全部拿到 `nonce_replayed`**
（测试 `test_15_concurrent_replays_only_one_wins` 及真实 HTTP 8 并发冒烟均验证过）。

主体撤销检查与 nonce 消费**共用同一个事务**（见上一节第 7 步），因此：

- 12 线程并发验证一个"已被撤销的一次性令牌"：全部得到 `subject_revoked`，nonce 原样
  保留，恢复后仍可正常使用（`test_31`）；
- 8 个一次性令牌与一次撤销并发竞争：每个令牌要么验证成功（nonce 已消费），要么被撤销
  （nonce 未消费），恢复后重验结果与之一一对应（`test_32`）。

`expires_at` 冗余入库，后台每 10 分钟（启动时也会执行一次）清除已过期行；撤销记录在
`cutoff + CAPABILITY_MAX_TTL <= now`（即能命中的令牌必然已全部过期）后一并清除，
保证两张表都不无限增长。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CAPABILITY_KEYRING` | （未设置时退化为单密钥/随机密钥模式） | 有序逗号分隔列表 `kid:secret`；**首项签发**、全体验签，按 `kid` 精确选键，详见[密钥轮换](#无中断密钥轮换capability_keyring) |
| `CAPABILITY_LEGACY_SECRET` | 空（无 kid 旧令牌被拒） | 仅用于校验升级前签发的**无 kid** 令牌；与环中密钥完全独立，不会被遍历试签 |
| `CAPABILITY_SECRET` | （启动时随机生成） | 旧版单密钥变量，仍然支持；等价于只含 `default:<secret>` 的环并自动兼作 legacy 键；**与 `CAPABILITY_KEYRING` 互斥**，同时设置会拒绝启动 |
| `CAPABILITY_ISSUER_KEY` | 空（签发不鉴权） | 设置后，调用 `/tokens/issue` 须带匹配的 `X-Issuer-Key` 头 |
| `CAPABILITY_ADMIN_KEY` | 空（管理接口停用） | 设置后，调用 `/tokens/revoke-subject`、`/tokens/revocations` 须带匹配的 `X-Admin-Key` 头；未设置时这两个接口返回 503 |
| `CAPABILITY_DB_PATH` | `./data/capabilities.db` | SQLite 文件路径，启动自动建库建表 |
| `CAPABILITY_FILES_DIR` | `./files` | 受保护下载目录 |
| `CAPABILITY_DEFAULT_TTL` | `300` | 默认有效期（秒） |
| `CAPABILITY_MAX_TTL` | `3600` | 有效期硬上限（秒）；也是轮换时旧键需要保留的最短时长 |

> 签发鉴权是可选项：能力令牌通常由内部可信服务签发，因此用环境变量配置一个共享密钥
> 即可，无需用户体系或第三方账号。
>
> 密钥环格式：按第一个冒号切分 `kid:secret`，因此 secret 可含冒号、不可含逗号；
> kid 前后空白会被去除。重复 kid、空 kid、空 secret、与 `CAPABILITY_SECRET` 冲突都会
> 在启动时直接报错（RuntimeError，进程退出），不会带病启动。

## 运行测试

测试通过 FastAPI `TestClient` 在进程内运行，自动使用临时目录，不影响任何真实数据：

```bash
# 若环境里没有 pytest，直接用 unittest 运行也可以：
python tests/test_api.py
```

覆盖：签发与 TTL 截断、路径规范化、签发密钥门禁、签名篡改、负载篡改、方法/路径绑定、
过期、畸形令牌、一次性消费、dry-run、**12 线程并发重放只有 1 个成功**、无令牌下载、
三种携带方式、HEAD/GET 绑定、缺失文件、目录穿越、健康检查，以及主体撤销相关的
管理端点鉴权（503/401）、撤销后旧令牌失效新令牌不受影响、截止时间边界（`iat == cutoff`
也被撤销）、**被撤销的一次性令牌不消耗 nonce**、恢复（含对未撤销主体的幂等恢复）、
撤销列表、dry-run 同样受撤销约束、**12 线程并发验证全部被撤销拦截**、
**8 令牌与撤销并发竞争的原子性**、过期撤销记录清理，以及密钥环相关的
新令牌写入活跃 kid、旧键继续验签、未知 kid 返回 `unknown_key`、**移除旧键立即拒绝**、
无 kid 旧令牌仅经 legacy secret 验证（禁止遍历密钥环试签）、kid 受签名保护、
**完整轮换（前置新键→旧令牌可用→移除旧键→旧令牌即失效）**、kid 类型校验、
密钥环解析与启动配置校验（重复 kid / 空密钥 / 冲突配置 / 空环拒绝启动）、
旧版单密钥模式兼容等 48 个用例。

## 部署说明

- Compose 将 SQLite 放在命名卷 `capability-data`（`/data`），把宿主机 `./files`
  只读挂载到 `/app/files`；
- 容器以非 root 用户（uid 10001）运行，并内置 `/health` 健康检查；
- 多副本部署时 SQLite 文件需放在共享块存储上，或将本服务作为单实例网关运行；
  也可自行把 `Database` 替换为其它支持唯一约束的存储而不改动令牌核心逻辑。

## 安全建议

1. 生产环境始终通过 `CAPABILITY_KEYRING` 设置强随机签名密钥并由密钥管理机制注入，
   不要提交到仓库；轮换采用"前置新键 → 等待最长 TTL → 移除旧键"，无需停服；
2. TTL 尽量短（分钟级），需要防重放的场景使用 `one_time=true`；
3. 令牌应通过 HTTPS（TLS）传输，查询参数形式可能出现在访问日志中，敏感场景优先用请求头；
4. 旧版无 kid 令牌应设置临时的 `CAPABILITY_LEGACY_SECRET` 过渡，待其全部过期后移除该变量，
   避免永久保留无 kid 这一隐式通道；密钥环中的 kid 使用有意义的日期/版本标识便于审计；
5. 撤销管理接口务必配置强随机 `CAPABILITY_ADMIN_KEY` 并只在管理面暴露；未配置时接口
   自动停用（503），不存在"忘记配置就裸奔"的窗口。

# 内网设备授权登录系统

无浏览器巡检终端经**人工确认**后登录内网的设备授权服务（Device Authorization Grant 简化实现）。
终端先取得随机设备码与人工短码，安全管理员在网页上核对设备后批准/拒绝，终端轮询并一次性领取
绑定批准者的访问令牌，凭令牌调用身份接口。

## 功能与安全规则

- 终端提交 `client_id` + `device_name`，获得随机**设备码**、6 位**人工短码**与 **5 分钟有效期**（`AUTH_TTL_SECONDS` 可调）。
- 网页可切换本地演示身份，输入人工短码核对设备，仅「待确认」项可**批准/拒绝**。
- 终端用 `client_id` + 设备码轮询；批准后**仅能领取一次**令牌，令牌绑定批准者，可凭它调用身份接口。
- **错客户端**查询或领取一律返回 `invalid_device`，无法查询或改变他人授权，也不泄露授权是否存在。
- 有效期届满即不可批准、拒绝或领取；**拒绝、过期、已领取均不可恢复**。
- 设备码、人工短码、令牌在 SQLite 中**仅存 HMAC-SHA256 哈希**（服务器盐 `SERVER_PEPPER`），明文只在接口响应中出现一次。
- 状态保存在 SQLite（WAL 模式），**重启保留**；领取状态置位与令牌插入在同一 `IMMEDIATE` 事务中一并生效或失败。
- 至少运行**两个应用服务进程**（`app1`/`app2`），经 Nginx 轮询；所有写操作持数据库写锁，
  并发批准、拒绝、轮询、领取在数据库层面**等价于串行执行**。

## 目录结构

```
app/
  config.py          # 环境变量配置
  security.py        # 随机码生成、HMAC 哈希、短码脱敏
  db.py              # SQLite 连接、WAL、IMMEDIATE 事务
  store.py           # 授权状态机与令牌领取（核心业务规则）
  schemas.py         # 请求模型
  main.py            # FastAPI 路由
  static/            # 演示页面（终端模拟 + 人工审批控制台）
tests/               # pytest：主流程、过期、哈希存储、重启持久化、并发竞争
nginx.conf           # 两个应用进程的负载均衡入口
docker-compose.yml   # app1 + app2 + nginx，共享 SQLite 数据卷
```

## 一键启动（Docker Compose）

```bash
# 可选：固定服务器盐（不设则使用 compose 中的默认值）
export SERVER_PEPPER="$(openssl rand -hex 32)"

docker compose up --build -d
```

浏览器入口：<http://localhost:8080/> （Nginx → app1/app2 两个进程轮询）

健康检查：`curl http://localhost:8080/health`

停止与清理：

```bash
docker compose down          # 保留数据卷，重启后授权/令牌仍在
docker compose down -v       # 同时删除 SQLite 数据卷
```

## 浏览器演示流程

1. 打开 <http://localhost:8080/>，左栏「巡检终端」填写客户端 ID 与设备名，点击**发起授权请求**。
2. 页面显示设备码、人工短码与到期时间；右栏会自动带入短码（也可手工输入）。
3. 顶部切换演示审批身份，右栏点击**查询待确认设备**核对客户端 ID/设备名，然后**批准**或**拒绝**。
4. 左栏点击**轮询授权状态**（或自动轮询），批准后点击**领取访问令牌**，再点击**调用身份接口**查看令牌绑定的身份。
5. 右栏列表展示全部授权（短码脱敏），可观察 `pending / approved / denied / expired` 状态与领取情况。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/device/authorize` | 终端发起，返回设备码、人工短码、有效期 |
| POST | `/api/device/poll` | 终端轮询状态（错客户端返回 404 `invalid_device`） |
| POST | `/api/device/token` | 批准后一次性领取令牌（重复领取 409） |
| GET  | `/api/identity` | Bearer 令牌换取身份信息 |
| GET  | `/api/admin/identities` | 演示身份列表 |
| GET  | `/api/admin/authorizations` | 全部授权（短码脱敏） |
| POST | `/api/admin/find` | 按人工短码核对设备 |
| POST | `/api/admin/decide` | 批准/拒绝（仅 pending 可操作） |
| GET  | `/health` | 健康检查 |

### 命令行示例

```bash
# 1. 发起
curl -s -X POST http://localhost:8080/api/device/authorize \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"term-01","device_name":"机房A巡检终端"}'

# 2. 管理员批准（user_code 取自上一步响应）
curl -s -X POST http://localhost:8080/api/admin/decide \
  -H 'Content-Type: application/json' \
  -d '{"user_code":"AB3K9M","approver":"sec-admin-zhang","decision":"approve"}'

# 3. 终端轮询并领取令牌
curl -s -X POST http://localhost:8080/api/device/token \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"term-01","device_code":"<device_code>"}'

# 4. 凭令牌调用身份接口
curl -s http://localhost:8080/api/identity -H 'Authorization: Bearer <access_token>'
```

## 状态机

```
pending ──approve──> approved ──claim（一次性，同事务写 token）──> approved + claimed_at
   │                    │
   ├──deny──> denied    └──有效期届满同样不可领取（authorization_expired）
   └──有效期届满──> expired（惰性固化，拒绝/过期/已领取均不可恢复）
```

## 本地开发与测试

```bash
pip install -r requirements.txt httpx pytest
pytest -q
uvicorn app.main:app --port 8000          # 单进程调试
AUTH_TTL_SECONDS=2 uvicorn app.main:app   # 短有效期演示过期
```

测试覆盖：完整批准/拒绝流程、错客户端隔离、过期不可操作、敏感值仅哈希落库、
重启后状态与令牌保留、多线程并发决策竞争（恰好一次成功）、并发领取恰好一张令牌、
轮询与写入并发的一致性。

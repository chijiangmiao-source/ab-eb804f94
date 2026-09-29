# 飞行数据链路 · 报文规则遮蔽审计

在报文规则上线隔离前，安全工程师按**优先顺序**录入至多 18 条五维规则
（协议 / 源 IPv4 CIDR / 目的 IPv4 CIDR / 源端口闭区间 / 目的端口闭区间），
系统对每条规则给出冻结裁决：

* **仍可命中（PARTIALLY_COVERED）**：存在不被任何更早规则覆盖的报文区域，
  返回该区域按 `(协议, 源地址, 目的地址, 源端口, 目的端口)` 排序的
  **最小报文见证**（单个具体五维点，不抽样、不枚举）。
* **完全遮蔽（FULLY_COVERED）**：整个区域都被更早规则覆盖，
  返回**覆盖它的更早规则标识集合**。

裁决以稳定的 `audit_id` 冻结；同标识改换载荷一律 `409` 拒绝，不改写既有结论。

## 判定方法（不是 CIDR 字符串重叠，也不抽样/枚举）

每条规则在五维整数空间中是一个笛卡尔积“盒子”：

| 维度 | 取值 |
|---|---|
| 协议 | TCP=0、UDP=1（BOTH = 两值） |
| 源/目的 IPv4 | 32 位整数闭区间（CIDR 的 network..broadcast） |
| 源/目的端口 | 0..65535 闭区间 |

先前规则的并集维护为一组**互不相交的盒子**（`app/geometry.py`）：

* 新规则区域先对并集逐维做“切前 / 切中 / 切后”的差集；
  差集为空 ⇒ 完全遮蔽，沿途盒子的属主并集即覆盖者集合；
* 差集非空 ⇒ 在剩余分片中取全局字典序最小点作为最小报文见证；
* 随后把新规则并入并集，重叠分片的属主集合取并集。

18 条规则、每盒至多切出 3⁵−1 片，盒子总数有确定上界；
对抗场景实测 ≤99 盒、毫秒级。测试中有小规模空间的**逐点枚举等价性校验**，
证明盒子集合与规则区域在每个报文点上完全一致。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/api/audits` | 提交一份审计（首次 201；逐字节一致的幂等重传 200；改换载荷 409；非法 400） |
| `GET` | `/api/audits/{audit_id}` | 重新查看被冻结的逐规则结论 |
| `GET` | `/api/audits` | 已有审计标识列表 |
| `GET` | `/` | 录入与查询页面（经上述真实 API 展示） |

提交示例：

```json
{
  "audit_id": "flight-route-2026-09a",
  "rules": [
    {"rule_id": "R1", "protocol": "TCP",
     "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
     "src_port": [0, 65535], "dst_port": [0, 65535]},
    {"rule_id": "R2", "protocol": "BOTH",
     "src_cidr": "10.0.0.0/8", "dst_cidr": "192.168.0.0/16",
     "src_port": [1000, 2000], "dst_port": [443, 443]}
  ]
}
```

约束：

* `protocol` ∈ `TCP` / `UDP` / `BOTH`；
* CIDR 必须严格合法（IPv4、掩码 0..32、**主机位必须为零**，如 `10.0.0.1/24` 拒绝）；
* 端口区间 `[起, 止]` 为 0..65535 整数且 起 ≤ 止；
* 同一提交内 `rule_id` 不得重复；规则数 1..18；
* 同一 `audit_id` 只接受逐字节等价的重传（规范化 JSON 的 SHA-256 指纹判定）。

## 运行（Docker Compose）

```bash
# 宿主机访问端口可用 HOST_PORT 配置（默认 8080）
HOST_PORT=18080 docker compose up -d --build web
curl -s http://localhost:18080/health
```

数据持久化在命名卷 `audit-data`（容器内 `/data`）。

### verify 服务

对**一条部分遮蔽、一条完全遮蔽及非法重传**执行代码测试、构建检查与 HTTP 冒烟，
以容器退出码报告结果：

```bash
docker compose up --build --abort-on-container-exit --exit-code-from verify verify
# 全部通过：verify 退出码 0；任一失败：退出码 1
```

verify 内部依次执行：

1. `compileall` 构建检查 + 关键模块导入；
2. `python -m unittest discover -s tests`（23 个用例，含逐点枚举等价性、
   部分/完全遮蔽、最小见证排序、非法 CIDR/端口/重复标识、冻结不改写等）；
3. 对运行中的 `web` 服务 HTTP 冒烟：健康端点、三类裁决场景与 400/409 拒绝。

## 无容器本地运行

纯 Python 3.11 标准库，无第三方依赖：

```bash
PORT=8080 DATA_DIR=./data python -m app.server
python -m unittest discover -s tests
BASE_URL=http://127.0.0.1:8080 python scripts/verify.py
```

## 目录结构

```
app/
  geometry.py   五维盒子集合代数（差集/并集/覆盖属主）
  rules.py      规则与 CIDR/端口校验、逐规则裁决、载荷指纹
  storage.py    原子落盘、冻结与冲突拒绝（文件锁）
  server.py     零依赖 HTTP API + 静态页面
  static/       录入/查询页面
tests/          几何引擎与 HTTP 端到端测试
scripts/verify.py  Compose verify 入口
Dockerfile  docker-compose.yml
```

# 查询历史分析器

读取本地执行记录和表统计，识别 **扫描过大**、**分区未裁剪**、**重复聚合**、**小文件** 四类问题，
给出可解释的分区 / 排序建议。建议应用前必须先生成 **模拟计划** 和 **回滚点**；
接口与页面都把估算和实测严格分开，不把估算当成实际收益。

- 无需外部依赖：Python 3.11+ 标准库 + 原生 JS，无构建步骤。
- 所有"实测"指标都由本地数据湖真实重放产生；所有"估算"都标注区间、依据与假设。
- 每次应用都会记录实测前后值；撤销从回滚点恢复并用同一查询再次实测。

## 快速开始

```bash
python3 -m app.server --seed          # 首次：生成演示数据湖 + 两周查询历史
# 打开 http://127.0.0.1:8000
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--seed` | 重建演示数据湖与历史（幂等，不加则仅在空库时初始化） |
| `--port` / `--host` | 监听地址，默认 `127.0.0.1:8000` |
| `--check` | 只初始化并退出（CI 用） |

数据目录默认 `./.data/`，可用 `QHA_DATA_DIR` 覆盖。首次建湖约 25–30 秒。

## 页面

| 标签 | 内容 |
|---|---|
| **建议** | 四类检测结果；每条含影响面、触发规则、依据、查询样本、模拟计划、应用前后对比与撤销入口 |
| **查询样本** | 按规范化指纹聚合的执行历史；可查看执行计划、样本明细并真实重放 |
| **验证** | 统计过期核对（逐表比对 zone map 与实际文件）、异常查询（错误 / 慢查询离群 / 扫描突增 / 无过滤全表扫描） |
| **应用与撤销记录** | 应用记录（实测前→后）、回滚点清单、追加式审计日志 |

## 工作原理

### 1. 执行记录与实测指标

`app/engine/executor.py` 是唯一的执行入口。每次执行都会：

1. 用分区目录值做**分区裁剪**；
2. 用每个文件的 zone map（列的 min/max/空值）做**文件级裁剪**；
3. 真正读取剩余 JSONL 文件并流式聚合；
4. 记录实测的 `bytes_scanned / rows_scanned / files_scanned / files_total / duration_ms`。

历史播种（`history_seed.py`）对每个查询形状真实重放一次，再按时间回填多条记录——
所以页面上任何"历史指标"都能用同一条查询重放复现。

### 2. 四类检测（`analyzer.py`）

| 类型 | 规则（可在 `CONFIG` 调整） | 给出的建议 |
|---|---|---|
| 扫描过大 | 扫描字节 / 返回字节 ≥ 50（返回字节下限 64 KiB）、且查询可裁剪 | 若已有分区目录 → 调整分区；否则 → 排序/聚簇 |
| 分区未裁剪 | 谓词有选择性，但实测裁剪率比投影低 ≥ 50 个百分点 | 按月分区，并附"排序"备选方案与取舍 |
| 重复聚合 | 同一规范化指纹执行 ≥ 12 次、累计 ≥ 3 秒、且含聚合 | 物化汇总表（需改写查询） |
| 小文件 | ≥ 24 个文件小于 512 KiB | 合并；若受分区目录下限约束，则改为按月分区 |

检测器之间做了去重：一个扫描问题只归因给一个根因，避免同一现象给出两条互相竞争的建议。
当模型认为调整布局不会带来确定收益时，**不给出建议**并说明原因。

### 3. 估算 vs 实测

- 模拟计划里的 `estimates` 全部带 `bound_low / bound_high / basis / assumptions`；
- 预估的 `duration_ms` 一律为 `null`——I/O 减少不等于耗时线性下降；
- 应用后同时返回 `before`（实测）、`after`（实测）和 `estimated_vs_measured`（含 `within_bounds`）；
- 页面用两块独立图表分别展示"实测前后"和"估算区间"，并明示"估算不是收益"。

### 4. 安全的应用流程（`actions.py`）

```
simulate  → 只读目录统计，写 simulations（含 state_fingerprint）
apply     → 校验指纹未变 → 实测 before → 创建回滚点（文件快照 + 目录清单）
          → 变更数据 → 实测 after → 写 applies + undo_log
undo      → 校验回滚点可用 → 恢复文件与目录 → 用同一查询再实测 → 标记 used
```

- 指纹不匹配时 apply 返回 `409 state_changed`，估算直接失效，强制重新模拟；
- 变更过程异常会自动恢复回滚点并把 apply 标记为 `failed`；
- 回滚点状态：`preparing → available → used`。

### 5. 统计与异常验证

- `verify_stats` 逐文件重算 zone map 与目录值比对，输出漂移样本；
- `stale_tables` 比较 `stats_updated_at` 与 `last_data_change_at`；
- `abnormal_executions` 检测：执行错误、慢于同指纹中位数 4 倍的离群、扫描量突增、无 WHERE 的全表扫描。

## API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/analyze` | 重新检测并持久化建议 |
| GET | `/api/advisories` | 建议列表（含样本执行与历史汇总） |
| POST | `/api/advisories/{id}/simulate` | 生成模拟计划（只读） |
| POST | `/api/simulations/{id}/apply` | 创建回滚点后应用并实测 |
| POST | `/api/applies/{id}/undo` | 从回滚点恢复并实测 |
| GET | `/api/undo-log` | 应用与撤销审计 |
| GET | `/api/rollback-points` | 回滚点清单 |
| GET | `/api/history/groups` | 按指纹聚合的历史 + 异常查询 |
| POST | `/api/executions` | 真实执行并写入历史 |
| GET | `/api/validations/stats(/{table})` | 统计过期与漂移核对 |
| POST | `/api/validations/stats/{table}/refresh` | 重算 zone map |
| GET | `/api/validations/anomalies` | 异常查询 |

错误统一返回 `{"error", "code", "detail"}`；`code` 取值包括 `query_error`、`state_changed`、
`not_undoable`、`simulation_superseded` 等。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试在临时目录建独立数据湖，覆盖：SQL 解析与指纹归一、真实裁剪、聚合正确性、四类检测、
估算边界、应用/撤销一致性、状态指纹守卫、统计过期与 zone map 漂移检测。

页面另有一条 DOM 级端到端检查（需要先启动服务并已完成种子）：

```bash
python3 -m app.server --seed --port 8765
BASE=http://127.0.0.1:8765 node tests/ui_e2e.js
```

它用 jsdom 真实加载 `web/index.html` 与 `web/app.js`，断言建议列表与过滤、依据与查询样本、
模拟计划的“估算不是收益”提示与区间、应用前后实测对比图、撤销后状态回落，以及验证页与
应用/撤销记录页的渲染，共 33 项检查。jsdom 不是运行时依赖，仅此脚本需要
（`npm i jsdom` 后把路径指到 `tests/ui_e2e.js` 顶部即可）。

## 目录结构

```
app/
  store.py             目录库（SQLite）与状态指纹
  api.py               路由与静态服务
  server.py            入口
  webui/__init__.py    静态资源
  engine/
    sqlparse_lite.py   受限 SQL 解析与规范化
    lake.py            数据湖生成 / 文件读写 / zone map
    executor.py        裁剪规划 + 真实执行
    analyzer.py        检测规则与收益投影
    actions.py         模拟 / 应用 / 撤销 / 统计校验
    history_seed.py    真实重放生成查询历史
web/                   单页前端
tests/                 引擎测试
```

## 已知边界

- SQL 仅支持文档化的子集；不支持 JOIN / 子查询 / 窗口函数，遇到会返回 422 而不是猜测。
- "排序/聚簇"的收益模型假设排序后每个文件覆盖一段连续键区间；对高度倾斜的键会偏差，
  因此投影始终给出区间而非单点。
- 本地耗时受机器负载影响，同一查询重放会有波动；页面对耗时使用"实测"标签但不做区间估算。

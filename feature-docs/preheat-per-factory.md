# 仪表盘预计算（数据预热）改造方案

## 背景

当前预热逻辑对所有用户使用同一份固定参数（写死的工厂 + 固定月份）。
改造目标：
1. 按角色配置默认工厂（每个角色看自己的工厂数据）
2. 月份支持"上个月"相对值（不再写死固定月份）
3. 预热任务按工厂 × 上个月逐一预热缓存

---

## 配置方式

在仪表盘的 `json_metadata.native_filter_configuration` 的相关条目上增加两类可选字段，**无需改动数据库 schema**。

### 工厂过滤器 — `preheatRoleDefaults`

```json
{
  "id": "FLTR_abc123",
  "name": "工厂",
  "filterType": "filter_select",
  "targets": [{"datasetId": 1, "column": {"name": "org_code"}}],
  "preheatRoleDefaults": {
    "南宁厂角色": ["南宁厂"],
    "北京厂角色": ["北京厂"],
    "Admin": ["南宁厂", "北京厂"]
  }
}
```

- 字段的**存在**本身即标识这是"工厂过滤器"，预热时自动识别
- 同时作为用户打开仪表盘时自动注入默认值的依据

### 月份/年份过滤器 — `preheatRelative`

```json
{ "id": "FLTR_def", "name": "月份", "preheatRelative": "last_month" }
{ "id": "FLTR_ghi", "name": "年份", "preheatRelative": "last_month_year" }
```

- `"last_month"` → 预热时动态计算为上个月月份数字（1–12）
- `"last_month_year"` → 预热时动态计算为上个月所在年份

---

## 运行时流程

### 用户打开仪表盘（Task 4）

```
Dashboard GET API
    → 读当前用户角色
    → 扫描 preheatRoleDefaults，取第一个匹配角色的工厂列表
    → 在响应中加入 preselectNativeFilters
         {FLTR_abc123: {extraFormData: {filters: [{col:"org_code", op:"IN", val:["南宁厂"]}]}}}
    → 前端 useFilters() 自动读取，覆盖工厂过滤器默认值
```

### Celery Beat 每日 08:00 预热（Task 2 + 3）

```
dashboard_cache_warmup
  for dashboard in dashboards:
    扫描 preheatRoleDefaults → 取所有角色工厂值的并集 → [南宁厂, 北京厂, ...]
    扫描 preheatRelative → 计算 last_month.month / last_month.year
    for factory_code in all_factories:
      override_values = {
        工厂filter_id: [{col:org_code, op:IN, val:[factory_code]}],
        月份filter_id: [{col:month,    op:IN, val:[last_month.month]}],
        年份filter_id: [{col:year,     op:IN, val:[last_month.year]}],
      }
      for chart in dashboard.slices:
        ChartWarmUpCacheCommand(override_values=override_values).run()
```

---

## 改动文件

| # | 文件 | 类型 | 说明 |
|---|---|---|---|
| 2 | `superset/commands/chart/warm_up_cache.py` | 修改 | `__init__` 加 `override_values`；`_get_native_filter_extras` 支持覆盖 |
| 3 | `superset/tasks/cache.py` | 修改 | `dashboard_cache_warmup` 按工厂×上月迭代 |
| 4 | `superset/views/dashboard.py` (或 REST API) | 修改 | 注入 `preselectNativeFilters` |

**无需**：新建数据库表、新建 API、修改前端过滤器组件。

---

## 开发任务

| # | 任务 | 涉及文件 | 状态 |
|---|---|---|---|
| T1 | `ChartWarmUpCacheCommand` 新增 `override_values` 参数，`_get_native_filter_extras` 支持按 filter_id 覆盖值 | `superset/commands/chart/warm_up_cache.py` | ✅ 已完成 |
| T2 | 新增 `_extract_preheat_overrides()` 辅助函数；`dashboard_cache_warmup` 改为按工厂 × 上月迭代，无 preheat 配置时保持原有行为 | `superset/tasks/cache.py` | ✅ 已完成 |
| T3 | 新增 `_build_preselect_native_filters()` 根据当前用户角色生成工厂默认值；在仪表盘 GET 响应中注入 `preselectNativeFilters` | `superset/dashboards/api.py` | ✅ 已完成 |
| T4 | 前端读取 API 响应中的 `preselectNativeFilters`，作为工厂过滤器的角色默认值（URL 参数优先） | `superset-frontend/src/dashboard/actions/hydrate.js` | ✅ 已完成 |
| T5 | 在目标仪表盘 `json_metadata` 中配置 `preheatRoleDefaults` 和 `preheatRelative` 字段 | 仪表盘数据（SQL/UI） | ⬜ 待配置（由 T6/T7 UI 替代） |
| T6 | 工厂过滤器编辑面板新增「预计算角色配置」区块：角色→工厂的动态行表格，保存为 `preheatRoleDefaults` | `FiltersConfigForm.tsx` · `types.ts` · `utils.ts` | ✅ 已完成 |
| T7 | 月份/年份过滤器编辑面板新增「预计算默认日期」下拉：上个月 / 上个月的年份，保存为 `preheatRelative` | `FiltersConfigForm.tsx` · `types.ts` · `utils.ts` | ✅ 已完成 |

---

## 配置操作步骤

1. 打开仪表盘编辑器 → 过滤器设置 → 选中「工厂」过滤器 → 底部「预计算角色配置」填写角色名与工厂值
2. 选中「月份」/「年份」过滤器 → 底部「预计算默认日期」选择"上个月"或"上个月的年份"
3. 保存仪表盘，配置即写入 `json_metadata`
4. 没有 `preheatRoleDefaults` 的仪表盘预热行为与改造前完全相同（向后兼容）

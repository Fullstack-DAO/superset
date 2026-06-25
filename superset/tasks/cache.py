# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Optional, Union
from urllib import request
from urllib.error import URLError

from celery.beat import SchedulingError
from celery.utils.log import get_task_logger
from sqlalchemy import and_, func

from superset import app, db, security_manager
from superset.extensions import celery_app
from superset.models.core import Log
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice
from superset.tags.models import Tag, TaggedObject
from superset.utils.date_parser import parse_human_datetime
from superset.utils.machine_auth import MachineAuthProvider

logger = get_task_logger(__name__)
logger.setLevel(logging.INFO)


def get_payload(chart: Slice, dashboard: Optional[Dashboard] = None) -> dict[str, int]:
    """Return payload for warming up a given chart/table cache."""
    payload = {"chart_id": chart.id}
    if dashboard:
        payload["dashboard_id"] = dashboard.id
    return payload


class Strategy:  # pylint: disable=too-few-public-methods
    """
    A cache warm up strategy.

    Each strategy defines a `get_payloads` method that returns a list of payloads to
    send to the `/api/v1/chart/warm_up_cache` endpoint.

    Strategies can be configured in `superset/config.py`:

        beat_schedule = {
            'cache-warmup-hourly': {
                'task': 'cache-warmup',
                'schedule': crontab(minute=1, hour='*'),  # @hourly
                'kwargs': {
                    'strategy_name': 'top_n_dashboards',
                    'top_n': 10,
                    'since': '7 days ago',
                },
            },
        }

    """

    def __init__(self) -> None:
        pass

    def get_payloads(self) -> list[dict[str, int]]:
        raise NotImplementedError("Subclasses must implement get_payloads!")


class DummyStrategy(Strategy):  # pylint: disable=too-few-public-methods
    """
    Warm up all charts.

    This is a dummy strategy that will fetch all charts. Can be configured by:

        beat_schedule = {
            'cache-warmup-hourly': {
                'task': 'cache-warmup',
                'schedule': crontab(minute=1, hour='*'),  # @hourly
                'kwargs': {'strategy_name': 'dummy'},
            },
        }

    """

    name = "dummy"

    def get_payloads(self) -> list[dict[str, int]]:
        return [get_payload(chart) for chart in db.session.query(Slice).all()]


class TopNDashboardsStrategy(Strategy):  # pylint: disable=too-few-public-methods
    """
    Warm up charts in the top-n dashboards.

        beat_schedule = {
            'cache-warmup-hourly': {
                'task': 'cache-warmup',
                'schedule': crontab(minute=1, hour='*'),  # @hourly
                'kwargs': {
                    'strategy_name': 'top_n_dashboards',
                    'top_n': 5,
                    'since': '7 days ago',
                },
            },
        }

    """

    name = "top_n_dashboards"

    def __init__(self, top_n: int = 5, since: str = "7 days ago") -> None:
        super().__init__()
        self.top_n = top_n
        self.since = parse_human_datetime(since) if since else None

    def get_payloads(self) -> list[dict[str, int]]:
        records = (
            db.session.query(Log.dashboard_id, func.count(Log.dashboard_id))
            .filter(and_(Log.dashboard_id.isnot(None), Log.dttm >= self.since))
            .group_by(Log.dashboard_id)
            .order_by(func.count(Log.dashboard_id).desc())
            .limit(self.top_n)
            .all()
        )
        dash_ids = [record.dashboard_id for record in records]
        dashboards = (
            db.session.query(Dashboard).filter(Dashboard.id.in_(dash_ids)).all()
        )

        return [
            get_payload(chart, dashboard)
            for dashboard in dashboards
            for chart in dashboard.slices
        ]


class DashboardTagsStrategy(Strategy):  # pylint: disable=too-few-public-methods
    """
    Warm up charts in dashboards with custom tags.

        beat_schedule = {
            'cache-warmup-hourly': {
                'task': 'cache-warmup',
                'schedule': crontab(minute=1, hour='*'),  # @hourly
                'kwargs': {
                    'strategy_name': 'dashboard_tags',
                    'tags': ['core', 'warmup'],
                },
            },
        }
    """

    name = "dashboard_tags"

    def __init__(self, tags: Optional[list[str]] = None) -> None:
        super().__init__()
        self.tags = tags or []

    def get_payloads(self) -> list[dict[str, int]]:
        payloads = []
        tags = db.session.query(Tag).filter(Tag.name.in_(self.tags)).all()
        tag_ids = [tag.id for tag in tags]

        # add dashboards that are tagged
        tagged_objects = (
            db.session.query(TaggedObject)
            .filter(
                and_(
                    TaggedObject.object_type == "dashboard",
                    TaggedObject.tag_id.in_(tag_ids),
                )
            )
            .all()
        )
        dash_ids = [tagged_object.object_id for tagged_object in tagged_objects]
        tagged_dashboards = db.session.query(Dashboard).filter(
            Dashboard.id.in_(dash_ids)
        )
        for dashboard in tagged_dashboards:
            for chart in dashboard.slices:
                payloads.append(get_payload(chart))

        # add charts that are tagged
        tagged_objects = (
            db.session.query(TaggedObject)
            .filter(
                and_(
                    TaggedObject.object_type == "chart",
                    TaggedObject.tag_id.in_(tag_ids),
                )
            )
            .all()
        )
        chart_ids = [tagged_object.object_id for tagged_object in tagged_objects]
        tagged_charts = db.session.query(Slice).filter(Slice.id.in_(chart_ids))
        for chart in tagged_charts:
            payloads.append(get_payload(chart))

        return payloads


strategies = [DummyStrategy, TopNDashboardsStrategy, DashboardTagsStrategy]


@celery_app.task(name="fetch_url")
def fetch_url(data: str, headers: dict[str, str]) -> dict[str, str]:
    """
    Celery job to fetch url
    """
    result = {}
    try:
        baseurl = app.config["WEBDRIVER_BASEURL"]
        url = f"{baseurl}api/v1/chart/warm_up_cache"
        logger.info("Fetching %s with payload %s", url, data)
        req = request.Request(
            url, data=bytes(data, "utf-8"), headers=headers, method="PUT"
        )
        response = request.urlopen(  # pylint: disable=consider-using-with
            req, timeout=600
        )
        logger.info(
            "Fetched %s with payload %s, status code: %s", url, data, response.code
        )
        if response.code == 200:
            result = {"success": data, "response": response.read().decode("utf-8")}
        else:
            result = {"error": data, "status_code": response.code}
            logger.error(
                "Error fetching %s with payload %s, status code: %s",
                url,
                data,
                response.code,
            )
    except URLError as err:
        logger.exception("Error warming up cache!")
        result = {"error": data, "exception": str(err)}
    return result


@celery_app.task(name="cache-warmup")
def cache_warmup(
    strategy_name: str, *args: Any, **kwargs: Any
) -> Union[dict[str, list[str]], str]:
    """
    Warm up cache.

    This task periodically hits charts to warm up the cache.

    """
    logger.info("Loading strategy")
    class_ = None
    for class_ in strategies:
        if class_.name == strategy_name:  # type: ignore
            break
    else:
        message = f"No strategy {strategy_name} found!"
        logger.error(message, exc_info=True)
        return message

    logger.info("Loading %s", class_.__name__)
    try:
        strategy = class_(*args, **kwargs)
        logger.info("Success!")
    except TypeError:
        message = "Error loading strategy!"
        logger.exception(message)
        return message

    user = security_manager.get_user_by_username(app.config["THUMBNAIL_SELENIUM_USER"])
    cookies = MachineAuthProvider.get_auth_cookies(user)
    headers = {
        "Cookie": f"session={cookies.get('session', '')}",
        "Content-Type": "application/json",
    }

    results: dict[str, list[str]] = {"scheduled": [], "errors": []}
    for payload in strategy.get_payloads():
        try:
            payload = json.dumps(payload)
            logger.info("Scheduling %s", payload)
            fetch_url.delay(payload, headers)
            results["scheduled"].append(payload)
        except SchedulingError:
            logger.exception("Error scheduling fetch_url for payload: %s", payload)
            results["errors"].append(payload)

    return results


def _extract_default_values(f: dict[str, Any]) -> list:
    """Extract a filter's configured default value(s) from defaultDataMask."""
    ddm = f.get("defaultDataMask", {}) or {}
    for clause in ddm.get("extraFormData", {}).get("filters", []) or []:
        val = clause.get("val")
        if val is not None:
            return val if isinstance(val, list) else [val]
    val = (ddm.get("filterState", {}) or {}).get("value")
    if val is not None:
        return val if isinstance(val, list) else [val]
    return []


def _extract_preheat_overrides(
    dashboard: Dashboard,
) -> list[Optional[dict[str, list]]]:
    """Scan native_filter_configuration and build preheat override combinations.

    Each returned element is an ``override_values`` dict mapping filter_id to a
    list of filter clauses. Filters NOT present in a dict fall back to their own
    ``defaultDataMask`` automatically (handled by ChartWarmUpCacheCommand), so
    e.g. 年度=2025 is applied to every combination without being listed here.

    Combination rules:
      - relative-date filters (preheatRelative, e.g. 月份) → applied to EVERY
        combination as a static override.
      - role-factory filter (preheatRoleDefaults, e.g. 工厂) → ONE combination
        per role (the role's full factory list as a single ``IN`` clause),
        PLUS one combination for the filter's own configured default value.

    With no preheat config, returns ``[None]`` (single no-override pass,
    preserving the original behaviour).
    """
    try:
        metadata = json.loads(dashboard.json_metadata or "{}")
    except json.JSONDecodeError:
        return [None]

    last_month = datetime.now().replace(day=1) - timedelta(days=1)

    static_overrides: dict[str, list] = {}
    # (filter_id, col_name, role_defaults, default_vals)
    role_filter: Optional[tuple[str, str, dict, list]] = None

    for f in metadata.get("native_filter_configuration", []):
        fid = f.get("id", "")
        col = (f.get("targets") or [{}])[0].get("column") or {}
        col_name = col.get("name", "") if isinstance(col, dict) else str(col)

        if role_defaults := f.get("preheatRoleDefaults"):
            role_filter = (fid, col_name, role_defaults, _extract_default_values(f))
        elif relative := f.get("preheatRelative"):
            val = last_month.month if relative == "last_month" else last_month.year
            static_overrides[fid] = [{"col": col_name, "op": "IN", "val": [val]}]

    if not role_filter:
        return [static_overrides] if static_overrides else [None]

    fid, col_name, role_defaults, default_vals = role_filter
    combos: list[Optional[dict[str, list]]] = []
    seen: set[tuple] = set()

    def add_combo(vals: list) -> None:
        if not vals:
            return
        key = tuple(sorted(str(v) for v in vals))
        if key in seen:
            return
        seen.add(key)
        overrides = dict(static_overrides)
        overrides[fid] = [{"col": col_name, "op": "IN", "val": list(vals)}]
        combos.append(overrides)

    # one combination per role (full factory list kept together as one IN)
    for vals in role_defaults.values():
        add_combo(vals)
    # plus the filter's own configured default value
    add_combo(default_vals)

    return combos or [None]



@celery_app.task(name="dashboard-cache-warmup")
def dashboard_cache_warmup(
    dashboard_ids: Optional[list[int]] = None,
) -> dict[str, Any]:
    """
    Warm up cache for all charts in specified dashboards, including
    dashboard native filter defaults so that cache keys match real usage.

    Calls ChartWarmUpCacheCommand directly (no HTTP round-trip needed).

    Args:
        dashboard_ids: List of dashboard IDs to warm up. If None, warms up
                       all dashboards.
    """
    # pylint: disable=import-outside-toplevel
    from flask import g as flask_g

    from superset.commands.chart.warm_up_cache import ChartWarmUpCacheCommand

    # Set up user context for query execution
    user = security_manager.get_user_by_username(
        app.config["THUMBNAIL_SELENIUM_USER"]
    )
    flask_g.user = user

    # 只对已发布的仪表盘进行预热查询
    if dashboard_ids:
        dashboards = (
            db.session.query(Dashboard)
            .filter(
                Dashboard.id.in_(dashboard_ids),
                Dashboard.published.is_(True),
            )
            .all()
        )
    else:
        dashboards = (
            db.session.query(Dashboard)
            .filter(Dashboard.published.is_(True))
            .all()
        )

    task_start = time.monotonic()

    results: dict[str, list[dict[str, Any]]] = {"success": [], "errors": []}

    for dashboard in dashboards:
        t0 = time.monotonic()
        logger.info(
            "Dashboard %d (%s): 开始预热",
            dashboard.id,
            dashboard.dashboard_title,
        )
        # Each element is an override_values dict (or None) representing one
        # preheat combination: one per role + one for the filter's own default,
        # each carrying the relative-date (月份) and falling back to other
        # filters' defaults (年度) automatically.
        override_list = _extract_preheat_overrides(dashboard)
        logger.info(
            "Dashboard %d: %d preheat combination(s) × %d chart(s)",
            dashboard.id,
            len(override_list),
            len(dashboard.slices),
        )

        for override_values in override_list:
            for chart in dashboard.slices:
                try:
                    result = ChartWarmUpCacheCommand(
                        chart_or_id=chart,
                        dashboard_id=dashboard.id,
                        extra_filters=None,
                        warm_up=True,
                        override_values=override_values,
                    ).run()
                    logger.info(
                        "Chart %d warmup result: %s", chart.id, result.get("viz_status")
                    )
                    if result.get("viz_error"):
                        results["errors"].append(result)
                    else:
                        results["success"].append(result)
                except Exception:  # pylint: disable=broad-except
                    logger.exception(
                        "Error warming up chart %d in dashboard %d",
                        chart.id,
                        dashboard.id,
                    )
                    results["errors"].append(
                        {"chart_id": chart.id, "dashboard_id": dashboard.id}
                    )

        logger.info(
            "Dashboard %d (%s): 预热完成，耗时 %.1fs（成功 %d，失败 %d）",
            dashboard.id,
            dashboard.dashboard_title,
            time.monotonic() - t0,
            len(results["success"]),
            len(results["errors"]),
        )

    logger.info(
        "Dashboard cache warmup complete: %d success, %d errors, 总耗时 %.1fs",
        len(results["success"]),
        len(results["errors"]),
        time.monotonic() - task_start,
    )
    return results

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
import logging
import math
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded

from superset import app, is_feature_enabled
from superset.commands.exceptions import CommandException
from superset.commands.report.exceptions import ReportScheduleUnexpectedError
from superset.commands.report.execute import AsyncExecuteReportScheduleCommand
from superset.commands.report.log_prune import AsyncPruneReportScheduleLogCommand
from superset.daos.report import ReportScheduleDAO
from superset.connectors.sqla.models import SqlaTable
from superset.extensions import celery_app, cache_manager
from superset.stats_logger import BaseStatsLogger
from superset.tasks.cron_util import cron_schedule_window
from superset.utils.core import LoggerLevel
from superset.utils.log import get_logger_from_status

logger = logging.getLogger(__name__)


DEFAULT_DYNAMIC_REFRESH_CONFIG = {
    "window_minutes": 360,
    "batch_size": 2,
    "start_delay_minutes": 0,
}

_QUEUE_KEY_PREFIX = "dynamic_refresh:queued"
_RUNNING_KEY_PREFIX = "dynamic_refresh:running"
_COMPLETED_KEY_PREFIX = "dynamic_refresh:completed"
_MARKER_TTL_FALLBACK_SECONDS = 12 * 60 * 60  # 12 hours keeps flags for the nightly window


def _marker_timeout_seconds(refresh_config: dict[str, int]) -> int:
    window_minutes = max(0, int(refresh_config.get("window_minutes", 0)))
    start_delay_minutes = max(0, int(refresh_config.get("start_delay_minutes", 0)))
    schedule_span = (window_minutes + start_delay_minutes) * 60
    return max(schedule_span + (4 * 60 * 60), _MARKER_TTL_FALLBACK_SECONDS)


def _build_window_marker(refresh_window: str, anchor: datetime) -> str:
    safe_window = refresh_window or "default"
    return f"{safe_window}:{anchor.strftime('%Y%m%d%H%M')}"


def _queued_cache_key(dataset_id: int, marker: str) -> str:
    return f"{_QUEUE_KEY_PREFIX}:{marker}:{dataset_id}"


def _running_cache_key(dataset_id: int, marker: str) -> str:
    return f"{_RUNNING_KEY_PREFIX}:{marker}:{dataset_id}"


def _completed_cache_key(dataset_id: int, marker: str) -> str:
    return f"{_COMPLETED_KEY_PREFIX}:{marker}:{dataset_id}"


def _chunked(sequence: List[int], chunk_size: int) -> Iterable[list[int]]:
    for index in range(0, len(sequence), chunk_size):
        yield sequence[index : index + chunk_size]


def _get_refresh_config(refresh_window: str) -> dict[str, int]:
    schedule_config = app.config.get("DYNAMIC_TABLE_REFRESH_SCHEDULE", {}) or {}

    base_config = DEFAULT_DYNAMIC_REFRESH_CONFIG.copy()
    default_override = schedule_config.get("default") or {}
    base_config.update({k: v for k, v in default_override.items() if k in base_config})

    window_override = schedule_config.get(refresh_window) or {}
    base_config.update({k: v for k, v in window_override.items() if k in base_config})

    base_config["batch_size"] = max(1, int(base_config.get("batch_size", 1)))
    base_config["window_minutes"] = max(0, int(base_config.get("window_minutes", 0)))
    base_config["start_delay_minutes"] = int(base_config.get("start_delay_minutes", 0))

    return base_config


def _schedule_dataset_refresh_jobs(refresh_window: str) -> None:
    dataset_ids = SqlaTable.get_refreshable_dataset_ids(refresh_window)
    if not dataset_ids:
        logger.info("No dynamic datasets scheduled for refresh window: %s", refresh_window)
        return

    refresh_config = _get_refresh_config(refresh_window)
    batch_size = refresh_config["batch_size"]
    window_minutes = refresh_config["window_minutes"]
    start_delay_minutes = refresh_config["start_delay_minutes"]

    start_eta = datetime.utcnow() + timedelta(minutes=start_delay_minutes)
    batches = math.ceil(len(dataset_ids) / batch_size)
    if batches <= 1 or window_minutes <= 0:
        interval_seconds = 0
    else:
        interval_seconds = int((window_minutes * 60) / max(batches - 1, 1))

    logger.info(
        "Scheduling %s dynamic datasets for %s refresh window using %s batches, interval %s seconds.",
        len(dataset_ids),
        refresh_window,
        batches,
        interval_seconds,
    )

    window_marker = _build_window_marker(refresh_window, start_eta)
    marker_timeout = _marker_timeout_seconds(refresh_config)

    scheduled_count = 0
    skipped_count = 0

    for batch_index, chunk in enumerate(_chunked(dataset_ids, batch_size)):
        eta = start_eta + timedelta(seconds=batch_index * interval_seconds)
        for dataset_id in chunk:
            queued_key = _queued_cache_key(dataset_id, window_marker)
            if cache_manager.cache.get(queued_key):
                logger.info(
                    "Dataset %s already queued for refresh marker %s, skipping duplicate scheduling.",
                    dataset_id,
                    window_marker,
                )
                skipped_count += 1
                continue

            cache_manager.cache.set(queued_key, "queued", timeout=marker_timeout)
            refresh_dataset.apply_async((dataset_id, refresh_window, window_marker), eta=eta)
            scheduled_count += 1

    logger.info(
        "Dynamic datasets scheduled for %s refresh window. Marker %s, first eta %s, scheduled %s, skipped %s, total candidates %s.",
        refresh_window,
        window_marker,
        start_eta,
        scheduled_count,
        skipped_count,
        len(dataset_ids),
    )


@celery_app.task(name="reports.scheduler")
def scheduler() -> None:
    """
    Celery beat main scheduler for reports
    """
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("reports.scheduler")

    if not is_feature_enabled("ALERT_REPORTS"):
        return
    active_schedules = ReportScheduleDAO.find_active()
    triggered_at = (
        datetime.fromisoformat(scheduler.request.expires)
        - app.config["CELERY_BEAT_SCHEDULER_EXPIRES"]
        if scheduler.request.expires
        else datetime.utcnow()
    )
    for active_schedule in active_schedules:
        for schedule in cron_schedule_window(
            triggered_at, active_schedule.crontab, active_schedule.timezone
        ):
            logger.info("Scheduling alert %s eta: %s", active_schedule.name, schedule)
            async_options = {"eta": schedule}
            if (
                active_schedule.working_timeout is not None
                and app.config["ALERT_REPORTS_WORKING_TIME_OUT_KILL"]
            ):
                async_options["time_limit"] = (
                    active_schedule.working_timeout
                    + app.config["ALERT_REPORTS_WORKING_TIME_OUT_LAG"]
                )
                async_options["soft_time_limit"] = (
                    active_schedule.working_timeout
                    + app.config["ALERT_REPORTS_WORKING_SOFT_TIME_OUT_LAG"]
                )
            execute.apply_async((active_schedule.id,), **async_options)


@celery_app.task(name="reports.execute", bind=True)
def execute(self: Celery.task, report_schedule_id: int) -> None:
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("reports.execute")

    task_id = None
    try:
        task_id = execute.request.id
        scheduled_dttm = execute.request.eta
        logger.info(
            "Executing alert/report, task id: %s, scheduled_dttm: %s",
            task_id,
            scheduled_dttm,
        )
        AsyncExecuteReportScheduleCommand(
            task_id,
            report_schedule_id,
            scheduled_dttm,
        ).run()
    except ReportScheduleUnexpectedError:
        logger.exception(
            "An unexpected occurred while executing the report: %s", task_id
        )
        self.update_state(state="FAILURE")
    except CommandException as ex:
        logger_func, level = get_logger_from_status(ex.status)
        logger_func(
            f"A downstream {level} occurred "
            f"while generating a report: {task_id}. {ex.message}",
            exc_info=True,
        )
        if level == LoggerLevel.EXCEPTION:
            self.update_state(state="FAILURE")


@celery_app.task(name="reports.prune_log")
def prune_log() -> None:
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("reports.prune_log")

    try:
        AsyncPruneReportScheduleLogCommand().run()
    except SoftTimeLimitExceeded as ex:
        logger.warning("A timeout occurred while pruning report schedule logs: %s", ex)
    except CommandException:
        logger.exception("An exception occurred while pruning report schedule logs")


@celery_app.task(name="dynamic_table.refresh_datas")
def refresh_datas() -> None:
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("dynamic_table.refresh_datas")
    logger.info("Scheduling refresh for evening dynamic datasets.")
    try:
        _schedule_dataset_refresh_jobs("evening")
    except CommandException:
        logger.exception("An exception occurred while scheduling dynamic dataset refresh jobs")
    logger.info("Completed scheduling for evening dynamic datasets.")

@celery_app.task(name="dynamic_table.refresh_datas2")
def refresh_datas2() -> None:
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("dynamic_table.refresh_datas2")
    logger.info("Scheduling refresh for morning dynamic datasets.")
    try:
        _schedule_dataset_refresh_jobs("morning")
    except CommandException:
        logger.exception("An exception occurred while scheduling dynamic dataset refresh jobs")
    logger.info("Completed scheduling for morning dynamic datasets.")


@celery_app.task(name="dynamic_table.refresh_dataset", bind=True)
def refresh_dataset(
    self: Celery.task,
    dataset_id: int,
    refresh_window: Optional[str] = None,
    window_marker: Optional[str] = None,
) -> None:
    stats_logger: BaseStatsLogger = app.config["STATS_LOGGER"]
    stats_logger.incr("dynamic_table.refresh_dataset")
    start_time = datetime.utcnow()
    target_window = refresh_window or "default"
    refresh_config = _get_refresh_config(target_window)
    marker = window_marker or _build_window_marker(target_window, start_time)
    marker_timeout = _marker_timeout_seconds(refresh_config)

    queued_key = _queued_cache_key(dataset_id, marker)
    running_key = _running_cache_key(dataset_id, marker)
    completed_key = _completed_cache_key(dataset_id, marker)

    existing_completed = cache_manager.cache.get(completed_key)
    if existing_completed:
        logger.info(
            "Dataset %s already completed for window %s marker %s via task %s, skipping duplicate task %s.",
            dataset_id,
            target_window,
            marker,
            existing_completed,
            self.request.id,
        )
        return

    existing_running = cache_manager.cache.get(running_key)
    if existing_running and existing_running != self.request.id:
        logger.info(
            "Dataset %s already running under task %s for window %s marker %s, skipping duplicate task %s.",
            dataset_id,
            existing_running,
            target_window,
            marker,
            self.request.id,
        )
        return

    cache_manager.cache.set(running_key, self.request.id, timeout=marker_timeout)
    logger.info(
        "Refreshing dynamic dataset %s for window %s, marker %s, task id %s",
        dataset_id,
        target_window,
        marker,
        self.request.id,
    )

    try:
        SqlaTable.refresh_dataset_by_id(dataset_id, expected_time_type=refresh_window)
    except CommandException as ex:
        elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
        logger.exception(
            "A command exception occurred while refreshing dataset %s after %.2f seconds: %s",
            dataset_id,
            elapsed_seconds,
            ex,
        )
        cache_manager.cache.delete(queued_key)
        self.update_state(state="FAILURE")
        raise
    except Exception as ex:  # pylint: disable=broad-except
        elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
        logger.exception(
            "An unexpected error occurred while refreshing dataset %s after %.2f seconds: %s",
            dataset_id,
            elapsed_seconds,
            ex,
        )
        cache_manager.cache.delete(queued_key)
        self.update_state(state="FAILURE")
        raise
    else:
        cache_manager.cache.set(completed_key, self.request.id, timeout=marker_timeout)
        logger.info(
            "Completed refresh of dynamic dataset %s for window %s marker %s in %.2f seconds, task id %s",
            dataset_id,
            target_window,
            marker,
            (datetime.utcnow() - start_time).total_seconds(),
            self.request.id,
        )
    finally:
        cache_manager.cache.delete(running_key)
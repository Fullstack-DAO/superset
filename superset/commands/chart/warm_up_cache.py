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
from typing import Any, Optional, Union

import simplejson as json
from flask import g

from superset.commands.base import BaseCommand
from superset.commands.chart.data.get_data_command import ChartDataCommand
from superset.commands.chart.exceptions import (
    ChartInvalidError,
    WarmUpCacheChartNotFoundError,
)
from superset.extensions import db
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice
from superset.utils.core import error_msg_from_exception
from superset.views.utils import get_dashboard_extra_filters, get_form_data, get_viz
from superset.viz import viz_types

logger = logging.getLogger(__name__)


class ChartWarmUpCacheCommand(BaseCommand):
    def __init__(
        self,
        chart_or_id: Union[int, Slice],
        dashboard_id: Optional[int],
        extra_filters: Optional[str],
        warm_up: bool = True,
    ):
        self._chart_or_id = chart_or_id
        self._dashboard_id = dashboard_id
        self._extra_filters = extra_filters
        self._warm_up = warm_up

    @staticmethod
    def _get_native_filter_extras(
        chart_id: int, dashboard_id: int
    ) -> list[dict[str, Any]]:
        """
        Extract native filter default values from a dashboard
        that apply to the given chart.

        Returns a list of filter clauses like:
            [{"col": "年", "op": "IN", "val": [2025]}, ...]
        """
        dashboard = db.session.query(Dashboard).filter_by(id=dashboard_id).first()
        if not dashboard or not dashboard.json_metadata:
            return []

        try:
            metadata = json.loads(dashboard.json_metadata)
        except json.JSONDecodeError:
            return []

        native_filters = metadata.get("native_filter_configuration", [])
        # dataMask at the dashboard level stores the last-applied filter
        # values (persisted when the dashboard is saved). This is the
        # fallback when defaultDataMask.extraFormData.filters is empty.
        dashboard_data_mask = metadata.get("dataMask", {})
        extra_filters: list[dict[str, Any]] = []

        logger.info(
            "Native filter extraction for chart %d, dashboard %d: "
            "%d native filters found, dataMask keys: %s",
            chart_id, dashboard_id,
            len(native_filters),
            list(dashboard_data_mask.keys()) if dashboard_data_mask else "none",
        )

        for native_filter in native_filters:
            filter_id = native_filter.get("id", "unknown")
            filter_name = native_filter.get("name", "unknown")

            # Determine if this filter applies to the chart.
            # The `scope` field (rootPath + excluded) is the source of
            # truth; `chartsInScope` is a pre-computed cache that can
            # become stale when charts are added/removed.
            scope = native_filter.get("scope", {})
            root_path = scope.get("rootPath", [])
            excluded = scope.get("excluded", [])

            if "ROOT_ID" in root_path:
                # Global scope — applies to all charts except excluded
                if chart_id in excluded:
                    logger.info(
                        "  Filter '%s' (id=%s): chart %d excluded by scope",
                        filter_name, filter_id, chart_id,
                    )
                    continue
            else:
                # Tab-level scope — fall back to chartsInScope
                charts_in_scope = native_filter.get("chartsInScope")
                if charts_in_scope is not None and chart_id not in charts_in_scope:
                    logger.info(
                        "  Filter '%s' (id=%s): chart %d NOT in "
                        "chartsInScope %s",
                        filter_name, filter_id, chart_id, charts_in_scope,
                    )
                    continue

            # Try 1: dashboard-level dataMask (last-applied/saved values)
            # — this reflects what users actually see when opening the
            #   dashboard, so it takes priority over defaultDataMask.
            filters: list[dict[str, Any]] = []
            if dashboard_data_mask:
                dm_entry = dashboard_data_mask.get(filter_id, {})
                dm_extra = dm_entry.get("extraFormData", {})
                filters = dm_extra.get("filters", [])
                if filters:
                    logger.info(
                        "  Filter '%s' (id=%s): using dashboard dataMask, "
                        "got %d filters: %s",
                        filter_name, filter_id, len(filters), filters,
                    )

            # Try 2: defaultDataMask.extraFormData.filters (configured default)
            if not filters:
                default_data_mask = native_filter.get("defaultDataMask", {})
                extra_form_data = default_data_mask.get("extraFormData", {})
                filters = extra_form_data.get("filters", [])
                if filters:
                    logger.info(
                        "  Filter '%s' (id=%s): using defaultDataMask, "
                        "got %d filters: %s",
                        filter_name, filter_id, len(filters), filters,
                    )

            if not filters:
                logger.info(
                    "  Filter '%s' (id=%s): in_scope=True but NO filters "
                    "found in dataMask or defaultDataMask",
                    filter_name, filter_id,
                )

            extra_filters.extend(filters)

        return extra_filters

    def run(self) -> dict[str, Any]:
        self.validate()
        chart: Slice = self._chart_or_id  # type: ignore

        try:
            form_data = get_form_data(chart.id, use_slice_data=True)[0]

            if form_data.get("viz_type") in viz_types:
                # Legacy visualizations.
                if not chart.datasource:
                    raise ChartInvalidError("Chart's datasource does not exist")

                if self._dashboard_id:
                    form_data["extra_filters"] = (
                        json.loads(self._extra_filters)
                        if self._extra_filters
                        else get_dashboard_extra_filters(chart.id, self._dashboard_id)
                    )

                g.form_data = form_data
                payload = get_viz(
                    datasource_type=chart.datasource.type,
                    datasource_id=chart.datasource.id,
                    form_data=form_data,
                    force=True,
                ).get_payload()
                delattr(g, "form_data")
                error = payload["errors"] or None
                status = payload["status"]
            else:
                # Non-legacy visualizations.
                query_context = chart.get_query_context()

                if not query_context:
                    raise ChartInvalidError(
                        "Chart's query context does not exist"
                    )

                query_context.force = True
                query_context.warm_up = self._warm_up

                # Log query details for debugging
                for idx, q in enumerate(query_context.queries):
                    logger.info(
                        "Warmup chart %d query[%d]: columns=%s, "
                        "metrics=%s, filters=%s, orderby=%s, "
                        "post_processing=%s, row_limit=%s, "
                        "order_desc=%s, extras=%s",
                        chart.id, idx,
                        q.columns, q.metrics, q.filter,
                        q.orderby, q.post_processing, q.row_limit,
                        q.order_desc, q.extras,
                    )

                # Inject dashboard native filter defaults.
                # Prepend to match the frontend's filter ordering:
                #   [...appendFilters(native), ...adhoc_simple_WHERE]
                if self._dashboard_id:
                    native_extras = self._get_native_filter_extras(
                        chart.id, self._dashboard_id
                    )
                    if native_extras:
                        logger.info(
                            "Injecting %d native filter defaults for "
                            "chart %d from dashboard %d",
                            len(native_extras),
                            chart.id,
                            self._dashboard_id,
                        )
                        for query_obj in query_context.queries:
                            query_obj.filter = (
                                native_extras + query_obj.filter
                            )

                command = ChartDataCommand(query_context)
                command.validate()
                payload = command.run()

                # Report the first error.
                for query in payload["queries"]:
                    error = query["error"]
                    status = query["status"]

                    if error is not None:
                        break
        except Exception as ex:  # pylint: disable=broad-except
            error = error_msg_from_exception(ex)
            status = None

        return {"chart_id": chart.id, "viz_error": error, "viz_status": status}

    def validate(self) -> None:
        if isinstance(self._chart_or_id, Slice):
            return
        chart = db.session.query(Slice).filter_by(id=self._chart_or_id).scalar()
        if not chart:
            raise WarmUpCacheChartNotFoundError()
        self._chart_or_id = chart

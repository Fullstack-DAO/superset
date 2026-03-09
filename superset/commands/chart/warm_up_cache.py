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
        extra_filters: list[dict[str, Any]] = []

        for native_filter in native_filters:
            # Check if this filter applies to the chart via chartsInScope
            charts_in_scope = native_filter.get("chartsInScope")
            if charts_in_scope is not None and chart_id not in charts_in_scope:
                continue

            # Extract default filter values
            default_data_mask = native_filter.get("defaultDataMask", {})
            extra_form_data = default_data_mask.get("extraFormData", {})
            filters = extra_form_data.get("filters", [])
            extra_filters.extend(filters)

        return extra_filters

    @staticmethod
    def _build_queries_from_form_data(
        form_data: dict[str, Any],
    ) -> list[dict[str, Any]] | None:
        """
        Build query dicts from the chart's current form_data,
        replicating the frontend's plugin-specific buildQuery logic.

        Returns None for unsupported viz types (caller should fall back
        to the saved query_context).
        """
        viz_type = form_data.get("viz_type")
        if viz_type == "table":
            return ChartWarmUpCacheCommand._build_table_queries(form_data)
        if viz_type == "pivot_table_v2":
            return ChartWarmUpCacheCommand._build_pivot_queries(form_data)
        return None

    @staticmethod
    def _build_table_queries(
        form_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Build queries for the table viz type.

        Matches the frontend's plugin-chart-table/src/buildQuery.ts:
        - aggregate mode: columns from groupby, orderby always descending
          on first metric when no sortByMetric is set
        - show_totals: appends a totals query without orderby/order_desc
        """
        metrics = form_data.get("metrics", [])
        time_grain_sqla = form_data.get("time_grain_sqla", "P1D")
        extras = {
            "time_grain_sqla": time_grain_sqla,
            "having": form_data.get("having", ""),
            "where": form_data.get("where", ""),
        }

        # Frontend table buildQuery: when no timeseries_limit_metric,
        # always orders by first metric DESCENDING (second elem = false).
        sort_by_metric = form_data.get("timeseries_limit_metric")
        if isinstance(sort_by_metric, list):
            sort_by_metric = sort_by_metric[0] if sort_by_metric else None

        order_desc = form_data.get("order_desc", True)
        if sort_by_metric:
            orderby: list = [[sort_by_metric, not order_desc]]
        elif metrics:
            orderby = [[metrics[0], False]]  # always descending
        else:
            orderby = []

        main_query: dict[str, Any] = {
            "filters": [],
            "extras": extras,
            "columns": form_data.get("groupby", []),
            "metrics": metrics,
            "orderby": orderby,
            "row_limit": form_data.get("row_limit", 10000),
            "series_limit": form_data.get("series_limit", 0),
            "order_desc": order_desc,
            "post_processing": [],
        }

        queries = [main_query]

        if (
            metrics
            and form_data.get("show_totals")
            and form_data.get("query_mode", "aggregate") != "raw"
        ):
            # Frontend sets orderby & order_desc to undefined for the
            # totals query—omit them so QueryObject uses its defaults.
            totals_query: dict[str, Any] = {
                "filters": [],
                "extras": dict(extras),
                "columns": [],
                "metrics": metrics,
                "row_limit": 0,
                "row_offset": 0,
                "series_limit": 0,
                "post_processing": [],
            }
            queries.append(totals_query)

        return queries

    @staticmethod
    def _build_pivot_queries(
        form_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Build queries for the pivot_table_v2 viz type.

        Matches the frontend's plugin-chart-pivot-table/src/plugin/buildQuery.ts:
        - columns = deduplicated [...groupbyColumns, ...groupbyRows]
        - orderby uses !order_desc (differs from table plugin)
        """
        metrics = form_data.get("metrics", [])
        order_desc = form_data.get("order_desc", True)
        time_grain_sqla = form_data.get("time_grain_sqla", "P1D")

        groupby_columns = form_data.get("groupbyColumns", [])
        groupby_rows = form_data.get("groupbyRows", [])
        # Frontend uses Array.from(new Set([...cols, ...rows]))
        seen: set[str] = set()
        columns: list[str] = []
        for col in list(groupby_columns) + list(groupby_rows):
            if col not in seen:
                seen.add(col)
                columns.append(col)

        series_limit_metric = form_data.get("series_limit_metric")
        if series_limit_metric:
            orderby: list = [[series_limit_metric, not order_desc]]
        elif metrics:
            orderby = [[metrics[0], not order_desc]]
        else:
            orderby = []

        return [
            {
                "filters": [],
                "extras": {
                    "time_grain_sqla": time_grain_sqla,
                    "having": form_data.get("having", ""),
                    "where": form_data.get("where", ""),
                },
                "columns": columns,
                "metrics": metrics,
                "orderby": orderby,
                "row_limit": form_data.get("row_limit", 10000),
                "series_limit": form_data.get("series_limit", 0),
                "order_desc": order_desc,
                "post_processing": [],
            }
        ]

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
                # Build a fresh query context from the chart's *current*
                # form_data (params column) instead of the saved
                # query_context, which may be stale if the chart was
                # modified without re-saving from the explore page.
                # The frontend always rebuilds queries via the plugin's
                # buildQuery(formData), so we must do the same.
                current_form_data = chart.form_data
                fresh_queries = self._build_queries_from_form_data(
                    current_form_data
                )

                if fresh_queries is not None:
                    query_context = chart.get_query_context_factory().create(
                        datasource={
                            "id": chart.datasource_id,
                            "type": chart.datasource_type,
                        },
                        queries=fresh_queries,
                        form_data=current_form_data,
                        result_type="full",
                        result_format="json",
                    )
                    logger.info(
                        "Chart %d: built fresh query context from "
                        "form_data (viz_type=%s, %d queries)",
                        chart.id,
                        current_form_data.get("viz_type"),
                        len(fresh_queries),
                    )
                else:
                    # Unsupported viz type – fall back to saved
                    # query_context.
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
                        "post_processing=%s, row_limit=%s",
                        chart.id, idx,
                        q.columns, q.metrics, q.filter,
                        q.orderby, q.post_processing, q.row_limit,
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

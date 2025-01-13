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
from datetime import datetime
from typing import Any, Optional

from flask import g
from flask_appbuilder.models.sqla import Model
from marshmallow import ValidationError

from superset import security_manager
from superset.charts.permissions import ChartPermissions
from superset.commands.base import BaseCommand, UpdateMixin
from superset.commands.chart.exceptions import (
    ChartForbiddenError,
    ChartInvalidError,
    ChartNotFoundError,
    ChartUpdateFailedError,
    DashboardsNotFoundValidationError,
    DatasourceTypeUpdateRequiredValidationError,
)
from superset.commands.utils import get_datasource_by_id
from superset.daos.chart import ChartDAO
from superset.daos.dashboard import DashboardDAO
from superset.daos.exceptions import DAOUpdateFailedError
from superset.exceptions import SupersetSecurityException
from superset.models.slice import Slice

logger = logging.getLogger(__name__)


def is_query_context_update(properties: dict[str, Any]) -> bool:
    return set(properties) == {"query_context", "query_context_generation"} and bool(
        properties.get("query_context_generation")
    )


class UpdateChartCommand(UpdateMixin, BaseCommand):
    def __init__(self, model_id: int, data: dict[str, Any]):
        self._model_id = model_id
        self._properties = data.copy()
        self._model: Optional[Slice] = None

    def run(self) -> Model:
        """
        执行图表更新逻辑。
        """
        self.validate()
        assert self._model

        try:
            # 分离 Slice 表字段和权限字段
            slice_fields = {key: value for key, value in self._properties.items() if hasattr(Slice, key)}
            additional_fields = {key: value for key, value in self._properties.items() if not hasattr(Slice, key)}
            self._properties["last_saved_at"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._properties["last_saved_by"] = g.user
            logger.info(f"Updating slice fields: {slice_fields}")
            logger.info(f"Additional fields: {additional_fields}")
            # 调用 ChartDAO 更新图表
            chart = ChartDAO.update(self._model, self._properties)

            return chart
        except DAOUpdateFailedError as ex:
            logger.exception(ex.exception)
            raise ChartUpdateFailedError() from ex

    def validate(self) -> None:
        exceptions: list[ValidationError] = []
        dashboard_ids = self._properties.get("dashboards")
        owner_ids: Optional[list[int]] = self._properties.get("owners")

        # Validate if datasource_id is provided datasource_type is required
        datasource_id = self._properties.get("datasource_id")
        if datasource_id is not None:
            datasource_type = self._properties.get("datasource_type", "")
            if not datasource_type:
                exceptions.append(DatasourceTypeUpdateRequiredValidationError())
        logger.info(f"the model_id is : {self._model_id}")
        # Validate/populate model exists
        self._model = ChartDAO.find_by_id_with_no_permission(self._model_id)
        if not self._model:
            raise ChartNotFoundError()

        # Check and update ownership; when only updating query context we ignore
        # ownership so the update can be performed by report workers
        if not is_query_context_update(self._properties):
            try:
                # security_manager.raise_for_ownership(self._model)
                user_id = g.user.id
                ChartPermissions.check_can_edit(user_id, self._model_id)
                owners = self.populate_owners(owner_ids)
                self._properties["owners"] = owners
            except SupersetSecurityException as ex:
                raise ChartForbiddenError() from ex
            except ValidationError as ex:
                exceptions.append(ex)

        # Validate/Populate datasource
        if datasource_id is not None:
            try:
                datasource = get_datasource_by_id(datasource_id, datasource_type)
                self._properties["datasource_name"] = datasource.name
            except ValidationError as ex:
                exceptions.append(ex)

        # Validate/Populate dashboards only if it's a list
        if dashboard_ids is not None:
            dashboards = DashboardDAO.find_by_ids(
                dashboard_ids,
                skip_base_filter=True,
            )
            if len(dashboards) != len(dashboard_ids):
                exceptions.append(DashboardsNotFoundValidationError())
            self._properties["dashboards"] = dashboards

        if exceptions:
            raise ChartInvalidError(exceptions=exceptions)

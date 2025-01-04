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
from superset.commands.base import BaseCommand, CreateMixin
from superset.commands.chart.exceptions import (
    ChartCreateFailedError,
    ChartInvalidError,
    DashboardsForbiddenError,
    DashboardsNotFoundValidationError,
    CreateChartForbiddenError,
)
from superset.commands.exceptions import (
    OwnersNotFoundValidationError,
    RolesNotFoundValidationError,
)
from superset.commands.utils import get_datasource_by_id, populate_roles
from superset.daos.chart import ChartDAO
from superset.daos.dashboard import DashboardDAO
from superset.daos.exceptions import DAOCreateFailedError
from superset.tasks.utils import get_current_user_object

logger = logging.getLogger(__name__)


class CreateChartCommand(CreateMixin, BaseCommand):
    def __init__(self, data: dict[str, Any]):
        self._properties = data.copy()

    def run(self) -> Model:
        """
        执行创建图表的主逻辑。
        """
        self.validate()
        try:
            # 设置最后保存时间和当前用户
            self._properties["last_saved_at"] = datetime.now()
            self._properties["last_saved_by"] = g.user

            # 设置所有者和角色权限
            self._properties["owners"] = self.populate_owners(
                self._properties.get("owners"))
            self._properties["roles"] = populate_roles(
                self._properties.get("roles"))

            # 调用 ChartDAO.create
            new_chart = ChartDAO.create(attributes=self._properties)

            # 添加用户和角色的默认权限
            ChartPermissions.set_default_permissions(
                chart=new_chart,
                user=g.user,
                roles=self._properties["roles"],
                permissions=["can_read", "can_edit", "can_add", "can_delete"],
            )
            return new_chart
        except DAOCreateFailedError as ex:
            logger.exception(ex.exception)
            raise ChartCreateFailedError() from ex

    def validate(self) -> None:
        """
        验证图表创建的输入数据。
        """
        exceptions = []
        datasource_type = self._properties["datasource_type"]
        datasource_id = self._properties["datasource_id"]
        dashboard_ids = self._properties.get("dashboards", [])
        owner_ids: Optional[list[int]] = self._properties.get("owners")
        role_ids: Optional[list[int]] = self._properties.get("roles")  # 假设有 roles 字段
        dataset_id = datasource_id
        logger.info(f"current dataset_id is {dataset_id}")
        current_user = get_current_user_object()

        # 校验 dataset 权限
        if not ChartPermissions.user_has_dataset_access(current_user, dataset_id):
            error_message = (
                f"User {current_user.username} "
                f"lacks dataset access, cannot create chart."
            )
            logger.error(error_message)  # 记录错误日志
            raise CreateChartForbiddenError("Chart permission denied message.")

        # 验证数据源
        try:
            datasource = get_datasource_by_id(datasource_id, datasource_type)
            self._properties["datasource_name"] = datasource.name
        except ValidationError as ex:
            exceptions.append(ex)

        # 验证和填充仪表盘
        dashboards = DashboardDAO.find_by_ids(dashboard_ids)
        if len(dashboards) != len(dashboard_ids):
            exceptions.append(DashboardsNotFoundValidationError())
        for dash in dashboards:
            if not security_manager.is_owner(dash):
                raise DashboardsForbiddenError()
        self._properties["dashboards"] = dashboards

        # 验证所有者
        try:
            owners = self.populate_owners(owner_ids)  # 通过 CreateMixin 调用
            self._properties["owners"] = [owner.id for owner in owners]
            self._owners = owners
        except OwnersNotFoundValidationError as ex:
            exceptions.append(ex)
        except ValidationError as ex:
            exceptions.append(ex)

        # 验证角色
        try:
            roles = populate_roles(role_ids)  # 直接调用独立的函数
            self._properties["roles"] = [role.id for role in roles]
            self._roles = roles
        except RolesNotFoundValidationError as ex:
            exceptions.append(ex)
        except ValidationError as ex:
            exceptions.append(ex)

        if exceptions:
            raise ChartInvalidError(exceptions=exceptions)




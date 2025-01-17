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
from typing import Any

from flask import g
from flask_babel import gettext as _

from superset import db
from superset.commands.base import BaseCommand
from superset.commands.chart.exceptions import (
    ChartDataCacheLoadError,
    ChartDataQueryFailedError,
)
from superset.commands.dataset.exceptions import DatasetAccessDeniedError
from superset.common.query_context import QueryContext
from superset.exceptions import CacheLoadError
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission

logger = logging.getLogger(__name__)


class ChartDataCommand(BaseCommand):
    _query_context: QueryContext

    def __init__(self, query_context: QueryContext):
        self._query_context = query_context

    def run(self, **kwargs: Any) -> dict[str, Any]:
        # caching is handled in query_context.get_df_payload
        # (also evals `force` property)
        self.check_permissions()
        cache_query_context = kwargs.get("cache", False)
        force_cached = kwargs.get("force_cached", False)
        try:
            payload = self._query_context.get_payload(
                cache_query_context=cache_query_context, force_cached=force_cached
            )
        except CacheLoadError as ex:
            raise ChartDataCacheLoadError(ex.message) from ex

        # TODO: QueryContext should support SIP-40 style errors
        for query in payload["queries"]:
            if query.get("error"):
                raise ChartDataQueryFailedError(
                    _("Error: %(error)s", error=query["error"])
                )

        return_value = {
            "query_context": self._query_context,
            "queries": payload["queries"],
        }
        if cache_query_context:
            return_value.update(cache_key=payload["cache_key"])

        return return_value

    def validate(self) -> None:
        pass

    def check_permissions(self) -> None:
        """
        Validate permissions for the current user and resource.
        """
        logger.debug("Starting permission check.")

        # 从 query_context 中获取 form_data
        form_data = self._query_context.form_data
        logger.debug(f"Form data: {form_data}")

        if not form_data:
            logger.warning("Permission check failed: "
                           "form_data is missing in query_context.")
            raise DatasetAccessDeniedError("form_data is missing in query_context.")

        # 从 form_data 中获取 slice_id
        slice_id = form_data.get("slice_id")
        # if not slice_id:
        #     logger.warning("Permission check failed: slice_id is missing in form_data.")
        #     raise DatasetAccessDeniedError("slice_id is missing in form_data.")

        datasource_info = form_data.get("datasource")
        if not datasource_info:
            logger.warning(
                "Permission check failed: datasource information is missing in form_data.")
            raise DatasetAccessDeniedError(
                "datasource information is missing in form_data.")

        if isinstance(datasource_info, dict):
            datasource_id = datasource_info.get("id")
            datasource_type = datasource_info.get("type")
        elif isinstance(datasource_info, str):
            try:
                datasource_id_str, datasource_type = datasource_info.split("__")
                datasource_id = int(datasource_id_str)
            except ValueError:
                logger.error(
                    "Permission check failed: datasource_info string format is invalid.")
                raise DatasetAccessDeniedError("Invalid datasource information format.")
        else:
            logger.error(
                "Permission check failed: datasource_info is neither dict nor str.")
            raise DatasetAccessDeniedError("Invalid datasource information format.")

        if not datasource_id or not datasource_type:
            logger.warning("Permission check failed: datasource id or type is missing.")
            raise DatasetAccessDeniedError("datasource id or type is missing.")

        logger.debug(
            f"Extracted slice_id: {slice_id}, "
            f"datasource_id: {datasource_id}, "
            f"datasource_type: {datasource_type}"
        )

        user = g.user
        if not user:
            logger.warning("Permission check failed: User information is missing.")
            raise DatasetAccessDeniedError("User information is missing.")

        user_id = user.id
        role_ids = [role.id for role in user.roles] if user.roles else []
        logger.debug(
            f"Checking permissions for user_id={user_id}, "
            f"role_ids={role_ids}, "
            f"datasource_id={datasource_id}"
        )

        # 初始化权限标志
        has_permission = False

        # 查询 UserPermission
        try:
            user_permission = db.session.query(UserPermission).filter_by(
                user_id=user_id, resource_id=slice_id, resource_type="chart"
            ).one_or_none()
            if user_permission:
                logger.info(
                    f"UserPermission found: can_read={user_permission.can_read}, "
                    f"can_edit={user_permission.can_edit}"
                )
                if user_permission.can_read and user_permission.can_edit:
                    has_permission = True
                    logger.info(
                        f"User {user_id} has read and "
                        f"edit permissions for datasource {datasource_id}."
                    )
            else:
                logger.error(
                    f"No UserPermission found for user_id={user_id} "
                    f"and datasource_id={datasource_id}."
                )
        except Exception as e:
            logger.error(f"Error querying UserPermission: {e}")
            raise DatasetAccessDeniedError("Error accessing user permissions.")

        # 查询 RolePermission
        if not has_permission and role_ids:
            try:
                role_permissions = db.session.query(RolePermission).filter(
                    RolePermission.role_id.in_(role_ids),
                    RolePermission.resource_id == slice_id,
                    RolePermission.can_read == True,
                    RolePermission.can_edit == True
                ).all()
                if role_permissions:
                    has_permission = True
                    logger.info(
                        f"User {user_id} has role-based permissions "
                        f"for datasource {datasource_id}."
                    )
                else:
                    logger.error(
                        f"No RolePermission found for role_ids={role_ids} "
                        f"and datasource_id={datasource_id}."
                    )
            except Exception as e:
                logger.error(f"Error querying RolePermission: {e}")
                raise DatasetAccessDeniedError("Error accessing role permissions.")

        if not has_permission:
            logger.error(
                f"Permission denied for user_id={user_id} on datasource_id={datasource_id}.")
            raise DatasetAccessDeniedError("Permission denied.")
        else:
            logger.error(
                f"Permission check passed for user_id={user_id} on datasource_id={datasource_id}.")

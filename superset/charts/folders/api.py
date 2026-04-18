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
from __future__ import annotations

from typing import Any

from flask import g, request, Response
from flask_appbuilder.api import expose, protect, safe
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from superset import db, security_manager
from superset.commands.chart.exceptions import (
    ChartAccessDeniedError,
    ChartNotFoundError,
)
from superset.constants import MODEL_API_RW_METHOD_PERMISSION_MAP
from superset.daos.chart import ChartDAO
from superset.extensions import event_logger
from superset.models.chart_folders import ChartMenuFolder, ChartMenuItem
from superset.views.base_api import BaseSupersetApi, requires_json


class ChartMenuRestApi(BaseSupersetApi):
    allow_browser_login = True
    class_permission_name = "Chart"
    method_permission_name = {
        "get": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
        "create_folder": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
        "update_folder": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
        "delete_folder": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
        "add_item": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
        "delete_item": MODEL_API_RW_METHOD_PERMISSION_MAP["get"],
    }
    resource_name = "chart_menu"
    openapi_spec_tag = "Chart Menu"

    @staticmethod
    def _get_name_from_payload() -> str:
        payload = request.json or {}
        name = payload.get("name", "")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Folder name is required")
        return name.strip()

    @staticmethod
    def _get_chart_id_from_payload() -> int:
        payload = request.json or {}
        chart_id = payload.get("chart_id")
        if not isinstance(chart_id, int):
            raise ValueError("chart_id is required")
        return chart_id

    @staticmethod
    def _get_chart(chart_id: int):
        chart = ChartDAO.find_by_id(chart_id, skip_base_filter=True)
        if not chart:
            raise ChartNotFoundError()

        can_access_chart = security_manager.is_owner(chart) or security_manager.can_access(
            "can_read", "Chart"
        )
        if not can_access_chart:
            raise ChartAccessDeniedError()

        return chart

    @classmethod
    def _serialize_item(cls, item: ChartMenuItem) -> dict[str, Any] | None:
        try:
            chart = cls._get_chart(item.chart_id)
        except (ChartAccessDeniedError, ChartNotFoundError):
            return None

        return {
            "id": item.id,
            "chart_id": chart.id,
            "slice_name": chart.slice_name,
            "url": chart.url,
        }

    @classmethod
    def _serialize_folder(cls, folder: ChartMenuFolder) -> dict[str, Any]:
        items = [
            serialized_item
            for item in folder.items
            if (serialized_item := cls._serialize_item(item)) is not None
        ]
        return {"id": folder.id, "name": folder.name, "items": items}

    @classmethod
    def _get_folders(cls) -> list[ChartMenuFolder]:
        return (
            db.session.query(ChartMenuFolder)
            .options(joinedload(ChartMenuFolder.items))
            .order_by(ChartMenuFolder.id.asc())
            .all()
        )

    @classmethod
    def _get_folder(cls, folder_id: int) -> ChartMenuFolder | None:
        return (
            db.session.query(ChartMenuFolder)
            .options(joinedload(ChartMenuFolder.items))
            .filter(ChartMenuFolder.id == folder_id)
            .one_or_none()
        )

    @classmethod
    def _folder_name_exists(
        cls,
        name: str,
        exclude_folder_id: int | None = None,
    ) -> bool:
        query = db.session.query(ChartMenuFolder).filter(
            ChartMenuFolder.name == name,
        )
        if exclude_folder_id is not None:
            query = query.filter(ChartMenuFolder.id != exclude_folder_id)
        return db.session.query(query.exists()).scalar()

    @staticmethod
    def _can_manage_folders() -> bool:
        return security_manager.is_admin()

    def _commit_or_500(self) -> Response | None:
        try:
            db.session.commit()
            return None
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

    @expose("/", methods=("GET",))
    @protect()
    @safe
    def get(self) -> Response:
        try:
            folders = self._get_folders()
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        return self.response(
            200,
            result=[self._serialize_folder(folder) for folder in folders],
        )

    @expose("/folder", methods=("POST",))
    @protect()
    @safe
    @requires_json
    @event_logger.log_this_with_context(log_to_statsd=False)
    def create_folder(self) -> Response:
        if not self._can_manage_folders():
            return self.response_403()

        try:
            name = self._get_name_from_payload()
        except ValueError as ex:
            return self.response_400(message=str(ex))

        try:
            folder_name_exists = self._folder_name_exists(name)
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if folder_name_exists:
            return self.response_400(message="Folder name already exists")

        db.session.add(ChartMenuFolder(user_id=g.user.id, name=name))
        response = self._commit_or_500()
        if response:
            return response
        return self.response(201)

    @expose("/folder/<int:folder_id>", methods=("PUT",))
    @protect()
    @safe
    @requires_json
    @event_logger.log_this_with_context(log_to_statsd=False)
    def update_folder(self, folder_id: int) -> Response:
        if not self._can_manage_folders():
            return self.response_403()

        try:
            folder = self._get_folder(folder_id)
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if not folder:
            return self.response_404()

        try:
            name = self._get_name_from_payload()
        except ValueError as ex:
            return self.response_400(message=str(ex))

        try:
            folder_name_exists = self._folder_name_exists(
                name,
                exclude_folder_id=folder.id,
            )
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if folder_name_exists:
            return self.response_400(message="Folder name already exists")

        folder.name = name
        response = self._commit_or_500()
        if response:
            return response
        return self.response(200)

    @expose("/folder/<int:folder_id>", methods=("DELETE",))
    @protect()
    @safe
    @event_logger.log_this_with_context(log_to_statsd=False)
    def delete_folder(self, folder_id: int) -> Response:
        if not self._can_manage_folders():
            return self.response_403()

        try:
            folder = self._get_folder(folder_id)
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if not folder:
            return self.response_404()

        db.session.delete(folder)
        response = self._commit_or_500()
        if response:
            return response
        return self.response(200)

    @expose("/folder/<int:folder_id>/items", methods=("POST",))
    @protect()
    @safe
    @requires_json
    @event_logger.log_this_with_context(log_to_statsd=False)
    def add_item(self, folder_id: int) -> Response:
        try:
            folder = self._get_folder(folder_id)
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if not folder:
            return self.response_404()

        try:
            chart_id = self._get_chart_id_from_payload()
            self._get_chart(chart_id)
        except ValueError as ex:
            return self.response_400(message=str(ex))
        except ChartAccessDeniedError:
            return self.response_403()
        except ChartNotFoundError:
            return self.response_404()

        if not any(item.chart_id == chart_id for item in folder.items):
            db.session.add(ChartMenuItem(folder_id=folder.id, chart_id=chart_id))
            response = self._commit_or_500()
            if response:
                return response

        return self.response(201)

    @expose("/folder/<int:folder_id>/items/<int:item_id>", methods=("DELETE",))
    @protect()
    @safe
    @event_logger.log_this_with_context(log_to_statsd=False)
    def delete_item(self, folder_id: int, item_id: int) -> Response:
        try:
            folder = self._get_folder(folder_id)
        except SQLAlchemyError as ex:
            db.session.rollback()
            return self.response_500(message=str(ex))

        if not folder:
            return self.response_404()

        item = next((item for item in folder.items if item.id == item_id), None)
        if not item:
            return self.response_404()

        db.session.delete(item)
        response = self._commit_or_500()
        if response:
            return response
        return self.response(200)

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

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from superset.charts.filters import ChartFilter
from superset.charts.permissions import ChartPermissions
from superset.daos.base import BaseDAO
from superset.extensions import db
from superset.models.core import FavStar, FavStarClassName
from superset.models.slice import Slice, slice_read_roles, slice_edit_roles
from superset.utils.core import get_user_id
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from flask_appbuilder.models.sqla import Model
from flask_appbuilder.models.sqla.interface import SQLAInterface
from typing import Any
from superset.daos.exceptions import (
    DAOCreateFailedError,
    DAODeleteFailedError,
    DAOUpdateFailedError,
)

if TYPE_CHECKING:
    from superset.connectors.sqla.models import BaseDatasource

logger = logging.getLogger(__name__)


class ChartDAO(BaseDAO[Slice]):
    base_filter = ChartFilter

    @staticmethod
    def favorited_ids(charts: list[Slice]) -> list[FavStar]:
        ids = [chart.id for chart in charts]
        return [
            star.obj_id
            for star in db.session.query(FavStar.obj_id)
            .filter(
                FavStar.class_name == FavStarClassName.CHART,
                FavStar.obj_id.in_(ids),
                FavStar.user_id == get_user_id(),
            )
            .all()
        ]

    @staticmethod
    def add_favorite(chart: Slice) -> None:
        ids = ChartDAO.favorited_ids([chart])
        if chart.id not in ids:
            db.session.add(
                FavStar(
                    class_name=FavStarClassName.CHART,
                    obj_id=chart.id,
                    user_id=get_user_id(),
                    dttm=datetime.now(),
                )
            )
            db.session.commit()

    @staticmethod
    def remove_favorite(chart: Slice) -> None:
        fav = (
            db.session.query(FavStar)
            .filter(
                FavStar.class_name == FavStarClassName.CHART,
                FavStar.obj_id == chart.id,
                FavStar.user_id == get_user_id(),
            )
            .one_or_none()
        )
        if fav:
            db.session.delete(fav)
            db.session.commit()


    @classmethod
    def find_by_id(
        cls,
        model_id: str | int,
        session: Session = None,
        skip_base_filter: bool = False,
    ) -> Slice | None:
        chart = super().find_by_id(model_id, session, skip_base_filter)
        if chart and not ChartPermissions.check_chart_permission(chart):
            return None  # 或者抛出异常
        return chart
    
    @classmethod
    def find_by_ids(
        cls,
        model_ids: list[str] | list[int],
        session: Session = None,
        skip_base_filter: bool = False,
    ) -> list[Slice]:
        charts = super().find_by_ids(model_ids, session, skip_base_filter)
        logging.info(f"Found charts: {charts}")
        return [chart for chart in charts if ChartPermissions.check_chart_permission(chart)]
    
    @classmethod
    def create(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        # 如果没有提供 item，创建一个新的 Slice 实例
        if not item:
            item = cls.model_cls()  # type: ignore  # pylint: disable=not-callable

        # 权限检查
        if not ChartPermissions.check_chart_permission(item, edit=True):
            raise PermissionError("User does not have permission to create this chart.")

        # 设置属性
        if attributes:
            for key, value in attributes.items():
                setattr(item, key, value)

        try:
            db.session.add(item)

            if commit:
                db.session.commit()
        except SQLAlchemyError as ex:  # pragma: no cover
            db.session.rollback()
            raise DAOCreateFailedError(exception=ex) from ex

        return item  # type: ignore
    
    
    @classmethod
    def find_all(cls) -> list[Slice]:
        charts = super().find_all()
        return [chart for chart in charts if ChartPermissions.check_chart_permission(chart)]


    @classmethod
    def update(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        if item and not ChartPermissions.check_chart_permission(item, edit=True):
            raise PermissionError("User does not have permission to update this chart.")

        return super().update(item, attributes, commit)
    

    @classmethod
    def delete(cls, items: list[Slice], commit: bool = True) -> None:
        for item in items:
            if not ChartPermissions.check_chart_permission(item):
                raise PermissionError(f"User does not have permission to delete chart {item.id}.")
        super().delete(items, commit)

    
    @staticmethod
    def add_read_role_to_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """Add a read role to a slice."""
        existing_role = db.session.query(slice_read_roles).filter_by(slice_id=slice_id, role_id=role_id, user_id=user_id).first()
        if existing_role:
            raise Exception("Read role already exists for this slice.")

        new_role = slice_read_roles.insert().values(slice_id=slice_id, role_id=role_id, user_id=user_id)
        db.session.execute(new_role)
        db.session.commit()

    @staticmethod
    def remove_read_role_from_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """Remove a read role from a slice."""
        delete_role = slice_read_roles.delete().where(
            (slice_read_roles.c.slice_id == slice_id) & 
            (slice_read_roles.c.role_id == role_id) & 
            (slice_read_roles.c.user_id == user_id)
        )
        result = db.session.execute(delete_role)
        db.session.commit()

        if result.rowcount == 0:
            raise Exception("Read role not found for this slice.")

    @staticmethod
    def get_read_roles_for_slice(slice_id: int) -> list:
        """Get all read roles for a slice."""
        roles = db.session.query(slice_read_roles).filter_by(slice_id=slice_id).all()
        return [{"role_id": role.role_id, "user_id": role.user_id} for role in roles]

    @staticmethod
    def add_edit_role_to_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """Add an edit role to a slice."""
        existing_role = db.session.query(slice_edit_roles).filter_by(slice_id=slice_id, role_id=role_id, user_id=user_id).first()
        if existing_role:
            raise Exception("Edit role already exists for this slice.")

        new_role = slice_edit_roles.insert().values(slice_id=slice_id, role_id=role_id, user_id=user_id)
        db.session.execute(new_role)
        db.session.commit()


    @staticmethod
    def remove_edit_role_from_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """Remove an edit role from a slice."""
        delete_role = slice_edit_roles.delete().where(
            (slice_edit_roles.c.slice_id == slice_id) & 
            (slice_edit_roles.c.role_id == role_id) & 
            (slice_edit_roles.c.user_id == user_id)
        )
        result = db.session.execute(delete_role)
        db.session.commit()

        if result.rowcount == 0:
            raise Exception("Edit role not found for this slice.")

    @staticmethod
    def get_edit_roles_for_slice(slice_id: int) -> list:
        """Get all edit roles for a slice."""
        roles = db.session.query(slice_edit_roles).filter_by(slice_id=slice_id).all()
        return [{"role_id": role.role_id, "user_id": role.user_id} for role in roles]
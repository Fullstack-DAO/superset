from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, List

from superset.charts.filters import ChartFilter
from superset.charts.permissions import ChartPermissions
from superset.daos.base import BaseDAO
from superset.extensions import db
from superset.models.core import FavStar, FavStarClassName
from superset.models.slice import Slice, slice_read_roles, slice_edit_roles
from superset.utils.core import get_user_id
from sqlalchemy.exc import SQLAlchemyError
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
    def favorited_ids(charts: List[Slice]) -> List[FavStar]:
        """获取用户收藏的图表 ID 列表。

        :param charts: Slice 对象列表
        :return: 收藏的图表 ID 列表
        """
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
        """将图表添加到用户的收藏中。

        :param chart: 要添加到收藏的 Slice 对象
        """
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
        """从用户的收藏中移除图表。

        :param chart: 要移除的 Slice 对象
        """
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
    def create(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        """创建新的图表。

        :param item: 要创建的 Slice 对象
        :param attributes: 要设置的属性字典
        :param commit: 是否提交到数据库
        :return: 创建的 Slice 对象
        """
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
    def find_all(cls) -> List[Slice]:
        """查找所有图表。

        :return: Slice 对象列表
        """
        charts = super().find_all()
        return [chart for chart in charts if ChartPermissions.check_chart_permission(chart)]

    @classmethod
    def update(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        """更新图表。

        :param item: 要更新的 Slice 对象
        :param attributes: 要更新的属性字典
        :param commit: 是否提交到数据库
        :return: 更新后的 Slice 对象
        """
        if item and not ChartPermissions.check_chart_permission(item, edit=True):
            raise PermissionError("User does not have permission to update this chart.")

        return super().update(item, attributes, commit)

    @classmethod
    def delete(cls, items: List[Slice], commit: bool = True) -> None:
        """删除图表。

        :param items: 要删除的 Slice 对象列表
        :param commit: 是否提交到数据库
        """
        for item in items:
            if not ChartPermissions.check_chart_permission(item):
                raise PermissionError(f"User does not have permission to delete chart {item.id}.")
        super().delete(items, commit)

    @staticmethod
    def add_read_role_to_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """为图表添加读取角色。

        :param slice_id: 图表 ID
        :param role_id: 角色 ID
        :param user_id: 用户 ID
        """
        existing_role = db.session.query(slice_read_roles).filter_by(slice_id=slice_id, role_id=role_id, user_id=user_id).first()
        if existing_role:
            raise Exception("Read role already exists for this slice.")

        new_role = slice_read_roles.insert().values(slice_id=slice_id, role_id=role_id, user_id=user_id)
        db.session.execute(new_role)
        db.session.commit()

    @staticmethod
    def remove_read_role_from_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """从图表中移除读取角色。

        :param slice_id: 图表 ID
        :param role_id: 角色 ID
        :param user_id: 用户 ID
        """
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
        """获取图表的所有读取角色。

        :param slice_id: 图表 ID
        :return: 角色列表
        """
        roles = db.session.query(slice_read_roles).filter_by(slice_id=slice_id).all()
        return [{"role_id": role.role_id, "user_id": role.user_id} for role in roles]

    @staticmethod
    def add_edit_role_to_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """为图表添加编辑角色。

        :param slice_id: 图表 ID
        :param role_id: 角色 ID
        :param user_id: 用户 ID
        """
        existing_role = db.session.query(slice_edit_roles).filter_by(slice_id=slice_id, role_id=role_id, user_id=user_id).first()
        if existing_role:
            raise Exception("Edit role already exists for this slice.")

        new_role = slice_edit_roles.insert().values(slice_id=slice_id, role_id=role_id, user_id=user_id)
        db.session.execute(new_role)
        db.session.commit()

    @staticmethod
    def remove_edit_role_from_slice(slice_id: int, role_id: int, user_id: int) -> None:
        """从图表中移除编辑角色。

        :param slice_id: 图表 ID
        :param role_id: 角色 ID
        :param user_id: 用户 ID
        """
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
        """获取图表的所有编辑角色。

        :param slice_id: 图表 ID
        :return: 角色列表
        """
        roles = db.session.query(slice_edit_roles).filter_by(slice_id=slice_id).all()
        return [{"role_id": role.role_id, "user_id": role.user_id} for role in roles]

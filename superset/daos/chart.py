from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, List

from superset.charts.filters import ChartFilter
from superset.extensions import db
from superset.models.core import FavStar, FavStarClassName
from superset.models.slice import Slice
from superset.models.permissions import UserPermission, RolePermission
from superset.utils.core import get_user_id
from sqlalchemy.exc import SQLAlchemyError
from superset.daos.exceptions import (
    DAOCreateFailedError,
    DAODeleteFailedError,
)

if TYPE_CHECKING:
    from superset.connectors.sqla.models import BaseDatasource

logger = logging.getLogger(__name__)


class ChartDAO:
    base_filter = ChartFilter

    @staticmethod
    def favorited_ids(charts: List[Slice]) -> List[int]:
        """
        获取当前用户收藏的图表 ID 列表。
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
        """
        将图表添加到当前用户的收藏中。
        """
        if chart.id not in ChartDAO.favorited_ids([chart]):
            try:
                db.session.add(
                    FavStar(
                        class_name=FavStarClassName.CHART,
                        obj_id=chart.id,
                        user_id=get_user_id(),
                        dttm=datetime.now(),
                    )
                )
                db.session.commit()
            except SQLAlchemyError as ex:
                db.session.rollback()
                logger.error(f"Error adding favorite chart: {ex}")
                raise DAOCreateFailedError(exception=ex)

    @staticmethod
    def remove_favorite(chart: Slice) -> None:
        """
        从当前用户的收藏中移除图表。
        """
        try:
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
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error removing favorite chart: {ex}")
            raise DAODeleteFailedError(exception=ex)

    @staticmethod
    def has_permission(chart_id: int, user, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限（同时检查用户和角色权限）。

        :param chart_id: 图表 ID
        :param user: 当前用户对象
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 是否有权限
        """
        permission_map = {
            'read': 'can_read',
            'edit': 'can_edit',
            'delete': 'can_delete',
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 检查用户直接权限
        user_permissions = db.session.query(UserPermission).filter(
            UserPermission.resource_type == "chart",
            UserPermission.resource_id == chart_id,
            UserPermission.user_id == user.id,
            getattr(UserPermission, permission_map[permission_type]) == True,
        ).count()

        if user_permissions > 0:
            return True

        # 检查用户角色权限
        role_permissions = db.session.query(RolePermission).filter(
            RolePermission.resource_type == "chart",
            RolePermission.resource_id == chart_id,
            RolePermission.role_id.in_([role.id for role in user.roles]),
            getattr(RolePermission, permission_map[permission_type]) == True,
        ).count()

        return role_permissions > 0

    @staticmethod
    def add_read_permission_to_user(chart_id: int, user_id: int) -> None:
        """
        为用户添加图表读取权限。

        :param chart_id: 图表 ID
        :param user_id: 用户 ID
        """
        try:
            existing_permission = db.session.query(UserPermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
                can_read=True,
            ).first()

            if existing_permission:
                raise Exception(
                    "Read permission already exists for this user and chart.")

            permission = UserPermission(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
                can_read=True,
            )
            db.session.add(permission)
            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error adding read permission to user: {ex}")
            raise DAOCreateFailedError(exception=ex)

    @staticmethod
    def add_read_permission_to_role(chart_id: int, role_id: int) -> None:
        """
        为角色添加图表读取权限。

        :param chart_id: 图表 ID
        :param role_id: 角色 ID
        """
        try:
            existing_permission = db.session.query(RolePermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
                can_read=True,
            ).first()

            if existing_permission:
                raise Exception(
                    "Read permission already exists for this role and chart.")

            permission = RolePermission(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
                can_read=True,
            )
            db.session.add(permission)
            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error adding read permission to role: {ex}")
            raise DAOCreateFailedError(exception=ex)

    @staticmethod
    def get_read_permissions(chart_id: int) -> dict:
        """
        获取图表的所有读取权限（包括用户和角色）。

        :param chart_id: 图表 ID
        :return: 包含用户和角色权限的字典
        """
        user_permissions = db.session.query(UserPermission).filter_by(
            resource_type="chart",
            resource_id=chart_id,
            can_read=True,
        ).all()

        role_permissions = db.session.query(RolePermission).filter_by(
            resource_type="chart",
            resource_id=chart_id,
            can_read=True,
        ).all()

        return {
            "users": [{"user_id": perm.user_id} for perm in user_permissions],
            "roles": [{"role_id": perm.role_id} for perm in role_permissions],
        }

    @staticmethod
    def get_edit_permissions(chart_id: int) -> dict:
        """
        获取图表的所有编辑权限（包括用户和角色）。

        :param chart_id: 图表 ID
        :return: 包含用户和角色权限的字典
        """
        user_permissions = db.session.query(UserPermission).filter_by(
            resource_type="chart",
            resource_id=chart_id,
            can_edit=True,
        ).all()

        role_permissions = db.session.query(RolePermission).filter_by(
            resource_type="chart",
            resource_id=chart_id,
            can_edit=True,
        ).all()

        return {
            "users": [{"user_id": perm.user_id} for perm in user_permissions],
            "roles": [{"role_id": perm.role_id} for perm in role_permissions],
        }

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

        # 获取当前用户
        user_id = get_user_id()
        user = db.session.query(db.user_model).filter_by(id=user_id).one_or_none()

        # 权限检查
        if not ChartDAO.has_permission(item.id, user, permission_type="edit"):
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
        # 获取当前用户
        user_id = get_user_id()
        user = db.session.query(db.user_model).filter_by(id=user_id).one_or_none()

        # 获取所有图表并进行权限过滤
        charts = super().find_all()
        return [
            chart
            for chart in charts
            if ChartDAO.has_permission(chart.id, user, permission_type="read")
        ]

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
        # 获取当前用户
        user_id = get_user_id()
        user = db.session.query(db.user_model).filter_by(id=user_id).one_or_none()

        # 权限检查
        if item and not ChartDAO.has_permission(item.id, user, permission_type="edit"):
            raise PermissionError("User does not have permission to update this chart.")

        # 调用父类方法更新图表
        return super().update(item, attributes, commit)

    @classmethod
    def delete(cls, items: List[Slice], commit: bool = True) -> None:
        """删除图表。

        :param items: 要删除的 Slice 对象列表
        :param commit: 是否提交到数据库
        """
        # 获取当前用户
        user_id = get_user_id()
        user = db.session.query(db.user_model).filter_by(id=user_id).one_or_none()

        # 对每个图表进行权限检查
        for item in items:
            if not ChartDAO.has_permission(item.id, user, permission_type="delete"):
                raise PermissionError(
                    f"User does not have permission to delete chart {item.id}.")

        # 调用父类方法删除图表
        super().delete(items, commit)

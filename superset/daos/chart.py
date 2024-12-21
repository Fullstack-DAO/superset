from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from superset.charts.filters import ChartFilter
from superset.charts.permissions import ChartPermissions
from superset.extensions import db
from superset.models.core import FavStar, FavStarClassName
from superset.models.slice import Slice
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.utils.core import get_user_id
from sqlalchemy.exc import SQLAlchemyError
from superset.daos.exceptions import (
    DAOCreateFailedError,
    DAODeleteFailedError,
)
from functools import wraps

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
        user_id = get_user_id()
        ids = [chart.id for chart in charts]
        return [
            star.obj_id
            for star in db.session.query(FavStar.obj_id)
            .filter(
                FavStar.class_name == FavStarClassName.CHART,
                FavStar.obj_id.in_(ids),
                FavStar.user_id == user_id,
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
    def add_permission_to_user(chart_id: int, user_id: int,
                               permission_type: str) -> None:
        """
        为用户添加图表权限（动态支持权限类型）。

        :param chart_id: 图表 ID
        :param user_id: 用户 ID
        :param permission_type: 权限类型 ('can_read', 'can_edit', 'can_delete')
        """
        if permission_type not in ["can_read", "can_edit", "can_delete"]:
            raise ValueError(f"Invalid permission type: {permission_type}")

        try:
            existing_permission = db.session.query(UserPermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
                **{permission_type: True},  # 动态检查指定的权限类型
            ).first()

            if existing_permission:
                raise Exception(
                    f"{permission_type} permission already exists for this user and "
                    f"chart."
                )

            permission = UserPermission(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
                **{permission_type: True},  # 动态设置指定的权限类型
            )
            db.session.add(permission)
            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error adding {permission_type} permission to user: {ex}")
            raise DAOCreateFailedError(exception=ex)

    @staticmethod
    def add_permission_to_role(chart_id: int, role_id: int,
                               permission_type: str) -> None:
        """
        为角色添加图表权限（动态支持权限类型）。

        :param chart_id: 图表 ID
        :param role_id: 角色 ID
        :param permission_type: 权限类型 ('can_read', 'can_edit', 'can_delete')
        """
        if permission_type not in ["can_read", "can_edit", "can_delete"]:
            raise ValueError(f"Invalid permission type: {permission_type}")

        try:
            existing_permission = db.session.query(RolePermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
                **{permission_type: True},  # 动态检查指定的权限类型
            ).first()

            if existing_permission:
                raise Exception(
                    f"{permission_type} permission already exists for this role and "
                    f"chart."
                )

            permission = RolePermission(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
                **{permission_type: True},  # 动态设置指定的权限类型
            )
            db.session.add(permission)
            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error adding {permission_type} permission to role: {ex}")
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

    @staticmethod
    def _get_current_user():
        """获取当前用户对象"""
        user_id = get_user_id()
        return db.session.query(db.user_model).filter_by(id=user_id).one_or_none()

    @classmethod
    def create(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
        roles: List[str] = None,  # 可选的角色列表
        permissions: List[str] = None,  # 可选的权限列表
    ) -> Slice:
        """
        创建新的图表。

        :param item: 要创建的 Slice 对象
        :param attributes: 要设置的属性字典
        :param commit: 是否提交到数据库
        :param roles: 分配权限的角色列表，例如 ["Admin", "Editor"]
        :param permissions: 分配的权限列表，例如 ["can_read", "can_edit"]
        :return: 创建的 Slice 对象
        """
        if not item:
            item = cls.model_cls()  # type: ignore  # pylint: disable=not-callable

        # 获取当前用户
        user = cls._get_current_user()
        if not user:
            raise PermissionError("No user is currently logged in.")

        # 检查当前用户是否有创建图表的权限
        if not ChartPermissions.has_permission(chart_id=None, user=user,
                                               permission_type="add"):
            raise PermissionError("User does not have permission to create a chart.")

        # 设置图表的属性
        if attributes:
            for key, value in attributes.items():
                setattr(item, key, value)

        # 初始化图表权限
        try:
            db.session.add(item)
            if commit:
                db.session.commit()

            # 添加默认权限：当前用户和指定角色自动获得相应权限
            ChartPermissions.set_default_permissions(
                chart=item,
                user=user,
                roles=roles,  # 如果 roles 为 None，默认会分配给 "Admin"
                permissions=permissions,
                # 如果 permissions 为 None，默认分配 "can_read" 和 "can_edit"
            )
        except SQLAlchemyError as ex:  # pragma: no cover
            db.session.rollback()
            raise DAOCreateFailedError(exception=ex) from ex

        return item  # type: ignore

    @classmethod
    def find_all(cls, permission_type: str = "read", check_permission: bool = True) -> \
    List[Slice]:
        """
        查找所有图表，同时可选地校验用户权限。

        :param permission_type: 动态指定权限类型（'read', 'edit', 'delete', 'add'），默认为 'read'
        :param check_permission: 是否校验用户权限，默认为 True
        :return: 符合条件的图表列表
        """
        user = cls._get_current_user()

        # 如果未登录用户直接返回空列表
        if check_permission and not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return []

        # 获取所有图表
        charts = super().find_all()

        # 如果不需要权限校验，直接返回所有图表
        if not check_permission:
            return charts

        # 获取用户有权限的图表 ID 列表
        allowed_chart_ids = ChartPermissions.get_allowed_chart_ids(user,
                                                                   permission_type)

        # 过滤出用户有权限的图表
        return [chart for chart in charts if chart.id in allowed_chart_ids]

    @classmethod
    def update(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        """
        更新图表，同时检查用户和角色的编辑权限。

        :param item: 要更新的图表对象 (Slice)
        :param attributes: 更新的属性字典
        :param commit: 是否提交到数据库，默认为 True
        :return: 更新后的图表对象
        """
        # 获取当前用户
        user = ChartDAO._get_current_user()
        if not user:
            raise PermissionError("No user is currently logged in.")

        # 校验 item 是否存在
        if not item:
            raise ValueError("The chart to be updated cannot be None.")

        # 检查当前用户是否有更新该图表的权限
        if not ChartPermissions.has_permission(chart_id=item.id, user=user,
                                               permission_type="edit"):
            raise PermissionError(
                f"User {user.username} does not have edit permission for chart {item.id}.")

        # 如果有权限，更新属性
        if attributes:
            for key, value in attributes.items():
                setattr(item, key, value)

        # 提交更新
        try:
            if commit:
                db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            raise DAOCreateFailedError(exception=ex) from ex

        return item

    @classmethod
    def delete(cls, items: list[Slice], commit: bool = True) -> None:
        """
        删除图表，同时检查用户和角色的删除权限。

        :param items: 要删除的图表对象列表
        :param commit: 是否提交到数据库，默认为 True
        """
        # 获取当前用户
        user = cls._get_current_user()
        if not user:
            raise PermissionError("No user is currently logged in.")

        # 校验传入的图表列表是否为空
        if not items:
            raise ValueError("The list of charts to be deleted cannot be empty.")

        # 权限检查，确保用户对每个图表都具有删除权限
        for item in items:
            if not ChartPermissions.has_permission(chart_id=item.id, user=user,
                                                   permission_type="delete"):
                raise PermissionError(
                    f"User {user.username} does not have delete permission for chart {item.id}."
                )

        # 删除图表对象
        try:
            for item in items:
                db.session.delete(item)

            # 提交事务
            if commit:
                db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            raise DAODeleteFailedError(exception=ex) from ex

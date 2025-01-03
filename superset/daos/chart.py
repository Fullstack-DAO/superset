from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import literal_column

from superset.charts.filters import ChartFilter
from superset.charts.permissions import ChartPermissions
from superset.daos.base import BaseDAO
from superset.extensions import db
from superset.models.core import FavStar, FavStarClassName
from superset.models.role_permission import RolePermission
from superset.models.slice import Slice
from flask_appbuilder import AppBuilder
from flask_appbuilder.security.sqla.models import User, Role
from superset.models.user_permission import UserPermission
from superset.utils.core import get_user_id
from sqlalchemy.exc import SQLAlchemyError
from superset.daos.exceptions import (
    DAOCreateFailedError,
    DAODeleteFailedError, DAOUpdateFailedError,
)
from sqlalchemy.orm import Session
from superset import app

if TYPE_CHECKING:
    from superset.connectors.sqla.models import BaseDatasource

logger = logging.getLogger(__name__)


class ChartDAO(BaseDAO[Slice]):
    base_filter = ChartFilter

    @staticmethod
    def favorited_ids(charts: list[Slice]) -> list[int]:
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
    def get_permissions(chart_id: int, permission_type: str) -> dict:
        """
        获取图表的指定权限（包括用户和角色）。

        :param chart_id: 图表 ID
        :param permission_type: 权限类型 ('can_read', 'can_edit', 'can_delete', 'can_add')
        :return: 包含用户和角色权限的字典
        """
        # 验证权限类型是否有效
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]
        if permission_type not in valid_permissions:
            raise ValueError(f"Invalid permission type: {permission_type}")

        # 调用 ChartPermissions.get_permissions
        try:
            permissions = ChartPermissions.get_permissions(chart_id, permission_type)
            return permissions
        except Exception as ex:
            logger.error(f"Error fetching permissions for chart {chart_id}: {str(ex)}")
            raise

    @staticmethod
    def get_current_user():
        """获取当前用户对象"""
        user_id = get_user_id()
        if not user_id:
            return None

        # 从 Flask AppBuilder 的 security_manager 获取用户模型
        appbuilder: AppBuilder = app.appbuilder
        user_model = appbuilder.sm.user_model  # 获取用户模型
        return db.session.query(user_model).filter_by(id=user_id).one_or_none()

    @classmethod
    def create_permission(
        cls,
        attributes: dict[str, Any],
        commit: bool = True,
    ) -> Slice:
        """
        创建新的图表，同时支持动态角色和权限。
        """
        try:
            # 初始化 Slice 对象
            item = Slice(**attributes)

            # 保存到数据库
            db.session.add(item)
            if commit:
                db.session.commit()

            # 返回创建的图表对象
            return item
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error creating chart: {ex}")
            raise DAOCreateFailedError(exception=ex) from ex

    @classmethod
    def find_all(
        cls,
        permission_type: str = "read",
        check_permission: bool = True
    ) -> list[Slice]:
        """
        查找所有图表，同时可选地校验用户权限。

        :param permission_type: 动态指定权限类型（'read', 'edit', 'delete', 'add'），默认为 'read'
        :param check_permission: 是否校验用户权限，默认为 True
        :return: 符合条件的图表列表
        """
        user = cls.get_current_user()

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
    def update_permission(
        cls,
        item: Slice | None = None,
        attributes: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> Slice:
        """
        更新图表逻辑。
        """
        if not item:
            raise ValueError("The chart to be updated cannot be None.")

        # 更新属性
        if attributes:
            for key, value in attributes.items():
                setattr(item, key, value)
        logger.info(f"ready to update: {item}")
        logger.info(f"the attributes is: {attributes}")
        # 提交数据库更改
        try:
            if commit:
                db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error updating chart {item.id}: {ex}")
            raise DAOUpdateFailedError(exception=ex) from ex

        return item

    @classmethod
    def delete(cls, items: list[Slice], commit: bool = True) -> None:
        """
        删除图表，同时检查用户和角色的删除权限。

        :param items: 要删除的图表对象列表
        :param commit: 是否提交到数据库，默认为 True
        """
        # 获取当前用户
        user = cls.get_current_user()
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

    @staticmethod
    def modify_permissions(
        chart_id: int,
        entity_type: str,
        entity_id: int,
        permissions: list[str],
        action: str
    ) -> None:
        """
        修改图表的权限。

        :param chart_id: 图表 ID
        :param entity_type: 实体类型 ('user' 或 'role')
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表 ['can_read', 'can_edit', 'can_add', 'can_delete']
        :param action: 操作类型 ('add' 或 'remove')
        """
        if action not in ["add", "remove"]:
            raise ValueError("Invalid action type: must be 'add' or 'remove'.")
        if entity_type not in ["user", "role"]:
            raise ValueError("Invalid entity type: must be 'user' or 'role'.")
        valid_permissions = ["can_read", "can_edit", "can_add", "can_delete"]
        logger.info(f"当前的permissions: {permissions}")
        for perm in permissions:
            if perm not in valid_permissions:
                raise ValueError(f"Invalid permission: {perm}")

        try:
            if entity_type == "user":
                permission_model = db.session.query(UserPermission).filter_by(
                    resource_type="chart",
                    resource_id=chart_id,
                    user_id=entity_id
                ).first()
                if action == "add":
                    if not permission_model:
                        # 创建新的 UserPermission 记录
                        permission_model = UserPermission(
                            resource_type="chart",
                            resource_id=chart_id,
                            user_id=entity_id,
                            can_read=False,
                            can_edit=False,
                            can_add=False,
                            can_delete=False,
                        )
                        db.session.add(permission_model)
                    # 设置指定的权限为 True
                    for perm in permissions:
                        logger.info(f"更新前的perm: {perm}")
                        setattr(permission_model, perm, True)
                        logger.info(f"更新后的perm: {perm}")
                elif action == "remove":
                    if permission_model:
                        # 删除 UserPermission 记录
                        db.session.delete(permission_model)
                    else:
                        # 尝试从不存在的权限中移除
                        raise ValueError(
                            f"User (ID: {entity_id}) is not a collaborator.")

            elif entity_type == "role":
                permission_model = db.session.query(RolePermission).filter_by(
                    resource_type="chart",
                    resource_id=chart_id,
                    role_id=entity_id
                ).first()
                if action == "add":
                    if not permission_model:
                        # 创建新的 RolePermission 记录
                        permission_model = RolePermission(
                            resource_type="chart",
                            resource_id=chart_id,
                            role_id=entity_id,
                            can_read=False,
                            can_edit=False,
                            can_add=False,
                            can_delete=False,
                        )
                        db.session.add(permission_model)
                    # 设置指定的权限为 True
                    for perm in permissions:
                        setattr(permission_model, perm, True)
                elif action == "remove":
                    if permission_model:
                        # 删除 RolePermission 记录
                        db.session.delete(permission_model)
                    else:
                        # 尝试从不存在的权限中移除
                        raise ValueError(
                            f"Role (ID: {entity_id}) is not a collaborator.")

            db.session.commit()
            logger.info(
                f"Successfully {'added' if action == 'add' else 'removed'}"
                f" permissions for {entity_type} ID {entity_id} on chart ID {chart_id}.")

        except Exception as ex:
            db.session.rollback()
            logger.error(f"Error modifying permissions: {ex}")
            raise

    @staticmethod
    def get_chart_and_check_permission(pk: int, permission_type: str) -> Slice | None:
        """
        获取图表并检查用户权限（代理到 ChartPermissions）。

        :param pk: 图表主键
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 图表对象，如果没有权限则返回 None
        """
        return ChartPermissions.get_chart_and_check_permission(pk, permission_type)

    @classmethod
    def find_by_ids(
        cls,
        model_ids: list[str] | list[int],
        session: Session = None,
        skip_base_filter: bool = False,
        permission_type: str = "read",  # 权限类型，默认为 "read"
        check_permission: bool = True,  # 是否进行权限校验
    ) -> list[Slice]:
        """
        Find a List of charts by a list of ids, if defined applies base_filter.
        Optionally checks for permissions before returning results.

        :param model_ids: List of chart IDs to search for.
        :param session: Database session.
        :param skip_base_filter: Whether to skip applying the base filter.
        :param permission_type: Type of permission (read, edit, etc.)
        :param check_permission: Whether to perform permission checks.
        :return: List of charts that match the IDs and pass the permission check.
        """
        # Step 1: Get the base result using the inherited method
        session = db.session
        charts = super().find_by_ids(model_ids, session=session,
                                     skip_base_filter=skip_base_filter)

        # Step 2: If no permission check is needed, return the results
        if not check_permission:
            return charts

        # Step 3: Get the current user
        user = cls.get_current_user()

        # If the user is not logged in and permission check is required, return an
        # empty list
        if user is None:
            logger.warning(f"Permission check failed: No user is currently logged in.")
            return []

        # Step 4: Filter charts by user permissions
        allowed_chart_ids = ChartPermissions.get_allowed_chart_ids(user,
                                                                   permission_type)

        # Step 5: Filter charts based on allowed IDs
        return [chart for chart in charts if chart.id in allowed_chart_ids]

    @classmethod
    def find_by_id(
        cls,
        model_id: str | int,
        session: Session = None,
        skip_base_filter: bool = False,
        permission_type: str = "read",  # 权限类型，默认为 "read"
        check_permission: bool = True,  # 是否校验权限
    ) -> Slice | None:
        """
        Find a chart by id, optionally applies `base_filter` and permission checks.

        :param model_id: The ID of the chart to retrieve.
        :param session: Database session.
        :param skip_base_filter: Whether to skip the base filter.
        :param permission_type: The type of permission to check (e.g., "read").
        :param check_permission: Whether to perform permission checks.
        :return: The chart object if found and permission check passes; otherwise None.
        """
        # Step 1: 调用父类方法获取对象
        session = db.session
        chart = super().find_by_id(
            model_id, session=session, skip_base_filter=skip_base_filter
        )

        # Step 2: 如果没有找到对象，直接返回 None
        if not chart:
            return None

        # Step 3: 检查权限（如果需要）
        if check_permission:
            user = cls.get_current_user()

            # 如果用户未登录，返回 None
            if not user:
                logger.warning(
                    f"Permission check failed: No user is currently logged in.")
                return None

            # 检查用户是否有权限访问该图表
            allowed_chart_ids = ChartPermissions.get_allowed_chart_ids(user,
                                                                       permission_type)
            if chart.id not in allowed_chart_ids:
                logger.warning(
                    f"Permission check failed for user {user.id} on chart {chart.id}. "
                    f"You have not {permission_type} access.")
                return None

        # Step 4: 返回对象
        return chart

    @classmethod
    def find_by_id_with_no_permission(
        cls,
        model_id: str | int,
        session: Session = None,
        skip_base_filter: bool = False,
    ) -> Slice | None:
        """
        Find a chart by id without applying permission checks.

        :param model_id: The ID of the chart to retrieve.
        :param session: Database session.
        :param skip_base_filter: Whether to skip the base filter.
        :return: The chart object if found; otherwise None.
        """
        # Step 1: 调用父类方法获取对象
        session = db.session
        chart = super().find_by_id(
            model_id, session=session, skip_base_filter=skip_base_filter
        )

        # Step 2: 如果没有找到对象，直接返回 None
        if not chart:
            return None

        # Step 3: 直接返回对象（不进行权限校验）
        return chart

    @classmethod
    def update_permissions(cls, resource_id: int, additional_fields: dict):
        user_permissions = additional_fields.get("user_permissions", [])
        role_permissions = additional_fields.get("role_permissions", [])

        # 更新 UserPermission 表
        for user_permission in user_permissions:
            user_id = user_permission["userId"]
            permissions = user_permission["permissions"]
            existing_permission = (
                db.session.query(UserPermission)
                .filter_by(resource_id=resource_id, resource_type="chart",
                           user_id=user_id)
                .first()
            )
            if existing_permission:
                existing_permission.can_read = "read" in permissions
                existing_permission.can_edit = "edit" in permissions
            else:
                new_permission = UserPermission(
                    user_id=user_id,
                    resource_type="chart",
                    resource_id=resource_id,
                    can_read="read" in permissions,
                    can_edit="edit" in permissions,
                )
                db.session.add(new_permission)

        # 更新 RolePermission 表
        for role_permission in role_permissions:
            role_id = role_permission["roleId"]
            permissions = role_permission["permissions"]
            existing_permission = (
                db.session.query(RolePermission)
                .filter_by(resource_id=resource_id, resource_type="chart",
                           role_id=role_id)
                .first()
            )
            if existing_permission:
                existing_permission.can_read = "read" in permissions
                existing_permission.can_edit = "edit" in permissions
            else:
                new_permission = RolePermission(
                    role_id=role_id,
                    resource_type="chart",
                    resource_id=resource_id,
                    can_read="read" in permissions,
                    can_edit="edit" in permissions,
                )
                db.session.add(new_permission)

        db.session.commit()

    @staticmethod
    def get_chart_access_info(chart_id: int) -> list[dict]:
        """
        获取指定 chart 的访问权限信息，返回指定格式的结果。
        """
        try:
            # 用户权限查询
            user_permissions_query = (
                db.session.query(
                    literal_column("'user'").label("type"),
                    User.id.label("id"),
                    User.username.label("name"),
                    UserPermission.can_read,
                    UserPermission.can_edit,
                    UserPermission.can_add,
                    UserPermission.can_delete,
                )
                .join(User, UserPermission.user_id == User.id)
                .filter(UserPermission.resource_type == "chart")
                .filter(UserPermission.resource_id == chart_id)
            )

            # 角色权限查询
            role_permissions_query = (
                db.session.query(
                    literal_column("'role'").label("type"),
                    Role.id.label("id"),
                    Role.name.label("name"),
                    RolePermission.can_read,
                    RolePermission.can_edit,
                    RolePermission.can_add,
                    RolePermission.can_delete,
                )
                .join(Role, RolePermission.role_id == Role.id)
                .filter(RolePermission.resource_type == "chart")
                .filter(RolePermission.resource_id == chart_id)
            )

            # 合并查询结果
            results = user_permissions_query.union_all(role_permissions_query).all()

            # 检查查询结果是否为空
            if not results:
                return []

            # 构建返回结果
            access_info = []
            for row in results:
                # 根据权限布尔值正确映射权限标签
                if (
                    row.can_read
                    and row.can_edit
                    and row.can_add
                    and row.can_delete
                ):
                    permission = "可管理"
                elif (
                    row.can_read
                    and row.can_edit
                ):
                    permission = "可编辑"
                elif row.can_read:
                    permission = "可阅读"
                else:
                    permission = "无权限"  # 默认无权限

                access_info.append(
                    {
                        "id": row.id,
                        "name": row.name,
                        "type": row.type,
                        "permission": permission,
                    }
                )

            return access_info

        except Exception as ex:
            logger.error(f"Error in get_chart_access_info: {ex}", exc_info=True)
            raise

    @staticmethod
    def is_collaborator_exist(chart_id: int, collaborator_id: int,
                              collaborator_type: str) -> bool:
        """
        检查协作者是否已经存在于 user_permissions 或 role_permissions 表中。

        :param chart_id: 图表 ID
        :param collaborator_id: 协作者 ID
        :param collaborator_type: 协作者类型 ('user' 或 'role')
        :return: 如果存在则返回 True，否则返回 False
        """
        if collaborator_type == "user":
            exists = (
                db.session.query(UserPermission)
                .filter(
                    UserPermission.resource_type == "chart",
                    UserPermission.resource_id == chart_id,
                    UserPermission.user_id == collaborator_id,
                )
                .first()
            )
        elif collaborator_type == "role":
            exists = (
                db.session.query(RolePermission)
                .filter(
                    RolePermission.resource_type == "chart",
                    RolePermission.resource_id == chart_id,
                    RolePermission.role_id == collaborator_id,
                )
                .first()
            )
        else:
            raise ValueError("Invalid collaborator_type. Must be 'user' or 'role'.")

        return exists is not None

    @staticmethod
    def add_collaborator(chart_id: int, collaborator_id: int,
                         collaborator_type: str) -> None:
        """
        添加协作者到 user_permissions 或 role_permissions 表中。

        :param chart_id: 图表 ID
        :param collaborator_id: 协作者 ID
        :param collaborator_type: 协作者类型 ('user' 或 'role')
        """
        try:
            if collaborator_type == "user":
                new_permission = UserPermission(
                    resource_type="chart",
                    resource_id=chart_id,
                    user_id=collaborator_id,
                    can_read=True,  # 默认权限
                    can_edit=False,
                    can_delete=False,
                    can_add=False,
                )
                db.session.add(new_permission)
            elif collaborator_type == "role":
                new_permission = RolePermission(
                    resource_type="chart",
                    resource_id=chart_id,
                    role_id=collaborator_id,
                    can_read=True,  # 默认权限
                    can_edit=False,
                    can_delete=False,
                    can_add=False,
                )
                db.session.add(new_permission)
            else:
                raise ValueError("Invalid collaborator_type. Must be 'user' or 'role'.")

            db.session.commit()
            logger.info(
                f"Successfully added collaborator: chart_id={chart_id}, collaborator_id={collaborator_id}, collaborator_type={collaborator_type}")
        except Exception as ex:
            db.session.rollback()  # 确保事务回滚
            logger.error(f"Error adding collaborator: {ex}")
            raise

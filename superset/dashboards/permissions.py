import logging
from typing import Any, Optional, List, Dict

from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime

from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.models.dashboard import Dashboard
from superset.tasks.utils import get_current_user_object
from superset.extensions import db
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder.security.sqla.models import User, Role

logger = logging.getLogger(__name__)


class DashboardPermissions:
    datamodel = SQLAInterface(Dashboard)  # 创建 datamodel 实例

    @staticmethod
    def set_default_permissions(
        dashboard: Dashboard,
        user: User,
        roles: List[Role] = None,
        permissions: List[str] = None,
    ) -> None:
        """
        设置仪表盘的默认权限。
        """
        roles = roles or []  # 如果没有传入角色，默认使用空列表
        permissions = permissions or ["can_read", "can_edit"]  # 默认权限

        try:
            # 为用户分配权限
            DashboardPermissions.add_permissions_to_user(dashboard.id, user.id, permissions)

            # 为每个角色分配权限
            for role in roles:
                DashboardPermissions.add_permissions_to_role(dashboard.id, role.id, permissions)
        except Exception as ex:
            logger.error(f"Error setting default permissions for dashboard {dashboard.id}: {ex}")
            raise

    @staticmethod
    def has_permission(dashboard_id: int, user: User, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限（同时检查用户和角色权限）。

        :param dashboard_id: 仪表盘 ID
        :param user: 当前用户对象
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 是否有权限
        """
        # 映射权限类型到具体字段
        permission_map = {
            'read': 'can_read',
            'edit': 'can_edit',
            'delete': 'can_delete',
            'add': 'can_add',
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 调用 get_permissions 以获取用户和角色的权限
        permissions = DashboardPermissions.get_permissions(dashboard_id, permission_map[permission_type])

        # 检查用户是否有权限
        user_has_permission = any(
            perm["user_id"] == user.id for perm in permissions["user_permissions"]
        )

        # 检查用户角色是否有权限
        role_has_permission = any(
            role.id in [perm["role_id"] for perm in permissions["role_permissions"]]
            for role in user.roles
        )

        return user_has_permission or role_has_permission

    @staticmethod
    def get_permissions(dashboard_id: int, permission_type: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        获取仪表盘的所有权限（包括用户和角色）。

        :param dashboard_id: 仪表盘 ID
        :param permission_type: 权限类型 ('can_read', 'can_edit', 'can_delete', 'can_add')
        :return: 包含用户和角色权限的字典
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        if permission_type not in valid_permissions:
            raise ValueError(f"Invalid permission type: {permission_type}")

        # 获取用户权限
        user_permissions = (
            db.session.query(UserPermission)
            .filter_by(
                resource_type="dashboard",
                resource_id=dashboard_id,
                **{permission_type: True},  # 动态查询指定的权限类型
            )
            .all()
        )

        # 获取角色权限
        role_permissions = (
            db.session.query(RolePermission)
            .filter_by(
                resource_type="dashboard",
                resource_id=dashboard_id,
                **{permission_type: True},  # 动态查询指定的权限类型
            )
            .all()
        )

        # 获取用户和角色的名称
        user_ids = [perm.user_id for perm in user_permissions]
        role_ids = [perm.role_id for perm in role_permissions]

        users = db.session.query(User).filter(User.id.in_(user_ids)).all()
        roles = db.session.query(Role).filter(Role.id.in_(role_ids)).all()

        user_map = {user.id: f"{user.first_name} {user.last_name}" for user in users}
        role_map = {role.id: role.name for role in roles}

        # 构建返回格式，包含用户和角色的名称
        return {
            "user_permissions": [
                {
                    "user_id": perm.user_id,
                    "user_name": user_map.get(perm.user_id, f"User {perm.user_id}"),
                    "permission_type": permission_type,
                }
                for perm in user_permissions
            ],
            "role_permissions": [
                {
                    "role_id": perm.role_id,
                    "role_name": role_map.get(perm.role_id, f"Role {perm.role_id}"),
                    "permission_type": permission_type,
                }
                for perm in role_permissions
            ],
        }

    @staticmethod
    def check_permission(dashboard: Dashboard, user: User, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限。

        :param dashboard: 仪表盘对象
        :param user: 当前用户对象
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 是否有权限
        """
        permission_map = {
            'read': 'can_read',
            'edit': 'can_edit',
            'delete': 'can_delete',
            'add': 'can_add',
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取用户权限
        user_permissions = (
            db.session.query(UserPermission)
            .filter_by(
                user_id=user.id,
                resource_type="dashboard",
                resource_id=dashboard.id,
            )
            .first()
        )

        if user_permissions and getattr(user_permissions, permission_map[permission_type]):
            return True

        # 获取角色权限
        role_permissions = (
            db.session.query(RolePermission)
            .filter(
                RolePermission.resource_type == "dashboard",
                RolePermission.resource_id == dashboard.id,
                RolePermission.role_id.in_([role.id for role in user.roles]),
                getattr(RolePermission, permission_map[permission_type]) == True,
                )
            .all()
        )

        return bool(role_permissions)

    @staticmethod
    def get_dashboard_and_check_permission(pk: int, permission_type: str) -> Optional[Dashboard]:
        """
        获取仪表盘并检查用户权限。

        :param pk: 仪表盘主键
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 仪表盘对象，如果没有权限则返回 None
        """
        dashboard = DashboardPermissions.datamodel.get(pk)
        if not dashboard:
            logger.warning("Dashboard with ID %s not found.", pk)
            return None

        user = get_current_user_object()
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return None

        if not DashboardPermissions.check_permission(dashboard, user, permission_type):
            logger.warning(
                f"User {user.username} does not have {permission_type} permission for "
                f"dashboard {pk}."
            )
            return None

        return dashboard

    @staticmethod
    def _add_permissions(
        dashboard_id: int, entity_id: int, permissions: List[str], entity_type: str
    ) -> None:
        """
        通用方法，为用户或角色添加权限。

        :param dashboard_id: 仪表盘 ID
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表
        :param entity_type: 实体类型 ('user' 或 'role')
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]
        invalid_permissions = [perm for perm in permissions if perm not in valid_permissions]
        if invalid_permissions:
            raise ValueError(f"Invalid permissions: {', '.join(invalid_permissions)}")

        permission_model = UserPermission if entity_type == "user" else RolePermission

        try:
            existing_permission = db.session.query(permission_model).filter_by(
                resource_type="dashboard",
                resource_id=dashboard_id,
                **{f"{entity_type}_id": entity_id},
            ).first()

            if not existing_permission:
                permission_data = {perm: True for perm in permissions}
                permission = permission_model(
                    resource_type="dashboard",
                    resource_id=dashboard_id,
                    **{f"{entity_type}_id": entity_id},
                    **permission_data,
                )
                db.session.add(permission)
            else:
                for perm in permissions:
                    setattr(existing_permission, perm, True)

            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(
                f"Failed to add permissions {permissions} to {entity_type} {entity_id} for dashboard {dashboard_id}: {ex}"
            )
            raise

    @staticmethod
    def add_permissions_to_user(dashboard_id: int, user_id: int, permissions: List[str]) -> None:
        """
        为用户添加权限，使用通用方法。
        """
        DashboardPermissions._add_permissions(dashboard_id, user_id, permissions, "user")

    @staticmethod
    def add_permissions_to_role(dashboard_id: int, role_id: int, permissions: List[str]) -> None:
        """
        为角色添加权限，使用通用方法。
        """
        DashboardPermissions._add_permissions(dashboard_id, role_id, permissions, "role")

    @staticmethod
    def _remove_permissions(
        dashboard_id: int, entity_id: int, permissions: List[str], entity_type: str
    ) -> None:
        """
        通用方法，从用户或角色移除多个权限。

        :param dashboard_id: 仪表盘 ID
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        :param entity_type: 实体类型 ('user' 或 'role')
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        invalid_permissions = [permission for permission in permissions if permission not in valid_permissions]
        if invalid_permissions:
            raise ValueError(f"Invalid permission(s): {', '.join(invalid_permissions)}")

        permission_model = UserPermission if entity_type == "user" else RolePermission

        try:
            # 查找权限记录
            existing_permission = db.session.query(permission_model).filter_by(
                resource_type="dashboard",
                resource_id=dashboard_id,
                **{f"{entity_type}_id": entity_id},
            ).first()

            if existing_permission:
                # 移除指定的权限
                for permission in permissions:
                    setattr(existing_permission, permission, False)

                # 如果所有权限都被移除，则删除该记录
                if not (
                    existing_permission.can_read
                    or existing_permission.can_edit
                    or existing_permission.can_delete
                    or existing_permission.can_add
                ):
                    db.session.delete(existing_permission)

                db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(
                f"Failed to remove permissions {permissions} from {entity_type} {entity_id} for dashboard {dashboard_id}: {ex}"
            )
            raise

    @staticmethod
    def remove_permissions_to_user(dashboard_id: int, user_id: int, permissions: List[str]) -> None:
        """
        从指定用户移除多个权限。

        :param dashboard_id: 仪表盘 ID
        :param user_id: 用户 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        DashboardPermissions._remove_permissions(dashboard_id, user_id, permissions, "user")

    @staticmethod
    def remove_permissions_to_role(dashboard_id: int, role_id: int, permissions: List[str]) -> None:
        """
        从指定角色移除多个权限。

        :param dashboard_id: 仪表盘 ID
        :param role_id: 角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        DashboardPermissions._remove_permissions(dashboard_id, role_id, permissions, "role")

    @staticmethod
    def get_allowed_dashboard_ids(user: User, permission_type: str) -> List[int]:
        """
        获取用户有指定权限的所有仪表盘 ID 列表。

        :param user: 当前用户
        :param permission_type: 动态指定权限类型（'read', 'edit', 'delete', 'add'）
        :return: 用户有权限的仪表盘 ID 列表
        """
        permission_map = {
            "read": "can_read",
            "edit": "can_edit",
            "delete": "can_delete",
            "add": "can_add",
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取用户直接权限的仪表盘 ID
        user_dashboard_ids = [
            perm.resource_id
            for perm in db.session.query(UserPermission).filter_by(
                user_id=user.id,
                resource_type="dashboard",
                **{permission_map[permission_type]: True},
            ).all()
        ]

        # 获取用户角色权限的仪表盘 ID
        user_roles = [role.id for role in user.roles]
        role_dashboard_ids = [
            perm.resource_id
            for perm in db.session.query(RolePermission).filter(
                RolePermission.role_id.in_(user_roles),
                RolePermission.resource_type == "dashboard",
                getattr(RolePermission, permission_map[permission_type]) == True,
                ).all()
        ]

        # 合并去重
        return list(set(user_dashboard_ids + role_dashboard_ids))

    @staticmethod
    def get_user_permissions(user_id: int, permission_type: str) -> List[int]:
        """
        获取指定用户有指定权限类型的所有仪表盘 ID 列表。

        :param user_id: 用户 ID
        :param permission_type: 权限类型 ('read', 'edit', 'delete', 'add')
        :return: 用户有权限的仪表盘 ID 列表
        """
        permission_map = {
            "read": "can_read",
            "edit": "can_edit",
            "delete": "can_delete",
            "add": "can_add",
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取用户的仪表盘权限
        user_permissions = [
            perm.resource_id
            for perm in db.session.query(UserPermission).filter_by(
                user_id=user_id,
                resource_type="dashboard",
                **{permission_map[permission_type]: True},
            ).all()
        ]
        return user_permissions

    @staticmethod
    def get_role_permissions(roles: List[Role], permission_type: str) -> List[int]:
        """
        获取指定角色有指定权限类型的所有仪表盘 ID 列表。

        :param roles: 角色列表
        :param permission_type: 权限类型 ('read', 'edit', 'delete', 'add')
        :return: 角色有权限的仪表盘 ID 列表
        """
        permission_map = {
            "read": "can_read",
            "edit": "can_edit",
            "delete": "can_delete",
            "add": "can_add",
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取角色的仪表盘权限
        role_ids = [role.id for role in roles]
        role_permissions = [
            perm.resource_id
            for perm in db.session.query(RolePermission).filter(
                RolePermission.role_id.in_(role_ids),
                RolePermission.resource_type == "dashboard",
                getattr(RolePermission, permission_map[permission_type]) == True,
                ).all()
        ]
        return role_permissions

    @staticmethod
    def create_dashboard_with_permissions(item: dict[str, Any], user: User, roles: List[Role]) -> Dashboard:
        """
        创建仪表盘并为其分配默认权限。

        :param item: 仪表盘数据
        :param user: 当前用户对象
        :param roles: 当前用户的角色列表
        :return: 创建的仪表盘对象
        """
        try:
            from superset.commands.dashboard.create import CreateDashboardCommand  # 确保正确导入
            new_dashboard = CreateDashboardCommand(item).run()
            DashboardPermissions.set_default_permissions(dashboard=new_dashboard, user=user, roles=roles)
            db.session.commit()  # 提交事务
            return new_dashboard
        except Exception as ex:
            logger.error(f"Error creating dashboard with permissions: {ex}", exc_info=True)
            db.session.rollback()
            raise

    @staticmethod
    def update_dashboard_with_permissions(
        pk: int,
        item: dict[str, Any],
        user: User,
        roles: List[Role]
    ) -> Dashboard:
        """
        更新仪表盘并处理权限。

        :param pk: 仪表盘主键
        :param item: 更新数据
        :param user: 当前用户对象
        :param roles: 当前用户的角色列表
        :return: 更新后的仪表盘对象
        """
        try:
            from superset.commands.dashboard.update import UpdateDashboardCommand  # 确保正确导入
            updated_dashboard = UpdateDashboardCommand(pk, item).run()

            # 处理权限更新
            DashboardPermissions.handle_permissions_update(
                dashboard_id=updated_dashboard.id,
                permissions_data=item
            )

            db.session.commit()  # 提交事务
            return updated_dashboard
        except Exception as ex:
            logger.error(f"Error updating dashboard with permissions: {ex}", exc_info=True)
            db.session.rollback()
            raise

    @staticmethod
    def handle_permissions_update(dashboard_id: int, permissions_data: dict[str, Any]) -> None:
        """
        根据传入的数据更新仪表盘的用户和角色权限。

        :param dashboard_id: 仪表盘 ID
        :param permissions_data: 包含权限信息的数据字典
        """
        try:
            user_permissions = permissions_data.get("user_permissions")
            role_permissions = permissions_data.get("role_permissions")

            if user_permissions:
                for user_perm in user_permissions:
                    user_id = user_perm.get("user_id")
                    permissions = user_perm.get("permissions", [])
                    if user_id:
                        DashboardPermissions.add_permissions_to_user(dashboard_id, user_id, permissions)

            if role_permissions:
                for role_perm in role_permissions:
                    role_id = role_perm.get("role_id")
                    permissions = role_perm.get("permissions", [])
                    if role_id:
                        DashboardPermissions.add_permissions_to_role(dashboard_id, role_id, permissions)
        except Exception as ex:
            logger.error(f"Error handling permissions update for dashboard {dashboard_id}: {ex}", exc_info=True)
            raise

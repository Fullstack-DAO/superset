import logging

from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object
from superset.extensions import db
from flask_appbuilder.models.sqla.interface import SQLAInterface

logger = logging.getLogger(__name__)


class ChartPermissions:
    datamodel = SQLAInterface(Slice)  # 创建 datamodel 实例

    @staticmethod
    def set_default_permissions(chart: Slice, user) -> None:
        """
        为新创建的图表设置默认权限。
        当前用户默认获得 can_read 和 can_edit 权限。
        """
        if not user:
            raise ValueError("User cannot be None when setting default permissions.")

        try:
            # 添加用户权限
            user_permission = UserPermission(
                resource_type="chart",
                resource_id=chart.id,  # 使用传递的 chart 对象的 ID
                user_id=user.id,
                can_read=True,
                can_edit=True,
                can_add=True,
            )
            db.session.add(user_permission)

            # 可选：为默认角色（如 Admin）添加权限
            admin_role = db.session.query(db.role_model).filter_by(name="Admin").first()
            if admin_role:
                role_permission = RolePermission(
                    resource_type="chart",
                    resource_id=chart.id,  # 使用传递的 chart 对象的 ID
                    role_id=admin_role.id,
                    can_read=True,
                    can_edit=True,
                    can_add=True,
                )
                db.session.add(role_permission)

            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error(f"Failed to set default permissions: {str(ex)}")
            raise

    @staticmethod
    def has_permission(chart_id: int, user, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限（同时检查用户和角色权限）。

        :param chart_id: 图表 ID
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
        permissions = ChartPermissions.get_permissions(chart_id,
                                                       permission_map[permission_type])

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
    def get_permissions(chart_id: int, permission_type: str) -> dict:
        """
        获取图表的所有权限（包括用户和角色），支持动态权限类型。

        :param chart_id: 图表 ID
        :param permission_type: 权限类型 ('can_read', 'can_edit', 'can_delete')
        :return: 包含用户和角色权限的字典，结构更易读。
        """
        if permission_type not in ["can_read", "can_edit", "can_delete", "can_add"]:
            raise ValueError(f"Invalid permission type: {permission_type}")

        # 获取用户权限
        user_permissions = (
            db.session.query(UserPermission, db.user_model)
            .join(db.user_model, UserPermission.user_id == db.user_model.id)
            .filter(
                UserPermission.resource_type == "chart",
                UserPermission.resource_id == chart_id,
                getattr(UserPermission, permission_type) == True,
            )
            .all()
        )

        # 获取角色权限
        role_permissions = (
            db.session.query(RolePermission, db.role_model)
            .join(db.role_model, RolePermission.role_id == db.role_model.id)
            .filter(
                RolePermission.resource_type == "chart",
                RolePermission.resource_id == chart_id,
                getattr(RolePermission, permission_type) == True,
            )
            .all()
        )

        # 构建更易理解的返回格式
        return {
            "user_permissions": [
                {
                    "user_id": user.id,
                    "user_name": f"{user.first_name} {user.last_name}".strip(),
                    # 获取用户全名
                    "permission_type": permission_type,
                }
                for _, user in user_permissions
            ],
            "role_permissions": [
                {
                    "role_id": role.id,
                    "role_name": role.name,  # 获取角色名称
                    "permission_type": permission_type,
                }
                for _, role in role_permissions
            ],
        }

    @staticmethod
    def check_permission(chart: Slice, user, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限。

        :param chart: 图表对象
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
                resource_type="chart",
                resource_id=chart.id,
            )
            .first()
        )

        if user_permissions and getattr(user_permissions,
                                        permission_map[permission_type]):
            return True

        # 获取角色权限
        role_permissions = (
            db.session.query(RolePermission)
            .filter(
                RolePermission.resource_type == "chart",
                RolePermission.resource_id == chart.id,
                RolePermission.role_id.in_([role.id for role in user.roles]),
                getattr(RolePermission, permission_map[permission_type]) == True,
            )
            .all()
        )

        return bool(role_permissions)

    @staticmethod
    def get_chart_and_check_permission(pk: int, permission_type: str) -> Slice | None:
        """
        获取图表并检查用户权限。

        :param pk: 图表主键
        :param permission_type: 权限类型 ('read', 'edit', 'delete')
        :return: 图表对象，如果没有权限则返回 None
        """
        chart = ChartPermissions.datamodel.get(pk)
        if not chart:
            logger.warning("Chart with ID %s not found.", pk)
            return None

        user = get_current_user_object()
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return None

        if not ChartPermissions.check_permission(chart.id, user, permission_type):
            logger.warning(
                f"User {user.username} does not have {permission_type} permission for "
                f"chart {pk}."
            )
            return None

        return chart

    @staticmethod
    def add_permissions_to_user(chart_id: int, user_id: int,
                                permissions: list[str]) -> None:
        """
        为指定用户添加多个权限。

        :param chart_id: 图表 ID
        :param user_id: 用户 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        for permission in permissions:
            if permission not in valid_permissions:
                raise ValueError(f"Invalid permission type: {permission}")

        try:
            # 检查是否已有权限记录
            existing_permission = db.session.query(UserPermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
            ).first()

            if not existing_permission:
                # 创建新的用户权限记录
                permission_data = {permission: True for permission in permissions}
                permission = UserPermission(
                    resource_type="chart",
                    resource_id=chart_id,
                    user_id=user_id,
                    **permission_data,
                )
                db.session.add(permission)
            else:
                # 更新已有的权限记录
                for permission in permissions:
                    setattr(existing_permission, permission, True)

            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error(
                f"Failed to add permissions {permissions} to user {user_id} for chart {chart_id}: {ex}")
            raise

    @staticmethod
    def add_permissions_to_role(chart_id: int, role_id: int,
                                permissions: list[str]) -> None:
        """
        为指定角色添加多个权限。

        :param chart_id: 图表 ID
        :param role_id: 角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        for permission in permissions:
            if permission not in valid_permissions:
                raise ValueError(f"Invalid permission type: {permission}")

        try:
            # 检查是否已有权限记录
            existing_permission = db.session.query(RolePermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
            ).first()

            if not existing_permission:
                # 创建新的角色权限记录
                permission_data = {permission: True for permission in permissions}
                permission = RolePermission(
                    resource_type="chart",
                    resource_id=chart_id,
                    role_id=role_id,
                    **permission_data,
                )
                db.session.add(permission)
            else:
                # 更新已有的权限记录
                for permission in permissions:
                    setattr(existing_permission, permission, True)

            db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error(
                f"Failed to add permissions {permissions} to role {role_id} for chart {chart_id}: {ex}")
            raise

    @staticmethod
    def remove_permissions_to_user(chart_id: int, user_id: int,
                                   permissions: list[str]) -> None:
        """
        从指定用户移除多个权限。

        :param chart_id: 图表 ID
        :param user_id: 用户 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        for permission in permissions:
            if permission not in valid_permissions:
                raise ValueError(f"Invalid permission type: {permission}")

        try:
            # 查找权限记录
            existing_permission = db.session.query(UserPermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                user_id=user_id,
            ).first()

            if existing_permission:
                # 移除指定的权限
                for permission in permissions:
                    setattr(existing_permission, permission, False)

                # 如果所有权限都被移除，则删除该记录
                if not (
                    existing_permission.can_read or existing_permission.can_edit or
                    existing_permission.can_delete or existing_permission.can_add):
                    db.session.delete(existing_permission)

                db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error(
                f"Failed to remove permissions {permissions} from user {user_id} for chart {chart_id}: {ex}")
            raise

    @staticmethod
    def remove_permissions_to_role(chart_id: int, role_id: int,
                                   permissions: list[str]) -> None:
        """
        从指定角色移除多个权限。

        :param chart_id: 图表 ID
        :param role_id: 角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        for permission in permissions:
            if permission not in valid_permissions:
                raise ValueError(f"Invalid permission type: {permission}")

        try:
            # 查找权限记录
            existing_permission = db.session.query(RolePermission).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                role_id=role_id,
            ).first()

            if existing_permission:
                # 移除指定的权限
                for permission in permissions:
                    setattr(existing_permission, permission, False)

                # 如果所有权限都被移除，则删除该记录
                if not (
                    existing_permission.can_read or existing_permission.can_edit or
                    existing_permission.can_delete or existing_permission.can_add):
                    db.session.delete(existing_permission)

                db.session.commit()
        except Exception as ex:
            db.session.rollback()
            logger.error(
                f"Failed to remove permissions {permissions} from role {role_id} for chart {chart_id}: {ex}")
            raise

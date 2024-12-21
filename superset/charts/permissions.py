import logging

from sqlalchemy.exc import SQLAlchemyError

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
    def set_default_permissions(
        chart: Slice,
        user,
        roles: list[str] = None,
        permissions: list[str] = None,
    ) -> None:
        """
        为新创建的图表设置默认权限。
        支持为用户和指定角色动态分配权限。

        :param chart: 图表对象
        :param user: 当前用户
        :param roles: 需要分配权限的角色名称列表，例如 ["Admin", "Editor"]
        :param permissions: 要分配的权限列表，例如 ["can_read", "can_edit"]
                           默认为 ["can_read", "can_edit"]
        """
        if not user:
            raise ValueError("User cannot be None when setting default permissions.")

        # 如果未指定权限，默认为 can_read 和 can_edit
        if permissions is None:
            permissions = ["can_read", "can_edit"]

        # 如果未指定角色，默认为 Admin
        if roles is None:
            roles = ["Admin"]

        try:
            # 初始化用户权限
            user_permission = UserPermission(
                resource_type="chart",
                resource_id=chart.id,
                user_id=user.id,
                can_read="can_read" in permissions,
                can_edit="can_edit" in permissions,
                can_add="can_add" in permissions,
                can_delete="can_delete" in permissions,
            )
            db.session.add(user_permission)

            # 为指定角色分配权限
            role_objects = db.session.query(db.role_model).filter(
                db.role_model.name.in_(roles)
            ).all()

            for role in role_objects:
                role_permission = RolePermission(
                    resource_type="chart",
                    resource_id=chart.id,
                    role_id=role.id,
                    can_read="can_read" in permissions,
                    can_edit="can_edit" in permissions,
                    can_add="can_add" in permissions,
                    can_delete="can_delete" in permissions,
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
        获取图表的所有权限（包括用户和角色）。

        :param chart_id: 图表 ID
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
                resource_type="chart",
                resource_id=chart_id,
                **{permission_type: True},  # 动态查询指定的权限类型
            )
            .all()
        )

        # 获取角色权限
        role_permissions = (
            db.session.query(RolePermission)
            .filter_by(
                resource_type="chart",
                resource_id=chart_id,
                **{permission_type: True},  # 动态查询指定的权限类型
            )
            .all()
        )

        # 构建返回格式
        return {
            "user_permissions": [
                {
                    "user_id": perm.user_id,
                    "permission_type": permission_type,
                }
                for perm in user_permissions
            ],
            "role_permissions": [
                {
                    "role_id": perm.role_id,
                    "permission_type": permission_type,
                }
                for perm in role_permissions
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
    def _add_permissions(
        chart_id: int, entity_id: int, permissions: list[str], entity_type: str
    ) -> None:
        """
        通用方法，为用户或角色添加权限。

        :param chart_id: 图表 ID
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表
        :param entity_type: 实体类型 ('user' 或 'role')
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]
        invalid_permissions = [perm for perm in permissions if
                               perm not in valid_permissions]
        if invalid_permissions:
            raise ValueError(f"Invalid permissions: {', '.join(invalid_permissions)}")

        permission_model = UserPermission if entity_type == "user" else RolePermission

        try:
            existing_permission = db.session.query(permission_model).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                **{f"{entity_type}_id": entity_id},
            ).first()

            if not existing_permission:
                permission_data = {perm: True for perm in permissions}
                permission = permission_model(
                    resource_type="chart",
                    resource_id=chart_id,
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
                f"Failed to add permissions {permissions} to {entity_type} {entity_id} for chart {chart_id}: {ex}"
            )
            raise

    @staticmethod
    def add_permissions_to_user(chart_id: int, user_id: int, permissions: list[str]) -> None:
        """
        为用户添加权限，使用通用方法。
        """
        ChartPermissions._add_permissions(chart_id, user_id, permissions, "user")

    @staticmethod
    def add_permissions_to_role(chart_id: int, role_id: int, permissions: list[str]) -> None:
        """
        为角色添加权限，使用通用方法。
        """
        ChartPermissions._add_permissions(chart_id, role_id, permissions, "role")

    @staticmethod
    def _remove_permissions(
        chart_id: int, entity_id: int, permissions: list[str], entity_type: str
    ) -> None:
        """
        通用方法，从用户或角色移除多个权限。

        :param chart_id: 图表 ID
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        :param entity_type: 实体类型 ('user' 或 'role')
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]

        # 验证权限类型是否合法
        invalid_permissions = [permission for permission in permissions if
                               permission not in valid_permissions]
        if invalid_permissions:
            raise ValueError(f"Invalid permission(s): {', '.join(invalid_permissions)}")

        permission_model = UserPermission if entity_type == "user" else RolePermission

        try:
            # 查找权限记录
            existing_permission = db.session.query(permission_model).filter_by(
                resource_type="chart",
                resource_id=chart_id,
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
        except Exception as ex:
            db.session.rollback()
            logger.error(
                f"Failed to remove permissions {permissions} from {entity_type} {entity_id} for chart {chart_id}: {ex}"
            )
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
        ChartPermissions._remove_permissions(chart_id, user_id, permissions, "user")

    @staticmethod
    def remove_permissions_to_role(chart_id: int, role_id: int,
                                   permissions: list[str]) -> None:
        """
        从指定角色移除多个权限。

        :param chart_id: 图表 ID
        :param role_id: 角色 ID
        :param permissions: 权限列表，例如 ['can_read', 'can_edit']
        """
        ChartPermissions._remove_permissions(chart_id, role_id, permissions, "role")

    @staticmethod
    def get_allowed_chart_ids(user, permission_type: str) -> list[int]:
        """
        获取用户有指定权限的所有图表 ID 列表。

        :param user: 当前用户
        :param permission_type: 动态指定权限类型（'read', 'edit', 'delete', 'add'）
        :return: 用户有权限的图表 ID 列表
        """
        permission_map = {
            "read": "can_read",
            "edit": "can_edit",
            "delete": "can_delete",
            "add": "can_add",
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取用户直接权限的图表 ID
        user_chart_ids = [
            perm.resource_id
            for perm in db.session.query(UserPermission).filter_by(
                user_id=user.id,
                resource_type="chart",
                **{permission_map[permission_type]: True},
            ).all()
        ]

        # 获取用户角色权限的图表 ID
        user_roles = [role.id for role in user.roles]
        role_chart_ids = [
            perm.resource_id
            for perm in db.session.query(RolePermission).filter(
                RolePermission.role_id.in_(user_roles),
                RolePermission.resource_type == "chart",
                getattr(RolePermission, permission_map[permission_type]) == True,
            ).all()
        ]

        # 合并去重
        return list(set(user_chart_ids + role_chart_ids))

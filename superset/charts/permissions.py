import logging
from typing import Optional, Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from superset.connectors.sqla.models import SqlaTable
from superset.commands.dataset.exceptions import DatasetAccessDeniedError
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object
from superset.extensions import db, security_manager
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder.security.sqla.models import User, Role

from superset.utils.core import get_user_id

logger = logging.getLogger(__name__)


def get_current_user_role_id():
    user = get_current_user_object()  # 获取当前登录的用户
    if user and user.roles:
        # 如果用户有角色，假设只有一个角色
        role_id = user.roles[0].id  # 获取第一个角色的 ID
        return role_id
    return None  # 如果没有角色，返回 None


class ChartPermissions:
    datamodel = SQLAInterface(Slice)  # 创建 datamodel 实例

    @staticmethod
    def set_default_permissions(
        chart: Slice,
        user: User,
        roles: list[Role] = None,
        permissions: list[str] = None,
        datasource_id: int = None,
        is_creator: bool = False,  # 默认值设为 False
    ) -> None:
        """
        设置图表的默认权限，并插入 datasource_id。
        """
        roles = roles or []  # 如果没有传入角色，默认使用空列表
        permissions = permissions or ["can_read", "can_edit"]  # 默认权限

        # 如果没有传入 datasource_id，使用 chart 中的 datasource_id
        datasource_id = datasource_id or chart.datasource_id

        try:
            # 为用户分配权限，并传递 is_creator 参数
            ChartPermissions.add_permissions_to_user(
                chart_id=chart.id,
                user_id=user.id,
                permissions=permissions,
                datasource_id=datasource_id,
                is_creator=is_creator  # 传递 is_creator 参数
            )

            # 为每个角色分配权限
            for role in roles:
                ChartPermissions.add_permissions_to_role(
                    chart_id=chart.id,
                    role_id=role.id,
                    permissions=permissions,
                    datasource_id=datasource_id
                )
        except Exception as ex:
            logger.error(
                f"Error setting default permissions for chart {chart.id}: {ex}"
            )
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
    def check_permission(chart: Slice, user: User, permission_type: str) -> bool:
        """
        检查用户是否有某种类型的权限。

        :param chart: 图表对象
        :param user: 当前用户对象
        :param permission_type: 权限类型 ('read', 'edit', 'delete', 'add')
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

        perm_field = permission_map[permission_type]

        # 检查用户自身权限
        user_has_permission = (
            db.session.query(UserPermission)
            .filter_by(
                user_id=user.id,
                resource_type="chart",
                resource_id=chart.id,
            )
            .filter(getattr(UserPermission, perm_field) == True)
            .first()
        )
        if user_has_permission:
            return True

        # 检查用户角色权限
        roles_ids = [role.id for role in user.roles]
        role_has_permission = (
            db.session.query(RolePermission)
            .filter(
                RolePermission.resource_type == "chart",
                RolePermission.resource_id == chart.id,
                RolePermission.role_id.in_(roles_ids),
                getattr(RolePermission, perm_field) == True,
            )
            .first()
        )
        return role_has_permission is not None

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
        chart_id: int,
        entity_id: int,
        permissions: list[str],
        entity_type: str,
        datasource_id: int,
        is_creator: bool = False  # 添加 is_creator 参数，默认为 False
    ) -> None:
        """
        通用方法，为用户或角色添加权限，并插入或更新数据时包含 datasource_id 和 is_creator。

        :param chart_id: 图表 ID
        :param entity_id: 用户或角色 ID
        :param permissions: 权限列表
        :param entity_type: 实体类型 ('user' 或 'role')
        :param datasource_id: 数据源 ID
        :param is_creator: 是否为创建者，仅对用户有效
        """
        valid_permissions = ["can_read", "can_edit", "can_delete", "can_add"]
        invalid_permissions = [perm for perm in permissions if perm not in
                               valid_permissions]
        if invalid_permissions:
            raise ValueError(f"Invalid permissions: {', '.join(invalid_permissions)}")

        # 根据 entity_type 确定使用哪个模型
        permission_model = UserPermission if entity_type == "user" else RolePermission

        try:
            # 查询是否已存在权限记录，增加 datasource_id 过滤条件
            existing_permission = db.session.query(permission_model).filter_by(
                resource_type="chart",
                resource_id=chart_id,
                datasource_id=datasource_id,  # 过滤条件中加入 datasource_id
                **{f"{entity_type}_id": entity_id},
            ).first()

            if not existing_permission:
                # 如果没有现有权限记录，创建新记录并包含 datasource_id 和 is_creator
                permission_data = {perm: True for perm in permissions}
                if entity_type == "user":
                    permission = permission_model(
                        resource_type="chart",
                        resource_id=chart_id,
                        user_id=entity_id,
                        datasource_id=datasource_id,  # 插入 datasource_id
                        is_creator=is_creator,  # 插入 is_creator
                        **permission_data,
                    )
                else:
                    permission = permission_model(
                        resource_type="chart",
                        resource_id=chart_id,
                        role_id=entity_id,
                        datasource_id=datasource_id,  # 插入 datasource_id
                        **permission_data,
                    )
                db.session.add(permission)
                logger.info(
                    f"Added new permissions {permission_data} to {entity_type} ID "
                    f"{entity_id} for chart ID {chart_id}"
                )
            else:
                # 如果已有权限记录，更新权限
                for perm in permissions:
                    setattr(existing_permission, perm, True)
                if entity_type == "user" and is_creator:
                    existing_permission.is_creator = True  # 更新 is_creator
                logger.info(
                    f"Updated permissions {permissions} for {entity_type} ID {entity_id} on chart ID {chart_id}"
                )
            db.session.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(
                f"Failed to add permissions {permissions} to {entity_type} {entity_id}"
                f" for chart {chart_id}: {ex}"
            )
            raise

    @staticmethod
    def add_permissions_to_user(
        chart_id: int,
        user_id: int,
        permissions: list[str],
        datasource_id: int,
        is_creator: bool = False  # 添加 is_creator 参数
    ) -> None:
        """
        为用户添加权限，使用通用方法，并传入 datasource_id 和 is_creator 标识。
        """
        ChartPermissions._add_permissions(
            chart_id=chart_id,
            entity_id=user_id,
            permissions=permissions,
            entity_type="user",
            datasource_id=datasource_id,
            is_creator=is_creator  # 传递 is_creator 参数
        )

    @staticmethod
    def add_permissions_to_role(chart_id: int, role_id: int, permissions: list[str],
                                datasource_id: int) -> None:
        """
        为角色添加权限，使用通用方法，并传入 datasource_id。
        """
        ChartPermissions._add_permissions(
            chart_id,
            role_id,
            permissions,
            "role",
            datasource_id)

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

    @staticmethod
    def get_user_permissions(user_id: int, permission_type: str) -> list[int]:
        """
        获取指定用户有指定权限类型的所有图表 ID 列表。

        :param user_id: 用户 ID
        :param permission_type: 权限类型 ('read', 'edit', 'delete', 'add')
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

        # 获取用户的图表权限
        user_permissions = [
            perm.resource_id
            for perm in db.session.query(UserPermission).filter_by(
                user_id=user_id,
                resource_type="chart",
                **{permission_map[permission_type]: True},
            ).all()
        ]
        return user_permissions

    @staticmethod
    def get_role_permissions(roles: list[Role], permission_type: str) -> list[int]:
        """
        获取指定角色有指定权限类型的所有图表 ID 列表。

        :param roles: 角色列表
        :param permission_type: 权限类型 ('read', 'edit', 'delete', 'add')
        :return: 角色有权限的图表 ID 列表
        """
        permission_map = {
            "read": "can_read",
            "edit": "can_edit",
            "delete": "can_delete",
            "add": "can_add",
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 获取角色的图表权限
        role_ids = [role.id for role in roles]
        role_permissions = [
            perm.resource_id
            for perm in db.session.query(RolePermission).filter(
                RolePermission.role_id.in_(role_ids),
                RolePermission.resource_type == "chart",
                getattr(RolePermission, permission_map[permission_type]) == True,
            ).all()
        ]
        return role_permissions

    @staticmethod
    def add_user_permission(
        resource_type: str, resource_id: int,
        user_id: int, permissions: list[str],
    ) -> None:
        """
        给指定 user_id 添加对某 chart/dashboard 的权限
        并在添加前可以验证:
          - 当前登录用户是否是此资源的管理员
          - 目标用户是否具备 dataset 访问权限 (如果资源是 chart)
        """
        # 1) 校验当前登录用户是否有权限做此操作
        current_user_id = get_user_id()
        if not ChartPermissions.is_admin_of_resource(
            current_user_id, resource_type, resource_id
        ):
            raise PermissionError(
                f"Current user {current_user_id} is not admin of {resource_type} "
                f"{resource_id}."
            )

        # 如果是 chart，需要验证目标 user 是否有 dataset 权限
        if resource_type == "chart":
            # 找到 chart
            chart = db.session.query(Slice).filter_by(id=resource_id).one_or_none()
            if not chart:
                raise ValueError(f"Chart {resource_id} not found.")
            # 校验 dataset
            if "can_edit" in permissions or "can_delete" in permissions or "can_add" in permissions:
                # 只有在要赋予写/删/add权限时，才需要 dataset 访问权限
                user_obj = security_manager.get_user_by_id(user_id)
                if not ChartPermissions.user_has_dataset_access(
                    user_obj, chart.datasource_id
                ):
                    raise PermissionError(
                        f"User {user_obj.username} lacks dataset access, cannot have "
                        f"write permission on chart."
                    )

        # 2) 在 user_permissions 表里插入或更新权限
        perm = UserPermission.query.filter_by(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if not perm:
            perm = UserPermission(
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            db.session.add(perm)

        # 更新布尔字段
        perm.can_read = "can_read" in permissions or perm.can_read
        perm.can_edit = "can_edit" in permissions or perm.can_edit
        perm.can_delete = "can_delete" in permissions or perm.can_delete
        perm.can_add = "can_add" in permissions or perm.can_add

        db.session.commit()
        logger.info(f"Granted {permissions} on {resource_type} {resource_id} "
                    f"to user {user_id}.")

    @staticmethod
    def remove_user_permission(
        resource_type: str, resource_id: int,
        user_id: int, permissions: list[str],
    ) -> None:
        """
        移除指定用户对资源的指定权限。例如 remove [can_edit]。
        若最终所有布尔字段都变为False，则干脆删除该记录。
        """
        current_user_id = get_user_id()
        # 同样校验当前用户是否有管理员权限
        if not ChartPermissions.is_admin_of_resource(
            current_user_id, resource_type, resource_id
        ):
            raise PermissionError(
                f"Current user {current_user_id} is not admin of {resource_type} {resource_id}."
            )

        perm = UserPermission.query.filter_by(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if not perm:
            logger.warning("Permission record not found, nothing to remove.")
            return

        if "can_read" in permissions:
            perm.can_read = False
        if "can_edit" in permissions:
            perm.can_edit = False
        if "can_delete" in permissions:
            perm.can_delete = False
        if "can_add" in permissions:
            perm.can_add = False

        if not (perm.can_read or perm.can_edit or perm.can_delete or perm.can_add):
            # 如果没有权限了，则删除记录
            db.session.delete(perm)
        db.session.commit()
        logger.info(f"Removed {permissions} from user {user_id} "
                    f"on {resource_type} {resource_id}.")

    @staticmethod
    def add_role_permission(
        resource_type: str, resource_id: int,
        role_id: int, permissions: list[str],
    ) -> None:
        """
        类似 add_user_permission，但面向角色
        """
        current_user_id = get_user_id()
        if not ChartPermissions.is_admin_of_resource(
            current_user_id, resource_type, resource_id
        ):
            raise PermissionError(
                f"Current user {current_user_id} is not admin of {resource_type} {resource_id}."
            )
        # 如果是 chart，需要验证此 role 是否有 dataset 访问
        # 具体判定见下 user_has_dataset_access_for_role(...)
        # (可选: 也可以 require that ANY user in that role can read the dataset)
        # ...
        perm = RolePermission.query.filter_by(
            role_id=role_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if not perm:
            perm = RolePermission(
                role_id=role_id,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            db.session.add(perm)
        perm.can_read = "can_read" in permissions or perm.can_read
        perm.can_edit = "can_edit" in permissions or perm.can_edit
        perm.can_delete = "can_delete" in permissions or perm.can_delete
        perm.can_add = "can_add" in permissions or perm.can_add
        db.session.commit()
        logger.info(
            f"Granted {permissions} on {resource_type} {resource_id} to role {role_id}.")

    @staticmethod
    def remove_role_permission(
        resource_type: str, resource_id: int,
        role_id: int, permissions: list[str],
    ) -> None:
        """
        移除角色某些权限
        """
        current_user_id = get_user_id()
        if not ChartPermissions.is_admin_of_resource(
            current_user_id, resource_type, resource_id
        ):
            raise PermissionError(
                f"Current user {current_user_id} is not admin of {resource_type} {resource_id}."
            )
        perm = RolePermission.query.filter_by(
            role_id=role_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if not perm:
            logger.warning("Permission record not found, nothing to remove.")
            return

        if "can_read" in permissions:
            perm.can_read = False
        if "can_edit" in permissions:
            perm.can_edit = False
        if "can_delete" in permissions:
            perm.can_delete = False
        if "can_add" in permissions:
            perm.can_add = False

        if not (perm.can_read or perm.can_edit or perm.can_delete or perm.can_add):
            db.session.delete(perm)

        db.session.commit()
        logger.info(
            f"Removed {permissions} from role {role_id} on {resource_type} {resource_id}.")

    # -------------------------------------------------------------------------
    # 辅助方法
    # -------------------------------------------------------------------------
    @staticmethod
    def user_has_dataset_access(user_obj: User, dataset_id: int) -> bool:
        """
        检查 user_obj 是否具有对某 SQLA Dataset 的访问权限（datasource_access）。
        如果 dataset 不存在或用户无权限，则返回 False。
        """
        logger.info(
            f"Checking dataset access for user {user_obj.username} (ID={user_obj.id}) "
            f"on dataset {dataset_id}."
        )
        if not user_obj:
            return False

        # 根据 dataset_id 查询 SqlaTable
        dataset = db.session.query(SqlaTable).filter_by(id=dataset_id).one_or_none()
        if not dataset:
            logger.warning(f"Dataset with id={dataset_id} does not exist.")
            return False

        # 调用 security_manager.can_access_datasource(...) 检查权限
        # 移除 user 参数
        has_access = security_manager.can_access_datasource(dataset)
        if not has_access:
            logger.info(
                f"User {user_obj.username} (id={user_obj.id}) has NO dataset_access "
                f"for dataset {dataset.table_name} (id={dataset_id})."
            )
        return has_access

    @staticmethod
    def check_role_permission(role_id=None, role_name=None) -> bool:
        # 确保至少传入一个 role_id 或 role_name
        if not role_id and not role_name:
            raise ValueError("必须提供 role_id 或 role_name")

        # SQL 查询，检查角色是否有权限
        query = """
        SELECT
            r.name AS role_name,
            p.name AS permission_name
        FROM
            ab_role r
        JOIN
            ab_permission_view_role pvr ON r.id = pvr.role_id
        JOIN
            ab_permission_view pv ON pvr.permission_view_id = pv.id
        JOIN
            ab_permission p ON pv.permission_id = p.id
        WHERE
        """

        # 根据传入的参数选择 role_id 或 role_name 作为查询条件
        params = {}

        if role_id:
            query += " r.id = :role_id"
            params['role_id'] = role_id
        elif role_name:
            query += " r.name = :role_name"
            params['role_name'] = role_name

        # 执行查询
        result = db.session.execute(
            text(query),
            params
        ).fetchall()

        # 如果查询结果不为空，说明角色有权限
        if result:
            return True
        else:
            return False

    @staticmethod
    def check_user_permission(user_id=None, user_name=None) -> bool:
        # 确保传入了有效的 user_id 或 user_name
        if not user_id and not user_name:
            raise ValueError("必须提供 user_id 或 user_name")

        # SQL 查询，检查用户是否有权限
        query = """
        SELECT
            u.username AS user_name,
            p.name AS permission_name
        FROM
            ab_user u
        JOIN
            ab_user_role ur ON u.id = ur.user_id
        JOIN
            ab_role r ON ur.role_id = r.id
        JOIN
            ab_permission_view_role pvr ON r.id = pvr.role_id
        JOIN
            ab_permission_view pv ON pvr.permission_view_id = pv.id
        JOIN
            ab_permission p ON pv.permission_id = p.id
        WHERE
        """

        # 根据提供的参数构建查询条件
        params = {}

        if user_id:
            query += " u.id = :user_id"
            params['user_id'] = user_id
        elif user_name:
            query += " u.username = :user_name"
            params['user_name'] = user_name

        # 执行查询
        result = db.session.execute(
            text(query),
            params
        ).fetchall()

        # 如果查询结果不为空，说明该用户有权限
        if result:
            return True
        else:
            return False

    @staticmethod
    def is_admin_of_resource(
        user_id: int, resource_type: str, resource_id: int
    ) -> bool:
        """
        判断 user_id 对该资源是否是“管理员”（can_delete && can_edit && can_add && can_read）。
        """
        if not user_id:
            return False
        perm = UserPermission.query.filter_by(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if not perm:
            return False
        # 判断是否拥有所有权限
        return all([
            perm.can_add,
            perm.can_read,
            perm.can_edit,
            perm.can_delete
        ])

    @staticmethod
    def interpret_frontend_permissions(perm_list: list[str]) -> dict[str, bool]:
        """
        将前端传来的["can_read", "can_edit", "can_add", "can_delete"]等转换为
        {can_read, can_edit, can_add, can_delete} 的布尔值，并根据这些权限推导出
        高层权限（例如 'admin', 'edit', 'read'）。
        """
        can_read = can_edit = can_add = can_delete = False
        logger.info(f"检查前端到底勾选的是什么内容: {perm_list}")

        # 逐个检查前端传过来的权限
        if "can_read" in perm_list:
            can_read = True
        if "can_edit" in perm_list:
            can_edit = True
        if "can_add" in perm_list:
            can_add = True
        if "can_delete" in perm_list:
            can_delete = True

        # 低层次权限字典
        permissions = {
            "can_read": can_read,
            "can_edit": can_edit,
            "can_add": can_add,
            "can_delete": can_delete,
        }

        # # 推导出高层次权限
        # # 如果命中了can_read, can_edit, can_add, can_delete，返回admin
        # if can_read and can_edit and can_add and can_delete:
        #     permissions["admin"] = True
        # # 如果只命中了can_edit或can_add，返回edit
        # elif can_edit or can_add:
        #     permissions["edit"] = True
        # # 如果命中了can_read，返回read
        # elif can_read:
        #     permissions["read"] = True

        return permissions

    @staticmethod
    def get_permissions_for_chart(user_id, chart_id):
        # 获取用户权限
        user_permissions = db.session.query(UserPermission).filter_by(
            user_id=user_id,
            resource_type='chart',
            resource_id=chart_id
        ).first()

        # 获取当前登录用户的角色 ID
        role_id = get_current_user_role_id()

        # 获取角色权限
        role_permission = None
        if role_id:
            role_permission = db.session.query(RolePermission).filter_by(
                role_id=role_id,
                resource_type='chart',
                resource_id=chart_id
            ).first()

        # 合并权限：用户权限和角色权限平级
        permissions = {
            'can_read': (user_permissions.can_read if user_permissions else False) or
                        (role_permission.can_read if role_permission else False),
            'can_edit': (user_permissions.can_edit if user_permissions else False) or
                        (role_permission.can_edit if role_permission else False),
            'can_delete': (
                              user_permissions.can_delete if user_permissions else False) or
                          (role_permission.can_delete if role_permission else False),
            'can_add': (user_permissions.can_add if user_permissions else False) or
                       (role_permission.can_add if role_permission else False),
        }

        return permissions

    @staticmethod
    def check_datasource_permissions(user_id=None, role_id=None, datasource_id=None) -> \
        Optional[bool]:
        # 查询 UserPermission
        logger.info(f"query datasource permissions user_id: {user_id}")
        logger.info(f"query datasource permissions role_id: {role_id}")
        logger.info(f"query datasource permissions datasource_id: {datasource_id}")

        user_permission = None
        if user_id:
            user_permission = db.session.query(UserPermission).filter_by(
                user_id=user_id, datasource_id=datasource_id).first()

        # 查询 RolePermission
        role_permission = None
        if role_id:
            role_permission = db.session.query(RolePermission).filter_by(
                role_id=role_id, datasource_id=datasource_id).first()

        # 确保 user_permission 和 role_permission 都不为 None
        if user_permission:
            logger.info(
                f"query datasource permissions user_permission.can_read: {user_permission.can_read}")
            logger.info(
                f"query datasource permissions user_permission.can_edit: {user_permission.can_edit}")
        else:
            logger.info("user_permission is None")

        if role_permission:
            logger.info(
                f"query datasource permissions role_permission.can_read: {role_permission.can_read}")
            logger.info(
                f"query datasource permissions role_permission.can_edit: {role_permission.can_edit}")
        else:
            logger.info("role_permission is None")

        # 判断 UserPermission 和 RolePermission 中是否同时满足 can_read 和 can_edit
        if user_permission and user_permission.can_read and user_permission.can_edit:
            return True  # 用户权限同时具备阅读和编辑权限

        if role_permission and role_permission.can_read and role_permission.can_edit:
            return True  # 角色权限同时具备阅读和编辑权限

        raise DatasetAccessDeniedError()  # 没有权限

    @staticmethod
    def check_datasource_read_permissions(user_id: int, role_id: int,
                                          datasource_id: int) -> None:
        """
        检查用户和角色对数据源的权限。
        如果有权限，什么也不做；如果没有权限，抛出异常。
        """
        logger.info(
            f"Checking permissions for user_id: {user_id}, role_id: {role_id}, datasource_id: {datasource_id}")

        # 查询 UserPermission
        user_permission = None
        if user_id:
            user_permission = db.session.query(UserPermission).filter_by(
                user_id=user_id, datasource_id=datasource_id
            ).first()

        # 查询 RolePermission
        role_permission = None
        if role_id:
            role_permission = db.session.query(RolePermission).filter_by(
                role_id=role_id, datasource_id=datasource_id
            ).first()

        # 日志记录
        if user_permission:
            logger.info(
                f"UserPermission - can_read: {user_permission.can_read}, can_edit: {user_permission.can_edit}")
        else:
            logger.info("UserPermission is None")

        if role_permission:
            logger.info(
                f"RolePermission - can_read: {role_permission.can_read}, can_edit: {role_permission.can_edit}")
        else:
            logger.info("RolePermission is None")

        # 判断权限
        if user_permission and user_permission.can_read:
            logger.info("User has read and edit permissions.")
            return  # 有权限，返回

        if role_permission and role_permission.can_read:
            logger.info("Role has read and edit permissions.")
            return  # 有权限，返回

        logger.error(
            "Permission denied: User and Role do not have required permissions.")
        raise DatasetAccessDeniedError()  # 没有权限，抛出异常

    # -------------------------------------------------------------------------
    # 权限映射方法
    # -------------------------------------------------------------------------
    @staticmethod
    def map_permissions_to_role(
        can_edit: bool,
        can_export: bool,
        can_delete: bool
    ) -> str:
        """
        根据权限映射为角色。
        - can_write, can_export, can_delete -> admin
        - can_write -> editor
        - 其他 -> viewer

        :param can_write: 是否有写权限
        :param can_export: 是否有导出权限
        :param can_delete: 是否有删除权限
        :return: 角色标签
        """
        if can_edit and can_export and can_delete:
            return "admin"
        elif can_edit and can_export:
            return "editor"
        elif can_export:
            return "viewer"

    # -------------------------------------------------------------------------
    # 权限获取所有图表的方法
    # -------------------------------------------------------------------------
    @staticmethod
    def get_all_chart_permissions(user: User) -> dict[int, dict[str, Any]]:
        """
        获取当前用户对所有图表的权限，并映射为角色标签。

        :param user: 当前用户对象
        :return: 权限字典，键为 chart_id，值为权限信息
        """
        permissions = {}

        # 获取所有涉及的 chart_ids
        user_perms = db.session.query(UserPermission).filter_by(
            user_id=user.id,
            resource_type="chart"
        ).all()
        role_ids = [role.id for role in user.roles] if user.roles else []
        role_perms = db.session.query(RolePermission).filter(
            RolePermission.role_id.in_(role_ids),
            RolePermission.resource_type == "chart"
        ).all()

        # 组织用户权限
        user_permissions_dict = {}
        for perm in user_perms:
            chart_id = perm.resource_id
            user_permissions_dict[chart_id] = {
                "can_read": perm.can_read,
                "can_edit": perm.can_edit,
                "can_delete": perm.can_delete,
                "can_add": perm.can_add
            }

        # 组织角色权限（合并所有角色的权限）
        role_permissions_dict = {}
        for perm in role_perms:
            chart_id = perm.resource_id
            if chart_id not in role_permissions_dict:
                role_permissions_dict[chart_id] = {
                    "can_read": False,
                    "can_edit": False,
                    "can_delete": False,
                    "can_add": False
                }
            role_permissions_dict[chart_id]["can_read"] = \
            role_permissions_dict[chart_id]["can_read"] or perm.can_read
            role_permissions_dict[chart_id]["can_edit"] = \
            role_permissions_dict[chart_id]["can_edit"] or perm.can_edit
            role_permissions_dict[chart_id]["can_delete"] = \
            role_permissions_dict[chart_id]["can_delete"] or perm.can_delete
            role_permissions_dict[chart_id]["can_add"] = \
            role_permissions_dict[chart_id]["can_add"] or perm.can_add

        # 获取所有 chart_ids
        all_chart_ids = set(user_permissions_dict.keys()).union(
            set(role_permissions_dict.keys()))

        for chart_id in all_chart_ids:
            user_perm = user_permissions_dict.get(chart_id, {
                "can_read": False,
                "can_edit": False,
                "can_delete": False,
                "can_add": False
            })
            role_perm = role_permissions_dict.get(chart_id, {
                "can_read": False,
                "can_edit": False,
                "can_delete": False,
                "can_add": False
            })

            # 合并权限
            final_permissions = {
                "can_read": user_perm["can_read"] or role_perm["can_read"],
                "can_edit": user_perm["can_edit"] or role_perm["can_edit"],
                "can_delete": user_perm["can_delete"] or role_perm["can_delete"],
                "can_add": user_perm["can_add"] or role_perm["can_add"]
            }

            # 根据权限映射角色标签
            role_label = ChartPermissions.map_permissions_to_role(
                can_edit=final_permissions["can_edit"],
                can_export=final_permissions["can_read"],  # 基于 can_read 推导 can_export
                can_delete=final_permissions["can_delete"]
            )

            # 基于 can_read 推导 can_export
            can_export = final_permissions["can_read"]

            permissions[chart_id] = {
                "can_read": final_permissions["can_read"],
                "can_write": final_permissions["can_edit"],  # 替换 can_edit 为 can_write
                "can_delete": final_permissions["can_delete"],
                "can_add": final_permissions["can_add"],
                "can_export": can_export,
                "role": role_label
            }

        return permissions

    @staticmethod
    def has_can_edit_permission(user_id: int, role_ids: list[int],
                                chart_id: int) -> bool:
        """
        判断用户或其角色是否对指定图表拥有 can_edit 权限。

        :param user_id: 用户 ID
        :param role_ids: 角色 ID 列表
        :param chart_id: 图表 ID
        :return: 如果拥有 can_edit 权限，返回 True；否则返回 False
        """
        # 查询用户权限
        user_perm = db.session.query(UserPermission).filter_by(
            user_id=user_id,
            resource_type='chart',
            resource_id=chart_id
        ).first()

        if user_perm and user_perm.can_edit:
            logger.debug(f"用户 ID {user_id} 对图表 ID {chart_id} 拥有 can_edit 权限。")
            return True

        # 查询角色权限
        role_perms = db.session.query(RolePermission).filter(
            RolePermission.role_id.in_(role_ids),
            RolePermission.resource_type == 'chart',
            RolePermission.resource_id == chart_id
        ).all()

        for perm in role_perms:
            if perm.can_edit:
                logger.debug(
                    f"用户的角色 ID {perm.role_id} 对图表 ID {chart_id} 拥有 can_edit 权限。")
                return True

        logger.debug(
            f"用户 ID {user_id} 及其角色对图表 ID {chart_id} 不拥有 can_edit 权限。")
        return False

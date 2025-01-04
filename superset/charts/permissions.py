import logging

from sqlalchemy.exc import SQLAlchemyError

from superset.connectors.sqla.models import SqlaTable
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object
from superset.extensions import db, security_manager
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder.security.sqla.models import User, Role

from superset.utils.core import get_user_id

logger = logging.getLogger(__name__)


class ChartPermissions:
    datamodel = SQLAInterface(Slice)  # 创建 datamodel 实例

    @staticmethod
    def set_default_permissions(
        chart: Slice,
        user: User,
        roles: list[Role] = None,
        permissions: list[str] = None,
    ) -> None:
        """
        设置图表的默认权限。
        """
        roles = roles or []  # 如果没有传入角色，默认使用空列表
        permissions = permissions or ["can_read", "can_edit"]  # 默认权限

        try:
            # 为用户分配权限
            ChartPermissions.add_permissions_to_user(chart.id, user.id, permissions)

            # 为每个角色分配权限
            for role in roles:
                ChartPermissions.add_permissions_to_role(chart.id, role.id, permissions)
        except Exception as ex:
            logger.error(
                f"Error setting default permissions for chart {chart.id}: {ex}")
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
                f"Failed to add permissions {permissions} to {entity_type} {entity_id}"
                f" for chart {chart_id}: {ex}"
            )
            raise

    @staticmethod
    def add_permissions_to_user(chart_id: int, user_id: int,
                                permissions: list[str]) -> None:
        """
        为用户添加权限，使用通用方法。
        """
        ChartPermissions._add_permissions(chart_id, user_id, permissions, "user")

    @staticmethod
    def add_permissions_to_role(chart_id: int, role_id: int,
                                permissions: list[str]) -> None:
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

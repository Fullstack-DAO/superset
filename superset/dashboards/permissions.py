import logging

from superset.models.dashboard import Dashboard
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.tasks.utils import get_current_user_object
from flask_appbuilder.models.sqla.interface import SQLAInterface

logger = logging.getLogger(__name__)


class DashboardPermissions:
    datamodel = SQLAInterface(Dashboard)  # 创建 datamodel 实例

    @staticmethod
    def has_read_permission(dashboard: Dashboard, user) -> bool:
        """
        检查用户是否有读取仪表盘的权限。
        """
        # 检查用户的个人权限 (UserPermission)
        user_permission = UserPermission.query.filter_by(
            user_id=user.id,
            resource_type='dashboard',
            resource_id=dashboard.id
        ).first()

        if user_permission and user_permission.can_read:
            return True

        # 检查用户所属角色的权限 (RolePermission)
        role_permissions = RolePermission.query.filter(
            RolePermission.resource_type == 'dashboard',
            RolePermission.resource_id == dashboard.id,
            RolePermission.role_id.in_([role.id for role in user.roles]),
            RolePermission.can_read == True
        ).all()

        if role_permissions:
            return True

        return False

    @staticmethod
    def check_user_permission(dashboard: Dashboard, user, permission_type: str) -> bool:
        """
        动态检查用户对仪表盘的具体权限。
        """
        # 定义需要检查的权限字段
        permission_map = {
            'read': 'can_read',
            'edit': 'can_edit',
            'delete': 'can_delete',
            'add': 'can_add',
            # 如果需要，可以扩展更多权限类型，例如 delete
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 检查用户的个人权限 (UserPermission)
        user_permission = UserPermission.query.filter_by(
            user_id=user.id,
            resource_type='dashboard',
            resource_id=dashboard.id
        ).first()

        if user_permission and getattr(user_permission,
                                       permission_map[permission_type]):
            return True

        # 检查用户所属角色的权限 (RolePermission)
        role_permissions = RolePermission.query.filter(
            RolePermission.resource_type == 'dashboard',
            RolePermission.resource_id == dashboard.id,
            RolePermission.role_id.in_([role.id for role in user.roles]),
            getattr(RolePermission, permission_map[permission_type]) == True
        ).all()

        if role_permissions:
            return True

        return False

    @staticmethod
    def check_dashboard_permission(dashboard: Dashboard, edit: bool = False) -> bool:
        """
        检查当前用户是否有对仪表盘的权限（读取或编辑）。
        """
        user = get_current_user_object()
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return False

        # 如果是编辑权限检查
        if edit:
            has_permission = DashboardPermissions.check_user_permission(dashboard, user,
                                                                        'edit')
        else:
            has_permission = DashboardPermissions.has_read_permission(dashboard, user)

        if has_permission:
            logger.info(
                f"User {user.username} has {'edit' if edit else 'read'} permission "
                f"for dashboard {dashboard.id}.")
        else:
            logger.warning(
                f"User {user.username} does not have {'edit' if edit else 'read'} permission for dashboard {dashboard.id}.")
        return has_permission

    @staticmethod
    def get_dashboard_and_check_permission(pk: int):
        """
        获取仪表盘并检查用户权限。
        """
        dashboard = DashboardPermissions.datamodel.get(pk)  # 获取仪表盘对象
        if not dashboard:
            logger.warning("Dashboard with ID %s not found.", pk)
            return None

        if not DashboardPermissions.check_dashboard_permission(dashboard):
            return None

        return dashboard

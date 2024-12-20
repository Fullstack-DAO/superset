import logging
from superset.models.role_permission import RolePermission
from superset.models.user_permission import UserPermission
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object
from flask_appbuilder.models.sqla.interface import SQLAInterface

logger = logging.getLogger(__name__)


class ChartPermissions:
    datamodel = SQLAInterface(Slice)  # 创建 datamodel 实例
    @staticmethod
    def has_read_permission(chart: Slice, user) -> bool:
        """
        检查用户是否有读取图表的权限。
        """
        # 检查用户的个人权限 (UserPermission)
        user_permission = UserPermission.query.filter_by(
            user_id=user.id,
            resource_type='chart',
            resource_id=chart.id
        ).first()

        if user_permission and user_permission.can_read:
            return True

        # 检查用户所属角色的权限 (RolePermission)
        role_permissions = RolePermission.query.filter(
            RolePermission.resource_type == 'chart',
            RolePermission.resource_id == chart.id,
            RolePermission.role_id.in_([role.id for role in user.roles]),
            RolePermission.can_read == True
        ).all()

        if role_permissions:
            return True

        return False

    @staticmethod
    def check_user_permission(chart: Slice, user, permission_type: str) -> bool:
        """
        动态检查用户对图表的具体权限。
        """
        # 定义需要检查的权限字段
        permission_map = {
            'read': 'can_read',
            'edit': 'can_edit',
            # 如果需要，可以扩展更多权限类型，例如 delete
        }

        if permission_type not in permission_map:
            raise ValueError(f"Unknown permission type: {permission_type}")

        # 检查用户的个人权限 (UserPermission)
        user_permission = UserPermission.query.filter_by(
            user_id=user.id,
            resource_type='chart',
            resource_id=chart.id
        ).first()

        if user_permission and getattr(user_permission,
                                       permission_map[permission_type]):
            return True

        # 检查用户所属角色的权限 (RolePermission)
        role_permissions = RolePermission.query.filter(
            RolePermission.resource_type == 'chart',
            RolePermission.resource_id == chart.id,
            RolePermission.role_id.in_([role.id for role in user.roles]),
            getattr(RolePermission, permission_map[permission_type]) == True
        ).all()

        if role_permissions:
            return True

        return False

    @staticmethod
    def check_chart_permission(chart: Slice, edit: bool = False) -> bool:
        """
        检查当前用户是否有对图表的权限（读取或编辑）。
        """
        user = get_current_user_object()
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return False

        # 如果是编辑权限检查
        if edit:
            has_permission = ChartPermissions.check_user_permission(chart, user, 'edit')
        else:
            has_permission = ChartPermissions.has_read_permission(chart, user)

        if has_permission:
            logger.info(
                f"User {user.username} has {'edit' if edit else 'read'} permission for chart {chart.id}.")
        else:
            logger.warning(
                f"User {user.username} does not have {'edit' if edit else 'read'} permission for chart {chart.id}.")
        return has_permission

    @staticmethod
    def get_chart_and_check_permission(pk: int):
        """
        获取图表并检查用户权限。
        """
        chart = ChartPermissions.datamodel.get(pk)  # 获取图表对象
        if not chart:
            logger.warning("Chart with ID %s not found.", pk)
            return None

        if not ChartPermissions.check_chart_permission(chart):
            return None

        return chart

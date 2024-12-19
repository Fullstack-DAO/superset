
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object

from superset import security_manager
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class ChartPermissions:
    @staticmethod
    def check_chart_permission(chart: Slice, edit: bool = False) -> bool:
        """检查用户对图表的访问权限。"""
        user = get_current_user_object()  # 获取当前用户
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return False

        logger.info("User %s is checking permissions for chart %s (edit: %s).",
                    user.username, chart.id, edit)

        # 检查图表的可见性范围
        if chart.visibility_scope == 'owner':
            has_permission = chart.created_by == user
            if has_permission:
                logger.info("User %s has permission to access chart %s as owner.",
                            user.username, chart.id)
            else:
                logger.warning(
                    "User %s does not have permission to access chart %s as owner.",
                    user.username, chart.id)
            return has_permission
        elif chart.visibility_scope == 'role':
            user_role_ids = {role.id for role in user.roles}
            chart_read_role_ids = {role.id for role in chart.read_roles}
            has_read_permission = bool(user_role_ids & chart_read_role_ids)
            if not has_read_permission:
                logger.warning(
                    "User %s does not have read permission for chart %s due to role "
                    "restrictions.",
                    user.username, chart.id)
                return False

        # 如果 edit 标志为 True，检查编辑权限
        if edit:
            chart_edit_role_ids = {role.id for role in chart.edit_roles}
            has_edit_permission = bool(user_role_ids & chart_edit_role_ids)
            if has_edit_permission:
                logger.info("User %s has edit permission for chart %s.", user.username,
                            chart.id)
            else:
                logger.warning("User %s does not have edit permission for chart %s.",
                               user.username, chart.id)
            return has_edit_permission

        # 默认情况下，用户具有读取权限
        logger.info("User %s has read permission for chart %s.", user.username,
                    chart.id)
        return True

    @staticmethod
    def get_chart_and_check_permission(datamodel, pk: int, edit: bool = False) -> \
    Optional[Slice]:
        """获取图表并检查用户权限。"""
        chart = datamodel.get(pk)  # 获取图表
        if not chart:
            logger.warning("Chart with ID %s not found.", pk)
            return None

        if not ChartPermissions.check_chart_permission(chart, edit=edit):
            logger.warning("User %s does not have permission to access chart %s.",
                           chart.created_by.username if chart.created_by else "Unknown",
                           chart.id)
            return None

        logger.info("User %s has permission to access chart %s.",
                    chart.created_by.username if chart.created_by else "Unknown",
                    chart.id)
        return chart

    @staticmethod
    def has_read_permission(chart: Slice) -> bool:
        """检查当前用户是否在图表的可读角色中。"""
        user = get_current_user_object()
        if not user:
            logger.warning("No user is currently logged in.")
            return False

        if chart.visibility_scope == 'owner':
            has_permission = chart.created_by == user
            if has_permission:
                logger.info("User %s has read permission for chart %s as owner.",
                            user.username, chart.id)
            else:
                logger.warning("User %s does not have read permission for chart %s as "
                               "owner.", user.username, chart.id)
            return has_permission
        elif chart.visibility_scope == 'role':
            user_role_ids = {role.id for role in user.roles}
            chart_read_role_ids = {role.id for role in chart.read_roles}
            has_read_permission = bool(user_role_ids & chart_read_role_ids)
            if has_read_permission:
                logger.info("User %s has read permission for chart %s via roles.",
                            user.username, chart.id)
            else:
                logger.warning(
                    "User %s does not have read permission for chart %s via roles.",
                    user.username, chart.id)
            return has_read_permission

        return False

    @staticmethod
    def check_user_permission() -> bool:
        """检查当前用户是否有权限添加或更新指定的所有者。"""
        user = get_current_user_object()  # 获取当前用户
        if not user:
            logger.warning("No user is currently logged in.")
            return False
        # 检查用户是否为管理员或具有编辑权限
        is_admin = "admin" in [role.name for role in user.roles]
        can_edit = security_manager.can_access("can_edit", "Chart")
        return is_admin or can_edit

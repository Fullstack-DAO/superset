from flask import g
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user
from flask_appbuilder.models.sqla.interface import SQLAInterface
from superset import security_manager
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class ChartPermissions:
    # 定义 datamodel 作为类属性
    datamodel = SQLAInterface(Slice)
    
    @staticmethod
    def check_chart_permission(chart: Slice, edit: bool = False) -> bool:
        user = get_current_user()  # 获取当前用户

        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return False
    
        logger.info("User %s is checking permissions for chart %s (edit: %s).", user.username, chart.id, edit)

        # 检查图表的可见性范围
        if chart.visibility_scope == 'owner':
            has_permission = chart.created_by == user
            if has_permission:
                logger.info("User %s has permission to access chart %s as owner.", user.username, chart.id)
            else:
                logger.warning("User %s does not have permission to access chart %s as owner.", user.username, chart.id)
            return has_permission
        elif chart.visibility_scope == 'role':
            if not any(role in chart.read_roles for role in user.roles):
                logger.warning("User %s does not have permission to access chart %s due to role restrictions.", user.username, chart.id)
                return False

        # 如果 edit 标志为 True，检查编辑权限
        if edit:
            if any(role in chart.edit_roles for role in user.roles):
                logger.info("User %s has edit permission for chart %s.", user.username, chart.id)
                return True
        else:
            logger.warning("User %s does not have edit permission for chart %s.", user.username, chart.id)
            return False
        logger.info("User %s has read permission for chart %s.", user.username, chart.id)
        return True

    @staticmethod
    def get_chart_and_check_permission(datamodel, pk: int) -> Optional[Slice]:
        chart = datamodel.get(pk)  # 获取图表
        if not chart:
            logger.warning("Chart with ID %s not found.", pk)
            return None

        user = get_current_user()  # 获取当前用户
        edit_permission = any(role in chart.edit_roles for role in user.roles) if user else False

        if not ChartPermissions.check_chart_permission(chart, edit=edit_permission):
            logger.warning("User %s does not have permission to access chart %s.", user.username if user else "Unknown", chart.id)
            return None
        logger.info("User %s has permission to access chart %s.", user.username if user else "Unknown", chart.id)
        return chart
    

    @staticmethod
    def has_read_permission(chart: Slice) -> bool:
        """
        检查当前用户是否在图表的可读角色中。

        :param chart: Slice 对象，表示要检查的图表
        :return: 如果用户有可读权限，则返回 True，否则返回 False
        """
        if g.user in chart.read_roles:
            logger.info("User %s has read permission for chart %s.", g.user.username, chart.id)
            return True
        logger.warning("User %s does not have read permission for chart %s.", g.user.username, chart.id)
        return False


    @staticmethod
    def check_user_permission() -> bool:
        """
        Check if the current user has permission to add or update the specified owner.

        :param owner_id: The ID of the owner to check permissions for.
        :return: True if the user has permission, False otherwise.
        """
        user = get_current_user()  # 获取当前用户
        return "admin" in user.roles or security_manager.can_access("can_edit", "Chart")

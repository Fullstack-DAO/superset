import logging
from typing import Optional
from flask_appbuilder.models.sqla.interface import SQLAInterface
from superset.models.slice import Slice
from superset.tasks.utils import get_current_user_object
from superset.extensions import security_manager

logger = logging.getLogger(__name__)


class ChartPermissions:
    @staticmethod
    def check_chart_permission(chart: Slice, edit: bool = False) -> bool:
        """
        检查用户对图表的访问权限。

        :param chart: 要检查的图表对象
        :param edit: 是否检查编辑权限
        :return: 如果用户有权限，则返回 True，否则返回 False
        """
        user = get_current_user_object()  # 获取当前用户
        if not user:
            logger.warning("Permission check failed: No user is currently logged in.")
            return False

        logger.info(
            "User '%s' is checking permissions for chart ID '%s' (edit: %s).",
            user.username, chart.id, edit
        )

        # 检查图表的可见性范围
        if chart.visibility_scope == 'owner':
            has_permission = chart.created_by == user
            if has_permission:
                logger.info(
                    "User '%s' has permission to access chart ID '%s' as owner.",
                    user.username, chart.id
                )
            else:
                logger.warning(
                    "User '%s' does not have permission to access chart ID '%s' as "
                    "owner.",
                    user.username, chart.id
                )
            return has_permission

        elif chart.visibility_scope == 'role':
            # 检查用户的角色与图表的 read_roles 或 edit_roles 是否匹配
            user_role_ids = {role.id for role in user.roles}
            chart_read_role_ids = {role.id for role in chart.read_roles}

            has_read_permission = bool(user_role_ids & chart_read_role_ids)
            if not has_read_permission:
                logger.warning(
                    "User '%s' does not have read permission for chart ID '%s' due to role restrictions.",
                    user.username, chart.id
                )
                return False

            # 如果 edit 标志为 True，进一步检查编辑权限
            if edit:
                chart_edit_role_ids = {role.id for role in chart.edit_roles}
                has_edit_permission = bool(user_role_ids & chart_edit_role_ids)
                if has_edit_permission:
                    logger.info(
                        "User '%s' has edit permission for chart ID '%s'.",
                        user.username, chart.id
                    )
                else:
                    logger.warning(
                        "User '%s' does not have edit permission for chart ID '%s'.",
                        user.username, chart.id
                    )
                return has_edit_permission

            logger.info(
                "User '%s' has read permission for chart ID '%s' via roles.",
                user.username, chart.id
            )
            return True

        logger.warning(
            "Unknown visibility_scope '%s' for chart ID '%s'. Access denied.",
            chart.visibility_scope, chart.id
        )
        return False

    @staticmethod
    def get_chart_and_check_permission(
        datamodel: SQLAInterface,
        pk: int,
        edit: bool = False
    ) -> Optional[Slice]:
        """
        获取图表并检查用户权限。

        :param datamodel: 数据模型接口
        :param pk: 图表的主键 ID
        :param edit: 是否检查编辑权限
        :return: 如果用户有权限，返回 Slice 对象；否则返回 None
        """
        # 通过 datamodel 获取指定主键的 Slice 对象
        chart = datamodel.get(pk)
        if not chart:
            logger.warning("Chart with ID '%s' not found.", pk)
            return None

        user = get_current_user_object()
        if not user:
            logger.warning("No user is currently logged in.")
            return None

        # 检查用户对图表的权限
        if not ChartPermissions.check_chart_permission(chart, edit=edit):
            logger.warning(
                "User '%s' does not have permission to access chart ID '%s'.",
                user.username, chart.id
            )
            return None

        logger.info(
            "User '%s' has permission to access chart ID '%s'.",
            user.username, chart.id
        )
        return chart

    @staticmethod
    def has_read_permission(chart: Slice) -> bool:
        """
        检查当前用户是否在图表的可读角色中。

        :param chart: Slice 对象，表示要检查的图表
        :return: 如果用户有可读权限，则返回 True，否则返回 False
        """
        user = get_current_user_object()  # 获取当前用户
        if not user:
            logger.warning("No user is currently logged in.")
            return False

        # 获取用户的角色 ID 和图表的 read_roles ID
        user_role_ids = {role.id for role in user.roles}
        chart_read_role_ids = {role.id for role in chart.read_roles}

        # 判断是否有交集
        has_permission = bool(user_role_ids & chart_read_role_ids)
        if has_permission:
            logger.info(
                "User '%s' has read permission for chart ID '%s'.",
                user.username, chart.id
            )
        else:
            logger.warning(
                "User '%s' does not have read permission for chart ID '%s'.",
                user.username, chart.id
            )
        return has_permission

    @staticmethod
    def check_user_permission() -> bool:
        """
        检查当前用户是否有权限添加或更新指定的所有者。

        :return: 如果用户有权限，则返回 True，否则返回 False
        """
        user = get_current_user_object()  # 获取当前用户
        if not user:
            logger.warning("No user is currently logged in.")
            return False

        # 如果用户是管理员，或者具有 'can_edit' 权限，则返回 True
        if "admin" in {role.name for role in user.roles}:
            logger.info("User '%s' is an admin.", user.username)
            return True

        if security_manager.can_access("can_edit", "Chart"):
            logger.info("User '%s' has 'can_edit' permission on charts.", user.username)
            return True

        logger.warning("User '%s' does not have permission to edit charts.", user.username)
        return False

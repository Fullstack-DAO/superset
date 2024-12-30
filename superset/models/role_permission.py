from sqlalchemy import Column, Integer, Boolean, ForeignKey, String
from superset import db, is_feature_enabled, security_manager
from flask_appbuilder import Model
from sqlalchemy.orm import relationship
import logging

logger = logging.getLogger(__name__)


class RolePermission(Model):
    __tablename__ = 'role_permissions'
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey('ab_role.id', ondelete='CASCADE'), nullable=False)
    resource_type = Column(String(100), nullable=False)  # 'chart' 或 'dashboard'
    resource_id = Column(Integer, nullable=False)  # 资源的 ID
    can_read = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    can_add = Column(Boolean, default=False)

    role = relationship("Role", backref="role_permissions")
    # dashboard = relationship('Dashboard', back_populates='user_permissions',
    # foreign_keys=[resource_id]) slice = relationship('Slice',
    # back_populates='user_permissions', foreign_keys=[resource_id])

    @staticmethod
    def delete_permission(role_id: int, resource_type: str, resource_id: int):
        """删除指定角色对某资源的权限记录"""
        permission = RolePermission.query.filter_by(
            role_id=role_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if permission:
            db.session.delete(permission)
            db.session.commit()
            logger.info(
                f"Deleted permission for role {role_id} on "
                f"{resource_type} {resource_id}."
            )
        else:
            logger.warning(
                f"No permission found to delete for role {role_id} on "
                f"{resource_type} {resource_id}."
            )

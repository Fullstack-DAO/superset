from sqlalchemy import Column, Integer, Boolean, ForeignKey, String
from flask_appbuilder import Model
from superset import db, is_feature_enabled, security_manager
from sqlalchemy.orm import relationship
import logging

logger = logging.getLogger(__name__)


class UserPermission(Model):
    __tablename__ = 'user_permissions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('ab_user.id', ondelete='CASCADE'), nullable=False)
    resource_type = Column(String(100), nullable=False)  # 'chart' 或 'dashboard'
    resource_id = Column(Integer, nullable=False)  # 资源的 ID
    can_read = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)

    user = relationship("User", backref="permissions", cascade="all, delete-orphan")

    @staticmethod
    def delete_permission(user_id: int, resource_type: str, resource_id: int):
        """删除用户的权限"""
        permission = UserPermission.query.filter_by(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if permission:
            db.session.delete(permission)
            db.session.commit()
            logger.info(f"Deleted permission for user {user_id} on {resource_type} {resource_id}.")
        else:
            logger.warning(f"No permission found to delete for user {user_id} on {resource_type} {resource_id}.")


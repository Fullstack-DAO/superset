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
    resource_id = Column(Integer, nullable=False)  # chart ID
    datasource_id = Column(Integer)  # dataset ID
    can_read = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    can_add = Column(Boolean, default=False)

    user = relationship("User", backref="user_permissions")
    # dashboard = relationship('Dashboard', back_populates='user_permissions', foreign_keys=[resource_id])
    # slice = relationship('Slice', back_populates='user_permissions', foreign_keys=[resource_id])

    @staticmethod
    def delete_permission(user_id: int, resource_type: str, resource_id: int):
        """删除指定用户对某资源的权限记录"""
        permission = UserPermission.query.filter_by(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id
        ).first()
        if permission:
            db.session.delete(permission)
            db.session.commit()
            logger.info(
                f"Deleted permission for user {user_id} on "
                f"{resource_type} {resource_id}"
            )
        else:
            logger.warning(
                f"No permission found to delete for user {user_id} on {resource_type} "
                f"{resource_id}."
            )


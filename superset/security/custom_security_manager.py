import logging
from flask import request, jsonify, g, redirect
from flask_appbuilder import expose
from flask_login import login_user
# from superset.views.base import BaseSupersetView
from flask_appbuilder import BaseView as BaseSupersetView
from superset import security_manager
from superset.security.manager import SupersetSecurityManager

logger = logging.getLogger(__name__)

class PseudoLoginView(BaseSupersetView):
    route_base = "/custom"
    default_view = "login_by_email"

    @expose("/login_by_email")
    def login_by_email(self):
        email = request.args.get("email")
        
        if not email:
            return jsonify({"status": "error", "message": "Email is required"}), 400
        
        user = security_manager.find_user(email=email)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
            
        login_user(user)
        return jsonify({
            "status": "success", 
            "user": {
                "username": user.username,
                "email": user.email,
                "roles": [r.name for r in user.roles]
            }
        })

class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
    
    def register_views(self):
        super().register_views()
        self.appbuilder.add_view_no_menu(PseudoLoginView)

    def sync_role_definitions(self):
        super().sync_role_definitions()
        try:
            # Grant permission to Public role so it can be accessed without login
            # 'Public' is the default name for the public role in FAB
            public_role = self.find_role("Public")
            if public_role:
                self.add_permission_role(public_role, "can_login_by_email", "PseudoLoginView")
                logger.info("Added can_login_by_email on PseudoLoginView to Public role")
        except Exception as e:
            logger.error(f"Error adding permission to Public role: {e}")

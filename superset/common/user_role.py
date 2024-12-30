from flask import request, Response
from flask_appbuilder.api import expose, protect, safe, BaseApi
from superset.extensions import db
from flask_appbuilder.security.sqla.models import User, Role

from superset.views.base_api import statsd_metrics


class UserOrRoleApi(BaseApi):
    resource_name = "user_or_role"

    @expose("/", methods=["GET"])
    @protect()
    @safe
    def search_user_or_role(self) -> Response:
        """
        在同一个接口中查询用户和角色:
          1. 使用 ?search=xxx 查询用户 (username) 和角色 (role.name) 的模糊匹配
          2. 先把结果都查出来
          3. 若都为空，返回空列表 []（示例1）
             或者返回 {}（示例2）
             或者直接返回 404（示例3）
        """

        search_str = request.args.get("search", "").strip()
        if not search_str:
            # 如果必须要有搜索字符串，不允许为空，则可以返回 400
            return self.response_400(message="Parameter 'search' is required.")

        # --- 1. 查询 User ---
        user_query = db.session.query(User).filter(
            # 对 username 做大小写不敏感的模糊搜索
            User.username.ilike(f"%{search_str}%")
        )
        users = user_query.all()

        # --- 2. 查询 Role ---
        role_query = db.session.query(Role).filter(
            Role.name.ilike(f"%{search_str}%")
        )
        roles = role_query.all()

        # 如果仅想先“查用户，如果匹配到就立即返回”，可在此处判断 users 是否非空再返回，
        # 否则再查角色，但示例这里一次性把两者都查出来。

        # --- 3. 构造返回数据 ---
        user_data = [
            {
                "id": user.id,
                "username": user.username,
            }
            for user in users
        ]
        role_data = [
            {
                "id": role.id,
                "name": role.name,
            }
            for role in roles
        ]

        # 如果都为空，返回空结果 / {} / 404

        # (A) 返回空列表 []
        if not user_data and not role_data:
            # return self.response(200, result=[])
            # 可以同时返回一个message
            return self.response(200, result=[], message="No user or role found.")

        # (B) 也可以返回空字典 {}
        # if not user_data and not role_data:
        #     return self.response(200, result={})

        # (C) 或者干脆返回 404
        # if not user_data and not role_data:
        #     return self.response_404(
        #         message="No matching user or role found."
        #     )

        # 如果找到了用户或角色，则正常返回
        result = {
            "users": user_data,
            "roles": role_data,
        }
        return self.response(200, result=result)

    @expose("/users_and_roles/", methods=["GET"])
    @protect()
    @safe
    @statsd_metrics
    def get_users_and_roles(self) -> Response:
        """
        返回系统中所有用户和角色的简单信息（id, name）。
        GET /api/v1/chart/users_and_roles/
        """
        # 查询 ab_user, ab_role
        users = db.session.query(User).all()
        roles = db.session.query(Role).all()

        # 构造返回的用户数据
        user_data = [
            {
                "id": user.id,
                "name": f"{user.username or ''} {user.first_name or ''} {user.last_name or ''}".strip()
                # 或者使用 user.username / user.email ...
            }
            for user in users
        ]

        # 构造返回的角色数据
        role_data = [
            {
                "id": role.id,
                "name": role.name,
            }
            for role in roles
        ]

        # 以 JSON 格式返回
        result = {
            "users": user_data,
            "roles": role_data,
        }
        return self.response(200, result=result)

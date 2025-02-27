from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH
import os
import requests
from flask import request, redirect, Response, session, url_for
import logging
import json

# 生产环境密钥 - 确保使用强密码
SECRET_KEY = 'lyIKAEGRDGQw5RtU7pLQgPxrSaUvBiJQW1/067h1g/UkL4N8oYYh1iiF'

# 数据库配置 - 使用生产环境的数据库
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:123456@localhost:5432/superset'

# 企业微信配置
WECOM_CORP_ID = 'wwc2d2bc12f207d229'
WECOM_AGENT_ID = '1000015'
WECOM_SECRET = 'cw97sg0T1hRcxIRNr0BuWbiVs_0O1qpQQmVEv8tE8rc'
WECOM_REDIRECT_URI = 'https://bi.fullstack-dao.com/oauth-authorized/wecom'
WECOM_DEFAULT_EMAIL_DOMAIN = 'fullstack-dao.com'  # 设置默认邮箱域名

# Flask-AppBuilder 配置
FAB_INDEX_URL = '/superset/dashboard/list/'  # 修改登录后的默认页面
FAB_BASE_URL = '/superset'
FAB_API_URL = '/api/v1'
FAB_SECURITY_URL_PREFIX = '/security'
FAB_SECURITY_LOGIN_URL = '/security/login'

# 认证相关配置
AUTH_TYPE = AUTH_DB  # 保持使用数据库认证作为主认证方式
AUTHENTICATION_PROVIDERS = ["db", "oauth"]  # 同时支持数据库和 OAuth 认证
AUTH_USER_REGISTRATION = True  # 允许用户注册
AUTH_USER_REGISTRATION_ROLE = "Public"  # 新用户的默认角色
AUTH_OAUTH_ALLOW_DB = True  # 允许数据库认证
AUTH_OAUTH_ALLOW_MULTIPLE_PROVIDERS = True  # 允许多个OAuth提供者
AUTH_OAUTH_PROVIDER_DEFAULT = "wecom"  # 设置默认OAuth提供者

# OAuth 基本配置
AUTH_OAUTH_PROVIDERS = ["wecom", "wecom_h5"]
AUTH_OAUTH_PROVIDER_DEFAULT = None

# OAuth 回调配置
OAUTH_CALLBACK_ROUTE = '/oauth-authorized'

# 主页重定向配置
TALISMAN_ENABLED = False
PREVENT_UNSAFE_DEFAULT_URLS = False

# OAuth 提供者配置
OAUTH_PROVIDERS = [
    {
        'name': 'wecom',
        'icon': 'fa-weixin',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': WECOM_CORP_ID,
            'client_secret': WECOM_SECRET,
            'api_base_url': 'https://qyapi.weixin.qq.com/cgi-bin/',
            'request_token_url': None,
            'access_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={client_id}&corpsecret={client_secret}',
            'authorize_url': f'https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid={WECOM_CORP_ID}&agentid={WECOM_AGENT_ID}&redirect_uri={WECOM_REDIRECT_URI}',
            'request_token_params': {
                'scope': 'snsapi_privateinfo',
                'response_type': 'code',
            },
        },
    },
    {
        'name': 'wecom_h5',
        'icon': 'fa-weixin',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': WECOM_CORP_ID,
            'client_secret': WECOM_SECRET,
            'api_base_url': 'https://qyapi.weixin.qq.com/cgi-bin/',
            'request_token_url': None,
            'access_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={client_id}&corpsecret={client_secret}',
            'authorize_url': f'https://open.weixin.qq.com/connect/oauth2/authorize?appid={WECOM_CORP_ID}&redirect_uri=https://bi.fullstack-dao.com/oauth-authorized/wecom_h5&response_type=code&scope=snsapi_privateinfo&state=wecom_h5#wechat_redirect',
            'request_token_params': {
                'scope': 'snsapi_privateinfo',
                'response_type': 'code',
            },
        },
    }
]

# 安全配置
WTF_CSRF_ENABLED = True
FAB_ADD_SECURITY_VIEWS = True
FAB_ADD_SECURITY_PERMISSION_VIEW = True
FAB_ADD_SECURITY_VIEW_MENU_VIEW = True
FAB_ADD_SECURITY_PERMISSION_VIEWS_VIEW = True

# Session 配置
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = 1800  # 30分钟

# 代理配置 - 取消注释并启用
ENABLE_PROXY_FIX = True
PROXY_FIX_CONFIG = {"x_for": 1, "x_proto": 1, "x_host": 1, "x_port": 1, "x_prefix": 1}

# Babel 配置
BABEL_DEFAULT_LOCALE = 'zh'
BABEL_DEFAULT_FOLDER = 'superset/translations'
LANGUAGES = {
    'en': {'flag': 'us', 'name': 'English'},
    'zh': {'flag': 'cn', 'name': 'Chinese'},
}

# UI 配置
ENABLE_JAVASCRIPT_CONTROLS = True
FAB_SECURITY_UI_VIEWS = True
HIDE_EDIT_BUTTONS = False
MENU_HIDE_USER_SECTION = False

# 其他配置
COPILOT_URL = "http://your-copilot-url.com"
REPORT_URL = "http://your-report-url.com"
DOCS_URL = "http://your-docs-url.com"

# WEBDRIVER 配置
WEBDRIVER_BASEURL = "https://bi.fullstack-dao.com"  # 改为生产环境域名
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL

# 禁用欢迎页面
WELCOME_PAGE_LAST_TAB = False

# 设置登录页面
LOGIN_URL = '/login/'

# 添加 DATA_DIR 配置
DATA_DIR = os.path.join(os.path.expanduser('~'), '.superset')

# 添加调试日志
import logging
logger = logging.getLogger(__name__)

# 设置日志级别为DEBUG以获取更多信息
logging.getLogger('flask_appbuilder').setLevel(logging.DEBUG)
logging.getLogger('superset.security').setLevel(logging.DEBUG)

# 添加OAuth回调路由处理函数
def init_oauth_views(app):
    """
    确保OAuth回调路由被正确注册，并处理企业微信OAuth登录流程
    """
    from flask import redirect, request, Response, session, url_for
    import json
    import requests

    # 创建一个普通函数作为路由处理函数
    def oauth_callback_handler(provider):
        logger.info(f"收到OAuth回调: {provider}, 参数: {request.args}")

        # 获取请求参数
        code = request.args.get('code')
        state = request.args.get('state')

        if not code:
            logger.error("未获取到code参数")
            return Response(json.dumps({"error": "未获取到code参数"}), status=400, mimetype='application/json')

        # 处理企业微信OAuth回调
        if provider == 'wecom' or provider == 'wecom_h5':
            try:
                # 获取访问令牌
                token_url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={WECOM_CORP_ID}&corpsecret={WECOM_SECRET}"
                logger.info(f"请求访问令牌: {token_url}")

                token_response = requests.get(token_url)
                token_data = token_response.json()
                logger.info(f"访问令牌响应: {token_data}")

                if 'access_token' not in token_data:
                    logger.error(f"获取访问令牌失败: {token_data}")
                    return Response(json.dumps({"error": "获取访问令牌失败"}), status=500, mimetype='application/json')

                access_token = token_data['access_token']

                # 获取用户信息
                user_info_url = f"https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token={access_token}&code={code}"
                logger.info(f"请求用户信息: {user_info_url}")

                user_response = requests.get(user_info_url)
                user_data = user_response.json()
                logger.info(f"用户信息响应: {user_data}")

                if 'UserId' not in user_data:
                    logger.error(f"获取用户ID失败: {user_data}")
                    return Response(json.dumps({"error": "获取用户ID失败"}), status=500, mimetype='application/json')

                user_id = user_data['UserId']

                # 获取用户详细信息
                user_detail_url = f"https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token={access_token}&userid={user_id}"
                logger.info(f"请求用户详细信息: {user_detail_url}")

                detail_response = requests.get(user_detail_url)
                detail_data = detail_response.json()
                logger.info(f"用户详细信息响应: {detail_data}")

                if 'name' not in detail_data:
                    logger.error(f"获取用户名称失败: {detail_data}")
                    return Response(json.dumps({"error": "获取用户名称失败"}), status=500, mimetype='application/json')

                # 构建用户信息
                username = detail_data.get('userid', '')
                name = detail_data.get('name', '')
                # 使用硬编码的域名，避免依赖全局变量
                default_email_domain = 'fullstack-dao.com'
                email = detail_data.get('email', f"{username}@{default_email_domain}")

                # 将用户信息存储在session中，供后续使用
                user_info = {
                    'username': username,
                    'name': name,
                    'email': email,
                    'first_name': name,
                    'last_name': '',
                    'role_keys': [],
                    'provider': provider,  # 记录认证提供者
                }
                session['oauth_user_info'] = user_info
                logger.info(f"已将用户信息存储在session中: {user_info}")

                # 尝试手动注册和登录用户
                try:
                    # 导入需要的模块
                    from flask_appbuilder.security.sqla.models import User
                    from superset import db, security_manager

                    # 检查用户是否已存在
                    logger.info(f"检查用户 {username} 是否已存在")
                    user = db.session.query(User).filter_by(username=username).first()

                    if not user:
                        logger.info(f"用户 {username} 不存在，正在创建新用户")
                        # 创建新用户
                        role = security_manager.find_role(AUTH_USER_REGISTRATION_ROLE)
                        logger.info(f"为新用户分配角色: {AUTH_USER_REGISTRATION_ROLE}")
                        user = security_manager.add_user(
                            username=username,
                            first_name=name,
                            last_name="",
                            email=email,
                            role=role,
                            password="OAUTH_USER"  # 设置一个无法直接登录的密码
                        )
                        db.session.commit()
                        logger.info(f"成功创建用户 {username}，用户ID: {user.id}")
                    else:
                        logger.info(f"用户 {username} 已存在，用户ID: {user.id}，无需重新注册")

                        # 更新用户信息（可选）
                        logger.info(f"更新用户 {username} 的信息")
                        user.first_name = name
                        user.email = email
                        db.session.commit()
                        logger.info(f"已更新用户 {username} 的信息")

                    # 登录用户
                    from flask_login import login_user
                    login_user(user)
                    logger.info(f"用户 {username} 已登录")

                    # 设置登录成功的cookie或session标记
                    session['authenticated'] = True
                    session['user_id'] = user.id

                except Exception as e:
                    logger.exception(f"注册/登录用户时发生错误: {e}")
                    # 尝试标准OAuth流程作为备选
                    return redirect(f'/security/oauth-authorized/{provider}?code={code}&state={state}')

                # 重定向到首页
                # 直接使用硬编码的URL，避免依赖全局变量
                target_url = '/superset/welcome'
                logger.info(f"重定向到首页: {target_url}")
                return redirect(target_url)

            except Exception as e:
                logger.exception(f"处理OAuth回调时发生错误: {e}")
                return Response(json.dumps({"error": str(e)}), status=500, mimetype='application/json')

        # 对于其他提供者，尝试标准OAuth流程
        return redirect(f'/security/oauth-authorized/{provider}?code={code}&state={state}')

    # 注册路由
    app.add_url_rule(
        '/oauth-authorized/<provider>',
        'oauth_callback',
        oauth_callback_handler,
        methods=['GET', 'POST']
    )

    # 注册特定提供者的路由
    app.add_url_rule(
        '/oauth-authorized/wecom',
        'oauth_callback_wecom',
        oauth_callback_handler,
        defaults={'provider': 'wecom'},
        methods=['GET', 'POST']
    )

    app.add_url_rule(
        '/oauth-authorized/wecom_h5',
        'oauth_callback_wecom_h5',
        oauth_callback_handler,
        defaults={'provider': 'wecom_h5'},
        methods=['GET', 'POST']
    )

    # 添加企业微信登录入口点
    def wecom_login():
        """企业微信扫码登录入口点"""
        authorize_url = f'https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid={WECOM_CORP_ID}&agentid={WECOM_AGENT_ID}&redirect_uri={WECOM_REDIRECT_URI}&state=wecom'
        logger.info(f"重定向到企业微信授权页面: {authorize_url}")
        return redirect(authorize_url)

    def wecom_h5_login():
        """企业微信H5登录入口点"""
        authorize_url = f'https://open.weixin.qq.com/connect/oauth2/authorize?appid={WECOM_CORP_ID}&redirect_uri=https://bi.fullstack-dao.com/oauth-authorized/wecom_h5&response_type=code&scope=snsapi_privateinfo&state=wecom_h5#wechat_redirect'
        logger.info(f"重定向到企业微信H5授权页面: {authorize_url}")
        return redirect(authorize_url)

    # 添加自动检测企业微信环境并重定向的功能
    def auto_wecom_login():
        """检测企业微信环境并自动重定向到相应的登录方式"""
        user_agent = request.headers.get('User-Agent', '').lower()
        logger.info(f"检测到User-Agent: {user_agent}")

        # 检测是否在企业微信内打开
        is_wecom = 'wxwork' in user_agent or 'micromessenger' in user_agent

        if is_wecom:
            logger.info("检测到企业微信环境，自动重定向到企业微信H5登录")
            return wecom_h5_login()
        else:
            logger.info("非企业微信环境，显示标准登录页面")
            # 返回None，继续处理标准登录页面
            return None

    # 注册企业微信登录入口点
    app.add_url_rule(
        '/login/wecom',
        'wecom_login',
        wecom_login,
        methods=['GET']
    )

    app.add_url_rule(
        '/login/wecom_h5',
        'wecom_h5_login',
        wecom_h5_login,
        methods=['GET']
    )

    # 注册登录页面前置处理
    @app.before_request
    def before_request():
        # 只处理登录页面请求
        if request.path == '/login/' or request.path == '/login':
            result = auto_wecom_login()
            if result is not None:
                return result

    logger.info("OAuth回调路由和登录入口点已注册")
    return app

# 使用路由处理函数
FLASK_APP_MUTATOR = init_oauth_views

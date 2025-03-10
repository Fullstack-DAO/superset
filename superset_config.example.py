from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH
import os
import requests
from flask import request, redirect, Response, session, url_for
import logging
import json
import time

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

# 设置登录页面 - 修改为正确的路径
LOGIN_URL = '/security/login'

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

                # 直接使用企业邮箱(biz_mail)，如果为空则提示用户设置
                if 'biz_mail' in detail_data and detail_data['biz_mail']:
                    email = detail_data['biz_mail']
                    logger.info(f"从接口获取到企业邮箱: {email}")
                else:
                    logger.warning(f"用户 {username} 未设置企业邮箱")
                    # 设置session变量，用于前端显示提示
                    session['email_not_set'] = True
                    session['email_not_set_message'] = f"您的企业邮箱未设置，请先在企业微信中设置邮箱"
                    # 重定向到正确的登录页面
                    return redirect('/security/login?error=email_not_set')

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
                    from sqlalchemy import or_

                    # 同时根据用户名和企业邮箱查询用户
                    user = db.session.query(User).filter(
                        or_(
                            User.username == username,
                            User.email == email
                        )
                    ).first()

                    if not user:
                        logger.info(f"用户 {username} 或邮箱 {email} 不存在")

                        # 对于企业微信H5登录，如果有企业邮箱，则自动创建用户
                        if provider == 'wecom_h5':
                            logger.info(f"企业微信H5登录，自动创建用户 {username}")
                            # 创建新用户
                            user = security_manager.add_user(
                                username=username,
                                first_name=name,
                                last_name="",
                                email=email,
                                role=security_manager.find_role("Public"),  # 使用默认角色
                                password="",  # 空密码，因为使用OAuth登录
                            )
                            logger.info(f"已创建用户 {username}")
                        else:
                            # 对于非H5登录，仍然返回提示信息
                            session['user_not_found'] = True
                            session['user_not_found_message'] = f"用户 {username} 不存在，请先从企业微信工作台登录"
                            # 修改为正确的登录页面路径
                            return redirect('/security/login?error=user_not_found')
                    else:
                        logger.info(f"找到用户 {user.username}，邮箱 {user.email}")

                        # 更新用户信息（可选）
                        # 如果找到的用户名与当前用户名不同，可能需要更新
                        if user.username != username:
                            logger.info(f"用户名不匹配，更新用户名从 {user.username} 到 {username}")
                            user.username = username

                        user.first_name = name
                        user.email = email
                        db.session.commit()
                        logger.info(f"已更新用户信息")

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

                # 重定向到首页或仪表板列表
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
        # 使用完整的URL，确保所有参数正确
        redirect_uri = "https://bi.fullstack-dao.com/oauth-authorized/wecom_h5"
        # 确保URL编码正确
        import urllib.parse
        encoded_redirect_uri = urllib.parse.quote(redirect_uri, safe='')

        # 记录当前时间戳，防止缓存
        timestamp = int(time.time())

        # 构建授权URL - 注意：企业微信内部应用H5登录使用不同的URL格式
        authorize_url = (
            f'https://open.weixin.qq.com/connect/oauth2/authorize?'
            f'appid={WECOM_CORP_ID}&'
            f'redirect_uri={encoded_redirect_uri}&'
            f'response_type=code&'
            f'scope=snsapi_privateinfo&'
            f'agentid={WECOM_AGENT_ID}&'
            f'state=wecom_h5_{timestamp}#wechat_redirect'
        )

        logger.info(f"重定向到企业微信H5授权页面: {authorize_url}")

        # 清除会话中的重定向标记，确保下次可以正常重定向
        session.pop('redirect_attempted', None)
        session.modified = True

        return redirect(authorize_url)

    # 添加自动检测企业微信环境并重定向的功能
    def auto_wecom_login():
        """检测企业微信环境并自动重定向到相应的登录方式"""
        # 添加防止循环重定向的检查
        if session.get('redirect_attempted'):
            logger.info("检测到重定向循环，跳过自动重定向")
            return None

        user_agent = request.headers.get('User-Agent', '').lower()
        logger.info(f"检测到User-Agent: {user_agent}")

        # 检测是否在企业微信内打开 - 更精确的检测逻辑
        is_wecom = 'wxwork' in user_agent and ('micromessenger' in user_agent or 'wechatdevtools' in user_agent)

        # 添加请求路径和来源检查，避免API请求也被重定向
        is_login_page = request.path in ['/login/', '/login', '/security/login']
        is_direct_access = not request.referrer or 'login' in request.referrer.lower()

        if is_wecom and is_login_page and is_direct_access:
            logger.info("检测到企业微信环境，自动重定向到企业微信H5登录")
            # 设置标记，防止循环重定向
            session['redirect_attempted'] = True
            # 确保会话被保存
            session.modified = True
            return wecom_h5_login()
        else:
            if not is_wecom:
                logger.info("非企业微信环境，显示标准登录页面")
            elif not is_login_page:
                logger.info(f"非登录页面请求 ({request.path})，跳过重定向")
            elif not is_direct_access:
                logger.info(f"非直接访问登录页面 (来源: {request.referrer})，跳过重定向")
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
        # 只处理登录页面请求 - 添加 /security/login 路径
        if request.path in ['/login/', '/login', '/security/login']:
            # 清除会话中的重定向标记，如果这不是登录页面的请求
            if request.args.get('error') == 'redirect_loop':
                logger.warning("检测到重定向循环错误，清除重定向标记")
                session.pop('redirect_attempted', None)
                session.modified = True
                return None

            # 检查是否已经尝试过太多次重定向
            redirect_count = session.get('redirect_count', 0)
            if redirect_count > 3:
                logger.error("重定向次数过多，可能存在循环重定向")
                session.pop('redirect_attempted', None)
                session.pop('redirect_count', None)
                session.modified = True
                # 重定向到带有错误参数的登录页面
                return redirect('/security/login?error=redirect_loop')

            # 增加重定向计数
            session['redirect_count'] = redirect_count + 1
            session.modified = True

            result = auto_wecom_login()
            if result is not None:
                return result

            # 如果没有重定向，重置计数
            session.pop('redirect_count', None)
            session.modified = True

    logger.info("OAuth回调路由和登录入口点已注册")
    return app

# 使用路由处理函数
FLASK_APP_MUTATOR = init_oauth_views

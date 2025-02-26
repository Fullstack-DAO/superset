from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH
import os
import requests
from flask import request
import logging

# 生产环境密钥 - 确保使用强密码
SECRET_KEY = 'lyIKAEGRDGQw5RtU7pLQgPxrSaUvBiJQW1/067h1g/UkL4N8oYYh1iiF'

# 数据库配置 - 使用生产环境的数据库
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:123456@localhost:5432/superset'

# 企业微信配置
WECOM_CORP_ID = 'wwc2d2bc12f207d229'
WECOM_AGENT_ID = '1000015'
WECOM_SECRET = 'cw97sg0T1hRcxIRNr0BuWbiVs_0O1qpQQmVEv8tE8rc'
WECOM_REDIRECT_URI = 'https://bi.fullstack-dao.com/oauth-authorized/wecom'

# Flask-AppBuilder 配置
FAB_INDEX_URL = '/superset/dashboard/list/'  # 修改登录后的默认页面
FAB_BASE_URL = '/superset'
FAB_API_URL = '/api/v1'
FAB_SECURITY_URL_PREFIX = '/security'
FAB_SECURITY_LOGIN_URL = '/security/login'

# 认证相关配置
AUTH_TYPE = AUTH_DB  # 保持使用数据库认证作为主认证方式
AUTHENTICATION_PROVIDERS = ["db", "oauth"]  # 同时支持数据库和 OAuth 认证
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
AUTH_OAUTH_ALLOW_DB = True
AUTH_OAUTH_ALLOW_MULTIPLE_PROVIDERS = True

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
                'scope': 'snsapi_userinfo',
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
                'scope': 'snsapi_base',
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

# 自定义安全管理器，确保OAuth回调路由被正确注册
class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        logger.info("Custom security manager initialized")
        # 不需要重复实现oauth_user_info方法，因为已经在security/manager.py中实现了

# 使用自定义安全管理器
CUSTOM_SECURITY_MANAGER = CustomSecurityManager

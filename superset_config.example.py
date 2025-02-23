from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH

SECRET_KEY = 'lyIKAEGRDGQw5RtU7pLQgPxrSaUvBiJQW1/067h1g/UkL4N8oYYh1iiF'
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:123456@localhost:5432/superset'

# 企业微信配置参数
WECOM_CORP_ID = 'wwc2d2bc12f207d229'
WECOM_AGENT_ID = '1000015'
WECOM_SECRET = 'cw97sg0T1hRcxIRNr0BuWbiVs_0O1qpQQmVEv8tE8rc'
WECOM_REDIRECT_URI = 'https://bi.fullstack-dao.com/oauth-authorized/wecom'

# 认证相关配置
AUTH_TYPE = AUTH_DB  # 使用数据库认证
AUTHENTICATION_PROVIDERS = ["db", "oauth"]  # 同时支持数据库和 OAuth 认证
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"

# OAuth 基本配置
AUTH_OAUTH_PROVIDERS = ["wecom"]
AUTH_OAUTH_PROVIDER_DEFAULT = None  # 移除默认提供者
AUTH_OAUTH_ALLOW_DB = True
AUTH_OAUTH_ALLOW_MULTIPLE_PROVIDERS = True

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
            'client_kwargs': {
                'scope': 'snsapi_userinfo',
                'verify': False,
                'token_endpoint_auth_method': 'client_secret_post'
            },
            'authorize_url': 'https://open.work.weixin.qq.com/wwopen/sso/qrConnect',  # 扫码登录地址
            'h5_authorize_url': 'https://open.weixin.qq.com/connect/oauth2/authorize',  # H5 登录地址
            'access_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
            'authorize_params': {
                'appid': WECOM_CORP_ID,
                'agentid': WECOM_AGENT_ID,
                'redirect_uri': WECOM_REDIRECT_URI,
                'response_type': 'code',
                'scope': 'snsapi_userinfo',
                'state': 'wecom'
            },
            'h5_authorize_params': {
                'appid': WECOM_CORP_ID,
                'agentid': WECOM_AGENT_ID,
                'redirect_uri': WECOM_REDIRECT_URI,
                'response_type': 'code',
                'scope': 'snsapi_base',  # H5登录使用 base 即可
                'state': 'wecom_h5'
            }
        }
    }
]

# 安全配置
FAB_ADD_SECURITY_VIEWS = True
WTF_CSRF_ENABLED = False  # 本地开发时暂时禁用
FAB_ADD_SECURITY_PERMISSION_VIEW = False
FAB_ADD_SECURITY_VIEW_MENU_VIEW = False
FAB_ADD_SECURITY_PERMISSION_VIEWS_VIEW = False

# # 自定义安全管理器
# CUSTOM_SECURITY_MANAGER = "superset.security.SupersetSecurityManager"

# Session 配置
SESSION_COOKIE_SAMESITE = None
SESSION_COOKIE_SECURE = False  # 本地开发环境设置为 False
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = 1800  # 30分钟


# 安全配置
WTF_CSRF_ENABLED = False  # 本地开发时暂时禁用
FAB_ADD_SECURITY_VIEWS = True
PUBLIC_ROLE_LIKE = "Gamma"  # 设置默认角色权限
PUBLIC_ROLE_LIKE_GAMMA = True

# URL 配置
PREFERRED_URL_SCHEME = 'https'
LOGIN_REDIRECT_URL = '/superset/welcome'

# 代理配置
ENABLE_PROXY_FIX = True
ENABLE_PROXY_FIX_FOR_HTTPS = True
PROXY_FIX_CONFIG = {
    "x_for": 1,
    "x_proto": 1,
    "x_host": 1,
    "x_port": 1,
    "x_prefix": 0
}

# 基本 Session 配置 - 只保留必要的
SESSION_COOKIE_SAMESITE = None  # 允许跨站点 cookie
SESSION_COOKIE_SECURE = True    # 只在 HTTPS 下发送 cookie

# Babel 配置
BABEL_DEFAULT_LOCALE = 'zh'  # 设置默认语言为中文
BABEL_DEFAULT_FOLDER = 'superset/translations'  # 翻译文件目录
LANGUAGES = {
    'en': {'flag': 'us', 'name': 'English'},
    'zh': {'flag': 'cn', 'name': 'Chinese'},
}

# 服务器配置
ENABLE_PROXY_FIX = True
WEBSERVER_ADDRESS = "0.0.0.0"
WEBSERVER_PORT = 9000

# 认证和会话配置
SESSION_COOKIE_SAMESITE = None
SESSION_COOKIE_SECURE = False  # 本地开发环境必须为 False
SESSION_COOKIE_HTTPONLY = True  # 增强安全性


# 代理配置（保留一个统一的配置）
PROXY_FIX_CONFIG = {
    "x_for": 1,
    "x_proto": 1,
    "x_host": 1,
    "x_port": 1,
    "x_prefix": 0
}

# URL 配置
PREFERRED_URL_SCHEME = 'http'  # 本地开发使用 http
LOGIN_REDIRECT_URL = '/superset/welcome'  # 不要在末尾加斜杠

# 添加登录相关配置
FAB_ADD_SECURITY_VIEWS = True  # 启用安全视图
WTF_CSRF_ENABLED = True  # 启用 CSRF 保护
WTF_CSRF_EXEMPT_LIST = ['superset.views.core.log']  # CSRF 豁免列表

# 代理配置
ENABLE_PROXY_FIX_FOR_HTTPS = True
PROXY_FIX_CONFIG = {
    "x_for": 1,
    "x_proto": 1,
    "x_host": 1,
    "x_port": 1,
    "x_prefix": 0
}

# URL 配置
PREFERRED_URL_SCHEME = 'http'  # 本地开发使用 http
LOGIN_REDIRECT_URL = '/superset/welcome'

# 移除这些配置
# SERVER_NAME = 'bi.fullstack-dao.com'
# APPLICATION_ROOT = '/superset'
# SCRIPT_NAME = '/superset'

# 移动端适配配置
ENABLE_RESPONSIVE_DASHBOARD = True
DASHBOARD_MOBILE_BREAKPOINT = 768

# UI 配置
ENABLE_JAVASCRIPT_CONTROLS = True  # 启用 JavaScript 控件
FAB_SECURITY_UI_VIEWS = True      # 启用安全视图
HIDE_EDIT_BUTTONS = False         # 显示编辑按钮
FAB_ADD_SECURITY_VIEWS = True     # 启用安全视图
MENU_HIDE_USER_SECTION = False    # 显示用户菜单部分

# 功能开关
FEATURE_FLAGS = {
    'DASHBOARD_NATIVE_FILTERS': True,
    'DASHBOARD_CROSS_FILTERS': True,
    'DASHBOARD_NATIVE_FILTERS_SET': True,
    'ENABLE_TEMPLATE_PROCESSING': True,
    'ENABLE_TEMPLATE_REMOVE_FILTERS': True,
}

# 其他配置
COPILOT_URL = "http://your-copilot-url.com"
REPORT_URL = "http://your-report-url.com"
DOCS_URL = "http://your-docs-url.com"

# 修改 WEBDRIVER 配置
WEBDRIVER_BASEURL = "http://localhost:8088"
WEBDRIVER_BASEURL_USER_FRIENDLY = "https://bi.fullstack-dao.com"

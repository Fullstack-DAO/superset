from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH

SECRET_KEY = 'lyIKAEGRDGQw5RtU7pLQgPxrSaUvBiJQW1/067h1g/UkL4N8oYYh1iiF'
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:123456@localhost:5432/superset'

# 企业微信配置参数
WECOM_CORP_ID = 'wwc2d2bc12f207d229'
WECOM_AGENT_ID = '1000015'
WECOM_SECRET = 'cw97sg0T1hRcxIRNr0BuWbiVs_0O1qpQQmVEv8tE8rc'
WECOM_REDIRECT_URI = 'http://bi.fullstack-dao.com/oauth-authorized/wecom'  # 使用企业微信后台配置的域名

# 使用默认的 SupersetSecurityManager
CUSTOM_SECURITY_MANAGER = SupersetSecurityManager

# 认证相关配置
AUTH_TYPE = AUTH_DB
AUTHENTICATION_PROVIDERS = ["db", "oauth"]
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
ENABLE_WECOM_LOGIN = True

# 服务器配置
ENABLE_PROXY_FIX = True
WEBSERVER_ADDRESS = "0.0.0.0"
WEBSERVER_PORT = 9000  # 改为数字类型
PREFERRED_URL_SCHEME = 'http'

# 代理配置
PROXY_FIX_CONFIG = {
    "x_for": 1,
    "x_proto": 1,
    "x_host": 1,
    "x_port": 1,
    "x_prefix": 1
}

# 登录重定向配置
LOGIN_REDIRECT_URL = '/superset/welcome'

# OAuth 提供者配置
OAUTH_PROVIDERS = [
    {
        'name': 'wecom',
        'remote_app': {
            'client_id': WECOM_CORP_ID,
            'client_secret': WECOM_SECRET,
            'api_base_url': 'https://qyapi.weixin.qq.com/cgi-bin/',
            'client_kwargs': {
                'scope': 'snsapi_userinfo',  # 保持 snsapi_userinfo 用于扫码登录
                'verify': False,
                'token_endpoint_auth_method': 'client_secret_post'
            },
            'authorize_url': 'https://open.work.weixin.qq.com/wwopen/sso/qrConnect',  # 扫码登录地址
            'h5_authorize_url': 'https://open.weixin.qq.com/connect/oauth2/authorize',  # 新增 H5 登录地址
            'authorize_params': {
                'appid': WECOM_CORP_ID,
                'agentid': WECOM_AGENT_ID,
                'redirect_uri': WECOM_REDIRECT_URI,
                'response_type': 'code',
                'scope': 'snsapi_userinfo'  # 保持 snsapi_userinfo
            },
            'h5_authorize_params': {  # 新增 H5 授权参数
                'appid': WECOM_CORP_ID,
                'agentid': WECOM_AGENT_ID,
                'redirect_uri': WECOM_REDIRECT_URI,
                'response_type': 'code',
                'scope': 'snsapi_base'  # H5 使用 snsapi_base
            }
        }
    }
]

# 移动端适配配置
ENABLE_RESPONSIVE_DASHBOARD = True
DASHBOARD_MOBILE_BREAKPOINT = 768

# 其他配置
COPILOT_URL = "http://your-copilot-url.com"
REPORT_URL = "http://your-report-url.com"
DOCS_URL = "http://your-docs-url.com"

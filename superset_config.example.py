from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH

SECRET_KEY = 'lyIKAEGRDGQw5RtU7pLQgPxrSaUvBiJQW1/067h1g/UkL4N8oYYh1iiF'
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:123456@localhost:5432/superset'
# SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://superset:superset@47.93.23.80:5432/superset'

# 企业微信配置参数
WECOM_CORP_ID = 'wwc2d2bc12f207d229'
WECOM_AGENT_ID = '1000015'
WECOM_SECRET = 'cw97sg0T1hRcxIRNr0BuWbiVs_0O1qpQQmVEv8tE8rc'
WECOM_REDIRECT_URI = 'http://bi.fullstack-dao.com/oauth-authorized/wecom'  # 移除端口号

# OAuth 提供者配置（删除重复的配置）
OAUTH_PROVIDERS = [
    {
        'name': 'wecom',
        'icon': 'fa-wechat',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': WECOM_CORP_ID,
            'client_secret': WECOM_SECRET,
            'api_base_url': 'https://qyapi.weixin.qq.com/cgi-bin/',
            'client_kwargs': {
                'scope': 'snsapi_userinfo',
                'verify': False
            },
            'request_token_url': None,
            'access_token_method': 'GET',
            'access_token_params': {
                'corpid': WECOM_CORP_ID,
                'corpsecret': WECOM_SECRET
            },
            'access_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
            'authorize_url': f'https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid={WECOM_CORP_ID}&agentid={WECOM_AGENT_ID}&redirect_uri={WECOM_REDIRECT_URI}',
            'userinfo_url': 'https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo'
        }
    }
]

# 启用企业微信登录按钮
ENABLE_WECOM_LOGIN = True

# 用户注册配置
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"

# 修改认证类型，同时支持数据库和OAuth认证
AUTH_TYPE = AUTH_DB

# 认证提供者配置 - 同时支持数据库和OAuth认证
AUTHENTICATION_PROVIDERS = ["db", "oauth"]

# OAuth 提供者配置
OAUTH_PROVIDERS = [
    {
        'name': 'wecom',
        'icon': 'fa-wechat',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': WECOM_CORP_ID,
            'client_secret': WECOM_SECRET,
            'api_base_url': 'https://qyapi.weixin.qq.com/cgi-bin/',
            'client_kwargs': {
                'scope': 'snsapi_userinfo',
                'verify': False
            },
            'request_token_url': None,
            'access_token_method': 'GET',
            'access_token_params': {
                'corpid': WECOM_CORP_ID,
                'corpsecret': WECOM_SECRET
            },
            'access_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
            'authorize_url': f'https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid={WECOM_CORP_ID}&agentid={WECOM_AGENT_ID}&redirect_uri={WECOM_REDIRECT_URI}',
            'userinfo_url': 'https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo'
        }
    }
]




# 其他配置
COPILOT_URL = "http://your-copilot-url.com"
REPORT_URL = "http://your-report-url.com"
DOCS_URL = "http://your-docs-url.com"

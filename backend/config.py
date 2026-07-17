import os
import re
import json
import secrets
import warnings
from typing import List, Literal, Optional, Any, Self
from uuid import uuid4
import argparse
import enum
import runpy
import ssl as _ssl
from urllib.parse import urlparse
from sqlalchemy.engine.url import URL as EngineURL
from pydantic import (
    BaseModel,
    ConfigDict,
    HttpUrl,
    SecretStr,
    EmailStr,
    model_validator,
    field_validator, computed_field,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
    JsonConfigSettingsSource,
    CliApp,
    CliSettingsSource
)
from constants import PROJECT_DIR, BASE_DIR


def _parse_args(name='example', description=None, usage='%(prog)s [options] args'):
    parser = argparse.ArgumentParser(prog=name, description=description, usage=usage)
    parser.add_argument('--config', default='config.yaml', type=str, help='configs in yaml')
    parser.add_argument('--verbose', action='store_true', default=False, help='verbose')
    return parser


def run_migrations():
    import logging.config
    from alembic import command
    from alembic.config import Config as AlembicConfig
    try:
        alembic_cfg = AlembicConfig(BASE_DIR / 'alembic.ini')

        migrations_path = BASE_DIR / 'migrations'
        alembic_cfg.set_main_option('script_location', str(migrations_path))
        if alembic_cfg.config_file_name:
            logging.config.fileConfig(alembic_cfg.config_file_name, disable_existing_loggers=False)

        logging.info('Running migrations')
        command.upgrade(alembic_cfg, 'head')
    except Exception as e:
        logging.exception(f'Error running migrations: {e}')


class BaseConfig(BaseModel):
    model_config = ConfigDict(extra='ignore')


class Status(enum.Enum):
    RUNNING = 'running'
    PAUSED = 'paused'
    Stopped = 'stopped'


class Feishu(BaseConfig):
    WEBHOOK_URL: SecretStr
    WEBHOOK_SECRET: SecretStr


class DataBase(BaseConfig):
    # model_config = ConfigDict(arbitrary_types_allowed=True)
    # driver: Literal[
    #     'mysql',
    #     'postgresql',
    #     'sqlite'
    # ] = 'postgresql'
    # host: str = 'localhost'
    # port: Optional[int] = 5432
    # username: Optional[SecretStr] = None
    # password: Optional[SecretStr] = None
    # database: Optional[str] = None

    ENABLE_IAM_TOKEN_AUTH: bool = False
    ENABLE_SESSION_SHARING: bool = False
    POOL_SIZE: Optional[int] = 5
    POOL_MAX_OVERFLOW: int = 0
    POOL_TIMEOUT: int = 30
    POOL_RECYCLE: int = 3600
    ENABLE_SQLITE_WAL: bool = True
    SQLITE_PRAGMA_BUSY_TIMEOUT: str = '5000'
    SQLITE_PRAGMA_CACHE_SIZE: str = '-65536'
    SQLITE_PRAGMA_JOURNAL_SIZE_LIMIT: str = '67108864'
    SQLITE_PRAGMA_MMAP_SIZE: str = '268435456'
    SQLITE_PRAGMA_SYNCHRONOUS: str = 'NORMAL'
    SQLITE_PRAGMA_TEMP_STORE: str = 'MEMORY'

    URL: str = 'sqlite:///example.db'
    SCHEMA: Optional[str] = None

    # @computed_field  # type: ignore[prop-decorator]
    # @property
    # def url(self) -> EngineURL:
    #     if 'mysql' in self.driver:
    #         driver_name = 'mysql+pymysql'
    #     elif 'postgresql' in self.driver:
    #         driver_name = 'postgresql+psycopg'
    #     else:
    #         driver_name = 'sqlite+pysqlite'
    #     return EngineURL.create(
    #         driver_name,
    #         username=None if 'sqlite' in self.driver else self.username,
    #         password=None if 'sqlite' in self.driver else self.password,
    #         host=None if 'sqlite' in self.driver else self.host,
    #         port=None if 'sqlite' in self.driver else self.port,
    #         database=self.database or 'sqlite.db' if 'sqlite' in self.driver else self.database
    #     )


class Redis(BaseConfig):
    URL: str = ''
    CLUSTER: bool = False
    KEY_PREFIX: str = 'example'
    SENTINEL_HOSTS: str = ''
    SENTINEL_PORT: str = '26379'
    SENTINEL_MAX_RETRY_COUNT: int = 2
    SOCKET_CONNECT_TIMEOUT: Optional[float] = None
    SOCKET_KEEPALIVE: bool = False
    HEALTH_CHECK_INTERVAL: Optional[int] = None
    RECONNECT_DELAY: Optional[float] = None


class Zmq(BaseConfig):
    ENDPOINT: str = 'tcp://127.0.0.1'
    PORT: int = 5555
    TOPIC: Optional[str] = None


class Audit(BaseConfig):
    # Comma separated list of urls to include in audit (whitelist mode)
    # When set, only these paths are audited and EXCLUDED_PATHS is ignored
    INCLUDED_PATHS: list[str] = []
    # Comma separated list for urls to exclude from audit
    EXCLUDED_PATHS: list[str] = []
    LOG_LEVEL: Literal['NONE', 'METADATA', 'REQUEST', 'REQUEST_RESPONSE'] = 'NONE'
    ENABLE_GET_REQUESTS: bool = False
    MAX_BODY_LOG_SIZE: int = 2048

    @field_validator('INCLUDED_PATHS', 'EXCLUDED_PATHS', mode='before')
    @classmethod
    def format_paths(cls, value):
        return [path.lstrip('/') for path in value if path]


class AioHttp(BaseConfig):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    CLIENT_TIMEOUT: Optional[float] = None
    CLIENT_ALLOW_REDIRECTS: bool = False
    CLIENT_SESSION_SSL: 'bool | str | _ssl.SSLContext' = True
    CLIENT_SSL_CERT_FILE: str = ''
    POOL_CONNECTIONS: Optional[int] = 100
    POOL_CONNECTIONS_PER_HOST: Optional[int] = 30
    POOL_DNS_TTL: int = 300

    @staticmethod
    def _build_ssl_context_from_file(path: str) -> '_ssl.SSLContext | None':
        """Create an SSLContext from a CA bundle file, or None if invalid."""
        if not path:
            return None
        if not os.path.isfile(path):
            return None
        ctx = _ssl.create_default_context(cafile=path)
        return ctx

    @model_validator(mode='after')
    def _parse_ssl(self):
        """Parse an SSL env var into a bool or SSLContext.

        - ``"true"``  → uses ``CLIENT_SSL_CERT_FILE`` context if set,
          otherwise ``True``  (default SSL verification via certifi)
        - ``"false"`` → ``False`` (no verification)
        - ``"/path/to/ca-bundle.crt"`` → ``SSLContext`` loading that CA file
          (takes precedence over ``CLIENT_SSL_CERT_FILE``)

        This allows users with corporate or internal CAs to point server
        at a custom CA bundle without disabling verification entirely.
        """
        _GLOBAL_SSL_CONTEXT = AioHttp._build_ssl_context_from_file(self.CLIENT_SSL_CERT_FILE)
        if self.CLIENT_SESSION_SSL is True:
            # Use the global dedicated CA bundle if configured, otherwise default
            self.CLIENT_SESSION_SSL = _GLOBAL_SSL_CONTEXT if _GLOBAL_SSL_CONTEXT is not None else True
            return self
        if self.CLIENT_SESSION_SSL is False:
            return self
        # Treat as a file path to a CA bundle (per-connection override)
        ctx = AioHttp._build_ssl_context_from_file(self.CLIENT_SESSION_SSL.strip())
        if ctx is not None:
            self.CLIENT_SESSION_SSL = ctx
        # Path was invalid — fall back to default
        self.CLIENT_SESSION_SSL = _GLOBAL_SSL_CONTEXT if _GLOBAL_SSL_CONTEXT is not None else True
        return self


class Smtp(BaseConfig):
    TLS: bool = True
    SSL: bool = False
    PORT: int = 587
    HOST: str | None = None
    USER: str | None = None
    PASSWORD: str | None = None
    EMAILS_FROM_EMAIL: EmailStr | None = None
    EMAILS_FROM_NAME: str | None = None
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 48
    EMAIL_TEST_USER: EmailStr = "test@example.com"


class Auth(BaseConfig):
    ENABLE: bool = True
    ADMIN_EMAIL: EmailStr = 'admin@example.com'
    ADMIN_PASSWORD: SecretStr = ''
    ADMIN_NAME: str = 'Admin'
    JWT_EXPIRES_IN: str = '1w'
    ENABLE_API_KEYS: bool = False
    ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS: bool = False
    CUSTOM_API_KEY_HEADER: str = "x-api-key"
    SHOW_ADMIN_DETAILS: bool = True
    # ENABLE_PASSWORD_AUTH: bool = True
    API_KEYS_ALLOWED_ENDPOINTS: str = ''
    ENABLE_INITIAL_ADMIN_SIGNUP: bool = False
    ENABLE_SIGNUP_PASSWORD_CONFIRMATION: bool = False
    TRUSTED_SIGNATURE_KEY: bytes = b''
    ENABLE_PASSWORD_VALIDATION: bool = False
    COOKIE_NAME: str = 'example-session'
    COOKIE_SAME_SITE: Literal["lax", "strict", "none"] | None = 'lax'
    COOKIE_SECURE: bool = False
    PASSWORD_HASH_ALGORITHM: Literal['bcrypt', 'argon2'] = 'bcrypt'
    PASSWORD_VALIDATION_REGEX_PATTERN: re.Pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'
    PASSWORD_VALIDATION_HINT: str = ''
    TRUSTED_EMAIL_HEADER: Optional[str] = None
    TRUSTED_NAME_HEADER: Optional[str] = None
    TRUSTED_GROUPS_HEADER: Optional[str] = None
    TRUSTED_ROLE_HEADER: Optional[str] = None
    SIGNOUT_REDIRECT_URL: Optional[str] = None

    @field_validator('PASSWORD_VALIDATION_REGEX_PATTERN', mode='before')
    @classmethod
    def compile_regex_pattern(cls, value) -> re.Pattern:
        try:
            return re.compile(rf'{value}')
        except Exception:
            return re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$')


class WebSocket(BaseConfig):
    ENABLE: bool = True
    EVENT_CALLER_TIMEOUT: Optional[int] = None
    MANAGER: str = ''
    REDIS_LOCK_TIMEOUT: int = 60
    REDIS_OPTIONS: dict = {'socket_timeout': None, 'socket_connect_timeout': None}
    REDIS_URL: Optional[str] = None
    REDIS_CLUSTER: Optional[bool] = False
    SENTINEL_HOSTS: str = ''
    SENTINEL_PORT: str = '26379'
    SERVER_ENGINEIO_LOGGING: Optional[bool] = None
    SERVER_LOGGING: bool = False
    SERVER_PING_INTERVAL: int = 25
    SERVER_PING_TIMEOUT: int = 20

    @model_validator(mode='after')
    def validate(self):
        self.SERVER_ENGINEIO_LOGGING = self.SERVER_ENGINEIO_LOGGING or self.SERVER_LOGGING
        return self


class OAuth(BaseConfig):
    # General OAuth
    ENABLE_OAUTH_SIGNUP: Optional[bool] = False
    ENABLE_EMAIL_FALLBACK: bool = False
    ENABLE_ID_TOKEN_COOKIE: bool = True
    MERGE_ACCOUNTS_BY_EMAIL: Optional[bool] = False
    AUTO_REDIRECT: Optional[bool] = False
    ALLOWED_DOMAINS: list[str] = ['*']
    BLOCKED_GROUPS: str = '[]'
    PROVIDERS: dict = {}
    ACCESS_TOKEN_REQUEST_INCLUDE_CLIENT_ID: bool = False
    MAX_SESSIONS_PER_USER: int = 10
    CLIENT_INFO_ENCRYPTION_KEY: Optional[str] = None
    SESSION_TOKEN_ENCRYPTION_KEY: Optional[str] = None
    AUTHORIZE_PARAMS: dict = {}

    # Role management
    ENABLE_ROLE_MANAGEMENT: Optional[bool] = False
    ROLES_SEPARATOR: str = ','
    ROLES_CLAIM: Optional[str] = 'roles'
    ADMIN_ROLES: list[str] = ['admin']
    ALLOWED_ROLES: list[str] = ['user', 'admin']
    # DEFAULT_USER_ROLE: str = 'pending'

    # Group management
    ENABLE_GROUP_MANAGEMENT: Optional[bool] = False
    ENABLE_GROUP_CREATION: Optional[bool] = False
    GROUPS_SEPARATOR: str = ';'
    GROUPS_CLAIM: Optional[str] = 'groups'
    GROUP_DEFAULT_SHARE: bool | str | None = True

    # OIDC provider settings
    PROVIDER_NAME: str | None = None
    OPENID_PROVIDER_URL: str | None = None
    CLIENT_ID: str | None = None
    CLIENT_SECRET: str | None = None
    OPENID_REDIRECT_URI: str | None = None
    SCOPES: str | None = None
    CODE_CHALLENGE_METHOD: str | None = None
    TOKEN_ENDPOINT_AUTH_METHOD: str | None = None
    OPENID_END_SESSION_ENDPOINT: str | None = None
    TIMEOUT: int | str | None = None
    CLIENT_TIMEOUT: int | str | None = ''

    # Claims
    EMAIL_CLAIM: Optional[str] = 'email'
    USERNAME_CLAIM: Optional[str] = 'name'
    PICTURE_CLAIM: Optional[str] = 'picture'
    SUB_CLAIM: Optional[str] = None
    AUDIENCE: Optional[str] = ''

    # Profile update toggles
    UPDATE_EMAIL_ON_LOGIN: Optional[bool] = False
    UPDATE_NAME_ON_LOGIN: Optional[bool] = False
    UPDATE_PICTURE_ON_LOGIN: Optional[bool] = False

    # Token
    REFRESH_TOKEN_INCLUDE_SCOPE: Optional[bool] = False

    # Allows external apps to exchange OAuth tokens
    ENABLE_TOKEN_EXCHANGE: bool = False
    ENABLE_BACKCHANNEL_LOGOUT: bool = False


class Ldap(BaseModel):
    ENABLE: bool = False
    SERVER_LABEL: str = 'LDAP Server'
    SERVER_HOST: str = 'localhost'
    SERVER_PORT: int = 389
    ATTRIBUTE_FOR_MAIL: str = 'mail'
    ATTRIBUTE_FOR_USERNAME: str = 'uid'
    APP_DN: str = ''
    APP_PASSWORD: str = ''
    SEARCH_BASE: str = ''
    SEARCH_FILTERS: str = ''
    USE_TLS: bool = True
    CA_CERT_FILE: str = ''
    VALIDATE_CERT: bool = True
    CIPHERS: str = 'ALL'
    ENABLE_GROUP_MANAGEMENT: bool = False
    ENABLE_GROUP_CREATION: bool = False
    ATTRIBUTE_FOR_GROUPS: str = 'memberOf'


class Ui(BaseModel):
    ENABLE_SIGNUP: bool = True
    ENABLE_LOGIN_FORM: bool = True
    ENABLE_PASSWORD_CHANGE_FORM: bool = True
    DEFAULT_LOCALE: str = ''
    DEFAULT_USER_ROLE: str = 'pending'
    DEFAULT_GROUP_ID: str = ''
    ENABLE_USER_WEBHOOKS: bool = False


class _S3(BaseConfig):
    ACCESS_KEY_ID: Optional[str] = None
    SECRET_ACCESS_KEY: Optional[str] = None
    ADDRESSING_STYLE: Optional[str] = None
    BUCKET_NAME: Optional[str] = None
    ENABLE_TAGGING: Optional[str] = None
    ENDPOINT_URL: Optional[str] = None
    KEY_PREFIX: Optional[str] = None
    REGION_NAME: Optional[str] = None
    USE_ACCELERATE_ENDPOINT: Optional[str] = None


class System(BaseConfig):
    RESET_CONFIG_ON_START: bool = False
    WEBUI_URL: str = ''
    WEBHOOK_URL: str = ''

    DEFAULT_USER_PERMISSIONS: dict = {
        'access_grants': {
            'allow_users': True,
        },
        'features': {
            'api_keys': False,
            'folders': True,
            'webhooks': False,
        },
        'settings': {
            'interface': True,
        },
    }
    ENABLE_PERSISTENT_CONFIG: bool = True
    ENABLE_OAUTH_PERSISTENT_CONFIG: bool = False

    ENABLE_SCIM: bool = False
    # ENABLE_VERSION_UPDATE_CHECK: bool = False
    # ENABLE_PYODIDE_FILE_PERSISTENCE: bool = False
    # ENABLE_PUBLIC_ACTIVE_USERS_COUNT: bool = False
    # ENABLE_EASTER_EGGS: bool = True
    ENABLE_USER_STATUS: bool = True

    FILE_MAX_COUNT: Optional[int] = None
    FILE_MAX_SIZE: Optional[int] = None
    ALLOWED_FILE_EXTENSIONS: list[str] = []
    ENABLE_FOLDERS: bool = False
    FOLDER_MAX_FILE_COUNT: int | str | None = ''

    AUTH: Auth = Auth()
    BYPASS_ADMIN_ACCESS_CONTROL: bool = True
    OAUTH: OAuth = OAuth()
    LDAP: Ldap = Ldap()
    UI: Ui = Ui()
    AUDIT: Audit = Audit()
    AIOHTTP: AioHttp = AioHttp()
    WEBSOCKET: WebSocket = WebSocket()
    STORAGE_PROVIDER: Literal["local", "s3"] = "local"
    S3: _S3 = _S3()

    # @model_validator(mode='after')
    # def config(self):
    #     from models.config import Config
    #     Config.configure(
    #         defaults=self.DEFAULT_CONFIG,
    #         enable_persistent=self.ENABLE_PERSISTENT_CONFIG,
    #         enable_oauth_persistent=self.ENABLE_OAUTH_PERSISTENT_CONFIG,
    #     )
    #     return self

    @computed_field
    @property
    def USER_PERMISSIONS(self) -> dict:
        return self.DEFAULT_USER_PERMISSIONS

    @computed_field
    @property
    def DEFAULT_CONFIG(self) -> dict:
        return {
            'file.max_count': self.FILE_MAX_COUNT,
            'file.max_size': self.FILE_MAX_SIZE,
            'file.allowed_extensions': self.ALLOWED_FILE_EXTENSIONS,
            'folders.enable': self.ENABLE_FOLDERS,
            'folders.max_file_count': self.FOLDER_MAX_FILE_COUNT,
            'user.permissions': self.USER_PERMISSIONS,
            'users.enable_status': self.ENABLE_USER_STATUS,
            'webui.url': self.WEBUI_URL,
            'webhook_url': self.WEBHOOK_URL,
            'ui.enable_signup': self.UI.ENABLE_SIGNUP,
            'ui.enable_login_form': self.UI.ENABLE_LOGIN_FORM,
            'ui.enable_password_change_form': self.UI.ENABLE_PASSWORD_CHANGE_FORM,
            'ui.default_locale': self.UI.DEFAULT_LOCALE,
            'ui.default_user_role': self.UI.DEFAULT_USER_ROLE,
            'ui.default_group_id': self.UI.DEFAULT_GROUP_ID,
            'ui.enable_user_webhooks': self.UI.ENABLE_USER_WEBHOOKS,
            'auth.admin.show': self.AUTH.SHOW_ADMIN_DETAILS,
            'auth.admin.email': self.AUTH.ADMIN_EMAIL,
            'auth.enable_api_keys': self.AUTH.ENABLE_API_KEYS,
            'auth.api_key.endpoint_restrictions': self.AUTH.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS,
            'auth.api_key.allowed_endpoints': self.AUTH.API_KEYS_ALLOWED_ENDPOINTS,
            'auth.jwt_expiry': self.AUTH.JWT_EXPIRES_IN,
            'oauth.enable_signup': self.OAUTH.ENABLE_OAUTH_SIGNUP,
            'oauth.auto_redirect': self.OAUTH.AUTO_REDIRECT,
            'oauth.refresh_token.include_scope': self.OAUTH.REFRESH_TOKEN_INCLUDE_SCOPE,
            'oauth.merge_accounts_by_email': self.OAUTH.MERGE_ACCOUNTS_BY_EMAIL,
            'oauth.client_id': self.OAUTH.CLIENT_ID,
            'oauth.client_secret': self.OAUTH.CLIENT_SECRET,
            'oauth.provider_url': self.OAUTH.OPENID_PROVIDER_URL,
            'oauth.end_session_endpoint': self.OAUTH.OPENID_END_SESSION_ENDPOINT,
            'oauth.redirect_uri': self.OAUTH.OPENID_REDIRECT_URI,
            'oauth.scopes': self.OAUTH.SCOPES,
            'oauth.timeout': self.OAUTH.TIMEOUT,
            'oauth.client.timeout': self.OAUTH.CLIENT_TIMEOUT,
            'oauth.token_endpoint_auth_method': self.OAUTH.TOKEN_ENDPOINT_AUTH_METHOD,
            'oauth.code_challenge_method': self.OAUTH.CODE_CHALLENGE_METHOD,
            'oauth.provider_name': self.OAUTH.PROVIDER_NAME,
            'oauth.sub_claim': self.OAUTH.SUB_CLAIM,
            'oauth.username_claim': self.OAUTH.USERNAME_CLAIM,
            'oauth.picture_claim': self.OAUTH.PICTURE_CLAIM,
            'oauth.email_claim': self.OAUTH.EMAIL_CLAIM,
            'oauth.group_claim': self.OAUTH.GROUPS_CLAIM,
            'oauth.enable_role_mapping': self.OAUTH.ENABLE_ROLE_MANAGEMENT,
            'oauth.enable_group_mapping': self.OAUTH.ENABLE_GROUP_MANAGEMENT,
            'oauth.enable_group_creation': self.OAUTH.ENABLE_GROUP_CREATION,
            'oauth.group_default_share': self.OAUTH.GROUP_DEFAULT_SHARE,
            'oauth.blocked_groups': self.OAUTH.BLOCKED_GROUPS,
            'oauth.roles_claim': self.OAUTH.ROLES_CLAIM,
            'oauth.allowed_roles': self.OAUTH.ALLOWED_ROLES,
            'oauth.admin_roles': self.OAUTH.ADMIN_ROLES,
            'oauth.allowed_domains': self.OAUTH.ALLOWED_DOMAINS,
            'oauth.update_picture_on_login': self.OAUTH.UPDATE_PICTURE_ON_LOGIN,
            'oauth.update_name_on_login': self.OAUTH.UPDATE_NAME_ON_LOGIN,
            'oauth.update_email_on_login': self.OAUTH.UPDATE_EMAIL_ON_LOGIN,
            'oauth.audience': self.OAUTH.AUDIENCE,
            'ldap.enable': self.LDAP.ENABLE,
            'ldap.server.label': self.LDAP.SERVER_LABEL,
            'ldap.server.host': self.LDAP.SERVER_HOST,
            'ldap.server.port': self.LDAP.SERVER_PORT,
            'ldap.server.attribute_for_mail': self.LDAP.ATTRIBUTE_FOR_MAIL,
            'ldap.server.attribute_for_username': self.LDAP.ATTRIBUTE_FOR_USERNAME,
            'ldap.server.app_dn': self.LDAP.APP_DN,
            'ldap.server.app_password': self.LDAP.APP_PASSWORD,
            'ldap.server.users_dn': self.LDAP.SEARCH_BASE,
            'ldap.server.search_filter': self.LDAP.SEARCH_FILTERS,
            'ldap.server.use_tls': self.LDAP.USE_TLS,
            'ldap.server.ca_cert_file': self.LDAP.CA_CERT_FILE,
            'ldap.server.validate_cert': self.LDAP.VALIDATE_CERT,
            'ldap.server.ciphers': self.LDAP.CIPHERS,
            'ldap.group.enable_management': self.LDAP.ENABLE_GROUP_MANAGEMENT,
            'ldap.group.enable_creation': self.LDAP.ENABLE_GROUP_CREATION,
            'ldap.server.attribute_for_groups': self.LDAP.ATTRIBUTE_FOR_GROUPS,
        }


class Spec(BaseModel):
    model_config = ConfigDict(extra='allow')


def parse_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and not v.startswith("["):
        return [i.strip() for i in v.split(",") if i.strip()]
    elif isinstance(v, list | str):
        return v
    raise ValueError(v)


class Settings(BaseSettings):
    PROJECT_NAME: str = "Backend Example"
    APP_TITLE: str = "Backend Example"
    APP_DESCRIPTION: str = "Example for backend"
    VERSION: str = json.loads((PROJECT_DIR / 'package.json').read_text()).get('version', '0.0.1')
    COMMIT_ID: str = 'ecd48e2'
    INSTANCE_ID: str = os.getenv('INSTANCE_ID', str(uuid4()))
    THREAD_POOL_SIZE: Optional[int] = None
    API_ROOT_PATH: str = "/api/v1"
    ENV: Literal["dev", "staging", "production"] = "dev"

    # DEBUG: bool = True
    FRONTEND_URL: str = "http://localhost:5173"

    SECRET_KEY: str = "85e6545531e0551b09c9f11f470d7db10979a4b0c1ea9a4605652ef5772dd143"  # openssl rand -hex 32
    # SECRET_KEY: str = secrets.token_urlsafe(32)
    # ENABLE_AUTH: bool = True
    # JWT_ALGORITHM: str = "HS256"
    # JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    # JWT_EXPIRES_IN: str = '1w'

    ENABLE_DB_MIGRATIONS: bool = True
    ENABLE_OTEL: bool = False
    # SENTRY_DSN: HttpUrl | None = None

    # ACCOUNT: str = 'test'
    RUN_MODULE: Optional[str] = None
    STATUS: Status = Status.RUNNING
    SMTP: Optional[Smtp] = Smtp()
    DATABASE: Optional[DataBase] = None
    REDIS: Optional[Redis] = Redis()
    ZMQ: Optional[Zmq] = Zmq()
    SYSTEM: Optional[System] = System()
    SPEC: Optional[Spec] = Spec()

    CORS_ORIGINS: List[str] = ['http://localhost:8000']
    # BACKEND_CORS_ORIGINS: Annotated[
    #     list[AnyUrl] | str, BeforeValidator(parse_cors)
    # ] = []
    # CORS_ALLOW_ORIGINS: list[str] = ['http://localhost:5173', 'http://localhost:8000']
    CORS_ALLOW_CUSTOM_SCHEME: list[str] = []
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List = ["*"]
    CORS_ALLOW_HEADERS: List = ["*"]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def name(self) -> str:
        return '-'.join([s.lower() for s in self.PROJECT_NAME.split()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def CORS_ALLOW_ORIGINS(self) -> list[str]:
        if '*' in self.CORS_ORIGINS:
            return ['*']
        else:
            return [str(origin).rstrip('/') for origin in self.CORS_ORIGINS + [self.FRONTEND_URL]]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def emails_enabled(self) -> bool:
        return bool(self.SMTP.HOST and self.SMTP.EMAILS_FROM_EMAIL)

    def _check_default_secret(self, var_name: str, value: str | None) -> None:
        if value == "changethis":
            message = (
                f'The value of {var_name} is "changethis", '
                "for security, please change it, at least for deployments."
            )
            if self.ENV == "dev":
                warnings.warn(message, stacklevel=1)
            else:
                raise ValueError(message)

    @model_validator(mode="after")
    def _validate_after(self) -> Self:
        self._check_default_secret("SECRET_KEY", self.SECRET_KEY)
        # self._check_default_secret(
        #     "FIRST_SUPERUSER_PASSWORD", self.FIRST_SUPERUSER_PASSWORD
        # )
        if not self.SMTP.EMAILS_FROM_NAME:
            self.SMTP.EMAILS_FROM_NAME = self.PROJECT_NAME
        if self.CORS_ALLOW_ORIGINS != ['*']:
            # You have to pick between a single wildcard or a list of origins.
            # Doing both will result in CORS errors in the browser.
            for origin in self.CORS_ALLOW_ORIGINS:
                self.validate_cors_origin(origin)
        return self

    def validate_cors_origin(self, origin):
        parsed_url = urlparse(origin)

        # Check if the scheme is either http or https, or a custom scheme
        schemes = ['http', 'https'] + self.CORS_ALLOW_CUSTOM_SCHEME
        if parsed_url.scheme not in schemes:
            raise ValueError(
                f"Invalid scheme in CORS_ALLOW_ORIGINS: '{origin}'. Only 'http' and 'https' and CORS_ALLOW_CUSTOM_SCHEME are allowed."
            )

        # Ensure that the netloc (domain + port) is present, indicating it's a valid URL
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL structure in CORS_ALLOW_ORIGINS: '{origin}'.")


    # TORTOISE_ORM: dict = {
    #     "connections": {
    #         # SQLite configuration
    #         "sqlite": {
    #             "engine": "tortoise.backends.sqlite",
    #             "credentials": {"file_path": f"{BASE_DIR}/db.sqlite3"},  # Path to SQLite database file
    #         },
    #         # PostgreSQL configuration
    #         # Install with: tortoise-orm[asyncpg]
    #         "postgres": {
    #             "engine": "tortoise.backends.asyncpg",
    #             "credentials": {
    #                 "host": "127.0.0.1",
    #                 "port": 5432,
    #                 "user": "postgres",
    #                 "password": "test123",
    #                 "database": "example",
    #             },
    #         },
    #     },
    #     "apps": {
    #         "models": {
    #             "models": ["models", "aerich.models"],
    #             "default_connection": "postgres",
    #         },
    #     },
    #     "use_tz": False,  # Whether to use timezone-aware datetimes
    #     "timezone": "Etc/GMT",  # Timezone setting
    # }
    # DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"

    model_config = SettingsConfigDict(
        extra='ignore',
        case_sensitive=False,
        nested_model_default_partial_update=True,
        validate_default=True,
        # enable_decoding=False,
        # env_prefix='',
        env_file=('.env', f'.env.{os.getenv('ENV', 'dev')}'),
        env_file_encoding='utf-8',
        env_nested_delimiter='__',
        # env_ignore_empty=True,
        # env_parse_none_str='null',
        env_parse_enums=True,
        cli_parse_args=True,
        cli_implicit_flags=True,
        cli_avoid_json=False,
        cli_kebab_case=True,
        cli_enforce_required=False,
        cli_ignore_unknown_args=True,
        cli_hide_none_type=True,
        cli_exit_on_error=True,
        yaml_file='config.yaml',
        yaml_file_encoding='utf-8',
        # yaml_config_section='settings',
        json_file='config.json',
        json_file_encoding='utf-8',
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
            YamlConfigSettingsSource(settings_cls),
            JsonConfigSettingsSource(settings_cls),
        )

    def cli_cmd(self) -> None:
        # CliApp.run_subcommand(self)
        global settings
        settings = self
        os.environ['NAME'] = settings.name
        os.environ['ENV'] = settings.ENV
        # os.environ['ACCOUNT'] = settings.ACCOUNT
        os.environ['ENABLE_OTEL'] = 'true' if settings.ENABLE_OTEL else 'false'
        if self.RUN_MODULE:
            runpy.run_module(self.RUN_MODULE, run_name='__main__', alter_sys=True)


def parse_settings(settings_class: type[Settings] = Settings, args_parser: Optional[argparse.ArgumentParser] = _parse_args()):
    cli_args = []
    global settings
    if args_parser:
        known_args, cli_args = args_parser.parse_known_args()
        if known_args.config.endswith('json'):
            settings_class.model_config['json_file'] = known_args.config
        elif known_args.config.endswith('yaml'):
            settings_class.model_config['yaml_file'] = known_args.config

    settings =  CliApp.run(
        settings_class,
        # cli_args=cli_args,
        cli_settings_source=CliSettingsSource(settings_class, root_parser=args_parser),
    )
    if settings.SYSTEM is not None:
        from models.config import Config

        Config.configure(
            defaults=settings.SYSTEM.DEFAULT_CONFIG,
            enable_persistent=settings.SYSTEM.ENABLE_PERSISTENT_CONFIG,
            enable_oauth_persistent=settings.SYSTEM.ENABLE_OAUTH_PERSISTENT_CONFIG,
        )
    if settings.ENABLE_DB_MIGRATIONS:
        run_migrations()
    return settings


settings: Optional['Settings'] = None
def get_settings(reload: bool = True):
    global settings
    if settings is None:
        raise ValueError("settings are not parsed")
    if reload:
        settings = type(settings)()
    return settings


if __name__ == "__main__":
    _settings = parse_settings()

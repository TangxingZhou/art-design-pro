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
    field_validator,
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
    driver: Literal[
        'mysql',
        'postgresql',
        'sqlite'
    ] = 'postgresql'
    host: str = 'localhost'
    port: Optional[int] = 5432
    username: Optional[SecretStr] = None
    password: Optional[SecretStr] = None
    database: Optional[str] = None

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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> EngineURL:
        if 'mysql' in self.driver:
            driver_name = 'mysql+pymysql'
        elif 'postgresql' in self.driver:
            driver_name = 'postgresql+psycopg'
        else:
            driver_name = 'sqlite+pysqlite'
        return EngineURL.create(
            driver_name,
            username=None if 'sqlite' in self.driver else self.username,
            password=None if 'sqlite' in self.driver else self.password,
            host=None if 'sqlite' in self.driver else self.host,
            port=None if 'sqlite' in self.driver else self.port,
            database=self.database or 'sqlite.db' if 'sqlite' in self.driver else self.database
        )


class Redis(BaseConfig):
    URL: str
    CLUSTER: bool = False
    KEY_PREFIX: str = 'example'
    SENTINEL_HOSTS: str = ''
    SENTINEL_PORT: str = '26379'
    SENTINEL_MAX_RETRY_COUNT: int = 2
    SOCKET_CONNECT_TIMEOUT: Optional[float] = None
    SOCKET_KEEPALIVE: bool = False
    HEALTH_CHECK_INTERVAL: Optional[int] = None
    RECONNECT_DELAY: Optional[float] = None


class ZMQ(BaseConfig):
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

        This allows users with corporate or internal CAs to point Open WebUI
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
    ENABLE_INITIAL_ADMIN_SIGNUP: bool = False
    ENABLE_SIGNUP_PASSWORD_CONFIRMATION: bool = False
    TRUSTED_SIGNATURE_KEY: bytes = b''
    ENABLE_PASSWORD_VALIDATION: bool = False
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
    DEFAULT_USER_ROLE: str = 'pending'
    ENABLE_SIGNUP: bool = False
    ENABLE_EMAIL_FALLBACK: bool = False
    ENABLE_ID_TOKEN_COOKIE: bool = True
    ACCESS_TOKEN_REQUEST_INCLUDE_CLIENT_ID: bool = False
    MAX_SESSIONS_PER_USER: int = 10
    ADMIN_ROLES: list[str] = ['admin']
    ALLOWED_DOMAINS: list[str] = ['*']
    ALLOWED_ROLES: list[str] = ['user', 'admin']
    AUDIENCE: str = ''
    AUTHORIZE_PARAMS: dict = {}
    BLOCKED_GROUPS = '[]'
    CLIENT_INFO_ENCRYPTION_KEY: Optional[str] = None
    SESSION_TOKEN_ENCRYPTION_KEY: Optional[str] = None
    CLIENT_TIMEOUT: str = ''
    EMAIL_CLAIM: str = 'email'
    GROUP_DEFAULT_SHARE: str | bool = True
    GROUPS_CLAIM: str = 'groups'
    GROUPS_SEPARATOR: str = ';'
    ENABLE_GROUP_MANAGEMENT: bool = False
    ENABLE_GROUP_CREATION: bool = False
    MERGE_ACCOUNTS_BY_EMAIL: bool = False
    PICTURE_CLAIM: str = 'picture'
    PROVIDERS: dict = {}
    REFRESH_TOKEN_INCLUDE_SCOPE: bool = False
    ROLES_CLAIM: str = 'roles'
    ROLES_SEPARATOR: str = ','
    ENABLE_ROLE_MANAGEMENT: bool = False
    SUB_CLAIM = None
    UPDATE_EMAIL_ON_LOGIN: bool = False
    UPDATE_NAME_ON_LOGIN: bool = False
    UPDATE_PICTURE_ON_LOGIN: bool = False
    USERNAME_CLAIM: str = 'name'
    # Allows external apps to exchange OAuth tokens
    ENABLE_TOKEN_EXCHANGE: bool = False
    ENABLE_BACKCHANNEL_LOGOUT: bool = False


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


class Platform(BaseConfig):
    pass


class Spec(BaseModel):
    model_config = ConfigDict(extra='allow')
    DEFAULT_USER_PERMISSIONS = {
        # 'workspace': {
        #     'models': USER_PERMISSIONS_WORKSPACE_MODELS_ACCESS,
        #     'knowledge': USER_PERMISSIONS_WORKSPACE_KNOWLEDGE_ACCESS,
        #     'prompts': USER_PERMISSIONS_WORKSPACE_PROMPTS_ACCESS,
        #     'tools': USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS,
        #     'skills': USER_PERMISSIONS_WORKSPACE_SKILLS_ACCESS,
        #     'models_import': USER_PERMISSIONS_WORKSPACE_MODELS_IMPORT,
        #     'models_export': USER_PERMISSIONS_WORKSPACE_MODELS_EXPORT,
        #     'prompts_import': USER_PERMISSIONS_WORKSPACE_PROMPTS_IMPORT,
        #     'prompts_export': USER_PERMISSIONS_WORKSPACE_PROMPTS_EXPORT,
        #     'tools_import': USER_PERMISSIONS_WORKSPACE_TOOLS_IMPORT,
        #     'tools_export': USER_PERMISSIONS_WORKSPACE_TOOLS_EXPORT,
        #     'skills_import': USER_PERMISSIONS_WORKSPACE_SKILLS_IMPORT,
        #     'skills_export': USER_PERMISSIONS_WORKSPACE_SKILLS_EXPORT,
        # },
        # 'sharing': {
        #     'models': USER_PERMISSIONS_WORKSPACE_MODELS_ALLOW_SHARING,
        #     'public_models': USER_PERMISSIONS_WORKSPACE_MODELS_ALLOW_PUBLIC_SHARING,
        #     'knowledge': USER_PERMISSIONS_WORKSPACE_KNOWLEDGE_ALLOW_SHARING,
        #     'public_knowledge': USER_PERMISSIONS_WORKSPACE_KNOWLEDGE_ALLOW_PUBLIC_SHARING,
        #     'prompts': USER_PERMISSIONS_WORKSPACE_PROMPTS_ALLOW_SHARING,
        #     'public_prompts': USER_PERMISSIONS_WORKSPACE_PROMPTS_ALLOW_PUBLIC_SHARING,
        #     'tools': USER_PERMISSIONS_WORKSPACE_TOOLS_ALLOW_SHARING,
        #     'public_tools': USER_PERMISSIONS_WORKSPACE_TOOLS_ALLOW_PUBLIC_SHARING,
        #     'skills': USER_PERMISSIONS_WORKSPACE_SKILLS_ALLOW_SHARING,
        #     'public_skills': USER_PERMISSIONS_WORKSPACE_SKILLS_ALLOW_PUBLIC_SHARING,
        #     'notes': USER_PERMISSIONS_NOTES_ALLOW_SHARING,
        #     'public_notes': USER_PERMISSIONS_NOTES_ALLOW_PUBLIC_SHARING,
        #     'folders': USER_PERMISSIONS_FOLDERS_ALLOW_SHARING,
        #     'public_chats': USER_PERMISSIONS_CHAT_ALLOW_PUBLIC_SHARING,
        #     'public_calendars': USER_PERMISSIONS_CALENDAR_ALLOW_PUBLIC_SHARING,
        # },
        # 'access_grants': {
        #     'allow_users': USER_PERMISSIONS_ACCESS_GRANTS_ALLOW_USERS,
        # },
        # 'chat': {
        #     'controls': USER_PERMISSIONS_CHAT_CONTROLS,
        #     'valves': USER_PERMISSIONS_CHAT_VALVES,
        #     'system_prompt': USER_PERMISSIONS_CHAT_SYSTEM_PROMPT,
        #     'params': USER_PERMISSIONS_CHAT_PARAMS,
        #     'file_upload': USER_PERMISSIONS_CHAT_FILE_UPLOAD,
        #     'web_upload': USER_PERMISSIONS_CHAT_WEB_UPLOAD,
        #     'delete': USER_PERMISSIONS_CHAT_DELETE,
        #     'delete_message': USER_PERMISSIONS_CHAT_DELETE_MESSAGE,
        #     'continue_response': USER_PERMISSIONS_CHAT_CONTINUE_RESPONSE,
        #     'regenerate_response': USER_PERMISSIONS_CHAT_REGENERATE_RESPONSE,
        #     'rate_response': USER_PERMISSIONS_CHAT_RATE_RESPONSE,
        #     'edit': USER_PERMISSIONS_CHAT_EDIT,
        #     'share': USER_PERMISSIONS_CHAT_SHARE,
        #     'export': USER_PERMISSIONS_CHAT_EXPORT,
        #     'import': USER_PERMISSIONS_CHAT_IMPORT,
        #     'stt': USER_PERMISSIONS_CHAT_STT,
        #     'tts': USER_PERMISSIONS_CHAT_TTS,
        #     'call': USER_PERMISSIONS_CHAT_CALL,
        #     'multiple_models': USER_PERMISSIONS_CHAT_MULTIPLE_MODELS,
        #     'temporary': USER_PERMISSIONS_CHAT_TEMPORARY,
        #     'temporary_enforced': USER_PERMISSIONS_CHAT_TEMPORARY_ENFORCED,
        # },
        # 'features': {
        #     # General features
        #     'api_keys': USER_PERMISSIONS_FEATURES_API_KEYS,
        #     'notes': USER_PERMISSIONS_FEATURES_NOTES,
        #     'folders': USER_PERMISSIONS_FEATURES_FOLDERS,
        #     'channels': USER_PERMISSIONS_FEATURES_CHANNELS,
        #     'direct_tool_servers': USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS,
        #     # Chat features
        #     'web_search': USER_PERMISSIONS_FEATURES_WEB_SEARCH,
        #     'image_generation': USER_PERMISSIONS_FEATURES_IMAGE_GENERATION,
        #     'code_interpreter': USER_PERMISSIONS_FEATURES_CODE_INTERPRETER,
        #     'memories': USER_PERMISSIONS_FEATURES_MEMORIES,
        #     'automations': USER_PERMISSIONS_FEATURES_AUTOMATIONS,
        #     'calendar': USER_PERMISSIONS_FEATURES_CALENDAR,
        #     'webhooks': USER_PERMISSIONS_FEATURES_USER_WEBHOOKS,
        # },
        # 'settings': {
        #     'interface': USER_PERMISSIONS_SETTINGS_INTERFACE,
        # },
    }


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
    # PROJECT_ROOT: str = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    # BASE_DIR: str = os.path.abspath(os.path.join(PROJECT_ROOT, os.pardir))
    # LOGS_ROOT: str = os.path.join(BASE_DIR, "logs")
    VERSION: str = json.loads((PROJECT_DIR / 'package.json').read_text())
    INSTANCE_ID = os.getenv('INSTANCE_ID', str(uuid4()))

    ENABLE_DB_MIGRATIONS = os.getenv('ENABLE_DB_MIGRATIONS', 'True').lower() == 'true'

    DEBUG: bool = True

    ENV: Literal["dev", "staging", "production"] = "dev"
    FRONTEND_HOST: str = "http://localhost:5173"
    API_V1_STR: str = "/api/v1"

    THREAD_POOL_SIZE: Optional[int] = None
    RESET_CONFIG_ON_START: bool = False

    SECRET_KEY: str = "85e6545531e0551b09c9f11f470d7db10979a4b0c1ea9a4605652ef5772dd143"  # openssl rand -hex 32
    # SECRET_KEY: str = secrets.token_urlsafe(32)
    ENABLE_AUTH: bool = True
    ENABLE_WEBSOCKET: bool = True
    ENABLE_SCIM: bool = False
    ENABLE_EMAIL_FALLBACK: bool = False
    CUSTOM_API_KEY_HEADER: str = "x-api-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    JWT_EXPIRES_IN: str = '1w'

    SENTRY_DSN: HttpUrl | None = None
    ENABLE_OTEL: bool = False
    WEBHOOK_URL: HttpUrl = ''

    CORS_ORIGINS: List = ["*"]
    # BACKEND_CORS_ORIGINS: Annotated[
    #     list[AnyUrl] | str, BeforeValidator(parse_cors)
    # ] = []
    CORS_ALLOW_ORIGINS: list[str] = ['http://localhost:5173', 'http://localhost:8080']
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
    def all_cors_origins(self) -> list[str]:
        return [str(origin).rstrip("/") for origin in self.CORS_ORIGINS] + [
            self.FRONTEND_HOST
        ]

    DATABASE: Optional[DataBase] = None
    # POSTGRES_SERVER: str
    # POSTGRES_PORT: int = 5432
    # POSTGRES_USER: str
    # POSTGRES_PASSWORD: str = ""
    # POSTGRES_DB: str = ""
    #
    # @computed_field  # type: ignore[prop-decorator]
    # @property
    # def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn:
    #     return PostgresDsn.build(
    #         scheme="postgresql+psycopg",
    #         username=self.POSTGRES_USER,
    #         password=self.POSTGRES_PASSWORD,
    #         host=self.POSTGRES_SERVER,
    #         port=self.POSTGRES_PORT,
    #         path=self.POSTGRES_DB,
    #     )

    # SMTP_TLS: bool = True
    # SMTP_SSL: bool = False
    # SMTP_PORT: int = 587
    # SMTP_HOST: str | None = None
    # SMTP_USER: str | None = None
    # SMTP_PASSWORD: str | None = None
    # EMAILS_FROM_EMAIL: EmailStr | None = None
    # EMAILS_FROM_NAME: str | None = None
    # EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 48
    # EMAIL_TEST_USER: EmailStr = "test@example.com"
    FIRST_SUPERUSER: EmailStr = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changethis"
    ADMIN_EMAIL: EmailStr = ''
    ADMIN_PASSWORD: str = ''
    ADMIN_NAME: str = 'Admin'
    BYPASS_ADMIN_ACCESS_CONTROL: bool = True
    SMTP: Optional[Smtp] = Smtp()

    # @model_validator(mode="after")
    # def _set_default_emails_from(self) -> Self:
    #     if not self.SMTP.EMAILS_FROM_NAME:
    #         self.SMTP.EMAILS_FROM_NAME = self.PROJECT_NAME
    #     return self

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
    def _enforce_non_default_secrets(self) -> Self:
        self._check_default_secret("SECRET_KEY", self.SECRET_KEY)
        # self._check_default_secret("DATABASE.database", self.DATABASE.database)
        self._check_default_secret(
            "FIRST_SUPERUSER_PASSWORD", self.FIRST_SUPERUSER_PASSWORD
        )
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
                f"Invalid scheme in CORS_ALLOW_ORIGIN: '{origin}'. Only 'http' and 'https' and CORS_ALLOW_CUSTOM_SCHEME are allowed."
            )

        # Ensure that the netloc (domain + port) is present, indicating it's a valid URL
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL structure in CORS_ALLOW_ORIGIN: '{origin}'.")


    TORTOISE_ORM: dict = {
        "connections": {
            # SQLite configuration
            "sqlite": {
                "engine": "tortoise.backends.sqlite",
                "credentials": {"file_path": f"{BASE_DIR}/db.sqlite3"},  # Path to SQLite database file
            },
            # PostgreSQL configuration
            # Install with: tortoise-orm[asyncpg]
            "postgres": {
                "engine": "tortoise.backends.asyncpg",
                "credentials": {
                    "host": "127.0.0.1",
                    "port": 5432,
                    "user": "postgres",
                    "password": "test123",
                    "database": "example",
                },
            },
        },
        "apps": {
            "models": {
                "models": ["models", "aerich.models"],
                "default_connection": "postgres",
            },
        },
        "use_tz": False,  # Whether to use timezone-aware datetimes
        "timezone": "Etc/GMT",  # Timezone setting
    }
    DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"

    # env: str = os.getenv('ENV', 'dev')
    ACCOUNT: str = 'test'
    RUN_MODULE: Optional[str] = None
    FEISHU: Optional[Feishu] = None
    REDIS: Optional[Redis] = None
    ZMQ: Optional[ZMQ] = None
    PLATFORM: Optional[Platform] = None
    SPEC: Optional[Spec] = None
    STATUS: Status = Status.RUNNING
    AUDIT: Audit = Audit()
    AUTH: Auth = Auth()
    OAUTH: OAuth = OAuth()
    AIOHTTP: AioHttp = AioHttp()
    WEBSOCKET: WebSocket = WebSocket()
    STORAGE_PROVIDER: Literal["local", "s3"] = "local"
    S3: _S3 = _S3()

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
        # os.environ['ENV'] = settings.env
        os.environ['ACCOUNT'] = settings.ACCOUNT
        if self.RUN_MODULE:
            runpy.run_module(self.RUN_MODULE, run_name='__main__', alter_sys=True)


def parse_settings(settings_class: type[Settings] = Settings, args_parser: Optional[argparse.ArgumentParser] = _parse_args()):
    cli_args = []
    if args_parser:
        known_args, cli_args = args_parser.parse_known_args()
        if known_args.config.endswith('json'):
            settings_class.model_config['json_file'] = known_args.config
        elif known_args.config.endswith('yaml'):
            settings_class.model_config['yaml_file'] = known_args.config
    return CliApp.run(
        settings_class,
        # cli_args=cli_args,
        cli_settings_source=CliSettingsSource(settings_class, root_parser=args_parser),
    )


settings: Optional['Settings'] = None
def get_settings(reload: bool = True):
    global settings
    if settings is None:
        raise ValueError("settings are not parsed")
    if reload:
        settings = type(Settings)()
    return settings


if __name__ == "__main__":
    _settings = parse_settings()

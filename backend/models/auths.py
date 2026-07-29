"""Auth credential models and data-access layer."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import bcrypt
from utils.db import Base, get_async_db_context
from models.users import (
    USERNAME_MAX_LENGTH,
    User,
    UserModel,
    UserProfileImageResponse,
    Users,
    normalize_username,
)
from utils.validate import validate_profile_image_url
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import Boolean, Column, String, Text, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

# Pre-computed hash verified on signin paths that lack a real credential
# (unknown user, inactive account) so response timing cannot reveal
# whether an account exists (CWE-208).
PLACEHOLDER_HASH = bcrypt.hashpw(b'placeholder', bcrypt.gensalt()).decode('utf-8')
PasswordVerifier = Callable[[str], Awaitable[bool]]


class Auth(Base):  # credential ↔ user linkage
    """Maps a user ID to an email/password pair with an active flag."""

    __tablename__ = 'auth'

    id = Column(String, primary_key=True, unique=True)  # mirrors User.id
    email = Column(String)  # login address, kept in sync with User.email
    password = Column(Text)  # argon2 / bcrypt hash
    active = Column(Boolean)  # account soft-disable toggle


class AuthModel(BaseModel):
    """Pydantic mirror of the ``auth`` table row."""

    id: str
    email: str
    password: str
    active: bool = True


class Token(BaseModel):
    """JWT bearer-token response wrapper."""

    token: str
    token_type: str


class ApiKey(BaseModel):
    api_key: str | None = None


class SigninResponse(Token, UserProfileImageResponse):
    pass


class SigninForm(BaseModel):
    email: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1, max_length=50)
    password: str

    @field_validator('email', 'username')
    @classmethod
    def normalize_identity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError('login identity cannot be blank')
        return normalized

    @model_validator(mode='after')
    def require_one_identity(self) -> 'SigninForm':
        if (self.email is None) == (self.username is None):
            raise ValueError('provide exactly one of email or username')
        return self


class LdapForm(BaseModel):
    user: str
    password: str


class ProfileImageUrlForm(BaseModel):
    profile_image_url: str


class UpdatePasswordForm(BaseModel):
    password: str
    new_password: str


class SignupForm(BaseModel):
    name: str
    email: str
    username: str | None = Field(default=None, max_length=USERNAME_MAX_LENGTH)
    password: str
    profile_image_url: str | None = '/user.png'

    @field_validator('username', mode='before')
    @classmethod
    def normalize_optional_username(cls, value: str | None) -> str | None:
        # Treat an empty optional input as omitted so creation can derive the
        # default username from the display name.
        return normalize_username(value)

    @field_validator('profile_image_url')
    @classmethod
    def check_profile_image_url(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_profile_image_url(v)
        return v


class AddUserForm(SignupForm):
    role: str | None = 'pending'


# --- data-access layer ---


class AuthsTable:
    """Provides CRUD operations for the Auth ↔ User lifecycle."""

    async def insert_new_auth(
        self,
        email: str,
        password: str,
        name: str,
        profile_image_url: str = '/user.png',
        role: str = 'pending',
        username: str | None = None,
        oauth: dict | None = None,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Create an Auth + User pair inside a single transaction."""
        async with get_async_db_context(db) as session:
            log.info('insert_new_auth')

            new_id = str(uuid.uuid4())

            credential = Auth(
                id=new_id,
                email=email,
                password=password,
                active=True,
            )
            session.add(credential)

            try:
                created_user = await Users.insert_new_user(
                    new_id,
                    name,
                    email,
                    profile_image_url,
                    role,
                    username=username,
                    oauth=oauth,
                    db=session,
                )
                # persist both records and reload generated defaults
                await session.commit()
                await session.refresh(credential)
                return created_user if credential and created_user else None
            except Exception:
                await session.rollback()
                raise

    async def _authenticate_user_by_identity(
        self,
        identity: str,
        identity_column: Any,
        verify_password: PasswordVerifier,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Authenticate one unambiguous user identity without leaking account state."""
        normalized_identity = identity.strip().lower()
        async with get_async_db_context(db) as session:
            query = (
                select(Auth, User)
                .join(User, Auth.id == User.id)
                .where(func.lower(identity_column) == normalized_identity)
                .limit(2)
            )
            matches = (await session.execute(query)).all()

            # Usernames are not yet constrained as unique in every deployed
            # database. Never select an arbitrary account when duplicates exist.
            if len(matches) != 1:
                if len(matches) > 1:
                    log.warning('Multiple users matched the login identity column %s', identity_column.key)
                await verify_password(PLACEHOLDER_HASH)
                return

            credential, user = matches[0]
            if not credential or not credential.active:
                await verify_password(PLACEHOLDER_HASH)
                return
            if not await verify_password(credential.password):
                return
            return UserModel.model_validate(user)

    async def authenticate_user(
        self,
        email: str,
        verify_password: PasswordVerifier,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Verify email + password credentials and return the matching user."""
        log.info('authenticate_user: %s', email)
        return await self._authenticate_user_by_identity(email, User.email, verify_password, db=db)

    async def authenticate_user_by_username(
        self,
        username: str,
        verify_password: PasswordVerifier,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Verify username + password credentials and return the matching user."""
        log.info('authenticate_user_by_username')
        return await self._authenticate_user_by_identity(username, User.username, verify_password, db=db)

    async def authenticate_user_by_api_key(
        self,
        api_key: str,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Look up the user that owns the given API key."""
        log.info('authenticate_user_by_api_key')
        if not api_key:
            return
        # delegate to the Users model for the actual lookup
        return await Users.get_user_by_api_key(api_key, db=db)

    async def authenticate_user_by_email(
        self,
        email: str,
        db: AsyncSession | None = None,
    ) -> UserModel | None:
        """Single-query auth via JOIN on Auth ↔ User, filtered by active flag."""
        log.info('authenticate_user_by_email: %s', email)
        # single JOIN avoids N+1 — returns (Auth, User) tuple or None
        async with get_async_db_context(db) as session:
            joined_query = (
                select(Auth, User).join(User, Auth.id == User.id).where(Auth.email == email, Auth.active.is_(True))
            )
            match = (await session.execute(joined_query)).first()
            if not match:
                return
            _, found_user = match
            return UserModel.model_validate(found_user)

    async def update_email_by_id(
        self,
        user_id: str,
        email: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Set a new email on the auth record and propagate to the user row."""
        async with get_async_db_context(db) as session:
            auth_row = await session.get(Auth, user_id)
            if auth_row is None:
                return False
            auth_row.email = email
            await session.commit()
            await Users.update_user_by_id(user_id, {'email': email}, db=session)
            return True
        # --- password modification ---

    async def update_user_password_by_id(
        self,
        user_id: str,
        new_password: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Set a new password hash for an existing user."""
        async with get_async_db_context(db) as session:
            auth_row = await session.get(Auth, user_id)
            if auth_row is None:
                return False
            auth_row.password = new_password
            await session.commit()
            return True

    async def delete_auth_by_id(
        self,
        id: str,
        db: AsyncSession | None = None,
    ) -> bool:
        """Remove a user and their auth credential in one transaction."""
        async with get_async_db_context(db) as session:
            if not await Users.delete_user_by_id(id, db=session):
                return False
            await session.execute(delete(Auth).where(Auth.id == id))
            await session.commit()
            return True


Auths = AuthsTable()  # singleton — module-level instance

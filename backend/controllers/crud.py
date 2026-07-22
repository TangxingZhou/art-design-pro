from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Generic, Literal, TypeVar

from fastapi import status
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator
from sqlalchemy import String, func, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, NoInspectionAvailable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import SQLModel

from constants import ERROR_MESSAGES
from utils.db import Base, get_async_db_context


class Query(BaseModel):
    """Generic list-query parameters.

    ``params`` is a field-to-value mapping. Every entry is an exact-match
    condition and multiple entries are joined with AND.
    """

    model_config = ConfigDict(extra="forbid")

    params: dict[str, Any] = Field(default_factory=lambda: {"_keyword": None})
    limit: int = Field(default=10, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
    order_by: str | None = None
    order: Literal["asc", "desc"] = "desc"

    @field_validator("params")
    @classmethod
    def include_keyword(cls, value: dict[str, Any]) -> dict[str, Any]:
        return value if "_keyword" in value else {"_keyword": None, **value}


class ResponseListSchema(BaseModel):
    total: int = 0
    items: list[Any] = Field(default_factory=list)


class ResponseSchema(BaseModel):
    code: int = status.HTTP_200_OK
    message: str | None = None
    data: Any = None


# The CRUD accepts both SQLModel tables and the project's declarative Base
# models. Runtime inspection below remains the authoritative model check.
SqlModelType = TypeVar("SqlModelType", bound=SQLModel | Base)
CreateFormType = TypeVar("CreateFormType", bound=BaseModel)
UpdateFormType = TypeVar("UpdateFormType", bound=BaseModel)
ResponseModelType = TypeVar("ResponseModelType", bound=BaseModel)
ResponseSchemaType = TypeVar("ResponseSchemaType", bound=ResponseSchema)
ResponseListSchemaType = TypeVar("ResponseListSchemaType", bound=ResponseListSchema)


class QueryError(ValueError):
    """Raised when a filter or sort expression is invalid or not allowed."""


class CRUD(
    Generic[
        SqlModelType,
        CreateFormType,
        UpdateFormType,
        ResponseModelType,
        ResponseSchemaType,
        ResponseListSchemaType,
    ]
):
    """Reusable async SQLAlchemy/SQLModel CRUD service.

    Filter example::

        Query(
            params={'status_code': 200, 'request_method': 'GET', '_keyword': None},
            order_by='created_at',
            order='desc',
            limit=50,
            offset=0,
        )

    Filter and sort fields are validated against the mapped columns of
    ``sql_model``. Subclasses that accept ``params['_keyword']`` must implement
    ``build_keyword_filter``.

    Object lookup always uses the model primary key. Models with composite
    primary keys accept a mapping or tuple as ``_id``.
    """

    def __init__(
        self,
        sql_model: type[SqlModelType],
        response_model: type[ResponseModelType],
        response_schema: type[ResponseSchemaType] = ResponseSchema,
        response_list_schema: type[ResponseListSchemaType] = ResponseListSchema,
    ) -> None:
        try:
            mapper = sa_inspect(sql_model)
        except NoInspectionAvailable as exc:
            raise TypeError(f"{sql_model!r} is not a mapped SQLAlchemy/SQLModel class") from exc

        self.sql_model = sql_model
        self.response_model = response_model
        self.response_schema = response_schema
        self.response_list_schema = response_list_schema

        self._columns = {attribute.key: getattr(sql_model, attribute.key) for attribute in mapper.column_attrs}
        self._column_types = {attribute.key: attribute.columns[0].type for attribute in mapper.column_attrs}
        self._primary_keys = tuple(column.key for column in mapper.primary_key)
        self._type_adapters = self._build_type_adapters()

    def _build_type_adapters(self) -> dict[str, TypeAdapter[Any] | None]:
        adapters: dict[str, TypeAdapter[Any] | None] = {}
        for field, column_type in self._column_types.items():
            try:
                python_type = column_type.python_type
                adapters[field] = TypeAdapter(python_type)
            except (AttributeError, NotImplementedError, TypeError):
                if self._is_string_column_type(column_type):
                    adapters[field] = TypeAdapter(str)
                else:
                    adapters[field] = None
        return adapters

    def _response(self, code: int, *, data: Any = None, message: str | None = None) -> ResponseSchemaType:
        return self.response_schema.model_validate({"code": code, "message": message, "data": data})

    def _serialize(self, obj: SqlModelType) -> ResponseModelType:
        return self.response_model.model_validate(obj, from_attributes=True)

    @staticmethod
    def _escape_like(value: Any) -> str:
        return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @staticmethod
    async def _hash_password(password: str) -> str:
        """Hash a plaintext password for a CRUD subclass when required.

        Password handling is opt-in because most CRUD models have no password
        field. A subclass can call this helper before delegating a password
        update operation to ``super()``::

            password_hash = await self._hash_password(form_data.password)
            return await super().update(_id, {"password": password_hash}, db=db)

        Existing bcrypt and Argon2 hashes are returned unchanged to prevent
        accidental double hashing. The local import avoids making authentication
        initialization a dependency of every module that imports generic CRUD.
        """

        from utils.auth import get_password_hash, is_password_hash

        if not password or is_password_hash(password):
            return password

        return await get_password_hash(password)

    def _coerce_scalar(self, field: str, value: Any) -> Any:
        if value is None:
            return None
        adapter = self._type_adapters[field]
        if adapter is None:
            return value
        try:
            return adapter.validate_python(value)
        except ValidationError as exc:
            raise QueryError(f"invalid value for filter field {field}: {value!r}") from exc

    @staticmethod
    def _is_string_column_type(column_type: Any) -> bool:
        return isinstance(column_type, String) or isinstance(getattr(column_type, "impl", None), String)

    def _build_filters(self, params: Mapping[str, Any]) -> list[ColumnElement[bool]]:
        filters: list[ColumnElement[bool]] = []
        for field, raw_value in params.items():
            if field not in self._columns:
                raise QueryError(f"unknown filter field: {field}")

            value = self._coerce_scalar(field, raw_value)
            column = self._columns[field]
            filters.append(column.is_(None) if value is None else column == value)

        return filters

    def build_keyword_filter(self, keyword: Any) -> ColumnElement[bool]:
        """Build the module-specific keyword expression.

        Subclasses should override this method and return one SQLAlchemy
        boolean expression, combining multiple searchable fields themselves.
        """

        raise QueryError(f"keyword filtering is not implemented for {self.sql_model.__name__}")

    @staticmethod
    def _has_keyword(keyword: Any) -> bool:
        if keyword is None:
            return False
        if isinstance(keyword, str):
            return bool(keyword.strip())
        return True

    def _build_order_by(
        self,
        requested: str | None,
        *,
        direction: Literal["asc", "desc"],
    ) -> list[ColumnElement[Any]]:
        order_expressions: list[ColumnElement[Any]] = []
        if requested is not None:
            if requested not in self._columns:
                raise QueryError(f"unknown sort field: {requested}")

            column = self._columns[requested]
            order_expressions.append(column.desc() if direction == "desc" else column.asc())

        return order_expressions

    def _validate_write_data(
        self,
        data: Mapping[str, Any],
        operation: str,
        *,
        allow_primary_keys: bool,
    ) -> None:
        unknown = set(data).difference(self._columns)
        if unknown:
            raise ValueError(f'{operation} contains unknown fields: {", ".join(sorted(unknown))}')
        if not allow_primary_keys:
            primary_keys = set(data).intersection(self._primary_keys)
            if primary_keys:
                raise ValueError(
                    f'{operation} cannot write primary-key fields: {", ".join(sorted(primary_keys))}'
                )

    def _create_instance(self, data: Mapping[str, Any]) -> SqlModelType:
        """Create a mapped instance and run SQLModel's Pydantic validators.

        ``table=True`` SQLModel classes bypass Pydantic field validators when
        called through their regular constructor. ``model_validate`` is needed
        for create-time transformations such as password hashing. Traditional
        SQLAlchemy declarative models continue to use their normal constructor.
        """

        if issubclass(self.sql_model, SQLModel):
            return self.sql_model.model_validate(dict(data))
        return self.sql_model(**dict(data))

    def _normalize_identity(self, identity: Any) -> dict[str, Any]:
        if isinstance(identity, Mapping):
            missing = set(self._primary_keys).difference(identity)
            extra = set(identity).difference(self._primary_keys)
            if missing or extra:
                expected = ", ".join(self._primary_keys)
                raise QueryError(f"identity must contain exactly these fields: {expected}")
            raw_values = [identity[field] for field in self._primary_keys]
        elif len(self._primary_keys) == 1:
            raw_values = [identity]
        elif isinstance(identity, Sequence) and not isinstance(identity, (str, bytes, bytearray)):
            if len(identity) != len(self._primary_keys):
                raise QueryError(f"identity expects {len(self._primary_keys)} values")
            raw_values = list(identity)
        else:
            expected = ", ".join(self._primary_keys)
            raise QueryError(f"composite identity must be a mapping or sequence for fields: {expected}")

        return {
            field: self._coerce_scalar(field, value)
            for field, value in zip(self._primary_keys, raw_values, strict=True)
        }

    async def _get_object(self, session: AsyncSession, values: Mapping[str, Any]) -> SqlModelType | None:
        primary_key = tuple(values[field] for field in self._primary_keys)
        return await session.get(
            self.sql_model,
            primary_key[0] if len(primary_key) == 1 else primary_key,
        )

    async def _get_one_by_fields(
        self,
        params: Mapping[str, Any],
        db: AsyncSession | None = None,
    ) -> ResponseSchemaType:
        """Return one record identified by exact-match business fields.

        This protected helper is intended for business-specific methods on a
        CRUD subclass. All entries in ``params`` are joined with AND, validated
        against the mapped columns, and converted to the column's Python type.

        The supplied field or field combination should have a database unique
        constraint. No match returns 404; multiple matches return 409.

        Example::

            class UserCRUD(CRUD):
                async def get_by_email(self, email: str, db=None):
                    return await self._get_one_by_fields(
                        {"email": email},
                        db=db,
                    )

            class OrderCRUD(CRUD):
                async def get_by_order_no(self, order_no: str, db=None):
                    return await self._get_one_by_fields(
                        {"order_no": order_no},
                        db=db,
                    )

        Use the public ``get`` method when looking up a record by primary key.
        """

        if not params:
            return self._response(
                status.HTTP_400_BAD_REQUEST,
                message="lookup fields cannot be empty",
            )

        try:
            filters = self._build_filters(params)
        except QueryError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        async with get_async_db_context(db) as session:
            stmt = select(self.sql_model).where(*filters)
            try:
                obj = (await session.execute(stmt)).scalars().one_or_none()
            except MultipleResultsFound:
                return self._response(
                    status.HTTP_409_CONFLICT,
                    message="lookup fields matched multiple records; fields must uniquely identify one record",
                )

            if obj is None:
                return self._response(
                    status.HTTP_404_NOT_FOUND,
                    message=ERROR_MESSAGES.NOT_FOUND,
                )

            return self._response(status.HTTP_200_OK, data=self._serialize(obj))

    async def get(self, _id: Any, db: AsyncSession | None = None) -> ResponseSchemaType:
        try:
            identity = self._normalize_identity(_id)
        except QueryError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        async with get_async_db_context(db) as session:
            obj = await self._get_object(session, identity)
            if obj is None:
                return self._response(
                    status.HTTP_404_NOT_FOUND,
                    message=ERROR_MESSAGES.NOT_FOUND,
                )
            return self._response(status.HTTP_200_OK, data=self._serialize(obj))

    async def list(self, query: Query | None = None, db: AsyncSession | None = None) -> ResponseSchemaType:
        query = query or Query()

        try:
            keyword = query.params.get("_keyword")
            filters = self._build_filters(
                {field: value for field, value in query.params.items() if field != "_keyword"}
            )
            keyword_filter = self.build_keyword_filter(keyword) if self._has_keyword(keyword) else None
            order_expressions = self._build_order_by(query.order_by, direction=query.order)
        except QueryError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        stmt = select(self.sql_model)
        if filters:
            stmt = stmt.where(*filters)
        if keyword_filter is not None:
            stmt = stmt.where(keyword_filter)

        async with get_async_db_context(db) as session:
            count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
            total = int((await session.execute(count_stmt)).scalar_one())

            if order_expressions:
                stmt = stmt.order_by(*order_expressions)
            stmt = stmt.offset(query.offset).limit(query.limit)

            result = await session.execute(stmt)
            items = [self._serialize(obj) for obj in result.scalars().all()]
            response_list = self.response_list_schema.model_validate({"total": total, "items": items})
            return self._response(status.HTTP_200_OK, data=response_list)

    async def create(
        self,
        form_data: CreateFormType | Mapping[str, Any],
        db: AsyncSession | None = None,
    ) -> ResponseSchemaType:
        data = dict(form_data) if isinstance(form_data, Mapping) else form_data.model_dump()
        try:
            self._validate_write_data(data, "create", allow_primary_keys=True)
        except ValueError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        async with get_async_db_context(db) as session:
            obj = self._create_instance(data)
            session.add(obj)
            try:
                await session.commit()
                await session.refresh(obj)
            except IntegrityError:
                await session.rollback()
                return self._response(status.HTTP_409_CONFLICT, message="The record conflicts with existing data.")
            except Exception:
                await session.rollback()
                raise

            return self._response(status.HTTP_201_CREATED, data=self._serialize(obj))

    async def update(
        self,
        _id: Any,
        form_data: UpdateFormType | Mapping[str, Any],
        db: AsyncSession | None = None,
    ) -> ResponseSchemaType:
        data = (
            dict(form_data)
            if isinstance(form_data, Mapping)
            else form_data.model_dump(exclude_unset=True)
        )
        try:
            self._validate_write_data(data, "update", allow_primary_keys=False)
        except ValueError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        try:
            identity = self._normalize_identity(_id)
        except QueryError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        async with get_async_db_context(db) as session:
            obj = await self._get_object(session, identity)
            if obj is None:
                return self._response(
                    status.HTTP_404_NOT_FOUND,
                    message=ERROR_MESSAGES.NOT_FOUND,
                )

            for field, value in data.items():
                setattr(obj, field, value)

            try:
                await session.commit()
                await session.refresh(obj)
            except IntegrityError:
                await session.rollback()
                return self._response(status.HTTP_409_CONFLICT, message="The record conflicts with existing data.")
            except Exception:
                await session.rollback()
                raise

            return self._response(status.HTTP_200_OK, data=self._serialize(obj))

    async def delete(self, _id: Any, db: AsyncSession | None = None) -> ResponseSchemaType:
        try:
            identity = self._normalize_identity(_id)
        except QueryError as exc:
            return self._response(status.HTTP_400_BAD_REQUEST, message=str(exc))

        async with get_async_db_context(db) as session:
            obj = await self._get_object(session, identity)
            if obj is None:
                return self._response(
                    status.HTTP_404_NOT_FOUND,
                    message=ERROR_MESSAGES.NOT_FOUND,
                )

            await session.delete(obj)
            try:
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            return self._response(status.HTTP_200_OK)

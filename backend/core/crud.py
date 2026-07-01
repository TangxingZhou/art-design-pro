from typing import Any, Dict, Generic, List, NewType, Tuple, Type, TypeVar, Union

from pydantic import BaseModel
from tortoise.expressions import Q
from tortoise.models import Model
from tortoise.backends.base.client import BaseDBAsyncClient

Total = NewType("Total", int)
ModelType = TypeVar("ModelType", bound=Model)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    def __init__(self, model: Type[ModelType]):
        self.model = model

    async def get(self, id: int, using_db: BaseDBAsyncClient | None = None) -> ModelType:
        query = self.model.filter(id=id)
        if using_db is not None:
            query = query.using_db(using_db)
        return await query.get()

    async def list(
        self,
        page: int,
        page_size: int,
        search: Q = Q(),
        order: list = [],
        using_db: BaseDBAsyncClient | None = None
    ) -> Tuple[Total, List[ModelType]]:
        query = self.model.filter(search)
        if using_db is not None:
            query = query.using_db(using_db)
        return await query.count(), await query.offset((page - 1) * page_size).limit(page_size).order_by(*order)

    async def create(self, obj_in: CreateSchemaType, using_db: BaseDBAsyncClient | None = None) -> ModelType:
        if isinstance(obj_in, Dict):
            obj_dict = obj_in
        else:
            obj_dict = obj_in.model_dump()
        obj = self.model(**obj_dict)
        await obj.save(using_db=using_db)
        return obj

    async def update(self, id: int, obj_in: Union[UpdateSchemaType, Dict[str, Any]], using_db: BaseDBAsyncClient | None = None) -> ModelType:
        if isinstance(obj_in, Dict):
            obj_dict = obj_in
        else:
            obj_dict = obj_in.model_dump(exclude_unset=True, exclude={"id"})
        obj = await self.get(id=id)
        obj = obj.update_from_dict(obj_dict)
        await obj.save(using_db=using_db)
        return obj

    async def remove(self, id: int, using_db: BaseDBAsyncClient | None = None) -> None:
        obj = await self.get(id=id, using_db=using_db)
        await obj.delete(using_db=using_db)

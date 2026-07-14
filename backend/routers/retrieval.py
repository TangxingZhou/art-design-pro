from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Iterator, Optional, Sequence, Union

import tiktoken
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
# from langchain_core.documents import Document
# from langchain_text_splitters import (
#     MarkdownHeaderTextSplitter,
#     RecursiveCharacterTextSplitter,
#     TokenTextSplitter,
# )
# from open_webui.config import (
#     DEFAULT_LOCALE,
#     ENV,
#     RAG_EMBEDDING_CONTENT_PREFIX,
#     RAG_EMBEDDING_MODEL_AUTO_UPDATE,
#     RAG_EMBEDDING_MODEL_TRUST_REMOTE_CODE,
#     RAG_EMBEDDING_QUERY_PREFIX,
#     RAG_RERANKING_MODEL_AUTO_UPDATE,
#     RAG_RERANKING_MODEL_TRUST_REMOTE_CODE,
#     UPLOAD_DIR,
# )
from constants import ERROR_MESSAGES, UPLOAD_DIR
# from open_webui.env import (
#     DEVICE_TYPE,
#     DOCKER,
#     RAG_EMBEDDING_TIMEOUT,
#     SENTENCE_TRANSFORMERS_BACKEND,
#     SENTENCE_TRANSFORMERS_CROSS_ENCODER_BACKEND,
#     SENTENCE_TRANSFORMERS_CROSS_ENCODER_MODEL_KWARGS,
#     SENTENCE_TRANSFORMERS_CROSS_ENCODER_SIGMOID_ACTIVATION_FUNCTION,
#     SENTENCE_TRANSFORMERS_MODEL_KWARGS,
# )
from utils.events import EVENTS, publish_event
from utils.db import get_async_db, get_async_session
from models.files import FileModel, Files, FileUpdateForm
# from open_webui.models.knowledge import Knowledges
# from models.config import Config

# Document loaders
# from open_webui.retrieval.loaders.youtube import YoutubeLoader
# from open_webui.retrieval.utils import (
#     build_loader_from_config,
#     get_loader_config,
#     filter_accessible_collections,
#     get_content_from_url,
#     get_embedding_function,
#     get_model_path,
#     get_reranking_function,
#     query_collection,
#     query_collection_with_hybrid_search,
#     query_doc,
#     query_doc_with_hybrid_search,
# )
# from open_webui.retrieval.vector.async_client import ASYNC_VECTOR_DB_CLIENT
# from open_webui.retrieval.vector.factory import VECTOR_DB_CLIENT
# from open_webui.retrieval.vector.utils import filter_metadata
# from open_webui.retrieval.web.azure import search_azure
# from open_webui.retrieval.web.bing import search_bing
# from open_webui.retrieval.web.bocha import search_bocha
# from open_webui.retrieval.web.brave import search_brave
# from open_webui.retrieval.web.brave_llm_context import search_brave_llm_context
# from open_webui.retrieval.web.duckduckgo import search_duckduckgo
# from open_webui.retrieval.web.exa import search_exa
# from open_webui.retrieval.web.external import search_external
# from open_webui.retrieval.web.firecrawl import search_firecrawl
# from open_webui.retrieval.web.google_pse import search_google_pse
# from open_webui.retrieval.web.jina_search import search_jina
# from open_webui.retrieval.web.kagi import search_kagi
#
# # Web search engines
# from open_webui.retrieval.web.main import SearchResult
# from open_webui.retrieval.web.microsoft_web_iq import search_microsoft_web_iq
# from open_webui.retrieval.web.mojeek import search_mojeek
# from open_webui.retrieval.web.ollama import search_ollama_cloud
# from open_webui.retrieval.web.perplexity import search_perplexity
# from open_webui.retrieval.web.perplexity_search import search_perplexity_search
# from open_webui.retrieval.web.searchapi import search_searchapi
# from open_webui.retrieval.web.searxng import search_searxng
# from open_webui.retrieval.web.serpapi import search_serpapi
# from open_webui.retrieval.web.serper import search_serper
# from open_webui.retrieval.web.serphouse import search_serphouse
# from open_webui.retrieval.web.serply import search_serply
# from open_webui.retrieval.web.serpstack import search_serpstack
# from open_webui.retrieval.web.sougou import search_sougou
# from open_webui.retrieval.web.tavily import search_tavily
# from open_webui.retrieval.web.utils import get_web_loader
# from open_webui.retrieval.web.yacy import search_yacy
# from open_webui.retrieval.web.yandex import search_yandex
# from open_webui.retrieval.web.ydc import search_youcom
# from open_webui.retrieval.web.linkup import search_linkup
from utils.storage import Storage
from utils.access_control import has_permission
from utils.access_control.files import has_access_to_file
from utils.auth import get_admin_user, get_verified_user
from utils.misc import (
    calculate_sha256_string,
    sanitize_text_for_db,
)
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

router = APIRouter()


class ProcessFileForm(BaseModel):
    file_id: str
    content: str | None = None
    collection_name: str | None = None


@router.post('/process/file')
async def process_file(
    request: Request,
    form_data: ProcessFileForm,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    """
    Process a file and save its content to the vector database.
    Process a file and save its content to the vector database.
    Note: granular session management is used to prevent connection pool exhaustion.
    The session is committed before external API calls, and updates use a fresh session.
    """
    # config = await get_retrieval_config()
    if user.role == 'admin':
        file = await Files.get_file_by_id(form_data.file_id, db=db)
    else:
        file = await Files.get_file_by_id_and_user_id(form_data.file_id, user.id, db=db)

    if file:
        try:
            collection_name = form_data.collection_name

            if collection_name is None:
                collection_name = f'file-{file.id}'
            else:
                await _validate_collection_access([collection_name], user, access_type='write')

            if form_data.content:
                text_content = form_data.content
            elif form_data.collection_name:
                text_content = file.data.get('content', '')
            else:
                text_content = ' '

            log.debug(f'text_content: {text_content}')
            await Files.update_file_data_by_id(
                file.id,
                {'content': text_content},
                db=db,
            )
            hash = calculate_sha256_string(text_content)

            if config.BYPASS_EMBEDDING_AND_RETRIEVAL:
                await Files.update_file_data_by_id(file.id, {'status': 'completed'}, db=db)
                await Files.update_file_hash_by_id(file.id, hash, db=db)
                await publish_event(
                    request,
                    EVENTS.RETRIEVAL_CONTENT_PROCESSED,
                    actor=user,
                    subject_id=file.id,
                    subject_type='file',
                    data={'collection_name': None, 'filename': file.filename},
                )
                return {
                    'status': True,
                    'collection_name': None,
                    'filename': file.filename,
                    'content': text_content,
                }
            else:
                try:
                    # Commit any pending changes before the slow embedding step.
                    # Note: file is already a Pydantic model (not ORM), so no expunge needed.
                    await db.commit()
                except Exception as e:
                    raise e

        except Exception as e:
            log.exception(e)
            # Fresh session for error status update.
            async with get_async_db() as session:
                await Files.update_file_data_by_id(
                    file.id,
                    {'status': 'failed'},
                    db=session,
                )
                # Clear the hash so the file can be re-uploaded after fixing the issue
                await Files.update_file_hash_by_id(file.id, None, db=session)

            if 'No pandoc was found' in str(e):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.PANDOC_NOT_INSTALLED,
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )

    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=ERROR_MESSAGES.NOT_FOUND)

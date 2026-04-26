import logging
import os
from contextlib import asynccontextmanager

from app.log import TRACE  # registers TRACE level before basicConfig runs

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import load_config
from app.deobfuscator import ResponseDeobfuscator
from app.pipeline import Pipeline
from app.privacy.engine import PrivacyEngine
from app.privacy.factory import create_detector
from app.privacy.session import SessionMap
from app.router import ProviderRouter

_pipeline: Pipeline | None = None

_log_level = os.environ.get("OBFUSPROXY_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("app").setLevel(_log_level)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pipeline

    config = load_config()
    session_map = SessionMap()
    detector = create_detector(config.privacy)
    engine = PrivacyEngine(detector, session_map)
    router = ProviderRouter(config)
    deob = ResponseDeobfuscator(engine)
    _pipeline = Pipeline(engine, router, deob)

    yield


app = FastAPI(title="ObfusProxy", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible /v1/chat/completions endpoint."""
    body = await request.json()
    stream = body.get("stream", False)

    if stream:
        return StreamingResponse(
            _pipeline.run_streaming(request, body),
            media_type="text/event-stream",
        )

    return JSONResponse(await _pipeline.run_non_streaming(request, body))


@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Anthropic-native /v1/messages endpoint — used by Claude Code and Anthropic SDK clients."""
    body = await request.json()
    stream = body.get("stream", False)

    if stream:
        return StreamingResponse(
            _pipeline.run_anthropic_streaming(request, body),
            media_type="text/event-stream",
        )

    data, status_code = await _pipeline.run_anthropic_non_streaming(request, body)
    return JSONResponse(data, status_code=status_code)


@app.post("/v1/completions")
async def completions(request: Request):
    """OpenAI-compatible /v1/completions (legacy) endpoint."""
    body = await request.json()
    stream = body.get("stream", False)

    if stream:
        return StreamingResponse(
            _pipeline.run_legacy_streaming(request, body),
            media_type="text/event-stream",
        )

    return JSONResponse(await _pipeline.run_legacy_non_streaming(request, body))


@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and clear its obfuscation mappings."""
    if not _pipeline:
        return JSONResponse({"error": "Pipeline not initialized"}, status_code=500)

    await _pipeline._engine._session_map.clear(session_id)
    return JSONResponse({"status": "ok", "session_id": session_id})

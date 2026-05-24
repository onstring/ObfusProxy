import json
import logging
import os
import uuid
from collections.abc import AsyncIterator

import httpx
from fastapi import Request

from app.deobfuscator import ResponseDeobfuscator, StreamingDeobfuscatorSession
from app.log import TRACE
from app.privacy.engine import PrivacyEngine
from app.router import ProviderRouter

_ANTHROPIC_API_BASE = "https://api.anthropic.com"
_ROLES_TO_OBFUSCATE = frozenset({"user", "tool"})
log = logging.getLogger(__name__)


def _fmt_user_messages(messages: list[dict]) -> str:
    """Format only user/tool messages for debug logging — skips system, assistant, tool defs."""
    filtered = [m for m in messages if m.get("role") in _ROLES_TO_OBFUSCATE]
    return json.dumps(filtered, indent=2)


class Pipeline:
    """
    Wires the privacy engine, provider router, and deobfuscator together.

    Handles both streaming and non-streaming request/response paths.
    """

    def __init__(
        self,
        engine: PrivacyEngine,
        router: ProviderRouter,
        deobfuscator: ResponseDeobfuscator,
    ) -> None:
        self._engine = engine
        self._router = router
        self._deob = deobfuscator

    def _get_session_id(self, request: Request) -> str:
        """Extract or mint a session ID from the request."""
        sid = request.headers.get("X-Session-Id")
        return sid if sid else str(uuid.uuid4())

    async def run_non_streaming(self, request: Request, body: dict) -> dict:
        """Process non-streaming chat completion request."""
        session_id = self._get_session_id(request)
        messages = body.get("messages", [])
        model = body.get("model")

        scrubbed = await self._engine.obfuscate(messages, session_id)
        log.log(TRACE, "[upstream-req] session=%s\n%s", session_id, _fmt_user_messages(scrubbed))
        response = await self._router.call(scrubbed, model=model, stream=False, api_key=self._extract_api_key(request))

        content = response.choices[0].message.content or ""
        log.log(TRACE, "[upstream-res] session=%s\n%s", session_id, content)
        restored = await self._deob.restore(content, session_id)

        response.choices[0].message.content = restored
        return response.model_dump()

    async def run_streaming(self, request: Request, body: dict) -> AsyncIterator[str]:
        """Process streaming chat completion request."""
        session_id = self._get_session_id(request)
        messages = body.get("messages", [])
        model = body.get("model")

        scrubbed = await self._engine.obfuscate(messages, session_id)
        log.log(TRACE, "[upstream-req] session=%s\n%s", session_id, _fmt_user_messages(scrubbed))
        stream = await self._router.call(scrubbed, model=model, stream=True, api_key=self._extract_api_key(request))

        session = StreamingDeobfuscatorSession(self._engine, session_id)
        accumulated = []

        async for chunk in stream:
            delta = chunk.choices[0].delta.content or ""

            restored_delta = await session.feed(delta)
            if restored_delta:
                accumulated.append(restored_delta)
                chunk.choices[0].delta.content = restored_delta
                yield f"data: {json.dumps(chunk.model_dump())}\n\n"

        final = await session.flush()
        if final:
            accumulated.append(final)
            chunk.choices[0].delta.content = final
            yield f"data: {json.dumps(chunk.model_dump())}\n\n"

        log.log(TRACE, "[upstream-res] session=%s\n%s", session_id, "".join(accumulated))
        yield "data: [DONE]\n\n"

    async def run_legacy_non_streaming(self, request: Request, body: dict) -> dict:
        """Process non-streaming completions (legacy) request."""
        session_id = self._get_session_id(request)
        prompt = body.get("prompt", "")
        model = body.get("model")

        obfuscated_prompt = await self._engine._obfuscate_text(prompt, session_id)

        response = await self._router.call(
            messages=[{"role": "user", "content": obfuscated_prompt}],
            model=model,
            stream=False,
            api_key=self._extract_api_key(request),
        )

        content = response.choices[0].text or ""
        restored = await self._deob.restore(content, session_id)

        response.choices[0].text = restored
        return response.model_dump()

    def _extract_api_key(self, request: Request) -> str | None:
        """Extract API key from Authorization: Bearer or x-api-key header, with env fallback.

        Used for the LiteLLM (/v1/chat/completions) path, where LiteLLM only takes a
        single api_key string. For Anthropic native (/v1/messages), prefer
        _anthropic_forward_headers, which preserves the original auth scheme.
        """
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:]
        return request.headers.get("x-api-key") or os.environ.get("ANTHROPIC_API_KEY")

    @staticmethod
    def _redact(value: str) -> str:
        """Show first 8 chars of a secret so we can identify it without leaking."""
        if not value:
            return "<empty>"
        return f"{value[:8]}…(len={len(value)})"

    def _anthropic_forward_headers(self, request: Request) -> dict[str, str]:
        """Build upstream headers preserving the client's original auth scheme.

        Anthropic accepts two auth schemes and they are NOT interchangeable:
          - API keys via `x-api-key: sk-ant-...`
          - OAuth (Claude subscription) via `Authorization: Bearer <token>` plus
            an `anthropic-beta: oauth-2025-04-20` style flag.
        Forwarding an OAuth token as `x-api-key` (or vice versa) yields 401.
        """
        headers = {
            "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
            "content-type": "application/json",
        }

        auth = request.headers.get("authorization", "")
        client_api_key = request.headers.get("x-api-key")
        env_key = os.environ.get("ANTHROPIC_API_KEY")
        scheme = "none"

        # Real Anthropic API keys start with `sk-ant-`. Clients pointed at a proxy
        # often send placeholders like "your-proxy-key" — ignore those and fall
        # back to env so the proxy-holds-the-key model still works.
        client_key_looks_real = bool(client_api_key) and client_api_key.startswith("sk-ant-")

        if auth.lower().startswith("bearer "):
            # OAuth token (Claude subscription) — forward verbatim.
            headers["authorization"] = auth
            scheme = f"bearer({self._redact(auth[7:])})"
        elif client_key_looks_real:
            headers["x-api-key"] = client_api_key
            scheme = f"x-api-key-client({self._redact(client_api_key)})"
        elif env_key:
            headers["x-api-key"] = env_key
            placeholder_note = f" (ignored client placeholder {self._redact(client_api_key)})" if client_api_key else ""
            scheme = f"x-api-key-env({self._redact(env_key)}){placeholder_note}"
        elif client_api_key:
            # No env key and client key doesn't look real — forward anyway; let
            # Anthropic surface the 401 with its own diagnostic.
            headers["x-api-key"] = client_api_key
            scheme = f"x-api-key-client-suspect({self._redact(client_api_key)})"

        # Forward anthropic-* metadata headers Claude Code includes (beta flags,
        # dangerous-direct-browser-access, etc.) — required for OAuth.
        for h in ("anthropic-beta", "anthropic-dangerous-direct-browser-access", "user-agent"):
            if v := request.headers.get(h):
                headers[h] = v

        log.debug(
            "[anthropic-auth] inbound: authorization=%s x-api-key=%s | outbound: scheme=%s headers=%s",
            self._redact(auth) if auth else "<absent>",
            self._redact(client_api_key) if client_api_key else "<absent>",
            scheme,
            sorted(headers.keys()),
        )
        return headers

    async def _obfuscate_content(
        self, content: str | list | None, session_id: str
    ) -> str | list | None:
        """Obfuscate a content field: plain string or list of text/tool_result blocks."""
        if isinstance(content, str):
            return await self._engine._obfuscate_text(content, session_id)
        if isinstance(content, list):
            result = []
            for block in content:
                if not isinstance(block, dict):
                    result.append(block)
                    continue
                btype = block.get("type")
                if btype == "text":
                    scrubbed = await self._engine._obfuscate_text(block["text"], session_id)
                    result.append({**block, "text": scrubbed})
                elif btype == "tool_result":
                    # tool_result.content is string or list of text blocks
                    tool_content = block.get("content", "")
                    if isinstance(tool_content, str):
                        result.append({**block, "content": await self._engine._obfuscate_text(tool_content, session_id)})
                    elif isinstance(tool_content, list):
                        scrubbed_blocks = []
                        for tb in tool_content:
                            if isinstance(tb, dict) and tb.get("type") == "text":
                                scrubbed_blocks.append({**tb, "text": await self._engine._obfuscate_text(tb["text"], session_id)})
                            else:
                                scrubbed_blocks.append(tb)
                        result.append({**block, "content": scrubbed_blocks})
                    else:
                        result.append(block)
                else:
                    result.append(block)
            return result
        return content

    async def _obfuscate_anthropic_messages(
        self, messages: list[dict], session_id: str
    ) -> list[dict]:
        """Obfuscate user and tool messages only; pass assistant messages through unchanged."""
        result = []
        for msg in messages:
            if msg.get("role") not in _ROLES_TO_OBFUSCATE:
                result.append(msg)
                continue
            scrubbed = await self._obfuscate_content(msg.get("content"), session_id)
            result.append({**msg, "content": scrubbed})
        return result

    async def run_anthropic_non_streaming(
        self, request: Request, body: dict
    ) -> tuple[dict, int]:
        """Forward obfuscated request to Anthropic /v1/messages, de-obfuscate response."""
        session_id = self._get_session_id(request)
        messages = await self._obfuscate_anthropic_messages(
            body.get("messages", []), session_id
        )
        scrubbed_body = {**body, "messages": messages}
        log.log(TRACE, "[upstream-req] session=%s\n%s", session_id, _fmt_user_messages(messages))

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{_ANTHROPIC_API_BASE}/v1/messages",
                    json=scrubbed_body,
                    headers=self._anthropic_forward_headers(request),
                    params=dict(request.query_params),
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            try:
                error_body = exc.response.json()
            except Exception:
                error_body = {"error": {"type": "upstream_error", "message": exc.response.text or str(exc)}}
            return error_body, exc.response.status_code

        raw_text = " | ".join(
            b["text"] for b in data.get("content", [])
            if isinstance(b, dict) and b.get("type") == "text"
        )
        log.log(TRACE, "[upstream-res] session=%s\n%s", session_id, raw_text)

        for block in data.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = await self._deob.restore(block["text"], session_id)

        return data, 200

    async def run_anthropic_streaming(
        self, request: Request, body: dict
    ) -> AsyncIterator[str]:
        """Stream obfuscated request through Anthropic /v1/messages, de-obfuscate deltas."""
        session_id = self._get_session_id(request)
        messages = await self._obfuscate_anthropic_messages(
            body.get("messages", []), session_id
        )
        scrubbed_body = {**body, "messages": messages}
        log.log(TRACE, "[upstream-req] session=%s\n%s", session_id, _fmt_user_messages(messages))

        deob_session = StreamingDeobfuscatorSession(self._engine, session_id)
        accumulated: list[str] = []

        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream(
                "POST",
                f"{_ANTHROPIC_API_BASE}/v1/messages",
                json=scrubbed_body,
                headers=self._anthropic_forward_headers(request),
                params=dict(request.query_params),
            ) as resp:
                if resp.status_code >= 400:
                    body_bytes = await resp.aread()
                    body_text = body_bytes.decode("utf-8", errors="replace")
                    log.error(
                        "[upstream-error] status=%s body=%s",
                        resp.status_code,
                        body_text[:500],
                    )
                    error_event = {
                        "type": "error",
                        "error": {
                            "type": "upstream_error",
                            "status": resp.status_code,
                            "message": body_text,
                        },
                    }
                    yield f"event: error\ndata: {json.dumps(error_event)}\n\n"
                    return
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        yield f"{line}\n"
                        continue

                    if not line.startswith("data:"):
                        # blank lines and other fields — skip, \n\n after data handles separation
                        continue

                    data_str = line[5:].strip()
                    try:
                        event = json.loads(data_str)
                    except (json.JSONDecodeError, ValueError):
                        yield f"{line}\n\n"
                        continue

                    event_type = event.get("type")

                    if event_type == "content_block_delta":
                        delta = event.get("delta", {})
                        if delta.get("type") == "text_delta":
                            restored = await deob_session.feed(delta["text"])
                            accumulated.append(restored)
                            delta["text"] = restored
                        yield f"data: {json.dumps(event)}\n\n"

                    elif event_type == "content_block_stop":
                        # Flush any buffered partial placeholder before closing the block
                        final = await deob_session.flush()
                        if final:
                            accumulated.append(final)
                            flush_event = {
                                "type": "content_block_delta",
                                "index": event.get("index", 0),
                                "delta": {"type": "text_delta", "text": final},
                            }
                            yield f"data: {json.dumps(flush_event)}\n\n"
                        log.log(TRACE, "[upstream-res] session=%s\n%s", session_id, "".join(accumulated))
                        yield f"data: {json.dumps(event)}\n\n"

                    else:
                        yield f"data: {json.dumps(event)}\n\n"

    async def run_legacy_streaming(self, request: Request, body: dict) -> AsyncIterator[str]:
        """Process streaming completions (legacy) request."""
        session_id = self._get_session_id(request)
        prompt = body.get("prompt", "")
        model = body.get("model")

        obfuscated_prompt = await self._engine._obfuscate_text(prompt, session_id)

        stream = await self._router.call(
            messages=[{"role": "user", "content": obfuscated_prompt}],
            model=model,
            stream=True,
            api_key=self._extract_api_key(request),
        )

        session = StreamingDeobfuscatorSession(self._engine, session_id)

        async for chunk in stream:
            delta = chunk.choices[0].text or ""

            restored_delta = await session.feed(delta)
            if restored_delta:
                chunk.choices[0].text = restored_delta
                yield f"data: {json.dumps(chunk.model_dump())}\n\n"

        final = await session.flush()
        if final:
            chunk.choices[0].text = final
            yield f"data: {json.dumps(chunk.model_dump())}\n\n"

        yield "data: [DONE]\n\n"

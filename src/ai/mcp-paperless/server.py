#!/usr/bin/env python3
"""
MCP proxy for Paperless-ngx with per-user document isolation.

Reads x-librechat-user-email from incoming request headers and restricts
all document access to documents owned by that Keycloak/Paperless user.
Admin credentials are used internally; users never see each other's data.
"""
from __future__ import annotations

import contextvars
import logging
import os
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
PAPERLESS_URL = os.environ["PAPERLESS_URL"].rstrip("/")
PAPERLESS_PUBLIC_URL = os.environ.get("PAPERLESS_PUBLIC_URL", PAPERLESS_URL)
PAPERLESS_ADMIN_USER = os.environ["PAPERLESS_ADMIN_USER"]
PAPERLESS_ADMIN_PASSWORD = os.environ["PAPERLESS_ADMIN_PASSWORD"]

# ── State ──────────────────────────────────────────────────────────────────────
_admin_token: str = ""
_uid_cache: dict[str, int | None] = {}  # email → paperless user id (None = not found)
_user_email: contextvars.ContextVar[str] = contextvars.ContextVar("user_email", default="")


# ── Admin auth ─────────────────────────────────────────────────────────────────
async def _ensure_token() -> None:
    global _admin_token
    if _admin_token:
        return
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{PAPERLESS_URL}/api/token/",
            json={"username": PAPERLESS_ADMIN_USER, "password": PAPERLESS_ADMIN_PASSWORD},
        )
        resp.raise_for_status()
        _admin_token = resp.json()["token"]
    log.info("Obtained Paperless admin token")


def _auth() -> dict[str, str]:
    return {"Authorization": f"Token {_admin_token}"}


# ── User resolution ────────────────────────────────────────────────────────────
async def _resolve_uid(email: str) -> int | None:
    if email in _uid_cache:
        return _uid_cache[email]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{PAPERLESS_URL}/api/users/",
            headers=_auth(),
            params={"search": email, "page_size": 10},
        )
    if not resp.is_success:
        log.warning("User lookup failed: HTTP %d", resp.status_code)
        _uid_cache[email] = None
        return None
    for user in resp.json().get("results", []):
        if user.get("email", "").lower() == email.lower():
            uid = int(user["id"])
            _uid_cache[email] = uid
            log.info("Resolved '%s' → Paperless UID %d", email, uid)
            return uid
    log.warning("No Paperless user found for email '%s'", email)
    _uid_cache[email] = None
    return None


# ── Middleware ─────────────────────────────────────────────────────────────────
class UserIdentityMiddleware(BaseHTTPMiddleware):
    """Extracts x-librechat-user-email from each request and resolves the Paperless UID."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        await _ensure_token()
        email = request.headers.get("x-librechat-user-email", "").strip()
        token = _user_email.set(email)
        if email:
            await _resolve_uid(email)
        try:
            return await call_next(request)
        finally:
            _user_email.reset(token)


# ── Guard helpers ──────────────────────────────────────────────────────────────
def _get_uid() -> int:
    email = _user_email.get()
    if not email:
        raise ValueError(
            "No user identity in request. "
            "Ensure LibreChat is configured to forward x-librechat-user-email to MCP servers."
        )
    uid = _uid_cache.get(email)
    if uid is None:
        raise ValueError(
            f"No Paperless account for '{email}'. "
            "Log in to Paperless once to activate your account."
        )
    return uid


def _fmt_doc(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc["id"],
        "title": doc.get("title", ""),
        "created": doc.get("created", ""),
        "modified": doc.get("modified", ""),
        "correspondent": doc.get("correspondent"),
        "tags": doc.get("tags", []),
        "url": f"{PAPERLESS_PUBLIC_URL}/documents/{doc['id']}/detail",
    }


# ── MCP tools ──────────────────────────────────────────────────────────────────
mcp = FastMCP(
    "paperless",
    instructions=(
        "Access Paperless-ngx document management. "
        "All operations are scoped to the authenticated user's own documents."
    ),
)


@mcp.tool()
async def search_documents(
    query: Annotated[str, "Full-text search query (leave empty to list all documents)"] = "",
    limit: Annotated[int, "Maximum number of results (1–50)"] = 20,
) -> list[dict[str, Any]]:
    """Search documents in Paperless-ngx. Returns only documents owned by the current user."""
    uid = _get_uid()
    params: dict[str, Any] = {"owner__id": uid, "page_size": min(limit, 50)}
    if query:
        params["query"] = query
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{PAPERLESS_URL}/api/documents/",
            headers=_auth(),
            params=params,
        )
        resp.raise_for_status()
    return [_fmt_doc(d) for d in resp.json().get("results", [])]


@mcp.tool()
async def get_document(
    document_id: Annotated[int, "Paperless document ID"],
) -> dict[str, Any]:
    """Get metadata for a specific document. Access is denied if the document is not owned by you."""
    uid = _get_uid()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{PAPERLESS_URL}/api/documents/{document_id}/", headers=_auth())
    if resp.status_code == 404:
        raise ValueError(f"Document {document_id} not found")
    resp.raise_for_status()
    doc = resp.json()
    if doc.get("owner") != uid:
        raise PermissionError(f"Document {document_id} is not accessible to you")
    return _fmt_doc(doc)


@mcp.tool()
async def get_document_content(
    document_id: Annotated[int, "Paperless document ID"],
) -> str:
    """Get the full extracted text content of a document."""
    uid = _get_uid()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{PAPERLESS_URL}/api/documents/{document_id}/", headers=_auth())
    if resp.status_code == 404:
        raise ValueError(f"Document {document_id} not found")
    resp.raise_for_status()
    doc = resp.json()
    if doc.get("owner") != uid:
        raise PermissionError(f"Document {document_id} is not accessible to you")
    return doc.get("content", "")


@mcp.tool()
async def list_tags() -> list[dict[str, Any]]:
    """List all document tags available in Paperless."""
    _get_uid()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{PAPERLESS_URL}/api/tags/", headers=_auth(), params={"page_size": 200}
        )
        resp.raise_for_status()
    return [{"id": t["id"], "name": t["name"]} for t in resp.json().get("results", [])]


@mcp.tool()
async def list_correspondents() -> list[dict[str, Any]]:
    """List all correspondents available in Paperless."""
    _get_uid()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{PAPERLESS_URL}/api/correspondents/",
            headers=_auth(),
            params={"page_size": 200},
        )
        resp.raise_for_status()
    return [{"id": c["id"], "name": c["name"]} for c in resp.json().get("results", [])]


# ── App ────────────────────────────────────────────────────────────────────────
app = mcp.http_app(transport="streamable-http")
app.add_middleware(UserIdentityMiddleware)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3000, log_level="info")

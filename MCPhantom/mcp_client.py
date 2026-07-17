"""MCP enumeration helpers used by the web server."""

from urllib.parse import unquote, urlparse, urlunparse

import httpx
from fastmcp import Client


def resolve_target_auth(url, username=None, password=None):
    """Return a credential-free URL and optional httpx auth."""

    parsed = urlparse(url)
    if parsed.username:
        username = unquote(parsed.username)
        password = unquote(parsed.password or "")

    auth = None
    if username:
        auth = httpx.BasicAuth(username, password or "")

    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"

    clean_url = urlunparse(
        (
            parsed.scheme,
            host,
            parsed.path or "",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    return clean_url, auth


def make_client(url, username=None, password=None, **kwargs):
    """Build a fastmcp Client, applying HTTP Basic Auth when provided."""

    clean_url, auth = resolve_target_auth(url, username, password)
    if auth is not None:
        kwargs["auth"] = auth
    return Client(clean_url, **kwargs)


def auth_from_payload(payload):
    username = str(payload.get("username", "") or "").strip() or None
    password = payload.get("password")
    if password is None:
        return username, None
    return username, str(password)


async def enumerate_server(client):
    """Enumerate all MCP capabilities."""

    resources = await client.list_resources()
    templates = await client.list_resource_templates()
    tools = await client.list_tools()

    try:
        prompts = await client.list_prompts()
    except Exception:
        prompts = []

    return resources, templates, tools, prompts


async def probe_server(client):
    """Check whether the endpoint responds like an MCP server."""

    try:
        await client.list_tools()
        return True, None
    except Exception as exc:
        message = str(exc)
        if "401" in message:
            return False, (
                "401 Unauthorized — the target requires HTTP Basic Auth. "
                "Enter username and password in the fields above."
            )
        return False, exc

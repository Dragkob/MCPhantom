"""MCP enumeration helpers used by the web server."""


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
        return False, exc

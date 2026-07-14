"""
Enumerates every capability exposed by an MCP server.
"""

from fastmcp import Client

from audit.models import Capability, CapabilityCollection


def _schema_dict(schema):
    if not schema:
        return {}
    if isinstance(schema, dict):
        return schema
    if hasattr(schema, "model_dump"):
        return schema.model_dump() or {}
    if hasattr(schema, "dict"):
        return schema.dict() or {}
    return {}


def _tool_parameters(tool):
    schema = _schema_dict(getattr(tool, "inputSchema", None))
    properties = schema.get("properties", {}) or {}
    if properties:
        return list(properties.keys())

    for candidate in (
        getattr(tool, "parameters", None),
        schema.get("parameters"),
        schema.get("args"),
    ):
        if not candidate:
            continue
        if isinstance(candidate, dict):
            return list(candidate.keys())
        if isinstance(candidate, list):
            names = []
            for item in candidate:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("key")
                    if name:
                        names.append(str(name))
                elif isinstance(item, str):
                    names.append(item)
            if names:
                return names

    return []


class DiscoveryEngine:

    def __init__(self, target: str, client=None):

        self.target = target
        self.client = client or Client(target)
        self._owns_client = client is None

    async def enumerate(self) -> CapabilityCollection:

        collection = CapabilityCollection()

        if self._owns_client:
            async with self.client:
                await self._populate(collection)
        else:
            await self._populate(collection)

        return collection

    async def _populate(self, collection):
        collection.resources = await self._resources()
        collection.resource_templates = await self._resource_templates()
        collection.tools = await self._tools()
        collection.prompts = await self._prompts()

    ###########################################################################
    # Resources
    ###########################################################################

    async def _resources(self):

        discovered = []

        try:

            resources = await self.client.list_resources()

        except Exception as e:

            print(f"[!] Failed to enumerate resources: {e}")

            return discovered

        for resource in resources:

            discovered.append(

                Capability(
                    type="resource",

                    name=getattr(resource, "name", "unknown"),

                    description=getattr(resource, "description", ""),

                    uri=str(getattr(resource, "uri", "")),

                    raw=resource
                )

            )

        return discovered

    ###########################################################################
    # Resource Templates
    ###########################################################################

    async def _resource_templates(self):

        discovered = []

        try:

            templates = await self.client.list_resource_templates()

        except Exception as e:

            print(f"[!] Failed to enumerate resource templates: {e}")

            return discovered

        for template in templates:

            discovered.append(

                Capability(

                    type="resource_template",

                    name=getattr(
                        template,
                        "name",
                        str(getattr(template, "uriTemplate", "template"))
                    ),

                    description=getattr(template, "description", ""),

                    uri_template=str(
                        getattr(template, "uriTemplate", "")
                        or getattr(template, "uri_template", "")
                        or getattr(template, "name", "")
                    ),

                    raw=template
                )

            )

        return discovered

    ###########################################################################
    # Tools
    ###########################################################################

    async def _tools(self):

        discovered = []

        try:

            tools = await self.client.list_tools()

        except Exception as e:

            print(f"[!] Failed to enumerate tools: {e}")

            return discovered

        for tool in tools:

            parameters = _tool_parameters(tool)

            discovered.append(

                Capability(

                    type="tool",

                    name=getattr(tool, "name", "unknown"),

                    description=getattr(tool, "description", ""),

                    parameters=parameters,

                    raw=tool

                )

            )

        return discovered

    ###########################################################################
    # Prompts
    ###########################################################################

    async def _prompts(self):

        discovered = []

        try:

            prompts = await self.client.list_prompts()

        except Exception:

            #
            # Prompt support is optional.
            #
            return discovered

        for prompt in prompts:

            arguments = getattr(prompt, "arguments", [])

            parameters = []

            for arg in arguments:

                parameters.append(
                    getattr(arg, "name", "")
                )

            discovered.append(

                Capability(

                    type="prompt",

                    name=getattr(prompt, "name", "unknown"),

                    description=getattr(prompt, "description", ""),

                    parameters=parameters,

                    raw=prompt

                )

            )

        return discovered
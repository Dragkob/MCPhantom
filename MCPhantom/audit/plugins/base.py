"""
plugins/base.py

Base class for every vulnerability plugin.
"""

from abc import ABC, abstractmethod

from audit.template_uri import substitute_payload
from audit.models import Finding, Response
from audit.payloads import payloads


class Plugin(ABC):

    ###########################################################################
    # Plugin Metadata
    ###########################################################################

    name = "Plugin"
    description = ""
    severity = "INFO"

    #
    # Capability tags this plugin should execute against.
    #

    tags = []

    #
    # Payload category from payloads.py
    #

    payload_category = None

    ###########################################################################
    # Plugin Selection
    ###########################################################################

    def match(self, capability):
        """
        Returns True if this plugin should execute against the capability.
        """

        return any(tag in capability.tags for tag in self.tags)

    ###########################################################################
    # Main Plugin Loop
    ###########################################################################

    async def run(self, client, capability, aggressive=False):

        findings = []

        self.print_banner(capability)

        for payload in self.get_payloads(aggressive):

            try:

                responses = await self.execute_payload(client,capability,payload.value)

                if not isinstance(responses, list):
                    responses = [responses]

                for response in responses:

                    result = self.analyze(
                        capability,
                        payload.value,
                        response
                    )

                    if result is None:
                        continue

                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)

            except Exception as e:

                print(f"[{self.name}] Payload failed: {payload.value}")
                print(e)

        return findings

    ###########################################################################
    # Plugin API
    ###########################################################################

    def response_text(self, response):
        text = response.text if response.success else response.error
        if not text and response.raw is not None:
            text = self.extract_result_text(response.raw)
        return (text or "").strip()

    @abstractmethod
    def analyze(self, capability, payload, response):
        """
        Analyse the response.

        Returns:

            Finding
            list[Finding]
            None
        """

        raise NotImplementedError

    ###########################################################################
    # Payload Handling
    ###########################################################################

    def get_payloads(self, aggressive=False):

        if self.payload_category is None:
            return []

        #
        # Future improvement:
        #   if aggressive:
        #       include larger payload sets
        #

        return payloads.get(self.payload_category)
    
    
    ###########################################################################
    # Build Tool Arguments
    ###########################################################################

    def build_tool_arguments(
        self,
        capability,
        target_parameter,
        payload
    ):

        arguments = {}

        for parameter in capability.parameters:

            p = parameter.lower()

            #
            # Parameter under test
            #

            if parameter == target_parameter:

                arguments[parameter] = payload
                continue

            #
            # Reasonable defaults
            #

            if any(x in p for x in ("url", "uri", "endpoint")):

                arguments[parameter] = "https://example.com"

            elif any(x in p for x in ("host", "hostname")):

                arguments[parameter] = "localhost"

            elif any(x in p for x in ("path", "file", "filename")):

                arguments[parameter] = "test.txt"

            elif "port" in p:

                arguments[parameter] = 80

            elif "timeout" in p:

                arguments[parameter] = 30

            elif any(x in p for x in ("verify", "tls", "ssl")):

                arguments[parameter] = True

            elif "id" in p:

                arguments[parameter] = 1

            elif any(x in p for x in ("user", "username")):

                arguments[parameter] = "test"

            elif "password" in p:

                arguments[parameter] = "password"

            elif "query" in p:

                arguments[parameter] = "test"

            elif any(x in p for x in ("command", "cmd", "exec", "execute", "shell", "bash")):

                arguments[parameter] = "whoami"

            else:

                arguments[parameter] = "test"

        return arguments

    ###########################################################################
    # Generic Payload Executor
    ###########################################################################

    async def execute_payload(
        self,
        client,
        capability,
        payload
    ):

        #
        # MCP Tool
        #

        if capability.type == "tool":

            responses = []

            parameters = capability.parameters or []

            #
            # No parameters
            #

            if not parameters:

                response = await self.call_tool(
                    client,
                    capability.name,
                    {}
                )

                return response

            #
            # Fuzz one parameter at a time
            #

            for parameter in parameters:

                arguments = self.build_tool_arguments(
                    capability,
                    parameter,
                    payload
                )

                response = await self.call_tool(
                    client,
                    capability.name,
                    arguments
                )

                response.parameter = parameter

                responses.append(response)

            return responses

        #######################################################################
        # Resource
        #######################################################################

        elif capability.type == "resource":

            uri = capability.uri

            if not uri:

                return Response(
                    success=False,
                    error="Missing resource URI."
                )

            if "{" in uri:

                while "{" in uri:

                    start = uri.index("{")
                    end = uri.index("}")

                    uri = (
                        uri[:start]
                        + payload
                        + uri[end + 1:]
                    )

            else:

                if not uri.endswith("/"):

                    uri += "/"

                uri += payload

            return await self.read_resource(
                client,
                uri
            )

        #######################################################################
        # Resource Template
        #######################################################################

        elif capability.type == "resource_template":

            template = capability.uri_template or capability.name or ""

            try:
                uri = substitute_payload(template, payload)
            except ValueError:
                return Response(
                    success=False,
                    error="Missing or invalid resource template."
                )

            return await self.read_resource(
                client,
                uri
            )

        #######################################################################
        # Prompt
        #######################################################################

        elif capability.type == "prompt":

            arguments = {}

            for parameter in capability.parameters or []:

                arguments[parameter] = payload

            try:

                result = await client.get_prompt(
                    capability.name,
                    arguments
                )

                return Response(
                    success=True,
                    raw=result,
                    text=str(result)
                )

            except Exception as e:

                return Response(
                    success=False,
                    error=str(e)
                )

        return Response(
            success=False,
            error=f"Unsupported capability type: {capability.type}"
        )
    
    ###########################################################################
    # Finding Helper
    ###########################################################################

    def finding(
        self,
        capability,
        payload,
        evidence,
        title,
        recommendation=""
    ):

        return Finding(
            plugin=self.name,
            severity=self.severity,
            title=title,
            capability=capability,
            payload=payload,
            evidence=evidence,
            recommendation=recommendation
        )

    ###########################################################################
    # MCP Helpers
    ###########################################################################

    def extract_result_text(self, result):
        if result is None:
            return ""

        if isinstance(result, (str, bytes)):
            return result.decode() if isinstance(result, bytes) else result

        direct = getattr(result, "text", None)
        if direct:
            return str(direct)

        items = getattr(result, "content", result)
        if isinstance(items, (str, bytes)):
            return items.decode() if isinstance(items, bytes) else items

        if isinstance(items, list):
            lines = []
            for item in items:
                if hasattr(item, "text"):
                    lines.append(str(item.text))
                elif isinstance(item, dict) and "text" in item:
                    lines.append(str(item["text"]))
                else:
                    lines.append(str(item))
            if lines:
                return "\n".join(lines)

        return str(result)

    async def call_tool(
        self,
        client,
        tool_name,
        arguments
    ):
        """
        Safely invoke an MCP tool.
        """

        try:

            result = await client.call_tool(
                tool_name,
                arguments
            )

            return Response(
                success=True,
                raw=result,
                text=self.extract_result_text(result)
            )

        except Exception as e:

            return Response(
                success=False,
                error=str(e)
            )

    ###########################################################################

    async def read_resource(
        self,
        client,
        uri
    ):
        """
        Safely read an MCP resource.
        """

        try:

            result = await client.read_resource(uri)

            text = ""

            #
            # FastMCP generally returns a list of content objects.
            #

            if isinstance(result, list):

                for item in result:

                    if hasattr(item, "text"):

                        text += item.text + "\n"

                    elif hasattr(item, "data"):

                        text += str(item.data) + "\n"

                    elif hasattr(item, "blob"):

                        text += str(item.blob) + "\n"

                    else:

                        text += str(item) + "\n"

            else:

                text = str(result)

            return Response(
                success=True,
                raw=result,
                text=text
            )

        except Exception as e:

            return Response(
                success=False,
                error=str(e)
            )

    ###########################################################################
    # Detection Helpers
    ###########################################################################

    def contains_error(self, response):

        if response is None:

            return False

        text = str(response).lower()

        indicators = [

            #
            # Generic
            #

            "error",
            "failed",
            "failure",
            "exception",
            "traceback",
            "stack trace",

            #
            # SQL
            #

            "sqlite",
            "mysql",
            "postgres",
            "postgresql",
            "sql syntax",
            "database error",

            #
            # Command execution
            #

            "permission denied",
            "command not found",
            "cannot execute",

            #
            # HTTP
            #

            "500 internal server error",
            "502 bad gateway",
            "503 service unavailable",

            #
            # Network
            #

            "connection refused",
            "connection reset",
            "timed out"

        ]

        return any(
            indicator in text
            for indicator in indicators
        )

    ###########################################################################

    def contains_any(
        self,
        response,
        keywords
    ):

        if response is None:

            return False

        text = str(response).lower()

        return any(
            keyword.lower() in text
            for keyword in keywords
        )

    ###########################################################################

    def contains_all(
        self,
        response,
        keywords
    ):

        if response is None:

            return False

        text = str(response).lower()

        return all(
            keyword.lower() in text
            for keyword in keywords
        )

    ###########################################################################
    # Console Output
    ###########################################################################

    def print_banner(
        self,
        capability
    ):

        print()

        print("=" * 70)

        print(f"[PLUGIN] {self.name}")

        print("=" * 70)

        print(f"Capability : {capability.name}")

        print(f"Type       : {capability.type}")

        if capability.parameters:

            print(
                "Parameters : "
                + ", ".join(capability.parameters)
            )

        if capability.tags:

            print(
                "Tags       : "
                + ", ".join(capability.tags)
            )

        print()

###############################################################################
# End of class
###############################################################################
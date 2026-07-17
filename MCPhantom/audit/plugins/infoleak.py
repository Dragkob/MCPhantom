"""
plugins/infoleak.py

Tests for Information Disclosure.

Looks for:
- Stack traces
- Database errors
- Secrets
- Tokens
- Keys
- Internal paths
"""

import re

from audit.plugins.base import Plugin


class InfoLeakPlugin(Plugin):

    name = "Information Disclosure"

    description = "Looks for leaked sensitive information."

    tags = ["INFOLEAK"]

    severity = "MEDIUM"

    ###########################################################################

    async def run(self, client, capability, aggressive=False):

        findings = []

        #
        # Resource
        #

        if capability.type == "resource":

            if capability.uri:

                response = await self.read_resource(
                    client,
                    capability.uri
                )

                findings.extend(
                    self.analyse(
                        capability,
                        response.text if response.success else response.error,
                        capability.uri
                    )
                )

        #
        # Resource Template
        #

        elif capability.type == "resource_template":

            if capability.uri_template:

                #
                # Try replacing template parameters with "test"
                #

                uri = re.sub(
                    r"\{.*?\}",
                    "test",
                    capability.uri_template
                )

                response = await self.read_resource(
                    client,
                    uri
                )

                findings.extend(
                    self.analyse(
                        capability,
                        response.text if response.success else response.error,
                        uri
                    )
                )

        #
        # Tools
        #

        elif capability.type == "tool":

            arguments = {}

            for parameter in capability.parameters or []:

                arguments[parameter] = "test"

            response = await self.call_tool(
                client,
                capability.name,
                arguments
            )

            findings.extend(
                self.analyse(
                    capability,
                    response.text if response.success else response.error,
                    str(arguments)
                )
            )

        return findings

    ###########################################################################

    def analyze(self, capability, payload, response):
        text = response.text if getattr(response, "success", False) else getattr(response, "error", "")
        return self.analyse(capability, text, payload)

    def analyse(
        self,
        capability,
        text,
        payload
    ):

        findings = []

        if not text:
            return findings

        lower = text.lower()

        #
        # Interesting keywords
        #

        keywords = [

            "traceback",

            "stack trace",

            "exception",

            "internal server error",

            "sqlite",

            "mysql",

            "postgres",

            "password",

            "secret",

            "token",

            "apikey",

            "api_key",

            "authorization",

            "bearer",

            "/home/",

            "/root/",

            "/etc/",

            "c:\\",

            "private key",

            "aws_access_key",

            "aws_secret",

            "-----begin"

        ]

        for keyword in keywords:

            if keyword in lower:

                findings.append(

                    self.finding(

                        capability=capability,

                        payload=payload,

                        title="Potential Information Disclosure",

                        evidence=f"Keyword detected: {keyword}",

                        recommendation=(
                            "Review the response for leaked sensitive "
                            "information or verbose error messages."
                        )

                    )

                )

        #
        # Generic exception detection
        #

        if self.contains_error(text):

            findings.append(

                self.finding(

                    capability=capability,

                    payload=payload,

                    title="Verbose Error Message",

                    evidence=text[:500],

                    recommendation=(
                        "Avoid exposing internal exceptions to clients."
                    )

                )

            )

        return findings
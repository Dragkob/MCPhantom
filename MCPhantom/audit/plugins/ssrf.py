"""
Server-Side Request Forgery detection plugin.
"""

from audit.plugins.base import Plugin


class SSRFPlugin(Plugin):

    name = "Server-Side Request Forgery"

    description = "Detects potential SSRF vulnerabilities."

    severity = "HIGH"

    tags = ["SSRF"]

    payload_category = "SSRF"

    def analyze(
        self,
        capability,
        payload,
        response
    ):

        text = response.text if response.success else response.error

        if not text:
            return None

        lower = text.lower()

        indicators = [

            #
            # AWS
            #

            "instance-id",
            "ami-id",
            "instance-type",
            "security-credentials",

            #
            # Azure
            #

            "compute",
            "subscriptionid",

            #
            # GCP
            #

            "project-id",

            #
            # Internal HTTP
            #

            "server:",
            "nginx",
            "apache",
            "internal server",

            #
            # Localhost
            #

            "127.0.0.1",
            "localhost"

        ]

        for indicator in indicators:

            if indicator in lower:

                return self.finding(

                    capability=capability,

                    payload=payload,

                    title="Potential SSRF",

                    evidence=f"Detected SSRF indicator: {indicator}",

                    recommendation=(
                        "Restrict outbound requests and validate "
                        "user-controlled URLs."
                    )

                )

        return None
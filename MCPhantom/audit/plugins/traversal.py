"""
Path Traversal detection plugin.
"""

from audit.plugins.base import Plugin


class PathTraversalPlugin(Plugin):

    name = "Path Traversal"

    description = "Detects directory traversal and arbitrary file read."

    severity = "HIGH"

    tags = ["TRAVERSAL"]

    payload_category = "TRAVERSAL"

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

        #######################################################################
        # Linux file disclosure
        #######################################################################

        linux = [

            "root:x:",
            "/bin/bash",
            "/bin/sh",
            "daemon:x:",
            "nologin",
            "home/",
            "/etc/passwd"

        ]

        #######################################################################
        # Windows file disclosure
        #######################################################################

        windows = [

            "[fonts]",
            "[extensions]",
            "for 16-bit app support",
            "windows registry editor",
            "system32",
            "boot loader",
            "drivers\\etc\\hosts"

        ]

        #######################################################################
        # Environment files
        #######################################################################

        env = [

            "aws_secret_access_key",
            "aws_access_key_id",
            "database_url",
            "secret_key",
            "jwt_secret",
            "private_key",
            "begin rsa private key",
            "begin openssh private key"

        ]

        if self.contains_any(lower, linux):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Possible Linux File Disclosure",

                evidence="Linux system file contents detected.",

                recommendation=(
                    "Restrict filesystem access and canonicalize paths."
                )

            )

        if self.contains_any(lower, windows):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Possible Windows File Disclosure",

                evidence="Windows configuration file detected.",

                recommendation=(
                    "Restrict filesystem access and validate paths."
                )

            )

        if self.contains_any(lower, env):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Sensitive Configuration Disclosure",

                evidence="Secrets or configuration detected.",

                recommendation=(
                    "Prevent arbitrary file access and protect secrets."
                )

            )

        return None
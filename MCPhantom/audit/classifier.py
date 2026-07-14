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

    ###########################################################################

    def _scan_uri(self, capability, tags):

        text = ""

        if capability.uri:
            text += capability.uri

        if capability.uri_template:
            text += capability.uri_template

        for token in self._tokenize(text):

            if token in self.keyword_map:
                tags.add(self.keyword_map[token])

        #
        # Detect URI template variables
        #

        variables = re.findall(r"\{(.*?)\}", text)

        for variable in variables:

            variable = variable.lower()

            if variable in self.keyword_map:
                tags.add(self.keyword_map[variable])

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
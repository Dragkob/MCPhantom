"""
Path Traversal detection plugin.
"""

import re
from urllib.parse import unquote

from audit.plugins.base import Plugin


class PathTraversalPlugin(Plugin):

    name = "Path Traversal"

    description = "Detects directory traversal and arbitrary file read."

    severity = "HIGH"

    tags = ["TRAVERSAL"]

    payload_category = "TRAVERSAL"

    FAILURE_MARKERS = (
        "no such file",
        "errno",
        "does not exist",
        "not found",
        "invalid path",
        "error reading resource",
        "error reading resource from template",
        "provided resource uri is invalid",
        "unknown resource",
    )

    LINUX_CONTENT_MARKERS = (
        "root:x:",
        "/bin/bash",
        "/bin/sh",
        "daemon:x:",
        "nologin",
    )

    SENSITIVE_PATH_MARKERS = (
        "etc/passwd",
        "etc/shadow",
        "win.ini",
        "proc/self",
        "id_rsa",
        ".env",
        "web.config",
        "hosts",
    )

    def _scrub_payload_reflection(self, text, payload):
        cleaned = text
        if not payload:
            return cleaned

        for needle in (payload, payload.replace("/", "\\")):
            if needle:
                cleaned = cleaned.replace(needle, " ")

        lowered = payload.lower()
        for token in ("etc/passwd", "etc/shadow", "win.ini"):
            if token in lowered:
                cleaned = re.sub(re.escape(token), " ", cleaned, flags=re.IGNORECASE)

        return cleaned

    def _looks_like_failure(self, text, response):
        lower = text.lower()
        if not response.success:
            return True
        return any(marker in lower for marker in self.FAILURE_MARKERS)

    def _looks_like_linux_disclosure(self, text):
        lower = text.lower()
        return any(marker in lower for marker in self.LINUX_CONTENT_MARKERS)

    def _payload_targets_sensitive_path(self, payload):
        decoded = unquote(str(payload or "")).lower()
        return any(marker in decoded for marker in self.SENSITIVE_PATH_MARKERS)

    def _looks_like_arbitrary_read(self, text, response, payload, baseline=""):
        scrubbed = self._scrub_payload_reflection(text, payload).strip()
        if not scrubbed or not response.success:
            return False

        if self._looks_like_failure(scrubbed, response):
            if not self._looks_like_linux_disclosure(scrubbed):
                return False

        baseline_text = self._scrub_payload_reflection(baseline, "").strip()
        if baseline and scrubbed == baseline_text:
            return False

        if payload and str(payload).strip() == scrubbed:
            return False

        return True

    def format_evidence(self, text, max_len=8000):
        excerpt = text.strip()
        if len(excerpt) > max_len:
            excerpt = excerpt[:max_len] + "\n...[truncated]"
        return excerpt

    def result_fingerprint(self, text, payload=""):
        scrubbed = self._scrub_payload_reflection(text, payload)
        normalized = re.sub(r"\s+", " ", scrubbed.strip())
        if not normalized:
            return None
        if len(normalized) > 400:
            normalized = normalized[:400]
        return normalized

    def finding_dedup_key(self, finding):
        fingerprint = self.result_fingerprint(finding.evidence, finding.payload)
        if fingerprint:
            return (
                finding.plugin,
                finding.capability.name,
                getattr(finding.capability, "type", ""),
                fingerprint,
            )

        return (
            finding.plugin,
            finding.capability.name,
            getattr(finding.capability, "type", ""),
            unquote(str(finding.payload or "")).strip(),
            finding.title,
        )

    def _make_finding(self, capability, payload, response, title, recommendation):
        text = self.response_text(response)
        return self.finding(
            capability=capability,
            payload=payload,
            title=title,
            evidence=self.format_evidence(text),
            recommendation=recommendation,
        )

    def analyze(
        self,
        capability,
        payload,
        response,
        baseline="",
    ):

        text = self.response_text(response)

        if not text:
            return None

        scrubbed = self._scrub_payload_reflection(text, payload)
        lower = scrubbed.lower()

        if self._looks_like_failure(scrubbed, response):
            if not self._looks_like_linux_disclosure(scrubbed):
                return None

        #######################################################################
        # Linux file disclosure
        #######################################################################

        if self._looks_like_linux_disclosure(scrubbed):

            return self._make_finding(
                capability,
                payload,
                response,
                title="Possible Linux File Disclosure",
                recommendation=(
                    "Restrict filesystem access and canonicalize paths."
                ),
            )

        #######################################################################
        # Windows file disclosure
        #######################################################################

        windows = [

            "[fonts]",
            "[extensions]",
            "for 16-bit app support",
            "windows registry editor",
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

        if self.contains_any(lower, windows):

            return self._make_finding(
                capability,
                payload,
                response,
                title="Possible Windows File Disclosure",
                recommendation=(
                    "Restrict filesystem access and validate paths."
                ),
            )

        if self.contains_any(lower, env):

            return self._make_finding(
                capability,
                payload,
                response,
                title="Sensitive Configuration Disclosure",
                recommendation=(
                    "Prevent arbitrary file access and protect secrets."
                ),
            )

        if (
            self._payload_targets_sensitive_path(payload)
            and self._looks_like_arbitrary_read(text, response, payload, baseline)
        ):
            return self._make_finding(
                capability,
                payload,
                response,
                title="Sensitive File Read via Path Traversal",
                recommendation=(
                    "Restrict filesystem access and canonicalize paths. "
                    "Never expose raw file reads on user-controlled paths."
                ),
            )

        if (
            baseline
            and self._looks_like_arbitrary_read(text, response, payload, baseline)
        ):
            return self._make_finding(
                capability,
                payload,
                response,
                title="Arbitrary File Read via Path Traversal",
                recommendation=(
                    "Restrict filesystem access and canonicalize paths."
                ),
            )

        return None
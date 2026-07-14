"""
SQL Injection plugin.
"""

import json
import re
from urllib.parse import unquote

from audit.plugins.base import Plugin


class SQLiPlugin(Plugin):

    name = "SQL Injection"

    description = "Detects potential SQL Injection vulnerabilities."

    severity = "HIGH"

    tags = ["SQLI"]

    payload_category = "SQLI"

    STRONG_INDICATORS = [
        "sql syntax",
        "syntax error",
        "database error",
        "sqlite",
        "mysql",
        "mariadb",
        "postgres",
        "postgresql",
        "oracle",
        "odbc",
        "pdoexception",
        "unclosed quotation",
        "quoted string not properly terminated",
        "near \"select\"",
        "near 'select'",
        "union select",
        "sqlstate",
        "warning: mysql",
        "you have an error in your sql",
        "unrecognized token",
        "no such table",
        "no such column",
        "operationalerror",
        "integrityerror",
    ]

    DATA_MARKERS = [
        "sqlite_master",
        "information_schema",
        "@@version",
        "table_name",
        "column_name",
        "create table",
    ]

    VERSION_MARKERS = [
        "sqlite",
        "mysql",
        "mariadb",
        "postgresql",
        "microsoft sql server",
        "oracle database",
        "oracle ",
    ]

    VERSION_REGEXES = [
        re.compile(r"sqlite\s*[\d.]+", re.I),
        re.compile(r"postgresql\s+[\d.]+(?:\s*\([^)]+\))?", re.I),
        re.compile(r"microsoft sql server[\s\d.]*", re.I),
        re.compile(r"(?:mysql|mariadb)[\s/-]*[\d.]+", re.I),
        re.compile(r"oracle database[\s\d.]*", re.I),
        re.compile(r"^\d+\.\d+(?:\.\d+)?(?:\.\d+)?$"),
    ]

    REFLECTED_ERROR_PREFIXES = (
        "provided resource uri is invalid",
        "error reading resource from template",
        "error reading resource",
        "invalid resource uri",
        "resource uri is invalid",
        "malformed uri",
        "invalid uri",
        "bad uri",
        "quantity api error",
        "price api error",
    )

    def response_text(self, response):
        text = response.text if response.success else response.error
        if not text and response.raw is not None:
            text = self.extract_result_text(response.raw)
        return (text or "").strip()

    def matched_indicator(self, payload, text):
        lower = self.effective_error_text(payload, text)
        for indicator in self.STRONG_INDICATORS:
            if indicator in lower:
                return indicator
        return None

    def effective_error_text(self, payload, text):
        lower = text.lower()
        for needle in (payload, unquote(payload)):
            if needle:
                lower = lower.replace(needle.lower(), " ")
        lower = re.sub(r"(price|quantity)://[^\s\"']*", " ", lower)
        return re.sub(r"\s+", " ", lower).strip()

    def is_reflected_template_error(self, payload, text):
        lower = text.lower()
        if not any(prefix in lower for prefix in self.REFLECTED_ERROR_PREFIXES):
            return False

        decoded = unquote(payload)
        for needle in (payload, decoded):
            if needle and needle.lower() in lower:
                return True
        return False

    def response_prefix_key(self, text):
        stripped = re.sub(r"\s+", " ", text.strip())
        lower = stripped.lower()
        for prefix in self.REFLECTED_ERROR_PREFIXES:
            if lower.startswith(prefix):
                return f"error-prefix:{prefix}"
        return None

    def is_generic_api_error(self, text, payload=""):
        if payload and self.is_reflected_template_error(payload, text):
            return True

        lower = text.lower()
        if self.matched_indicator(payload, text):
            return False

        generic_markers = (
            "api error",
            "error reading resource",
            "invalid request",
            "bad request",
            "not found",
            "failed to fetch",
            "provided resource uri is invalid",
            "invalid uri",
            "resource uri is invalid",
        )
        if any(marker in lower for marker in generic_markers):
            return True
        return False

    def looks_like_data_leak(self, payload, text):
        if not self.payload_mentions_union(payload):
            return False
        if self.is_reflected_template_error(payload, text):
            return False
        lower = self.effective_error_text(payload, text)
        return any(marker in lower for marker in self.DATA_MARKERS)

    def parse_json_rows(self, text):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return []

        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("rows", "data", "results", "items"):
                rows = data.get(key)
                if isinstance(rows, list) and rows:
                    return [row for row in rows if isinstance(row, dict)]
            return [data]
        return []

    def table_preview(self, text):
        rows = self.parse_json_rows(text)
        if len(rows) >= 1:
            columns = []
            for row in rows[:8]:
                for key in row.keys():
                    if key not in columns:
                        columns.append(str(key))
            if columns:
                rendered = [" | ".join(columns)]
                for row in rows[:8]:
                    rendered.append(
                        " | ".join(str(row.get(col, "")) for col in columns)
                    )
                return "\n".join(rendered)

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) < 2:
            return ""

        for delimiter in ("|", "\t", ","):
            parsed = []
            for line in lines[:12]:
                if delimiter not in line:
                    break
                cells = [cell.strip() for cell in line.split(delimiter)]
                if len(cells) < 2:
                    break
                parsed.append(cells)
            if len(parsed) >= 2:
                widths = [
                    max(len(row[idx]) for row in parsed)
                    for idx in range(len(parsed[0]))
                ]
                return "\n".join(
                    " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row))
                    for row in parsed
                )

        if all(":" in line for line in lines[:6]):
            pairs = []
            for line in lines[:12]:
                key, _, value = line.partition(":")
                if not key.strip():
                    break
                pairs.append((key.strip(), value.strip()))
            if len(pairs) >= 2:
                key_width = max(len(key) for key, _ in pairs)
                return "\n".join(
                    f"{key.ljust(key_width)} | {value}"
                    for key, value in pairs
                )

        return ""

    def has_valid_table_data(self, text, baseline=""):
        if self.is_generic_api_error(text):
            return False

        preview = self.table_preview(text)
        if not preview:
            return False

        if baseline:
            baseline_preview = self.table_preview(baseline)
            if baseline_preview and preview == baseline_preview:
                return False

        lower = text.lower()
        if lower.startswith("error") and "sql" not in lower:
            return False

        return True

    def payload_mentions_union(self, payload):
        decoded = unquote(payload).lower()
        return "union" in payload.lower() or "union" in decoded

    def is_version_payload(self, payload):
        decoded = unquote(payload).lower()
        needles = (
            "sqlite_version",
            "@@version",
            "version()",
            "v$version",
            "v%24version",
            "banner",
        )
        combined = payload.lower() + " " + decoded
        return any(needle in combined for needle in needles)

    def looks_like_version_string(self, value):
        text = str(value).strip()
        if not text or len(text) > 300:
            return False

        lower = text.lower()
        if lower.startswith("error") or "syntax error" in lower:
            return False

        if any(marker in lower for marker in self.VERSION_MARKERS):
            return True

        return any(pattern.search(text) for pattern in self.VERSION_REGEXES)

    def extract_version_output(self, text):
        stripped = text.strip()
        if not stripped:
            return None

        rows = self.parse_json_rows(text)
        if rows:
            for row in rows:
                for value in row.values():
                    candidate = str(value).strip()
                    if self.looks_like_version_string(candidate):
                        return candidate

        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        for line in lines[:6]:
            if self.looks_like_version_string(line):
                return line

        for pattern in self.VERSION_REGEXES:
            match = pattern.search(stripped)
            if match:
                return match.group(0).strip()

        if len(lines) == 1 and re.fullmatch(r"[\d.]+", lines[0]):
            return lines[0]

        return None

    def looks_like_version_leak(self, payload, text, baseline=""):
        if not self.is_version_payload(payload):
            return False

        if not text.strip() or self.is_generic_api_error(text):
            return False

        if self.is_payload_reflection_only(payload, text, baseline):
            return False

        if baseline and text.strip() == baseline.strip():
            return False

        return self.extract_version_output(text) is not None

    def result_fingerprint(self, text, baseline="", payload=""):
        stripped = text.strip()
        if not stripped:
            return None

        if baseline and stripped == baseline.strip():
            return None

        if payload and self.is_reflected_template_error(payload, stripped):
            return None

        prefix_key = self.response_prefix_key(stripped)
        if prefix_key:
            return prefix_key

        preview = self.table_preview(stripped)
        if preview:
            return f"table:{preview}"

        version = self.extract_version_output(stripped)
        if version:
            return f"version:{version}"

        normalized = re.sub(r"\s+", " ", stripped)
        if len(normalized) > 800:
            normalized = normalized[:800]
        return f"raw:{normalized}"

    def looks_like_union_proof(self, payload, text, baseline=""):
        if not self.payload_mentions_union(payload):
            return False

        stripped = text.strip()
        if not stripped or self.is_generic_api_error(text):
            return False

        if baseline and stripped == baseline.strip():
            return False

        if re.fullmatch(r"\d+", stripped):
            return True

        if len(stripped) <= 120 and not stripped.lower().startswith("error"):
            if re.fullmatch(r"[\d\s,.-]+", stripped):
                return True

        return False

    def is_payload_reflection_only(self, payload, text, baseline=""):
        return self.is_reflected_template_error(payload, text)

    def looks_like_result_set(self, text, baseline="", payload=""):
        if self.is_generic_api_error(text, payload):
            return False

        if payload and self.is_payload_reflection_only(payload, text, baseline):
            return False

        if baseline and text.strip() == baseline.strip():
            return False

        lower = self.effective_error_text(payload, text) if payload else text.lower()

        if self.parse_json_rows(text):
            return True

        numbers = re.findall(r"\b\d+(?:\.\d+)?\b", text)
        if len(numbers) >= 2 and not lower.startswith("error"):
            if baseline and text.strip() != baseline.strip():
                if payload and all(part in text for part in payload.split() if part.isdigit()):
                    return False
                return True

        if re.search(r"\b(select|from|where|union)\b", lower):
            if "error" not in lower[:80]:
                return True

        return False

    def proof_score(self, payload, text, baseline=""):
        if self.is_reflected_template_error(payload, text):
            return 0

        if self.is_generic_api_error(text, payload):
            return 0

        if self.is_payload_reflection_only(payload, text, baseline):
            return 0

        lower = text.lower()

        if self.looks_like_version_leak(payload, text, baseline):
            return 110

        if self.has_valid_table_data(text, baseline):
            return 100

        if self.looks_like_union_proof(payload, text, baseline):
            return 95

        indicator = self.matched_indicator(payload, text)
        if indicator:
            return 90

        if self.looks_like_data_leak(payload, text):
            return 85

        if self.looks_like_result_set(text, baseline, payload):
            return 35

        if self.contains_error(text):
            return 10

        return 0

    def proof_level(self, payload, text, baseline=""):
        score = self.proof_score(payload, text, baseline)
        if score >= 50:
            return "strong"
        if score > 0:
            return "weak"
        return None

    def format_evidence(self, payload, text, indicator=None, title_hint="", baseline="", version_output=None):
        excerpt = text.strip()
        if len(excerpt) > 1500:
            excerpt = excerpt[:1500] + "\n...[truncated]"

        table_view = self.table_preview(excerpt)
        parts = [f"Payload: {payload}"]
        if version_output:
            parts.append("Database version (privilege-relevant output):")
            parts.append(version_output)
        if indicator:
            parts.append(f"Matched: {indicator}")
        if title_hint:
            parts.append(f"Signal: {title_hint}")
        if baseline:
            parts.append("Baseline response:")
            parts.append(baseline[:400] + ("..." if len(baseline) > 400 else ""))
        parts.append("Raw response:")
        parts.append(excerpt)
        if table_view:
            parts.append("Table view:")
            parts.append(table_view)
        return "\n".join(parts)

    def build_finding(self, capability, payload, text, level, baseline=""):
        indicator = self.matched_indicator(payload, text)
        version_output = self.extract_version_output(text) if self.is_version_payload(payload) else None

        if self.looks_like_version_leak(payload, text, baseline):
            title = "SQL Injection - Database Version Leaked"
            hint = f"Version output: {version_output}"
            severity = "CRITICAL"
        elif self.has_valid_table_data(text, baseline):
            title = "SQL Injection - Data Extracted"
            hint = "Valid table/row data returned"
            severity = "CRITICAL"
        elif indicator:
            title = "SQL Injection Confirmed"
            hint = f"Database error: {indicator}"
            severity = "CRITICAL"
        elif self.looks_like_union_proof(payload, text, baseline):
            title = "SQL Injection Confirmed"
            hint = "UNION payload returned scalar query output"
            severity = "CRITICAL"
        elif self.looks_like_data_leak(payload, text):
            title = "SQL Injection - Schema/Data Leak"
            hint = "UNION or metadata visible in response"
            severity = "CRITICAL"
        elif self.looks_like_result_set(text, baseline, payload):
            title = "SQL Injection - Result Set Returned"
            hint = "Response diverged from baseline with query-like data"
            severity = "HIGH"
        else:
            title = "Potential SQL Injection Signal"
            hint = "Generic error only"
            severity = "MEDIUM" if level == "weak" else "HIGH"

        result = self.finding(
            capability=capability,
            payload=payload,
            title=title,
            evidence=self.format_evidence(
                payload,
                text,
                indicator=indicator,
                title_hint=hint,
                baseline=baseline,
                version_output=version_output,
            ),
            recommendation=(
                "Use parameterized queries and avoid concatenating "
                "user-controlled input into SQL statements. "
                "Database version disclosure aids privilege escalation "
                "and targeted exploit selection."
            ),
        )
        result.severity = severity
        return result

    def evaluate(self, capability, payload, response, baseline=""):
        text = self.response_text(response)
        if not text:
            return None, None

        level = self.proof_level(payload, text, baseline)
        if not level:
            return None, None

        return self.build_finding(capability, payload, text, level, baseline), level

    def analyze(self, capability, payload, response):
        finding, level = self.evaluate(capability, payload, response)
        if level == "weak":
            return None
        return finding

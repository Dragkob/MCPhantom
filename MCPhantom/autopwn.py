import asyncio
import re

from urllib.parse import unquote

from audit.classifier import CapabilityClassifier
from audit.discovery import DiscoveryEngine
from audit.mcp_logging import quiet_mcp_teardown_logging
from audit.plugin_loader import load_plugins
from audit.safety import (
    SAFE_MODE,
    SQLI_PAYLOAD_DELAY_SEC,
    filter_sqli_payloads_safe,
    is_mutating_tool,
    parallel_check_limit,
    sqli_parallel_limit,
)
from mcp_client import make_client, resolve_target_auth

MAX_PAYLOADS = 3
PAYLOAD_LIMITS = {
    "CMDI": 24,
    "SSRF": 4,
    "TRAVERSAL": 18,
}
CHECK_TIMEOUT = 30
SQLI_CHECK_TIMEOUT = 120
MCP_CLIENT_DRAIN_SEC = 0.5
TRAVERSAL_CHECK_TIMEOUT = 90
PAYLOAD_TIMEOUT = 8
MAX_PARALLEL_CHECKS = 4
MAX_PARALLEL_PAYLOADS = 6

VULN_TAGS = frozenset({"SSRF", "CMDI", "SQLI", "TRAVERSAL", "IDOR", "INFOLEAK"})

TAG_PARAM_KEYWORDS = {
    "SSRF": ("url", "uri", "endpoint", "host", "hostname", "domain", "ip", "port"),
    "CMDI": ("command", "cmd", "exec", "execute", "shell", "bash"),
    "SQLI": ("sql", "db", "database", "query", "item", "price", "product", "platform", "name", "search", "filter", "term", "category", "type", "value"),
    "TRAVERSAL": ("path", "file", "filename", "directory", "folder"),
    "IDOR": ("id", "userid", "docid", "uuid", "document", "record"),
}

CLASSIFIER_TAG_TO_PLUGIN = {
    "URL": "SSRF",
    "HOST": "SSRF",
    "PORT": "SSRF",
    "COMMAND": "CMDI",
    "DATABASE": "SQLI",
    "PATH": "TRAVERSAL",
    "FILE": "TRAVERSAL",
    "DIRECTORY": "TRAVERSAL",
    "ID": "IDOR",
    "DOCUMENT": "IDOR",
    "SECRET": "INFOLEAK",
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def normalize_payload(value):
    return unquote(str(value or "")).strip()


def deduplicate_findings(findings):
    from audit.plugins.sqli import SQLiPlugin
    from audit.plugins.traversal import PathTraversalPlugin

    sqli = SQLiPlugin()
    traversal = PathTraversalPlugin()
    unique = {}
    ranked = []

    for finding in findings:
        if finding.plugin == "SQL Injection":
            key = sqli.finding_dedup_key(finding)
        elif finding.plugin == "Path Traversal":
            key = traversal.finding_dedup_key(finding)
        else:
            key = (
                finding.plugin,
                finding.capability.name,
                getattr(finding.capability, "type", ""),
                normalize_payload(finding.payload),
                finding.title,
            )

        score = 0
        prefer_current = False
        if finding.plugin == "SQL Injection":
            raw = sqli.extract_raw_response(finding.evidence)
            score = sqli.proof_score(finding.payload, raw)
        elif finding.plugin == "Path Traversal":
            prefer_current = True

        previous = unique.get(key)
        if previous is None:
            unique[key] = finding
            ranked.append(key)
            continue

        if finding.plugin == "SQL Injection":
            prev_raw = sqli.extract_raw_response(previous.evidence)
            prev_score = sqli.proof_score(previous.payload, prev_raw)
            if score > prev_score:
                unique[key] = finding
        elif prefer_current:
            if len(normalize_payload(finding.payload)) < len(normalize_payload(previous.payload)):
                unique[key] = finding

    return [unique[key] for key in ranked]


def finding_dedup_key_dict(finding_dict):
    from audit.plugins.sqli import SQLiPlugin
    from audit.plugins.traversal import PathTraversalPlugin

    if finding_dict.get("plugin") == "SQL Injection":
        sqli = SQLiPlugin()
        raw = sqli.extract_raw_response(finding_dict.get("evidence", ""))
        fingerprint = sqli.result_fingerprint(raw, payload=finding_dict.get("payload", ""))
        if fingerprint:
            return (
                finding_dict.get("plugin"),
                finding_dict.get("capability"),
                finding_dict.get("type"),
                fingerprint,
            )

        return (
            finding_dict.get("plugin"),
            finding_dict.get("capability"),
            finding_dict.get("type"),
            normalize_payload(finding_dict.get("payload")),
            finding_dict.get("title"),
        )

    if finding_dict.get("plugin") == "Path Traversal":
        traversal = PathTraversalPlugin()
        fingerprint = traversal.result_fingerprint(
            finding_dict.get("evidence", ""),
            finding_dict.get("payload", ""),
        )
        if fingerprint:
            return (
                finding_dict.get("plugin"),
                finding_dict.get("capability"),
                finding_dict.get("type"),
                fingerprint,
            )

    return (
        finding_dict.get("plugin"),
        finding_dict.get("capability"),
        finding_dict.get("type"),
        normalize_payload(finding_dict.get("payload")),
        finding_dict.get("title"),
    )


def finding_to_dict(finding):
    return {
        "plugin": finding.plugin,
        "severity": finding.severity,
        "title": finding.title,
        "capability": finding.capability.name,
        "type": finding.capability.type,
        "payload": finding.payload,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
    }


def match_parameters(capability, plugin_tag, classifier=None):
    if capability.type != "tool":
        return [None]

    keywords = TAG_PARAM_KEYWORDS.get(plugin_tag, ())
    matched = []

    for param in capability.parameters or []:
        lowered = param.lower()
        if keywords and any(keyword in lowered for keyword in keywords):
            matched.append(param)
            continue

        if classifier is None:
            continue

        semantic = classifier.keyword_map.get(lowered)
        if semantic and CLASSIFIER_TAG_TO_PLUGIN.get(semantic) == plugin_tag:
            matched.append(param)
            continue

        for keyword, semantic_tag in classifier.keyword_map.items():
            if keyword in lowered and CLASSIFIER_TAG_TO_PLUGIN.get(semantic_tag) == plugin_tag:
                matched.append(param)
                break

    return list(dict.fromkeys(matched))


def limited_payloads(plugin):
    limit = PAYLOAD_LIMITS.get(plugin.payload_category, MAX_PAYLOADS)
    return plugin.get_payloads(aggressive=False)[:limit]


def plugin_payloads(plugin, unsafe=False):
    if plugin.payload_category == "SQLI":
        payloads = plugin.get_payloads(aggressive=unsafe)
        if SAFE_MODE and not unsafe:
            return filter_sqli_payloads_safe(payloads)
        return payloads
    if unsafe:
        limit = PAYLOAD_LIMITS.get(plugin.payload_category, MAX_PAYLOADS)
        return plugin.get_payloads(aggressive=True)[:limit]
    return limited_payloads(plugin)


def collect_findings(result):
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]


async def cancel_tasks_quietly(tasks, drain_sec=MCP_CLIENT_DRAIN_SEC):
    """Cancel in-flight work and give the MCP SSE client time to close cleanly."""
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    if drain_sec:
        await asyncio.sleep(drain_sec)


async def drain_mcp_client(drain_sec=MCP_CLIENT_DRAIN_SEC):
    if drain_sec:
        await asyncio.sleep(drain_sec)


class SmartScanner:

    def __init__(self, target, username=None, password=None):
        self.target = target
        self.username = username
        self.password = password
        self.clean_url, _ = resolve_target_auth(target, username, password)
        self.classifier = CapabilityClassifier()
        self.plugins = load_plugins()

    def _client(self):
        return make_client(self.target, self.username, self.password)

    def classify_all(self, collection):
        capabilities = []
        for capability in collection.all():
            capability.tags = self.classifier.classify(capability)
            capabilities.append(capability)
        return capabilities

    def should_test(self, capability, plugin):
        if capability.type == "prompt":
            return False

        #
        # Never fuzz write/store tools — payloads in file_name or similar can
        # overwrite real files (e.g. store_file + ../../../../etc/passwd).
        #
        if is_mutating_tool(capability):
            return False

        #
        # Substitutable URI template slots are generic injection surfaces.
        # Do not rely on parameter names alone (e.g. {platform}, {name}).
        #
        if (
            capability.type == "resource_template"
            and plugin.payload_category == "SQLI"
            and self._has_template_slots(capability)
        ):
            return True

        if (
            capability.type == "resource_template"
            and plugin.payload_category == "TRAVERSAL"
            and self._has_traversal_surface(capability)
        ):
            return True

        if not plugin.match(capability):
            return False

        if not any(tag in capability.tags for tag in plugin.tags):
            return False

        if plugin.name == "Information Disclosure":
            if capability.type == "tool":
                return "SECRET" in capability.tags or "INFOLEAK" in capability.tags
            return capability.type in ("resource", "resource_template")

        if plugin.payload_category == "TRAVERSAL":
            return capability.type == "resource_template"

        if plugin.payload_category == "SQLI":
            if capability.type == "tool":
                for tag in plugin.tags:
                    if match_parameters(capability, tag, self.classifier):
                        return True
            return False

        if capability.type == "tool":
            for tag in plugin.tags:
                if match_parameters(capability, tag, self.classifier):
                    return True
            return False

        return capability.type in ("resource", "resource_template")

    def target_parameters(self, capability, plugin, unsafe=False):
        if capability.type != "tool":
            return [None]

        params = []
        for tag in plugin.tags:
            params.extend(match_parameters(capability, tag, self.classifier))
        params = list(dict.fromkeys(params))

        if unsafe and not params and capability.parameters:
            if plugin.payload_category in ("SQLI", "CMDI", "SSRF", "TRAVERSAL", "IDOR"):
                return list(capability.parameters)

        return params if params else [None]

    def _has_template_slots(self, capability):
        text = (capability.uri_template or "") + (capability.uri or "")
        return bool(re.search(r"\{[^}]+\}", text))

    def _has_traversal_surface(self, capability):
        text = " ".join(
            part
            for part in (
                capability.uri_template,
                capability.uri,
                capability.name,
                capability.description,
            )
            if part
        ).lower()

        if not text:
            return False

        hints = (
            "file",
            "path",
            "folder",
            "directory",
            "getfile",
            "readfile",
            "filename",
            "filepath",
            "upload",
            "download",
        )
        return any(hint in text for hint in hints)

    def untested_reason(self, capability):
        if capability.type == "prompt":
            return "Prompts are not fuzzed by AutoPwn"

        if is_mutating_tool(capability):
            return "Write/store/delete tool, skipped to avoid modifying server data"

        if capability.type == "resource":
            if SAFE_MODE:
                return (
                    "Static resource URI. Safe mode only tests SQLi on "
                    "template placeholders, not fixed URIs"
                )
            return "No matching read-only checks were scheduled for this resource"

        if capability.type == "resource_template":
            if not self._has_template_slots(capability):
                return "Template has no substitutable placeholders"
            if (
                not self._has_traversal_surface(capability)
                and not any(tag in VULN_TAGS for tag in capability.tags)
            ):
                return "Template surface did not match any plugin profile"
            return "No matching vulnerability checks were scheduled"

        if capability.type == "tool":
            return "Tool arguments did not match any safe, read-only test profile"

        return "Not included in the AutoPwn test plan"

    def build_untested(self, capabilities):
        tested = {capability.name for capability, _ in self.build_jobs(capabilities)}
        untested = []
        seen = set()

        for capability in capabilities:
            if capability.name in tested or capability.name in seen:
                continue
            seen.add(capability.name)
            untested.append({
                "name": capability.name,
                "type": capability.type,
                "reason": self.untested_reason(capability),
                "runnable": self.can_run_anyway(capability),
            })

        return untested

    def can_run_anyway(self, capability):
        return capability.type != "prompt"

    def _should_test_force(self, capability, plugin):
        if capability.type == "prompt":
            return False

        if capability.type == "resource":
            if plugin.name == "Information Disclosure":
                return True
            if plugin.payload_category == "SQLI":
                return bool(capability.uri)
            return plugin.match(capability)

        if capability.type == "resource_template":
            if plugin.name == "Information Disclosure":
                return True
            if plugin.payload_category == "SQLI" and self._has_template_slots(capability):
                return True
            if plugin.payload_category == "TRAVERSAL" and self._has_traversal_surface(capability):
                return True
            return plugin.match(capability)

        if capability.type == "tool":
            if plugin.name == "Information Disclosure":
                return True
            if plugin.payload_category == "SQLI":
                return bool(capability.parameters)
            if plugin.match(capability):
                return True
            if capability.parameters and plugin.payload_category:
                return True

        return False

    def build_force_jobs(self, capability):
        if not self.can_run_anyway(capability):
            return []

        jobs = []
        seen = set()
        for plugin in self.plugins:
            if not self._should_test_force(capability, plugin):
                continue
            key = (capability.name, plugin.name)
            if key in seen:
                continue
            seen.add(key)
            jobs.append((capability, plugin))
        return jobs

    def estimate_job_tests(self, capability, plugin, unsafe=False):
        if plugin.name == "Information Disclosure":
            return 1
        if capability.type == "tool":
            params = self.target_parameters(capability, plugin, unsafe=unsafe)
            payload_count = len(plugin_payloads(plugin, unsafe=unsafe)) or 1
            return len(params) * min(MAX_PAYLOADS, payload_count)
        payloads = plugin_payloads(plugin, unsafe=unsafe)
        return len(payloads) or min(MAX_PAYLOADS, len(limited_payloads(plugin)) or 1)

    def build_plan(self, capabilities):
        entries = []
        total_tests = 0

        for capability in capabilities:
            actionable = [tag for tag in capability.tags if tag in VULN_TAGS]
            template_surface = (
                capability.type == "resource_template"
                and (
                    self._has_template_slots(capability)
                    or self._has_traversal_surface(capability)
                )
            )
            if not actionable and not template_surface:
                continue

            for plugin in self.plugins:
                if not self.should_test(capability, plugin):
                    continue

                if plugin.name == "Information Disclosure":
                    tests = 1
                elif capability.type == "tool":
                    params = self.target_parameters(capability, plugin)
                    tests = len(params) * min(MAX_PAYLOADS, len(plugin_payloads(plugin)) or 1)
                else:
                    tests = len(plugin_payloads(plugin)) or min(MAX_PAYLOADS, len(limited_payloads(plugin)) or 1)

                total_tests += tests
                entries.append({
                    "plugin": plugin.name,
                    "capability": capability.name,
                    "type": capability.type,
                    "tags": [tag for tag in plugin.tags if tag in capability.tags],
                    "tests": tests,
                })

        return {
            "capabilities": len(capabilities),
            "targets": len(entries),
            "tests": total_tests,
            "entries": entries,
            "safe_mode": SAFE_MODE,
            "skipped": self.build_untested(capabilities),
        }

    async def run_infoleak(self, client, plugin, capability):
        return await plugin.run(client, capability, aggressive=False)

    async def sqli_baseline(self, client, plugin, capability):
        if capability.type == "resource_template" and capability.uri_template:
            uri = re.sub(r"\{.*?\}", "1", capability.uri_template)
            response = await plugin.read_resource(client, uri)
            return plugin.response_text(response)

        if capability.type == "resource" and capability.uri:
            response = await plugin.read_resource(client, capability.uri)
            return plugin.response_text(response)

        return ""

    def pick_sqli_findings(self, candidates):
        if not candidates:
            return []

        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        seen = set()
        findings = []

        for entry in ranked:
            score = entry[0]
            finding = entry[1]
            fingerprint = entry[2] if len(entry) > 2 else finding.evidence

            if score < 50 or not fingerprint:
                continue
            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            findings.append(finding)

        return findings

    def pick_best_findings(self, candidates):
        return self.pick_sqli_findings(candidates)

    def check_timeout_for(self, plugin):
        if plugin.payload_category == "SQLI":
            return SQLI_CHECK_TIMEOUT
        if plugin.payload_category == "TRAVERSAL":
            return TRAVERSAL_CHECK_TIMEOUT
        return CHECK_TIMEOUT

    async def _sqli_test_payload(self, plugin, client, capability, payload, baseline, param=None):
        if payload.value == "1":
            return []

        try:
            if capability.type == "tool" and param is not None:
                arguments = plugin.build_tool_arguments(
                    capability,
                    param,
                    payload.value,
                )
                response = await asyncio.wait_for(
                    plugin.call_tool(client, capability.name, arguments),
                    timeout=PAYLOAD_TIMEOUT,
                )
                response.parameter = param
            else:
                response = await asyncio.wait_for(
                    plugin.execute_payload(client, capability, payload.value),
                    timeout=PAYLOAD_TIMEOUT,
                )
        except (asyncio.TimeoutError, Exception):
            return []

        if not isinstance(response, list):
            response = [response]

        hits = []
        seen = set()
        for item in response:
            text = plugin.response_text(item)
            score = plugin.proof_score(payload.value, text, baseline)
            finding, level = plugin.evaluate(
                capability,
                payload.value,
                item,
                baseline,
            )
            if finding and level == "strong":
                fingerprint = plugin.result_fingerprint(text, baseline, payload.value)
                if fingerprint and fingerprint not in seen:
                    seen.add(fingerprint)
                    hits.append((score, finding, fingerprint))

        return hits

    async def run_sqli_plugin(self, client, plugin, capability, unsafe=False):
        from audit.plugins.sqli import SQLiPlugin

        if not isinstance(plugin, SQLiPlugin):
            return await self.run_payload_plugin(
                client,
                plugin,
                capability,
                unsafe=unsafe,
            )

        baseline = await self.sqli_baseline(client, plugin, capability)
        payloads = [p for p in plugin_payloads(plugin, unsafe=unsafe) if p.value != "1"]
        parallel = 6 if unsafe else sqli_parallel_limit()
        semaphore = asyncio.Semaphore(parallel)
        candidates = []

        async def run_one(payload, param=None):
            async with semaphore:
                if SAFE_MODE and not unsafe and SQLI_PAYLOAD_DELAY_SEC:
                    await asyncio.sleep(SQLI_PAYLOAD_DELAY_SEC)
                return await self._sqli_test_payload(
                    plugin,
                    client,
                    capability,
                    payload,
                    baseline,
                    param,
                )

        tasks = []
        if capability.type == "tool":
            for param in self.target_parameters(capability, plugin, unsafe=unsafe):
                for payload in payloads:
                    tasks.append(asyncio.create_task(run_one(payload, param)))
        else:
            for payload in payloads:
                tasks.append(asyncio.create_task(run_one(payload)))

        if not tasks:
            return []

        if SAFE_MODE and not unsafe:
            candidates = []
            try:
                for finished in asyncio.as_completed(tasks):
                    batch = await finished
                    if not batch:
                        continue
                    candidates.extend(batch)
                    if self.pick_sqli_findings(candidates):
                        break
            finally:
                await cancel_tasks_quietly(tasks)
            return self.pick_sqli_findings(candidates)

        results = await asyncio.gather(*tasks)
        candidates = []
        for batch in results:
            candidates.extend(batch)

        return self.pick_sqli_findings(candidates)

    async def traversal_baseline(self, client, plugin, capability):
        from audit.template_uri import substitute_payload

        template = capability.uri_template or capability.name or ""
        if capability.type != "resource_template" or not template:
            return ""

        try:
            response = await plugin.read_resource(
                client,
                substitute_payload(template, "test"),
            )
            return plugin.response_text(response)
        except Exception:
            return ""

    async def run_traversal_plugin(self, client, plugin, capability):
        payloads = limited_payloads(plugin)
        baseline = await self.traversal_baseline(client, plugin, capability)
        semaphore = asyncio.Semaphore(MAX_PARALLEL_PAYLOADS)
        findings = []

        async def run_one(payload):
            async with semaphore:
                try:
                    response = await asyncio.wait_for(
                        plugin.execute_payload(
                            client,
                            capability,
                            payload.value,
                        ),
                        timeout=PAYLOAD_TIMEOUT,
                    )
                except (asyncio.TimeoutError, Exception):
                    return []

                if not isinstance(response, list):
                    response = [response]

                hits = []
                for item in response:
                    finding = plugin.analyze(
                        capability,
                        payload.value,
                        item,
                        baseline=baseline,
                    )
                    if finding:
                        hits.append(finding)
                return hits

        tasks = [
            asyncio.create_task(run_one(payload))
            for payload in payloads
        ]

        try:
            for finished in asyncio.as_completed(tasks):
                batch = await finished
                if not batch:
                    continue
                findings.extend(batch)
                break
        finally:
            await cancel_tasks_quietly(tasks)

        return deduplicate_findings(findings)

    async def run_payload_plugin(self, client, plugin, capability, unsafe=False):
        if plugin.payload_category == "SQLI":
            return await self.run_sqli_plugin(
                client,
                plugin,
                capability,
                unsafe=unsafe,
            )

        if plugin.payload_category == "TRAVERSAL":
            return await self.run_traversal_plugin(client, plugin, capability)

        findings = []
        stop_early = plugin.payload_category not in ("CMDI",)
        payloads = plugin_payloads(plugin, unsafe=unsafe) if unsafe else limited_payloads(plugin)

        if capability.type == "tool":
            params = self.target_parameters(capability, plugin, unsafe=unsafe)

            for param in params:
                for payload in payloads:
                    arguments = plugin.build_tool_arguments(
                        capability,
                        param,
                        payload.value,
                    )
                    response = await plugin.call_tool(
                        client,
                        capability.name,
                        arguments,
                    )
                    response.parameter = param
                    findings.extend(
                        collect_findings(
                            plugin.analyze(capability, payload.value, response)
                        )
                    )
                    if findings and stop_early:
                        return findings
            return findings

        for payload in payloads:
            try:
                response = await plugin.execute_payload(
                    client,
                    capability,
                    payload.value,
                )
            except Exception:
                continue

            if not isinstance(response, list):
                response = [response]

            for item in response:
                findings.extend(
                    collect_findings(
                        plugin.analyze(capability, payload.value, item)
                    )
                )

            if findings and stop_early:
                break

        return findings

    def build_jobs(self, capabilities):
        jobs = []
        for capability in capabilities:
            actionable = any(tag in VULN_TAGS for tag in capability.tags)
            template_surface = (
                capability.type == "resource_template"
                and (
                    self._has_template_slots(capability)
                    or self._has_traversal_surface(capability)
                )
            )
            if not actionable and not template_surface:
                continue
            for plugin in self.plugins:
                if self.should_test(capability, plugin):
                    jobs.append((capability, plugin))
        return jobs

    async def run_check(self, capability, plugin, client=None, unsafe=False):
        params = self.target_parameters(capability, plugin, unsafe=unsafe)
        timeout = self.check_timeout_for(plugin)

        try:
            if client is None:
                async with self._client() as owned:
                    result = await self._run_check_with_client(
                        owned,
                        capability,
                        plugin,
                        timeout,
                        unsafe=unsafe,
                    )
                    await drain_mcp_client()
            else:
                result = await self._run_check_with_client(
                    client,
                    capability,
                    plugin,
                    timeout,
                    unsafe=unsafe,
                )
        except asyncio.TimeoutError:
            return {
                "params": params,
                "result_list": [],
                "status": "timeout",
                "error": f"Timed out after {timeout}s",
            }
        except Exception as exc:
            return {
                "params": params,
                "result_list": [],
                "status": "error",
                "error": str(exc),
            }

        result_list = (
            result
            if isinstance(result, list)
            else ([result] if result is not None else [])
        )
        return {
            "params": params,
            "result_list": result_list,
            "status": "vulnerable" if result_list else "clean",
        }

    async def _run_check_with_client(self, client, capability, plugin, timeout, unsafe=False):
        if plugin.name == "Information Disclosure":
            return await asyncio.wait_for(
                self.run_infoleak(client, plugin, capability),
                timeout=timeout,
            )
        return await asyncio.wait_for(
            self.run_payload_plugin(client, plugin, capability, unsafe=unsafe),
            timeout=timeout,
        )

    async def run_capability_anyway(self, capability_name, capability_type=None):
        async with self._client() as client:
            engine = DiscoveryEngine(self.clean_url, client=client)
            collection = await engine.enumerate()
            capabilities = self.classify_all(collection)

            capability = None
            for item in capabilities:
                if item.name != capability_name:
                    continue
                if capability_type and item.type != capability_type:
                    continue
                capability = item
                break

            if capability is None:
                return {
                    "ok": False,
                    "error": f"Capability not found: {capability_name}",
                }

            if not self.can_run_anyway(capability):
                return {
                    "ok": False,
                    "error": "Prompts cannot be fuzzed by AutoPwn",
                }

            jobs = self.build_force_jobs(capability)
            if not jobs:
                return {
                    "ok": False,
                    "error": "No checks available for this surface",
                }

            coverage = []
            findings = []
            tests_added = 0
            plan_entries = []

            for job_capability, plugin in jobs:
                check = await self.run_check(
                    job_capability,
                    plugin,
                    client=client,
                    unsafe=True,
                )
                result_list = check.get("result_list", [])
                findings.extend(result_list)
                tests_added += self.estimate_job_tests(
                    job_capability,
                    plugin,
                    unsafe=True,
                )

                entry = {
                    "capability": job_capability.name,
                    "type": job_capability.type,
                    "plugin": plugin.name,
                    "parameters": check.get("params", [])
                    if job_capability.type == "tool"
                    else [],
                    "status": check.get("status", "clean"),
                    "findings": len(result_list),
                    "error": check.get("error", ""),
                    "forced": True,
                }
                coverage.append(entry)
                plan_entries.append({
                    "plugin": plugin.name,
                    "capability": job_capability.name,
                    "type": job_capability.type,
                    "tags": [tag for tag in plugin.tags if tag in job_capability.tags],
                    "tests": self.estimate_job_tests(
                        job_capability,
                        plugin,
                        unsafe=True,
                    ),
                    "forced": True,
                })

            await drain_mcp_client()

            unique_findings = deduplicate_findings(findings)
            return {
                "ok": True,
                "capability": capability.name,
                "type": capability.type,
                "coverage": coverage,
                "findings": [finding_to_dict(item) for item in unique_findings],
                "jobs_run": len(jobs),
                "tests_added": tests_added,
                "plan_entries": plan_entries,
            }

    async def scan_stream(self):
        findings = []
        coverage = []
        executed = 0
        plan = {"capabilities": 0, "targets": 0, "tests": 0, "entries": []}
        sent_done = False
        streamed_finding_keys = set()

        try:
            async with self._client() as client:
                engine = DiscoveryEngine(self.clean_url, client=client)
                collection = await engine.enumerate()
                capabilities = self.classify_all(collection)
                plan = self.build_plan(capabilities)
                jobs = self.build_jobs(capabilities)

                yield {
                    "event": "start",
                    "url": self.clean_url,
                    "plan": plan,
                }

                if not jobs:
                    sent_done = True
                    yield self._done_event(plan, executed, coverage, findings)
                    return

                semaphore = asyncio.Semaphore(parallel_check_limit())

                async def guarded_run(capability, plugin):
                    async with semaphore:
                        return capability, plugin, await self.run_check(
                            capability,
                            plugin,
                            client=client,
                        )

                tasks = [
                    asyncio.create_task(guarded_run(capability, plugin))
                    for capability, plugin in jobs
                ]

                for finished in asyncio.as_completed(tasks):
                    capability, plugin, check = await finished
                    executed += 1
                    result_list = check.get("result_list", [])
                    findings.extend(result_list)

                    yield {
                        "event": "progress",
                        "message": (
                            f"Finished {capability.name} ({plugin.name}) "
                            f"[{executed}/{len(jobs)}]"
                        ),
                        "executed": executed,
                        "total": len(jobs),
                        "capability": capability.name,
                        "plugin": plugin.name,
                    }

                    entry = {
                        "capability": capability.name,
                        "type": capability.type,
                        "plugin": plugin.name,
                        "parameters": check.get("params", [])
                        if capability.type == "tool"
                        else [],
                        "status": check.get("status", "clean"),
                        "findings": len(result_list),
                        "error": check.get("error", ""),
                    }
                    coverage.append(entry)
                    yield {"event": "coverage", "entry": entry}

                    for finding in result_list:
                        finding_dict = finding_to_dict(finding)
                        dedup_key = finding_dedup_key_dict(finding_dict)
                        if dedup_key in streamed_finding_keys:
                            continue
                        streamed_finding_keys.add(dedup_key)
                        yield {
                            "event": "finding",
                            "finding": finding_dict,
                        }

                await drain_mcp_client()
                sent_done = True
                yield self._done_event(plan, executed, coverage, findings)
        except Exception as exc:
            yield {"event": "error", "ok": False, "error": str(exc)}
            if coverage or findings:
                sent_done = True
                yield self._done_event(
                    plan,
                    executed,
                    coverage,
                    findings,
                    partial=True,
                    note=str(exc),
                )
        finally:
            if not sent_done:
                yield self._done_event(
                    plan,
                    executed,
                    coverage,
                    findings,
                    partial=True,
                )

    def _done_event(
        self,
        plan,
        executed,
        coverage,
        findings,
        partial=False,
        note="",
    ):
        findings = deduplicate_findings(findings)
        findings.sort(
            key=lambda item: SEVERITY_ORDER.get(item.severity.upper(), 99)
        )

        prefix = "AutoPwn complete"
        if partial:
            prefix = "AutoPwn finished (partial)"

        raw = (
            f"{prefix}: {len(findings)} finding(s) "
            f"from {executed}/{plan.get('targets', 0)} targeted checks."
        )
        if note:
            raw += f" Note: {note}"

        return {
            "event": "done",
            "ok": True,
            "partial": partial,
            "url": self.clean_url,
            "plan": plan,
            "executed": executed,
            "coverage": coverage,
            "findings": [finding_to_dict(item) for item in findings],
            "summary": {
                "total": len(findings),
                "critical": sum(
                    1 for f in findings if f.severity.upper() == "CRITICAL"
                ),
                "high": sum(
                    1 for f in findings if f.severity.upper() == "HIGH"
                ),
                "medium": sum(
                    1 for f in findings if f.severity.upper() == "MEDIUM"
                ),
                "low": sum(
                    1 for f in findings if f.severity.upper() == "LOW"
                ),
                "info": sum(
                    1 for f in findings if f.severity.upper() == "INFO"
                ),
            },
            "raw": raw,
        }

    async def scan(self):
        final = None
        async for event in self.scan_stream():
            if event.get("event") == "done":
                final = event
            elif event.get("event") == "error":
                return {
                    "ok": False,
                    "error": event.get("error", "AutoPwn failed"),
                    "url": self.clean_url,
                }
        return final or {
            "ok": False,
            "error": "AutoPwn produced no result",
            "url": self.clean_url,
        }


async def run_autopwn(url, username=None, password=None):
    quiet_mcp_teardown_logging()
    scanner = SmartScanner(url, username, password)
    return await scanner.scan()


async def run_autopwn_stream(url, username=None, password=None):
    quiet_mcp_teardown_logging()
    scanner = SmartScanner(url, username, password)
    async for event in scanner.scan_stream():
        yield event


async def run_capability_anyway(url, capability_name, capability_type=None, username=None, password=None):
    quiet_mcp_teardown_logging()
    scanner = SmartScanner(url, username, password)
    return await scanner.run_capability_anyway(capability_name, capability_type)

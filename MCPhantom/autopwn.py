from fastmcp import Client
import asyncio
import re

from audit.classifier import CapabilityClassifier
from audit.discovery import DiscoveryEngine
from audit.plugin_loader import load_plugins

MAX_PAYLOADS = 3
PAYLOAD_LIMITS = {
    "CMDI": 5,
    "SSRF": 4,
}
CHECK_TIMEOUT = 30
SQLI_CHECK_TIMEOUT = 120
PAYLOAD_TIMEOUT = 8
MAX_PARALLEL_CHECKS = 4
MAX_PARALLEL_PAYLOADS = 6

VULN_TAGS = frozenset({"SSRF", "CMDI", "SQLI", "TRAVERSAL", "IDOR", "INFOLEAK"})

TAG_PARAM_KEYWORDS = {
    "SSRF": ("url", "uri", "endpoint", "host", "hostname", "domain", "ip", "port"),
    "CMDI": ("command", "cmd", "exec", "execute", "shell", "bash"),
    "SQLI": ("sql", "db", "database", "query", "item", "price", "product"),
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


def deduplicate_findings(findings):
    unique = {}
    for finding in findings:
        key = (
            finding.plugin,
            finding.capability.name,
            finding.payload,
            finding.title,
        )
        unique[key] = finding
    return list(unique.values())


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


def plugin_payloads(plugin):
    if plugin.payload_category == "SQLI":
        return plugin.get_payloads(aggressive=False)
    return limited_payloads(plugin)


def collect_findings(result):
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]


class SmartScanner:

    def __init__(self, target):
        self.target = target
        self.classifier = CapabilityClassifier()
        self.plugins = load_plugins()

    def classify_all(self, collection):
        capabilities = []
        for capability in collection.all():
            capability.tags = self.classifier.classify(capability)
            capabilities.append(capability)
        return capabilities

    def should_test(self, capability, plugin):
        if capability.type == "prompt":
            return False

        if not plugin.match(capability):
            return False

        if not any(tag in capability.tags for tag in plugin.tags):
            return False

        if plugin.name == "Information Disclosure":
            if capability.type == "tool":
                return "SECRET" in capability.tags or "INFOLEAK" in capability.tags
            return capability.type in ("resource", "resource_template")

        if capability.type == "tool":
            for tag in plugin.tags:
                if match_parameters(capability, tag, self.classifier):
                    return True
            return False

        return capability.type in ("resource", "resource_template")

    def target_parameters(self, capability, plugin):
        if capability.type != "tool":
            return [None]

        params = []
        for tag in plugin.tags:
            params.extend(match_parameters(capability, tag, self.classifier))
        return list(dict.fromkeys(params))

    def build_plan(self, capabilities):
        entries = []
        total_tests = 0

        for capability in capabilities:
            actionable = [tag for tag in capability.tags if tag in VULN_TAGS]
            if not actionable:
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

    async def run_sqli_plugin(self, client, plugin, capability):
        from audit.plugins.sqli import SQLiPlugin

        if not isinstance(plugin, SQLiPlugin):
            return await self.run_payload_plugin(client, plugin, capability)

        baseline = await self.sqli_baseline(client, plugin, capability)
        payloads = [p for p in plugin_payloads(plugin) if p.value != "1"]
        semaphore = asyncio.Semaphore(MAX_PARALLEL_PAYLOADS)
        candidates = []

        async def run_one(payload, param=None):
            async with semaphore:
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
            for param in self.target_parameters(capability, plugin):
                for payload in payloads:
                    tasks.append(asyncio.create_task(run_one(payload, param)))
        else:
            for payload in payloads:
                tasks.append(asyncio.create_task(run_one(payload)))

        if tasks:
            results = await asyncio.gather(*tasks)
            candidates = []
            for batch in results:
                candidates.extend(batch)

        return self.pick_sqli_findings(candidates)

    async def run_payload_plugin(self, client, plugin, capability):
        if plugin.payload_category == "SQLI":
            return await self.run_sqli_plugin(client, plugin, capability)

        findings = []
        stop_early = True

        if capability.type == "tool":
            params = self.target_parameters(capability, plugin)

            for param in params:
                for payload in limited_payloads(plugin):
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

        for payload in limited_payloads(plugin):
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
            if not any(tag in VULN_TAGS for tag in capability.tags):
                continue
            for plugin in self.plugins:
                if self.should_test(capability, plugin):
                    jobs.append((capability, plugin))
        return jobs

    async def run_check(self, capability, plugin):
        params = self.target_parameters(capability, plugin)
        timeout = self.check_timeout_for(plugin)

        try:
            async with Client(self.target) as client:
                if plugin.name == "Information Disclosure":
                    result = await asyncio.wait_for(
                        self.run_infoleak(client, plugin, capability),
                        timeout=timeout,
                    )
                else:
                    result = await asyncio.wait_for(
                        self.run_payload_plugin(client, plugin, capability),
                        timeout=timeout,
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

    async def scan_stream(self):
        findings = []
        coverage = []
        executed = 0
        plan = {"capabilities": 0, "targets": 0, "tests": 0, "entries": []}
        sent_done = False

        try:
            engine = DiscoveryEngine(self.target)
            collection = await engine.enumerate()
            capabilities = self.classify_all(collection)
            plan = self.build_plan(capabilities)
            jobs = self.build_jobs(capabilities)

            yield {
                "event": "start",
                "url": self.target,
                "plan": plan,
            }

            if not jobs:
                sent_done = True
                yield self._done_event(plan, executed, coverage, findings)
                return

            semaphore = asyncio.Semaphore(MAX_PARALLEL_CHECKS)

            async def guarded_run(capability, plugin):
                async with semaphore:
                    return capability, plugin, await self.run_check(
                        capability,
                        plugin,
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
                    yield {
                        "event": "finding",
                        "finding": finding_to_dict(finding),
                    }

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
            "url": self.target,
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
                    "url": self.target,
                }
        return final or {
            "ok": False,
            "error": "AutoPwn produced no result",
            "url": self.target,
        }


async def run_autopwn(url):
    scanner = SmartScanner(url)
    return await scanner.scan()


async def run_autopwn_stream(url):
    scanner = SmartScanner(url)
    async for event in scanner.scan_stream():
        yield event

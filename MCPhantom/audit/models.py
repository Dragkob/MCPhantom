"""
Shared dataclasses used throughout the framework.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


# =============================================================================
# Generic Capability
# =============================================================================

@dataclass
class Capability:
    """
    Represents any MCP capability:
        - Resource
        - Resource Template
        - Tool
        - Prompt
    """

    type: str
    name: str
    description: str = ""

    uri: str | None = None
    uri_template: str | None = None

    parameters: List[str] = field(default_factory=list)

    raw: Any = None

    tags: List[str] = field(default_factory=list)


# =============================================================================
# Capability Collection
# =============================================================================

@dataclass
class CapabilityCollection:

    resources: List[Capability] = field(default_factory=list)

    resource_templates: List[Capability] = field(default_factory=list)

    tools: List[Capability] = field(default_factory=list)

    prompts: List[Capability] = field(default_factory=list)

    def all(self):

        yield from self.resources
        yield from self.resource_templates
        yield from self.tools
        yield from self.prompts


# =============================================================================
# Finding
# =============================================================================

@dataclass
class Finding:

    plugin: str

    severity: str

    title: str

    capability: Capability

    payload: str

    evidence: str

    recommendation: str = ""


# =============================================================================
# Plugin Result
# =============================================================================

@dataclass
class PluginResult:

    vulnerable: bool

    findings: List[Finding] = field(default_factory=list)


# =============================================================================
# Response Wrapper
# =============================================================================

@dataclass
class Response:

    success: bool

    text: str = ""

    error: str = ""

    raw: Any = None


# =============================================================================
# Payload
# =============================================================================

@dataclass
class Payload:

    plugin: str

    value: str

    description: str = ""


# =============================================================================
# Fingerprint
# =============================================================================

@dataclass
class Fingerprint:

    capability: Capability

    tags: List[str]

    confidence: int = 0


# =============================================================================
# Report
# =============================================================================

@dataclass
class AuditReport:

    target: str

    capabilities: CapabilityCollection

    findings: List[Finding] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)
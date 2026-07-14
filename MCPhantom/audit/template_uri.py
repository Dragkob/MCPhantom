"""Helpers for resolving MCP resource template URIs."""

import re


def template_variables(template):
    return list(dict.fromkeys(re.findall(r"\{([^}]+)\}", template or "")))


def expand_template(template, values):
    names = template_variables(template)
    missing = [name for name in names if not str(values.get(name, "")).strip()]

    if missing:
        raise ValueError(f"Missing template values: {', '.join(missing)}")

    return template.format(
        **{name: str(values[name]).strip() for name in names}
    )


def substitute_payload(template, payload):
    names = template_variables(template)
    if not names:
        return template
    return expand_template(
        template,
        {name: str(payload) for name in names},
    )

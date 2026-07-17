"""Reduce noisy MCP HTTP/SSE teardown errors during scan disconnect."""

import logging

_INSTALLED = False


class _SuppressClosedResourceTracebacks(logging.Filter):
    def filter(self, record):
        if not record.exc_info or not record.exc_info[0]:
            return True
        return record.exc_info[0].__name__ != "ClosedResourceError"


def quiet_mcp_teardown_logging():
    global _INSTALLED
    if _INSTALLED:
        return

    filt = _SuppressClosedResourceTracebacks()
    for name in ("mcp.client.streamable_http", "mcp.client", "mcp"):
        logging.getLogger(name).addFilter(filt)

    _INSTALLED = True

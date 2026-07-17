import asyncio, json, logging, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from audit.mcp_logging import quiet_mcp_teardown_logging
from autopwn import run_autopwn, run_autopwn_stream, run_capability_anyway
from mcp_client import auth_from_payload, enumerate_server, make_client, probe_server, resolve_target_auth

HOST = "127.0.0.1"
PORT = 1337
BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "logo.png"
FAVICON_CACHE = {}


def build_favicon(size=32):
    size = max(16, min(int(size), 256))
    cache_key = f"png-{size}"
    if cache_key in FAVICON_CACHE:
        return FAVICON_CACHE[cache_key]

    try:
        from PIL import Image
    except ImportError:
        return LOGO_PATH.read_bytes()

    image = Image.open(LOGO_PATH).convert("RGBA")
    width, height = image.size
    crop_width = min(width, int(height * 1.05))
    icon = image.crop((0, 0, crop_width, height))
    icon = icon.resize((size, size), Image.Resampling.LANCZOS)

    buffer = BytesIO()
    icon.save(buffer, format="PNG")
    data = buffer.getvalue()
    FAVICON_CACHE[cache_key] = data
    return data


def compact_text(value):
    text = "" if value is None else str(value).strip()
    return text or "-"


def schema_params(schema):
    if not isinstance(schema, dict):
        return "-"

    properties = schema.get("properties", {}) or {}
    if not properties:
        return "-"

    return ", ".join(properties.keys())


def resource_to_row(item):
    return {
        "name": compact_text(getattr(item, "name", None)),
        "uri": compact_text(getattr(item, "uri", None)),
        "description": compact_text(getattr(item, "description", None)),
    }


def template_to_row(item):
    return {
        "template": compact_text(getattr(item, "uriTemplate", None)),
        "description": compact_text(getattr(item, "description", None)),
    }


def tool_to_row(item):
    schema = getattr(item, "inputSchema", {}) or {}
    return {
        "name": compact_text(getattr(item, "name", None)),
        "parameters": schema_params(schema),
        "description": compact_text(getattr(item, "description", None)),
        "schema": {
            "properties": schema.get("properties", {}) or {},
            "required": schema.get("required", []) or [],
        },
    }


def prompt_to_row(item):
    schema = getattr(item, "arguments", {}) or getattr(item, "inputSchema", {}) or {}
    return {
        "name": compact_text(getattr(item, "name", None)),
        "description": compact_text(getattr(item, "description", None)),
        "schema": {
            "properties": schema.get("properties", {}) or {},
            "required": schema.get("required", []) or [],
        },
    }


def render_result_text(result):
    items = getattr(result, "content", result)
    lines = []

    if isinstance(items, (str, bytes)):
        return items.decode() if isinstance(items, bytes) else items

    for item in items:
        if hasattr(item, "text"):
            lines.append(str(item.text))
        elif isinstance(item, dict) and "text" in item:
            lines.append(str(item["text"]))
        else:
            lines.append(str(item))

    return "\n".join(lines) if lines else "-"


async def run_recon(url, username=None, password=None):
    clean_url, _ = resolve_target_auth(url, username, password)
    async with make_client(url, username, password) as client:
        ok, error = await probe_server(client)
        if not ok:
            return {
                "ok": False,
                "error": str(error),
                "url": clean_url,
            }

        resources, templates, tools, prompts = await enumerate_server(client)

        return {
            "ok": True,
            "url": clean_url,
            "summary": {
                "resources": len(resources),
                "templates": len(templates),
                "tools": len(tools),
                "prompts": len(prompts),
            },
            "resources": [resource_to_row(item) for item in resources],
            "templates": [template_to_row(item) for item in templates],
            "tools": [tool_to_row(item) for item in tools],
            "prompts": [prompt_to_row(item) for item in prompts],
            "raw": "Discovery complete.",
        }


def expand_template(template, values):
    from audit.template_uri import expand_template as _expand_template

    return _expand_template(template, values)


async def read_resource_at(url, uri, username=None, password=None):
    async with make_client(url, username, password) as client:
        result = await client.read_resource(uri)
        return render_result_text(result)


async def read_template_at(url, template, values, username=None, password=None):
    uri = expand_template(template, values)
    return await read_resource_at(url, uri, username, password)


async def call_tool_at(url, name, arguments, username=None, password=None):
    async with make_client(url, username, password) as client:
        result = await client.call_tool(name, arguments)
        return render_result_text(result)


async def run_prompt_at(url, name, arguments, username=None, password=None):
    async with make_client(url, username, password) as client:
        method = getattr(client, "get_prompt", None) or getattr(client, "call_prompt", None)

        if method is None:
            raise RuntimeError("Prompt execution is not supported by this client.")

        try:
            result = await method(name, arguments)
        except TypeError:
            result = await method(name, arguments=arguments)

        return render_result_text(result) if hasattr(result, "content") else str(result)


INDEX_PATH = BASE_DIR / "dashboard.html"
_PAGE_CACHE = {"mtime": None, "content": ""}


def load_page():
    mtime = INDEX_PATH.stat().st_mtime
    if _PAGE_CACHE["mtime"] != mtime:
        _PAGE_CACHE["content"] = INDEX_PATH.read_text(encoding="utf-8")
        _PAGE_CACHE["mtime"] = mtime
    return _PAGE_CACHE["content"]



class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send_html(load_page())
            return
        if path == "/logo.png" and LOGO_PATH.exists():
            data = LOGO_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/favicon.png" and LOGO_PATH.exists():
            query = parse_qs(urlparse(self.path).query)
            size = query.get("size", ["32"])[0]
            data = build_favicon(size)
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(404, "Not Found")

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _send_ndjson_stream(self, coroutine):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        async def pump():
            async for event in coroutine:
                line = json.dumps(event, ensure_ascii=False) + "\n"
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()

        try:
            asyncio.run(pump())
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            line = json.dumps({"event": "error", "ok": False, "error": str(exc)}) + "\n"
            try:
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    def _run_action(self, coroutine):
        try:
            result = asyncio.run(coroutine)
            self._send_json({"ok": True, "result": result})
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, 500)

    def do_POST(self):
        path = urlparse(self.path).path
        payload = self._read_json_body()

        if payload is None:
            self._send_json({"ok": False, "error": "Invalid JSON"}, 400)
            return

        url = str(payload.get("url", "")).strip()
        if not url:
            self._send_json({"ok": False, "error": "Missing url"}, 400)
            return

        username, password = auth_from_payload(payload)

        if path == "/api/recon":
            try:
                result = asyncio.run(run_recon(url, username, password))
                self._send_json(result)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
            return

        if path == "/api/autopwn":
            if payload.get("stream"):
                self._send_ndjson_stream(run_autopwn_stream(url, username, password))
                return
            try:
                result = asyncio.run(run_autopwn(url, username, password))
                self._send_json(result)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
            return

        if path == "/api/autopwn-run-anyway":
            name = str(payload.get("name", "")).strip()
            capability_type = str(payload.get("type", "")).strip() or None
            if not name:
                self._send_json({"ok": False, "error": "Missing name"}, 400)
                return
            try:
                result = asyncio.run(
                    run_capability_anyway(url, name, capability_type, username, password)
                )
                self._send_json(result)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 500)
            return

        if path == "/api/read-resource":
            uri = str(payload.get("uri", "")).strip()
            if not uri:
                self._send_json({"ok": False, "error": "Missing uri"}, 400)
                return
            self._run_action(read_resource_at(url, uri, username, password))
            return

        if path == "/api/read-template":
            template = str(payload.get("template", "")).strip()
            values = payload.get("values", {}) or {}
            if not template:
                self._send_json({"ok": False, "error": "Missing template"}, 400)
                return
            self._run_action(read_template_at(url, template, values, username, password))
            return

        if path == "/api/call-tool":
            name = str(payload.get("name", "")).strip()
            arguments = payload.get("arguments", {}) or {}
            if not name:
                self._send_json({"ok": False, "error": "Missing name"}, 400)
                return
            self._run_action(call_tool_at(url, name, arguments, username, password))
            return

        if path == "/api/run-prompt":
            name = str(payload.get("name", "")).strip()
            arguments = payload.get("arguments", {}) or {}
            if not name:
                self._send_json({"ok": False, "error": "Missing name"}, 400)
                return
            self._run_action(run_prompt_at(url, name, arguments, username, password))
            return

        self.send_error(404, "Not Found")

    def send_error(self, code, message=None, explain=None):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._send_json({"ok": False, "error": message or "Not Found"}, code)
            return
        super().send_error(code, message, explain)


def main():
    quiet_mcp_teardown_logging()
    logging.basicConfig(level=logging.WARNING)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"MCPhantom web server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
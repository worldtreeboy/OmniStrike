<p align="center">
  <img src="docs/banner.png" alt="OmniStrike Banner" width="700">
</p>

<h1 align="center">OmniStrike</h1>

<p align="center">
  <strong>One extension to replace them all.</strong><br>
  21 vulnerability scanners, 4 passive analyzers, and AI-powered analysis — in a single JAR.
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/badge/version-1.14-blue?style=flat-square" alt="Version"></a>
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
                        │  │ 16 Active   4 Passive    │   │
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

**21 Modules, One JAR** &mdash; SQLi, XSS, SSRF, SSTI, RCE, XXE, deserialization, GraphQL, CORS, cache poisoning, path traversal, CRLF, auth bypass, host header injection, HPP, prototype pollution, and more. All deduplicated, all in one place.

${\color{#FF0000}\textbf{S}}{\color{#FF4500}\textbf{c}}{\color{#FF8C00}\textbf{a}}{\color{#FFA500}\textbf{n}}$ ${\color{#FFD700}\textbf{W}}{\color{#ADFF2F}\textbf{h}}{\color{#32CD32}\textbf{i}}{\color{#00CC00}\textbf{l}}{\color{#00CED1}\textbf{e}}$ ${\color{#1E90FF}\textbf{Y}}{\color{#4169E1}\textbf{o}}{\color{#6A5ACD}\textbf{u}}$ ${\color{#8A2BE2}\textbf{B}}{\color{#9400D3}\textbf{r}}{\color{#BA55D3}\textbf{o}}{\color{#FF00FF}\textbf{w}}{\color{#FF1493}\textbf{s}}{\color{#FF69B4}\textbf{e}}$ &mdash; Set your target scope, click Start, and just browse. OmniStrike automatically scans every in-scope request in real time — no manual triggering needed. Want more control? Right-click any request to scan it ad-hoc.

**AI-Augmented** &mdash; Optionally delegate analysis to Claude, Gemini, Codex, or OpenCode CLI. The AI generates targeted payloads, bypasses WAFs, and performs multi-round adaptive scanning.

**Built for Speed** &mdash; **Smart character filter probing** reduces active payloads from 35+ to 5-10 per parameter. Concurrent execution on a bounded thread pool. Non-blocking passive analysis.

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
           Payload: test' AND SLEEP(5)-- -
           Baseline: 142ms (max of 3) → Injected: 5,203ms (+5,061ms)
           DB: MySQL (fingerprinted via error pattern)

 CRITICAL  Blind SSRF via Collaborator — param 'q'
           Payload: https://<collaborator>.oastify.com
           DNS interaction from 10.0.0.5 after 2.3s

 HIGH      XSS Confirmed: img onerror in HTML_BODY — param 'q'
           Filter probe: PASS=[<>"=] BLOCK=['()/]
           Adaptive payload: <img src=x onerror=alert`1`>  (backtick call — parens blocked)

 HIGH      SSTI: Jinja2 Detected — param 'q'
           Probe: {{7*7}} → Response contains '49' (expression evaluated)
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
<summary><strong>Active Scanners (16 Modules)</strong> &mdash; click to expand</summary>

<br>

<details>
<summary><strong>SQLi Detector</strong></summary>

Authentication bypass (52 payloads), error-based (45 payloads), UNION-based (5 variants), **time-based blind** (68 payloads across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, CockroachDB with **multi-baseline measurement**), boolean-blind with confirmation (32 pairs), OOB via Collaborator, XML body injection. DB fingerprinting for 15 database engines. Comment-as-space and encoding bypasses.
</details>

<details>
<summary><strong>XSS Scanner</strong></summary>

**Context-aware injection** across 6 reflection contexts (HTML body, attribute, JavaScript, template literal, comment, CSS). **Smart character filter probing** — probes `<>"'/(;)={}[]|!` to determine which characters survive server-side filtering, then selects only viable payloads and generates **adaptive evasions** tailored to the filter profile. 9-phase passive DOM XSS analysis with variable flow tracking. **Client-side template injection (CSTI)** detection for AngularJS/Vue. **Framework-specific XSS** — auto-detects AngularJS, Angular 2+, Vue.js, React/Next.js, and jQuery from response fingerprints, then fires targeted payloads: 18 AngularJS sandbox escapes (version-specific from 1.2.0 through 1.6+), 9 Angular DomSanitizer bypasses, 15 Vue template/v-html exploits, 12 React dangerouslySetInnerHTML and href javascript: vectors, 14 jQuery .html() sink and CVE payloads (CVE-2012-6708, CVE-2020-11023). **DOM clobbering** and **mutation XSS (mXSS)** pattern detection. **URL path segment injection**. **Encoding negotiation XSS** (UTF-7, ISO-2022-JP, overlong UTF-8). **Response header injection** via CRLF. Filter evasion with mutation XSS, SVG payloads, unicode escapes, polyglot vectors. Blind XSS via Collaborator.
</details>

<details>
<summary><strong>SSRF Scanner</strong></summary>

Collaborator OOB detection, 28 cloud metadata endpoints (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba, Oracle, Hetzner, OpenStack, IBM, Linode, Rancher, Consul, Docker API), DNS rebinding, 49 localhost bypasses (IPv6, hex, octal, DNS wildcards, enclosed alphanumeric, nip.io/xip.io), 31 protocol smuggling payloads (gopher to Redis/SMTP/MongoDB/PostgreSQL/MySQL/Memcached, LDAP, TFTP, SFTP, netdoc, Kubernetes secrets).
</details>

<details>
<summary><strong>SSTI Scanner</strong></summary>

Detection for **20 template engines** (Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf, Mako, Tornado, Smarty, Blade, ERB, Slim, Handlebars, EJS, Nunjucks, Dust, Jade/Pug, Mustache, Liquid, Groovy, Plates). 34 polyglot probes, engine-specific error patterns, 32 OOB payloads via Collaborator.
</details>

<details>
<summary><strong>Command Injection</strong></summary>

Time-based blind (32 Unix `sleep` + 13 Windows `ping` payloads), output-based (33 Unix + 19 Windows probes), OOB via Collaborator (26 Unix + 15 Windows). `$IFS` space bypass, `%0a` newline injection, env variable concatenation, backtick nesting, CRLF variants, double-encoding, wildcard substitution. **139 total payloads** across Unix and Windows.
</details>

<details>
<summary><strong>XXE Scanner</strong></summary>

**Target fingerprinting** via Server/X-Powered-By headers to detect OS and runtime — tailors file targets and skips irrelevant payloads. **SAML context detection**. Classic file read (130+ Linux + 65+ Windows targets), error-based XXE, blind OOB via Collaborator (14 payloads: parameter entity, FTP, JAR, netdoc, gopher, PHP filter/expect), XInclude injection, JSON-to-XML conversion. **Bypass techniques**: UTF-16 LE/BE encoding with BOM, HTML-encoded parameter entities, CDATA section wrapping, nested entity definitions.
</details>

<details>
<summary><strong>Deserialization Scanner</strong></summary>

**6-language coverage** with passive fingerprinting, active payload injection, and OOB confirmation:

- **Java** — 16 time-based gadget chains (CommonsCollections 1-7, Spring1-2, BeanUtils, Groovy1, Hibernate1, C3P0, JRMPClient, ROME, BeanShell1, Myfaces1, Jdk7u21, Vaadin1, Click1), 32 vulnerable library signatures
- **.NET** — 12 BinaryFormatter + 15 JSON.NET + 7 XML serializer payloads
- **PHP** — 14 chains (WordPress, Magento, Laravel, Monolog, Drupal, ThinkPHP, CakePHP)
- **Python** — 12 payloads (pickle, YAML `unsafe_load`, jsonpickle, subprocess pickle)
- **Ruby** — 8 payloads (Marshal.load gadget chains, YAML/Psych `!!ruby/object` ERB template, `Gem::Installer`, `Gem::Requirement`, `Net::FTP`, `OpenURI`), 3 OOB payloads. Detects Marshal data in cookies and YAML object tags in responses.
- **Node.js** — `node-serialize` IIFE/require/Buffer payloads, `cryo`, `funcster`, `js-yaml` detection, 3 OOB payloads (HTTP callback, nslookup, curl). Detects serialization library markers in responses.

38 suspect cookie name patterns. Time-based, error-based, and OOB detection across all languages.
</details>

<details>
<summary><strong>GraphQL Scanner</strong></summary>

**7-phase testing**: introspection & discovery (4 bypass techniques, IDE detection across 9 paths), schema analysis (sensitive field detection, dangerous mutations, debug types), injection via arguments (SQLi, NoSQLi, CMDi, SSTI, path traversal + OOB), authorization & IDOR testing (ID enumeration, mutation auth bypass), DoS & resource abuse (batch queries, 50-alias fan-out, 10-level nesting, circular fragments), HTTP-level tests (GET-based queries, content-type bypass, CSRF), error & info disclosure (framework fingerprinting for Apollo/Hasura/GraphQL Yoga/Absinthe/Strawberry/Ariadne/Lighthouse/Juniper/Sangria/Hot Chocolate/GraphQL.js). Auto-generates executable queries from introspection schema.
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
<summary><strong>CRLF Injection</strong></summary>

Header injection via query/body parameters with 8 encoding variants. HTTP response splitting via double CRLF. Header-to-header injection via reflected headers. Set-Cookie injection for session fixation.
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

Server-side `__proto__` and `constructor.prototype` injection via JSON body manipulation. Express and Fastify gadget detection. Automatic cleanup after testing.
</details>

<details>
<summary><strong>Path Traversal / LFI</strong></summary>

Unix file reads (16 target files) and Windows file reads (8 targets). 20 encoding bypasses: double URL encoding, null byte, UTF-8 overlong, `....//` sequences, Tomcat `..;/` bypass. 4 PHP wrappers: `php://filter`, `php://input`, `zip://`, `data://`. Pattern-based content confirmation with 16+ detection signatures.
</details>

</details>

<details>
<summary><strong>Passive Analyzers (4 Modules)</strong> &mdash; click to expand</summary>

<br>

| Module | Capabilities |
|---|---|
| **Client-Side Analyzer** | DOM XSS source-to-sink flow analysis, prototype pollution via client JS, hardcoded secrets/API keys, insecure `postMessage` handlers, open redirect patterns, dangerous `eval`/`Function` usage, endpoint extraction. 10 check categories. |
| **Hidden Endpoint Finder** | Extracts API endpoints, internal paths, and URLs from JavaScript, HTML, and JSON responses using 13+ regex patterns. Results shared via the internal data bus. |
| **Subdomain Collector** | Discovers subdomains from CSP headers, CORS headers, HTTP redirects, and response body content. |
| **Security Header Analyzer** | Audits HSTS, CSP, CORS, cookie flags (Secure, HttpOnly, SameSite), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server version disclosure. Per-host deduplication. |

</details>

<details>
<summary><strong>AI Vulnerability Analyzer (1 Module)</strong> &mdash; click to expand</summary>

<br>

| Mode | Description |
|---|---|
| **Smart Fuzzing** | LLM analyzes the HTTP exchange and generates targeted payloads based on parameter names, content types, and technology indicators. |
| **WAF Bypass** | When payloads are blocked, the LLM generates evasion variants specific to the observed blocking behavior. |
| **Adaptive Scanning** | Multi-round testing where each round's results inform the next payload set. |
| **Cross-File Batch Scan** | Queue multiple JS/HTML responses and analyze them together for cross-file DOM XSS, shared prototype pollution chains, and cross-file data flows. |

Supports **Claude CLI**, **Gemini CLI**, **Codex CLI**, and **OpenCode CLI**. No API keys configured in the extension — uses locally authenticated CLI tools.

</details>

---

## Detection Capabilities

| Capability | Detail |
|---|---|
| **Multi-baseline timing** | Time-based blind detectors take 3 baseline samples and apply `Math.max()` to reduce false positives from network jitter |
| **Boolean-blind confirmation** | Tentative findings are re-verified with a confirmation request before reporting |
| **Smart filter probing** | Probes which characters survive server-side filtering, then selects only viable payloads and generates adaptive evasions |
| **Context-aware XSS** | Payloads adapt to 6 distinct reflection contexts with per-context evasion strategies |
| **WAF bypass** | Comment-as-space, newline injection, `$IFS` substitution, encoding variants, null bytes, and other techniques across all modules |
| **OOB detection** | Blind SQLi, XXE, SSRF, RCE, and deserialization via Burp Collaborator callbacks |
| **Deduplication** | Findings deduplicated by normalized URL with cross-module overlap prevention |

### OWASP Top 10 Coverage

| OWASP Category | OmniStrike Modules |
|---|---|
| **A01 Broken Access Control** | Auth Bypass, CORS Misconfiguration, IDOR via GraphQL |
| **A02 Cryptographic Failures** | Security Header Analyzer (cookie flags, HSTS) |
| **A03 Injection** | SQLi, XSS, SSTI, CMDi, CRLF, XXE, HPP |
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

### Automated Scope-Based Scanning (Hands-Free)

1. Open the **OmniStrike** tab. Enter target domains in **Target Scope**.
2. Toggle modules on/off in the sidebar. Click **Start**.
3. That's it — just browse normally through Burp Proxy. Every in-scope request is **automatically intercepted and scanned** by all enabled modules in real time. No need to manually select requests or click "scan." You browse, OmniStrike hunts.

### AI Scanning Setup

1. Install and authenticate a CLI tool: `npm install -g @anthropic-ai/claude-code` (or Gemini/Codex/OpenCode).
2. In the OmniStrike tab, select the CLI tool, click **Apply Settings** and **Test Connection**.
3. Right-click any request > select a module > **AI Scan**.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Burp Suite** | Professional (recommended) or Community. OOB detection requires Professional. |
| **Java** | JDK/JRE 17+ |
| **AI module** (optional) | [Claude CLI](https://www.npmjs.com/package/@anthropic-ai/claude-code), [Gemini CLI](https://www.npmjs.com/package/@google/gemini-cli), [Codex CLI](https://www.npmjs.com/package/@openai/codex), or [OpenCode CLI](https://github.com/opencode-ai/opencode) |

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

## Security Notice

OmniStrike is designed for **authorized penetration testing** and **security research** only. Active scanners send additional HTTP requests to target applications. Use exclusively against systems you have explicit written permission to test.

---

## License

MIT License. See [LICENSE](LICENSE).

---

<p align="center">
  <strong>One JAR. 20 modules. Zero configuration.</strong><br>
  <sub>Stop managing extensions. Start finding vulnerabilities.</sub>
</p>

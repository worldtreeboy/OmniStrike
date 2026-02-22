<p align="center">
  <h1 align="center">OmniStrike</h1>
  <p align="center">
    <strong>All-in-one vulnerability scanner extension for Burp Suite</strong>
  </p>
  <p align="center">
    <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/github/v/release/worldtreeboy/OmniStrike?style=for-the-badge&color=blue" alt="Release"></a>
    <a href="https://github.com/worldtreeboy/OmniStrike/stargazers"><img src="https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=for-the-badge&color=yellow" alt="Stars"></a>
    <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=for-the-badge&color=green" alt="Downloads"></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=for-the-badge" alt="License"></a>
    <img src="https://img.shields.io/badge/Java-17+-orange?style=for-the-badge&logo=openjdk" alt="Java 17+">
    <img src="https://img.shields.io/badge/Burp_Suite-Montoya_API-red?style=for-the-badge" alt="Montoya API">
  </p>
</p>

---

OmniStrike is a Burp Suite extension that consolidates 22 vulnerability scanning modules into a single JAR. It covers injection testing (SQLi, XSS, SSRF, SSTI, RCE, XXE, deserialization, NoSQL injection, prototype pollution, cache poisoning, path traversal, CORS misconfiguration, host header injection, CRLF injection, authentication bypass, HTTP parameter pollution, GraphQL abuse), passive analysis (client-side security, endpoint discovery, subdomain collection, security header auditing), and optional AI-powered scanning via local CLI tools. Built exclusively on the Montoya API.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Scanner Modules](#scanner-modules)
- [AI-Powered Scanning](#ai-powered-scanning)
- [Building from Source](#building-from-source)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Scanning

- **22 scanner modules** covering OWASP Top 10 and beyond, replacing multiple standalone Burp extensions
- **17 active scanners** with payload injection across query parameters, body parameters, cookies, JSON fields, XML bodies, and HTTP headers
- **4 passive analyzers** that inspect traffic without sending additional requests
- **1 AI module** (optional) for LLM-driven vulnerability analysis

### Detection Capabilities

- **Multi-phase injection testing** — each active scanner runs multiple detection phases (error-based, time-based blind, boolean-blind, OOB, output-based) for thorough coverage
- **Multi-baseline time measurement** — time-based blind detectors take 3 baseline samples and apply `Math.max()` to reduce false positives from network jitter
- **Boolean-blind confirmation** — tentative boolean-blind findings are re-verified with a confirmation request before reporting
- **Context-aware XSS** — payloads adapt to 6 distinct reflection contexts (HTML body, attribute, JavaScript, URL, CSS, raw)
- **WAF bypass payloads** — comment-as-space (`/**/`), newline injection (`%0a`), `$IFS` substitution, URL encoding variants, null byte appending, and other evasion techniques across all injection modules
- **Out-of-band (OOB) detection** — blind SQLi, blind XXE, blind SSRF, blind RCE, and blind deserialization via Burp Collaborator callbacks

### Workflow Integration

- **Right-click context menu** — scan any request directly from Proxy, Repeater, or Target with a single click
- **Custom scan builder** — select specific modules, toggle settings, and launch targeted scans
- **Burp Dashboard integration** — all findings appear natively in Burp's Dashboard Issue Activity and Site Map
- **Deduplication** — findings are deduplicated by normalized URL and cross-module overlap prevention
- **Concurrent active scanning** — active scanners execute on a bounded thread pool for efficient parallel testing
- **Non-blocking architecture** — passive modules run on a dedicated background executor; Burp's proxy thread is never blocked
- **Export** — findings exportable as CSV or Markdown for pentest reports

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Burp Suite** | Professional (recommended) or Community Edition. OOB detection and Collaborator features require Professional. |
| **Java** | JDK/JRE 17 or higher |
| **AI module** (optional) | One of: [Claude CLI](https://www.npmjs.com/package/@anthropic-ai/claude-code), [Gemini CLI](https://www.npmjs.com/package/@google/gemini-cli), [Codex CLI](https://www.npmjs.com/package/@openai/codex), or [OpenCode CLI](https://github.com/opencode-ai/opencode). Must be installed and authenticated on your system. |

---

## Installation

### Option 1: Pre-built JAR (Recommended)

1. Download `omnistrike.jar` from the [latest release](https://github.com/worldtreeboy/OmniStrike/releases/latest).
2. Open Burp Suite and navigate to **Extensions** > **Installed**.
3. Click **Add**.
4. Set **Extension type** to **Java**.
5. Click **Select file** and choose the downloaded `omnistrike.jar`.
6. Click **Next**. The extension loads and the **OmniStrike** tab appears in the Burp Suite toolbar.

### Option 2: Build from Source

See [Building from Source](#building-from-source).

---

## Usage

### Quick Start — Right-Click Scanning

The fastest way to scan a target:

1. Browse the target application through Burp Proxy, or select a request in Repeater/Target.
2. Right-click the request.
3. Select **Send to OmniStrike (All Modules)**.
4. Findings appear in the Burp Dashboard (Issue Activity) and in the OmniStrike tab.

No scope configuration, no start button. The scan runs immediately against the selected request.

### Automated Scanning — Scope-Based

For continuous scanning as you browse:

1. Open the **OmniStrike** tab in Burp Suite.
2. Enter target domains in the **Target Scope** field (e.g., `example.com, api.example.com`).
3. Enable or disable individual modules in the left sidebar.
4. Click **Start**.
5. Browse the target application through Burp Proxy. OmniStrike intercepts proxied traffic and runs enabled modules against in-scope requests automatically.
6. Monitor results in the **Active Findings** and **Passive Findings** tabs.
7. Click **Export CSV** or **Export Markdown** to generate a report.

### Targeted Scanning — Custom Module Selection

For fine-grained control over which modules to run:

1. Right-click a request in Proxy, Repeater, or Target.
2. Select **Send to OmniStrike (Custom)**.
3. In the dialog, select which modules to enable and adjust per-module settings.
4. Click **Scan**. Only the selected modules run against the target request.

### Per-Module Scanning

To scan for a single vulnerability type:

1. Right-click a request.
2. Navigate to **Send to OmniStrike** > **Active Scanners** (or **Passive Analyzers**).
3. Select the specific module (e.g., **SQLi Detector**).
4. Choose **Normal Scan** for pattern-based detection, or **AI Scan** for LLM-driven analysis (if configured).

### Context Menu Reference

```
Send to OmniStrike (All Modules)
Send to OmniStrike (Custom)
Queue for AI Batch Scan (n queued)
Clear Batch Queue (n)
Send to OmniStrike >
  Active Scanners
    Authentication Bypass > Normal Scan | AI Scan
    SQLi Detector > Normal Scan | AI Scan
    XSS Scanner > Normal Scan | AI Scan
    SSRF Scanner > Normal Scan | AI Scan
    SSTI Scanner > Normal Scan | AI Scan
    Command Injection > Normal Scan | AI Scan
    XXE Scanner > Normal Scan | AI Scan
    Deserialization > Normal Scan | AI Scan
    NoSQL Injection > Normal Scan | AI Scan
    GraphQL Tool > Normal Scan | AI Scan
    CORS Misconfiguration > Normal Scan | AI Scan
    Cache Poisoning > Normal Scan | AI Scan
    CRLF Injection > Normal Scan | AI Scan
    Host Header Injection > Normal Scan | AI Scan
    HTTP Parameter Pollution > Normal Scan | AI Scan
    Prototype Pollution > Normal Scan | AI Scan
    Path Traversal > Normal Scan | AI Scan
  Passive Analyzers
    Client-Side Analyzer > Normal Scan | AI Scan
    Hidden Endpoint Finder > Normal Scan | AI Scan
    Subdomain Collector > Normal Scan | AI Scan
    Security Header Analyzer > Normal Scan | AI Scan
Stop OmniStrike Scans
```

**Normal Scan** runs the pattern-based scanner only. **AI Scan** runs LLM-driven analysis only. They do not overlap.

---

## Configuration

### OmniStrike Tab — Main Panel

| Section | Description |
|---|---|
| **Target Scope** | Comma-separated list of target domains. Only requests matching these domains are scanned in automated mode. Not required for right-click scans. |
| **Module Sidebar** | Toggle individual modules on/off. Modules are grouped by category: AI Analysis, Active Scanners, Passive Analyzers. |
| **Start / Stop** | Controls the automated traffic interception scanner. |
| **Active Findings** | Table of findings from active scanner modules with severity, confidence, URL, parameter, and description. |
| **Passive Findings** | Table of findings from passive analyzer modules. |
| **Activity Log** | Real-time log of scan activity, module execution, and errors. |
| **Export CSV / Export Markdown** | Export all findings for reporting. |

### Module-Specific Settings

Click any module in the sidebar to access its configuration panel. Each active scanner exposes relevant options (e.g., payload categories, timeout thresholds, detection phases to enable/disable).

### AI Vulnerability Analyzer Settings

Navigate to the **AI Vulnerability Analyzer** panel in the module sidebar:

| Setting | Description |
|---|---|
| **CLI Tool** | Select from Claude CLI, Gemini CLI, Codex CLI, or OpenCode CLI. |
| **Max Payloads** | Limit the number of AI-generated payloads per scan. |
| **Smart Fuzzing** | AI generates targeted payloads based on request context. |
| **WAF Bypass** | When payloads are blocked, AI generates evasion variants. |
| **Adaptive Scanning** | Multi-round AI-guided testing that adjusts payloads based on previous responses. |
| **Test Connection** | Verify the selected CLI tool is installed and authenticated. |
| **Apply Settings** | Save the current AI configuration. |

---

## Scanner Modules

### Active Scanners (17 Modules)

| Module | Detection Techniques |
|---|---|
| **Authentication Bypass** | 6-phase auth enforcement testing: strip Authorization header, strip Cookie header, strip custom auth headers (X-Auth-Token, X-API-Key, X-Access-Token, Token, Api-Key, X-Session-Token), empty/null auth values (empty Bearer, Bearer null, Basic), HTTP method override bypass via X-HTTP-Method-Override/X-Method-Override/X-HTTP-Method headers, path manipulation bypass (double slash, dot segment, semicolon traversal, uppercase, URL-encoded dot). Response comparison with status code matching, 15% body length tolerance, and auth-failure keyword detection. |
| **SQLi Detector** | Authentication bypass (52 payloads), error-based (45 payloads), UNION-based (5 variants), time-based blind (68 payloads across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, CockroachDB), boolean-blind with confirmation (32 pairs), OOB via Collaborator, XML body injection. DB fingerprinting for 15 database engines. Comment-as-space and encoding bypasses. |
| **XSS Scanner** | Context-aware injection across 6 reflection contexts (HTML body, attribute, JavaScript, URL, CSS, raw). 9-phase DOM XSS detection. Filter evasion with mutation XSS, SVG payloads, unicode escapes, polyglot vectors. Blind XSS via Collaborator. |
| **SSRF Scanner** | Collaborator OOB detection, 28 cloud metadata endpoints (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba, Oracle, Hetzner, OpenStack, IBM, Linode, Rancher, Consul, Docker API), DNS rebinding, 49 localhost bypasses (IPv6, hex, octal, DNS wildcards, enclosed alphanumeric, nip.io/xip.io, service-specific ports), 31 protocol smuggling payloads (gopher to Redis/SMTP/MongoDB/PostgreSQL/MySQL/Memcached, LDAP, TFTP, SFTP, netdoc, Kubernetes secrets). |
| **SSTI Scanner** | Detection for 20 template engines (Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf, Mako, Tornado, Smarty, Blade, ERB, Slim, Handlebars, EJS, Nunjucks, Dust, Jade/Pug, Mustache, Liquid, Groovy, Plates). 34 polyglot probes, engine-specific error patterns, 32 OOB payloads via Collaborator. |
| **Command Injection** | Time-based blind (32 Unix `sleep` + 13 Windows `ping` payloads), output-based (33 Unix + 19 Windows command execution probes), OOB via Collaborator (26 Unix + 15 Windows). `$IFS` space bypass, `%0a` newline injection, env variable concatenation, backtick nesting, CRLF variants, double-encoding, wildcard substitution. 139 total payloads across Unix and Windows. |
| **XXE Scanner** | Classic file read (158 Linux + 64 Windows file targets covering system files, proc filesystem, SSH keys, web server configs, database configs, container/cloud credentials, CI/CD secrets), blind OOB via Collaborator with external DTD, XInclude injection, JSON-to-XML content type conversion. 17 XML content types detected. 90+ XML parser error patterns across Java, .NET, Python, C, and Perl. 52+ DTD processing error patterns. |
| **Deserialization Scanner** | Java gadget chains (16 time-based: CommonsCollections 1-7, Spring1-2, BeanUtils, Groovy1, Hibernate1, C3P0, JRMPClient, ROME, BeanShell1, Myfaces1, Jdk7u21, Vaadin1, Click1; 32 vulnerable library signatures), .NET (12 BinaryFormatter/ObjectStateFormatter/LosFormatter payloads + 15 JSON.NET + 7 XML serializer payloads), PHP (14 chains: WordPress, Magento, CakePHP, Laravel, Monolog, Yii2, Guzzle, Drupal, PHPUnit, Slim, CodeIgniter4, ThinkPHP), Python (12 pickle/YAML/jsonpickle payloads). 38 suspect cookie name patterns. Time-based and OOB detection. |
| **NoSQL Injection** | MongoDB operator injection (`$gt`, `$ne`, `$regex`, `$where` JavaScript execution — 23 param + 16 JSON auth bypass, 38 error-based, 14 boolean param + 12 boolean JSON pairs, 10 time-based + 6 JSON time, 10 `$where` JS + 7 JSON pairs), CouchDB (11 JSON payloads), Elasticsearch (14 JSON payloads including script execution, wildcard, aggregation), SSJI (11 expression probes, 13 output probes, 5+5 time-based, 15 OOB payloads). 6 DB error pattern categories (MongoDB, Cassandra, CouchDB, Redis, DynamoDB, Elasticsearch). |
| **GraphQL Scanner** | 7-phase comprehensive testing: introspection & discovery (full introspection query, 4 bypass techniques for disabled introspection, GraphiQL/Playground/Voyager IDE detection across 9 paths, field suggestion enumeration via intentional typos), schema analysis (sensitive auth/PII field detection, dangerous mutation identification, debug/internal type exposure, unbounded list arguments, deprecated field usage), injection via GraphQL arguments (SQLi, NoSQLi, CMDi, SSTI, path traversal payloads injected into extracted query arguments + OOB via Collaborator), authorization & IDOR testing (sequential/UUID ID enumeration, mutation authorization bypass, nested object traversal for horizontal privilege escalation), DoS & resource abuse (batch query arrays, 50-alias fan-out, 10-level deep nesting, circular fragment spreads, directive overloading, query cost/complexity analysis), HTTP-level tests (GET-based query execution, content-type bypass with `application/x-www-form-urlencoded`, CSRF on state-changing mutations), error & info disclosure (verbose error extraction via malformed queries, debug mode detection, framework fingerprinting for Apollo/Hasura/GraphQL Yoga/Absinthe/Strawberry/Ariadne/Lighthouse/Juniper/Sangria/Hot Chocolate/GraphQL.js). Auto-generates executable queries from introspection schema with proper argument types. |
| **CORS Misconfiguration** | Reflected `Origin` header, `null` origin trust, subdomain trust validation, scheme downgrade (HTTPS to HTTP), wildcard with credentials, preflight request bypass. |
| **Cache Poisoning** | Unkeyed header reflection detection across 30 header vectors (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `Via`, `CF-Connecting-IP`, `Fastly-Client-IP`, etc.), 29 unkeyed query parameter tests (UTM params, tracking IDs, cache busters), cacheability analysis (Cache-Control, Age, X-Cache, CF-Cache-Status headers), optional cache poison confirmation with clean request verification. |
| **CRLF Injection** | Header injection via query/body parameters with 8 encoding variants (standard URL-encoded CRLF, LF-only, CR-only, UTF-8 overlong, null byte prefix, literal backslash, line folding with space/tab). HTTP response splitting via double CRLF for full body injection. Header-to-header injection via reflected headers (`X-Forwarded-For`, `Referer`, `User-Agent`). Set-Cookie injection for session fixation attacks. |
| **Host Header Injection** | Password reset poisoning via Collaborator, routing-based SSRF, duplicate `Host` header, override headers (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`). |
| **HTTP Parameter Pollution** | 4-phase HPP testing: duplicate parameter with canary value to detect which occurrence the server uses (first, last, both), conflicting parameter values for privilege escalation (15 privilege-related parameter patterns including admin, role, permissions), WAF bypass via payload splitting across duplicate parameters (XSS payloads split across duplicates), parameter precedence detection (FIRST vs LAST vs BOTH). Tests URL query, body, and cookie parameters. |
| **Prototype Pollution** | Server-side `__proto__` and `constructor.prototype` injection via JSON body manipulation. Express and Fastify gadget detection. Automatic cleanup of injected properties after testing. |
| **Path Traversal / LFI** | Unix file reads (16 target files: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/proc/self/environ`, `/proc/version`, SSH keys, crontabs, etc.) and Windows file reads (8 target files: `win.ini`, `boot.ini`, `hosts`, `web.config`, SAM, etc.). 20 encoding bypasses: double URL encoding, null byte + extension, backslash normalization, UTF-8 overlong sequences, URL-encoded dots, `....//` double-dot sequences, `..;/` Tomcat bypass. 4 PHP wrappers: `php://filter` (base64 + ROT13), `php://input`, `zip://`, `data://`, `zlib://`. Pattern-based file content confirmation with 16+ detection signatures. |

### Passive Analyzers (4 Modules)

| Module | Detection Capabilities |
|---|---|
| **Client-Side Analyzer** | DOM XSS source-to-sink flow analysis, prototype pollution via client-side JavaScript, hardcoded secrets and API keys, insecure `postMessage` handlers, open redirect patterns, dangerous `eval`/`Function` usage, localStorage/sessionStorage issues, endpoint extraction. 10 check categories. |
| **Hidden Endpoint Finder** | Extracts API endpoints, internal paths, and URLs from JavaScript, HTML, and JSON responses using 13+ regex patterns. Results shared across modules via the internal data bus. |
| **Subdomain Collector** | Discovers subdomains from CSP headers, CORS headers, HTTP redirects, and response body content. |
| **Security Header Analyzer** | Audits HSTS, Content-Security-Policy, CORS configuration, cookie security flags (Secure, HttpOnly, SameSite), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server version disclosure. Per-host+path deduplication to avoid redundant findings. |

---

## AI-Powered Scanning

AI scanning is completely optional. OmniStrike functions fully without it. When enabled, OmniStrike delegates analysis to a locally installed CLI tool — no API keys are configured within the extension.

### Supported CLI Tools

| CLI Tool | Install Command |
|---|---|
| **Claude CLI** | `npm install -g @anthropic-ai/claude-code` |
| **Gemini CLI** | `npm install -g @google/gemini-cli` |
| **Codex CLI** | `npm install -g @openai/codex` |
| **OpenCode CLI** | See [OpenCode documentation](https://github.com/opencode-ai/opencode) |

### Setup

1. Install and authenticate one of the CLI tools listed above.
2. In Burp Suite, navigate to the **OmniStrike** tab > **AI Vulnerability Analyzer** panel.
3. Select the CLI tool from the dropdown.
4. Click **Apply Settings**.
5. Click **Test Connection** to verify the CLI is reachable.

### AI Scanning Modes

| Mode | Description |
|---|---|
| **Smart Fuzzing** | The LLM analyzes the HTTP exchange and generates targeted payloads based on observed parameter names, content types, and technology stack indicators. |
| **WAF Bypass** | When a payload is blocked (detected by WAF response patterns), the LLM generates encoding and evasion variants specific to the observed blocking behavior. |
| **Adaptive Scanning** | Multi-round testing where each round's results inform the next set of payloads. The LLM iterates until attack vectors are exhausted. |
| **Full AI Scan** | Combines Smart Fuzzing, WAF Bypass, and Adaptive Scanning in a single run. |
| **Cross-File Batch Scan** | Queue multiple JavaScript/HTML responses, then analyze them together in a single LLM prompt. Detects cross-file DOM XSS, shared prototype pollution chains, insecure `postMessage` handlers, and data flows spanning multiple files. Use **Scrape Site Map** to auto-populate the queue from Burp's site map. |

### AI Batch Scan Workflow

**Option A — Manual queue via right-click:**

1. Select JavaScript or HTML responses in Proxy History.
2. Right-click > **Queue for AI Batch Scan**.
3. Repeat for additional files (queue limit: 100).
4. Open the **AI Vulnerability Analyzer** panel > click **Run Batch Scan**.
5. The LLM receives all queued files in a single context and reports cross-file findings.

**Option B — One-click site map scrape:**

1. Set your target scope in the top bar (e.g., `example.com`).
2. Browse the target application so Burp populates the site map.
3. Open the **AI Vulnerability Analyzer** panel > click **Scrape Site Map**.
4. The extension queries Burp's site map for all in-scope JavaScript and HTML responses and adds them to the batch queue automatically.
5. Click **Run Batch Scan** to analyze all scraped files together.

### Module-Specific AI Prompts

When you invoke AI Scan on a specific module (e.g., **SQLi Detector** > **AI Scan**), the LLM prompt is scoped to that vulnerability type. This eliminates cross-type noise and produces focused results.

### Collaborator Integration

AI-generated payloads automatically incorporate the current Burp Collaborator address for blind/OOB vectors (DNS exfiltration, blind XXE, blind SSRF, blind RCE). Requires Burp Suite Professional.

---

## Building from Source

### Requirements

- JDK 17 or higher
- Gradle 7+ (the included Gradle wrapper handles this automatically)

### Build Steps

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
```

The output JAR is located at `build/libs/omnistrike.jar`.

### Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `montoya-api` | 2026.2 | Burp Suite Montoya extension API |
| `gson` | 2.11.0 | JSON serialization/deserialization |

Both dependencies are bundled into the shadow JAR. No external runtime dependencies are required.

### Project Structure

```
omnistrike/
├── build.gradle.kts
├── settings.gradle.kts
└── src/main/java/com/omnistrike/
    ├── OmniStrikeExtension.java            # Montoya API entry point
    ├── framework/
    │   ├── ModuleRegistry.java             # Module lifecycle management
    │   ├── TrafficInterceptor.java         # Routes proxied traffic to modules
    │   ├── OmniStrikeContextMenu.java      # Right-click context menu provider
    │   ├── OmniStrikeScanCheck.java        # Burp Dashboard/Scanner integration
    │   ├── FindingsStore.java              # Central findings storage with listener pattern
    │   ├── DeduplicationStore.java         # URL+parameter deduplication
    │   ├── DashboardReporter.java          # Findings → Burp Dashboard bridge
    │   ├── ActiveScanExecutor.java         # Bounded thread pool for active scanning
    │   ├── ScopeManager.java              # Target domain filtering
    │   ├── SharedDataBus.java             # Inter-module data sharing
    │   └── CollaboratorManager.java       # Burp Collaborator lifecycle and polling
    ├── model/
    │   ├── ScanModule.java                # Module interface contract
    │   ├── Finding.java                   # Finding data model (builder pattern)
    │   ├── Severity.java                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    │   ├── Confidence.java                # CERTAIN, FIRM, TENTATIVE
    │   ├── ModuleCategory.java            # Module grouping enum
    │   └── ModuleConfig.java              # Per-module configuration
    ├── modules/
    │   ├── ai/                            # AI-powered analysis
    │   │   ├── AiVulnAnalyzer.java        # LLM orchestration, fuzzing, WAF bypass, batch scan
    │   │   └── llm/
    │   │       ├── LlmClient.java         # CLI process execution
    │   │       ├── CliBackend.java         # Process I/O management
    │   │       ├── LlmProvider.java        # Claude, Gemini, Codex, OpenCode definitions
    │   │       └── LlmAnalysisResult.java # Parsed LLM response model
    │   ├── recon/                          # Passive analyzers
    │   │   ├── ClientSideAnalyzer.java
    │   │   ├── HiddenEndpointFinder.java
    │   │   ├── SubdomainCollector.java
    │   │   └── SecurityHeaderAnalyzer.java
    │   └── injection/                     # Active scanners
    │       ├── SmartSqliDetector.java
    │       ├── XssScanner.java
    │       ├── SsrfScanner.java
    │       ├── SstiScanner.java
    │       ├── CommandInjectionScanner.java
    │       ├── XxeScanner.java
    │       ├── DeserializationScanner.java
    │       ├── NoSqlInjectionScanner.java
    │       ├── GraphqlTool.java
    │       ├── AuthBypassScanner.java
    │       ├── CorsMisconfScanner.java
    │       ├── CachePoisonScanner.java
    │       ├── CrlfInjectionScanner.java
    │       ├── HostHeaderScanner.java
    │       ├── HttpParamPollutionScanner.java
    │       ├── PrototypePollutionScanner.java
    │       └── PathTraversalScanner.java
    └── ui/
        ├── MainPanel.java                 # Top-level tab UI
        ├── ModuleListPanel.java           # Grouped module sidebar
        ├── ScanConfigDialog.java          # Custom scan launch dialog
        ├── FindingsOverviewPanel.java     # Findings table and detail view
        ├── RequestResponsePanel.java      # HTTP request/response viewer
        ├── LogPanel.java                  # Activity log
        └── modules/
            ├── GenericModulePanel.java    # Default module settings panel
            └── AiModulePanel.java         # AI module configuration panel
```

---

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes with a descriptive message.
4. Push to your fork and open a pull request.

When submitting a pull request:

- Ensure the project compiles cleanly (`./gradlew shadowJar`).
- Test the built JAR in Burp Suite against a local target (e.g., [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Web Security Academy](https://portswigger.net/web-security)).
- Include a description of the change and its testing methodology.

For bug reports and feature requests, open an issue on [GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues).

---

## Security Notice

OmniStrike is designed for **authorized penetration testing** and **security research** only. Active scanner modules send additional HTTP requests to the target application. Use this tool exclusively against systems you have explicit written permission to test. Unauthorized use against systems you do not own or have permission to test may violate applicable laws.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

---

<p align="center">
  Built for penetration testers. One JAR. 22 modules. Zero configuration.
</p>

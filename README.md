<div align="center">

# OmniStrike

### The All-in-One Burp Suite Attack Framework

**27 modules. SQL exploitation engine. AI-powered fuzzing. Prerequisite chain automation. Custom OOB server. One JAR.**

[![Version](https://img.shields.io/badge/v1.42-blue?style=for-the-badge)](https://github.com/worldtreeboy/OmniStrike/releases)
[![Java](https://img.shields.io/badge/Java_17+-orange?style=for-the-badge&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Burp Suite](https://img.shields.io/badge/Montoya_API-E8350E?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)](https://portswigger.net/burp)
[![License](https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=for-the-badge&color=yellow)](https://github.com/worldtreeboy/OmniStrike/stargazers)
[![Downloads](https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=for-the-badge&color=brightgreen)](https://github.com/worldtreeboy/OmniStrike/releases)

[**Download**](https://github.com/worldtreeboy/OmniStrike/releases/latest) ·
[Modules](#-modules) ·
[OmniMap](#-omnimap-exploiter) ·
[AI Scanning](#-ai-scanning) ·
[Stepper](#-stepper--prerequisite-chain) ·
[Custom OOB](#-custom-oob-server) ·
[Build](#-building-from-source)

</div>

---

## Why OmniStrike?

Most Burp extensions do one thing. You end up with 15 extensions loaded, fighting for threads, duplicating requests, and missing the gaps between them.

OmniStrike replaces that entire stack with a **single extension** — 19 active scanners, 6 passive analyzers, an AI fuzzer, a SQL exploitation engine, a prerequisite request chain (Stepper), a wordlist generator, and a built-in OOB callback server. Everything shares one thread pool, one deduplication store, one findings database, and one Collaborator pipeline.

**Drop one JAR. Get everything.**

---

## Quick Start

```
1.  Download omnistrike.jar from Releases
2.  Burp Suite → Extensions → Add → Java → select omnistrike.jar
3.  Set target scope → click Start → browse normally
4.  Or right-click any request → Send to OmniStrike
```

---

## Modules

### Active Scanners (19)

| Module | Highlights |
|:---|:---|
| **SQLi Detector** | Auth bypass, error-based, UNION, time-based blind (3-step verification), boolean-blind (2-round), 64 OOB payloads. ~375 payloads/param across 10 database engines. |
| **OmniMap Exploiter** | Post-detection SQL exploitation engine — sqlmap-equivalent. 4 techniques (UNION, Error, Boolean blind, Time blind), 5 DBMS dialects, auto boundary/DBMS detection, parallel extraction, WAF bypass tamper engine. [Details below](#-omnimap-exploiter). |
| **XSS Scanner** | 6 reflection contexts, smart filter probing, adaptive evasion, DOM XSS flow analysis, CSTI, framework-specific payloads (Angular/Vue/React/jQuery), blind XSS via Collaborator. |
| **SSRF Scanner** | Collaborator OOB, cloud metadata with multi-marker validation (AWS/Azure/GCP/Oracle), DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads. |
| **SSTI Scanner** | 20 template engines, large-number canaries, template syntax consumption verification, 32 OOB payloads. |
| **Command Injection** | 3-step time-based, structural regex output matching, 140 payloads/param (Unix + Windows), `$IFS`/`%0a`/backtick/double-encoding bypasses. |
| **XXE Scanner** | 4-phase: XML body, XInclude, JSON→XML, Content-Type forcing. UTF-16 bypass, SAML detection, 14 OOB payloads. |
| **Deserialization** | 6 languages, 137+ gadget chains, passive fingerprinting, OOB-first detection, blind spray mode. [Details below](#-deserialization-scanner). |
| **WebSocket Scanner** | Passive frame analysis + OOB-first active fuzzing across 8 injection categories. [Details below](#-websocket-scanner). |
| **GraphQL Tool** | 7-phase: introspection (4 bypasses), schema analysis, injection (SQLi/NoSQLi/CMDi/SSTI/traversal), IDOR, DoS config, HTTP-level, error disclosure. |
| **CORS Misconfiguration** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials, preflight bypass. |
| **Cache Poisoning** | 30 unkeyed header vectors, 29 unkeyed query params, cacheability analysis, poison confirmation. |
| **Host Header Injection** | Password reset poisoning via Collaborator, routing SSRF, duplicate Host, override headers. |
| **HTTP Param Pollution** | Duplicate param precedence, privilege escalation patterns, WAF bypass via splitting. |
| **Prototype Pollution** | Server-side `__proto__`/`constructor.prototype` with canary persistence verification, behavioral gadgets. |
| **Path Traversal / LFI** | 24 Unix / 9 Windows targets with structural content validation, 26 encoding bypasses, PHP wrappers (filter/data/iconv). |
| **Bypass URL Parser** | Comprehensive 403/401 bypass scanner. 13 modes: mid-paths, end-paths, case substitution, char encoding (single/double/triple/unicode), HTTP methods, HTTP versions, method override headers, scheme spoofing, IP spoofing, port spoofing, URL rewrite headers, user-agent rotation, combined multi-header combos. Baseline comparison with classification (BYPASS/POTENTIAL/DIFFERENT/SAME). |
| **CSRF Manipulator** | 11 token manipulation tests (remove, empty, random, truncated, char flip, case swap, static fake, nonce reuse, Referer/Origin removal, token relocation, method change). Right-click only. |
| **LDAP Injection** | 4-phase: error-based (2+ signature requirement), boolean differential (2-round verification with baseline stability check), auth bypass (multi-signal confirmation), wildcard amplification. Targets OpenLDAP, Active Directory, Java JNDI, PHP, Python, .NET, Ruby. Right-click only. Zero false positive design. |

### Passive Analyzers (6)

| Module | Highlights |
|:---|:---|
| **Client-Side Analyzer** | DOM XSS source-to-sink, prototype pollution, hardcoded secrets with entropy validation, postMessage, open redirects, endpoint extraction. Auto-skips minified libraries. |
| **Hidden Endpoint Finder** | Extracts API endpoints and paths from JS/HTML/JSON via 13+ regex patterns. |
| **Subdomain Collector** | Discovers subdomains from CSP, CORS, redirects, and response bodies. |
| **Security Header Analyzer** | HSTS, CSP, CORS, cookie flags, X-Frame-Options, Referrer-Policy, server version disclosure. Consolidated findings per host. JWT-in-Cookie detection. |
| **Technology Fingerprinter** | Detects web servers, languages, frameworks, CMS, JS libraries, WAF/CDN, caches, and cloud platforms from headers, cookies, body patterns, and error pages. Version disclosure flagged. |
| **Sensitive Data Exposure** | Scans responses for credit cards (Luhn-validated), SSNs (range-validated), bulk emails/phones, internal IPs, JWTs, database connection strings, AWS ARNs, crypto addresses, IBANs. All values redacted in findings. |

### Framework Tools (2)

| Module | Highlights |
|:---|:---|
| **AI Vulnerability Analyzer** | AI-powered security analysis with smart fuzzing, WAF bypass, and adaptive multi-round scanning. CLI-based — supports Claude Code, Gemini CLI, Codex CLI, OpenCode CLI. Disabled by default. |
| **Wordlist Generator** | Passive word harvester — collects words from proxied traffic for building domain-specific wordlists. History scraping support. |

---

## OmniMap Exploiter

Post-detection SQL injection exploitation engine — extracts databases, tables, columns, and data from confirmed injection points. All payloads sourced from sqlmap.

| Technique | Speed | Method |
|:---|:---|:---|
| **UNION** | Fastest | Full row per request. NEGATIVE WHERE mode, DBMS-aware hex markers. |
| **Error-based** | Fast | Data inside DBMS error messages. MySQL (EXTRACTVALUE, UPDATEXML, FLOOR, etc), PostgreSQL (CAST), MSSQL (IN/CONVERT), Oracle (XMLType, UTL_INADDR). Inference fallback. |
| **Boolean blind** | Medium | Bisection via true/false page comparison. Parallel multi-threaded extraction. Adaptive tiers (a-z > 0-9 > full ASCII). |
| **Time-based blind** | Slowest | DBMS-agnostic — tries ALL 5 DBMS sleep functions. Zero-sleep validation + consistency checks. |

**Capabilities**: 5 DBMS dialects (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) · Auto boundary detection · 3-strategy DBMS fingerprinting · Level/Risk system · WAF bypass (9 tamper transforms) · Database tree view · CSV export

---

## Deserialization Scanner

**6 languages, 137+ gadget chains**, OOB-first Collaborator detection, blind spray mode.

| Language | Chains | Highlights |
|:---|:---:|:---|
| **Java** | 34 | Full ysoserial coverage (CommonsCollections 1-7, Spring, Hibernate, Groovy, C3P0, ROME, etc) |
| **.NET** | 32 × 9 | Gadget + Formatter dropdowns (ysoserial.net-style) |
| **PHP** | 47 | phpggc port — Laravel, Symfony, Monolog, Guzzle, WordPress, Doctrine, CodeIgniter4, ThinkPHP |
| **Python** | 26 | Pickle protocol 0/2/4, PyYAML, jsonpickle |
| **Ruby** | 13 | Marshal binary encoding, Rails ActiveSupport, Oj library |
| **Node.js** | 17 | node-serialize, js-yaml, cryo, funcster, prototype pollution |

**Payload Generator** — standalone tool (replaces ysoserial/ysoserial.net/phpggc). 4 output encodings, terminal-style preview, one-click copy.

---

## WebSocket Scanner

| Category | Detection Strategy | Confidence |
|:---|:---|:---:|
| CSWSH | Binary accept/reject origin validation | CERTAIN |
| SQL Injection | OOB (xp_dirtree, extractvalue) → Error-based fallback | CERTAIN / FIRM |
| Command Injection | OOB (nslookup, curl) → Time-based (3x statistical, >=4s delta) | CERTAIN / FIRM |
| SSRF | Collaborator URLs in URL params | CERTAIN |
| SSTI | Multi-engine OOB → Math eval ({{7*7}}→49) | CERTAIN / FIRM |
| XSS | OOB (img onerror fetch) → Canary reflection | CERTAIN / FIRM |
| IDOR | ID substitution + response diff | TENTATIVE |
| AuthZ Bypass | Auth vs unauth response comparison | FIRM |

---

## AI Scanning

Right-click any request to trigger AI analysis. **Never auto-fires** — zero wasted tokens.

**Capabilities**: Smart fuzzing · WAF fingerprinting + bypass · Adaptive multi-round scanning (up to 5 rounds with full response feedback) · Cross-file batch analysis · Payload learning from confirmed findings · Collaborator data exfiltration · Fuzz history (remembers every payload per URL/param/vuln type) · Multi-step exploitation

| CLI Tool | Binary | Description |
|:---|:---|:---|
| **Claude Code** | `claude` | Anthropic's CLI agent |
| **Gemini CLI** | `gemini` | Google's CLI agent |
| **Codex CLI** | `codex` | OpenAI's CLI agent |
| **OpenCode CLI** | `opencode` | Open-source CLI agent |

All CLI tools read prompts from stdin to prevent command injection. No API keys needed — uses your existing CLI authentication.

---

## Stepper — Prerequisite Chain

Multi-step web flows (login → CSRF token → session refresh → form load) produce single-use tokens that expire immediately. Testing the final request requires replaying the entire chain first.

**Stepper automates this.** Send each prerequisite request to Stepper, define extraction rules (regex, header, cookie, JSON path), and every outgoing HTTP request — Repeater, Intruder, OmniStrike active scans — automatically triggers the full chain first, extracting fresh tokens and patching them into the outgoing request.

- **Automatic cookie jar** — captures all `Set-Cookie` headers from chain responses and injects them into subsequent requests
- **Variable substitution** — use `{{variable_name}}` placeholders in any request header or body
- **4 extraction types** — Body Regex, Header, Cookie, JSON Path
- **Token cache with TTL** — prevents redundant chain re-runs during high-throughput active scanning
- **Recursion-safe** — Stepper's own prerequisite requests don't re-trigger the chain
- **Serialized execution** — concurrent requests share one chain run, then all use cached results

---

## Custom OOB Server

Built-in Out-of-Band callback server — no Burp Professional required, no internet required. Works on air-gapped intranets.

- **HTTP listener** — catches `http://<your-ip>:<port>/<payload-id>` callbacks
- **DNS listener** — catches DNS queries where the first subdomain label is the payload ID
- **Transparent** — all modules automatically use Custom OOB when enabled (same `CollaboratorManager` API as Burp Collaborator)
- **AI Analyzer included** — AI-generated OOB payloads route through the custom listener too

Configure via the OmniStrike tab: select network interface, set HTTP port + DNS port, click Start.

---

## Framework Features

| Feature | Description |
|:---|:---|
| **Scope filtering** | Only scans in-scope hosts — never touches third-party traffic |
| **Static resource skip** | Active scanners skip `.js`, `.css`, `.png`, etc. — passive analyzers still run |
| **Cross-module dedup** | Normalized URL deduplication prevents redundant findings |
| **Inter-module data sharing** | SharedDataBus lets modules share discovered endpoints, subdomains, and parameters |
| **Session Keep-Alive** | Right-click login request → Set as Session Login Request. Auto-replays periodically. |
| **Wordlist Generator** | Passive word harvester with history scraping — builds domain-specific wordlists from proxied traffic |
| **29 UI themes** | CyberPunk, Dracula, Monokai, Nord, Solarized, and more. Scoped theming: OmniStrike-only (default) or Apply Globally. Ambient Glow breathing effect. |
| **Request/Response highlighting** | All modules annotate findings with byte-range markers in Burp Dashboard |
| **OOB-first strategy** | Collaborator/Custom OOB payloads fire before time-based; if OOB confirms, remaining phases skipped |
| **3-step timing verification** | Baseline → true delay → false must NOT delay |
| **Smart filter probing** | Probes which characters survive filtering, then sends only viable payloads |
| **Burp Dashboard integration** | Findings appear as native scan issues in the Dashboard task box |

---

## Detection Philosophy

OmniStrike is built around **zero false positives**. Every finding requires structural proof — not just response differences.

1. **OOB-first** — Collaborator/Custom OOB payloads fire before anything else. If OOB confirms, skip everything else.
2. **Multi-step verification** — Time-based uses 3-step validation. Boolean-blind uses 2-round confirmation. Error-based requires regex-validated error strings.
3. **Smart payload selection** — Probes which characters survive WAF/filtering, then generates only viable payloads. No shotgun approach.
4. **Structural evidence** — Every finding includes the request, response, matched pattern, and byte-range highlighting. No guesswork.

---

## Building from Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
# → build/libs/omnistrike.jar
```

Requires **JDK 17+**. Dependencies: `montoya-api 2026.2`, `gson 2.11.0`.

---

## Contributing

1. Fork and create a feature branch
2. `./gradlew shadowJar` must compile cleanly
3. Test against [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Academy](https://portswigger.net/web-security)
4. Open a PR

[GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues) for bugs and feature requests.

---

## Changelog

<details>
<summary><b>v1.41 (2026-03-06)</b> — Technology Fingerprinter, Sensitive Data Exposure</summary>

- **Technology Fingerprinter**: New passive module — detects web servers, languages, frameworks, CMS, JS libraries, WAF/CDN, caches, and cloud platforms from headers, cookies, body patterns, and error pages. Version disclosure flagged as LOW severity. Dedup per host+tech.
- **Sensitive Data Exposure**: New passive module — scans response bodies for credit cards (Luhn-validated), SSNs (range-validated), bulk emails/phones (5+ threshold), internal IPs, JWTs, database connection strings, AWS ARNs, crypto addresses, and IBANs (check digit validated). 512KB body cap, content-type filtered, all values redacted in findings.
</details>

<details>
<summary><b>v1.40 (2026-03-05)</b> — Wordlist Generator</summary>

- **Wordlist Generator**: Passive word harvester — collects words from proxied traffic for building domain-specific wordlists. History scraping support. Consolidated endpoint findings.
</details>

<details>
<summary><b>v1.39 (2026-03-04)</b> — Theme Scoping, Bypass URL Parser</summary>

- **Theme Scoping**: Themes now default to **OmniStrike Only** — Burp's Proxy, Repeater, Intruder etc. stay native. Toggle "Apply Globally" to theme the entire Burp Suite. Selecting "Default" fully reverts to Burp's native look-and-feel with zero leftover styling.
- **Bypass URL Parser**: New active scanner module — comprehensive 403/401 bypass tool. 13 bypass modes (mid-paths, end-paths, case substitution, char encoding, HTTP methods/versions, method override headers, scheme/IP/port spoofing, URL rewrite headers, user-agent rotation, combined multi-header combos). Baseline comparison with automatic classification (BYPASS/POTENTIAL/DIFFERENT/SAME). Custom UI panel with mode selection, results table, export to JSON, context menu integration.
- **Native Mode Default**: OmniStrike now loads with Burp's native L&F by default — no dark/neon styling applied until a theme is explicitly selected.
- **Mouse Listener Fix**: Fixed hover listener accumulation on theme switches (buttons no longer accumulate event handlers).
- **Generation Counter**: Theme application uses a monotonic generation counter to prevent stale `invokeLater` callbacks from interfering with scope/theme changes.
</details>

<details>
<summary><b>v1.38 (2026-03-03)</b> — Custom OOB improvements, bug fixes</summary>

- **Custom OOB**: Replaced `com.sun.net.httpserver` with raw `ServerSocket` for broader JDK compatibility. Self-test after start. Crash reporting to Activity Log.
- **DNS-aware template resolution**: `resolveTemplate()` now generates DNS-compatible payload IDs for Custom OOB DNS payloads in SSTI + WebSocket modules.
- **HTTP OOB payloads**: Added HTTP OOB payloads for Custom OOB compatibility in SSTI and WebSocket scanners.
- **Bug fixes**: Fixed Collaborator polling restart after stop/start cycle, XXE DOCTYPE/JSON injection logic, Fastjson deserialization payload encoding.
</details>

<details>
<summary><b>v1.37 (2026-03-03)</b> — Stepper, Custom OOB DNS</summary>

- **Stepper — Prerequisite Request Chain**: New framework tool. Automates multi-step authentication flows by replaying prerequisite requests before every outgoing HTTP request. Automatic cookie jar, 4 extraction types (Body Regex, Header, Cookie, JSON Path), variable substitution with `{{placeholders}}`, token cache with TTL, recursion-safe, serialized execution with lock.
- **Custom OOB DNS Listener**: Self-hosted DNS server (UDP DatagramSocket) alongside existing HTTP listener. Parses RFC 1035 DNS queries, extracts payload ID from first subdomain label, responds with A record. DNS failure is non-fatal — HTTP still works.
- **CustomOobInteraction**: Now supports `InteractionType.DNS` (was hardcoded to HTTP).
- **UI**: DNS port field added to Custom OOB configuration. Preview shows both HTTP and DNS payload formats.
</details>

<details>
<summary><b>v1.36 (2026-03-02)</b> — CSRF Manipulator</summary>

- **CSRF Manipulator**: 11 token manipulation tests with baseline comparison. Auto-detects CSRF tokens via wildcard patterns. Skips Bearer-only endpoints.
- **Security Header Analyzer**: Consolidated findings per host. JWT-in-Cookie detection.
</details>

<details>
<summary><b>v1.35 (2026-02-28)</b> — OmniMap 4 techniques</summary>

- **OmniMap**: UNION, Error-based, Boolean blind, Time-based blind extraction. 5 DBMS dialects. DBMS re-detection. Inference fallback.
</details>

<details>
<summary><b>v1.34 (2026-02-27)</b> — OmniMap Exploiter</summary>

- Initial OmniMap release — boolean blind extraction, 5 DBMS dialects, auto boundary detection, parallel extraction, WAF bypass tamper engine.
</details>

<details>
<summary><b>v1.33 (2026-02-27)</b> — WebSocket Scanner</summary>

- Passive frame analysis + OOB-first active fuzzing across 8 injection categories.
</details>

<details>
<summary><b>v1.30 (2026-02-27)</b> — Deserialization expansion</summary>

- 137+ chains (47 PHP, 26 Python, 17 Node.js, 13 Ruby). PHP function dropdown. Encoding-aware preview.
</details>

---

## Security Notice

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively against systems you have written permission to test.

---

<div align="center">
<sub>Built with the Montoya API. No legacy interfaces.</sub>
</div>

<div align="center">

# ⚡ OmniStrike

### Focused, state-aware security scanning for Burp Suite

Turn any request into a deliberate security test with parameter-level targeting,<br/>
session automation, technology-aware probes, OOB detection, and optional AI analysis.

[![Release](https://img.shields.io/badge/release-v1.84-8b5cf6?style=for-the-badge&labelColor=111827)](https://github.com/worldtreeboy/OmniStrike/releases/latest)
[![Java](https://img.shields.io/badge/Java-17%2B-f59e0b?style=for-the-badge&logo=openjdk&logoColor=white&labelColor=111827)](https://adoptium.net/)
[![Burp Suite](https://img.shields.io/badge/Burp-Montoya_API-f97316?style=for-the-badge&labelColor=111827)](https://portswigger.net/burp)
[![License](https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=for-the-badge&color=22c55e&labelColor=111827)](LICENSE)

[**Download the JAR**](https://github.com/worldtreeboy/OmniStrike/releases/latest) ·
[Quick start](#-quick-start) ·
[Scanner catalog](#-scanner-catalog) ·
[Stepper](#-stepper) ·
[Build](#-build-from-source)

</div>

---

<table>
  <tr>
    <td align="center"><strong>13</strong><br/>active scanning engines</td>
    <td align="center"><strong>10</strong><br/>technology-aware scanners</td>
    <td align="center"><strong>7</strong><br/>passive analyzers</td>
    <td align="center"><strong>5</strong><br/>framework tools</td>
    <td align="center"><strong>1</strong><br/>self-contained JAR</td>
  </tr>
</table>

> [!IMPORTANT]
> OmniStrike is explicit by design. Nothing scans proxy traffic automatically. Active scanners and passive analyzers run only when you send a request to OmniStrike from Burp's context menu.

## ✨ Why OmniStrike

- **Pick exactly what to test.** Select individual query, body, cookie, JSON, header, and path parameters, then choose the modules to run.
- **Keep complex sessions alive.** Refresh login cookies or replay multi-step authentication flows before a probe leaves Burp.
- **Go beyond generic payload lists.** Run focused scanners for modern injection classes, enterprise platforms, cloud products, and API technologies.
- **Detect blind behavior.** Use Burp Collaborator, ProjectDiscovery Interactsh, or OmniStrike's custom HTTP/DNS OOB listener.
- **Keep control of AI.** AI analysis is optional, disabled by default, and supports local CLI or API-key backends.
- **Review findings in one place.** Findings appear in OmniStrike and are forwarded to Burp's Dashboard with request/response evidence.

~~~mermaid
flowchart LR
    A["Request in Burp"] --> B["Send to OmniStrike"]
    B --> C["Choose parameters"]
    C --> D["Choose modules"]
    D --> E["Refresh session / run Stepper"]
    E --> F["Active + passive analysis"]
    F --> G["Evidence-backed findings"]
    G --> H["OmniStrike UI"]
    G --> I["Burp Dashboard"]
~~~

## 🚀 Quick start

### 1. Install

Download [<code>omnistrike.jar</code>](https://github.com/worldtreeboy/OmniStrike/releases/latest), then open:

~~~text
Burp Suite → Extensions → Installed → Add → Java
~~~

Select the JAR and open the new **OmniStrike** tab.

### 2. Send a request

In Proxy, Repeater, or another Burp request editor:

~~~text
Right-click request → Send to OmniStrike (All Modules)
~~~

### 3. Shape the scan

Tick the parameters and modules you want, then start the scan. Static assets such as JavaScript, CSS, and images are skipped by active injection modules automatically.

> [!TIP]
> Manual scans bypass OmniStrike's scan deduplication, so sending the same request again performs a real rescan.

## 🎯 Scanner catalog

### Active scanning engines

| Engine | Coverage highlights |
|:--|:--|
| **SQL injection** | Error, UNION, time-based, and OOB probes across major DBMS families; REST path support. |
| **Command injection** | Output, timing, and OOB confirmation for Unix, Windows, and server-side JavaScript contexts. |
| **SSRF** | Collaborator/OOB callbacks, localhost bypasses, DNS rebinding, and protocol-oriented payloads. |
| **SSTI** | Fingerprints and probes for 20 template-engine families with reflection guards. |
| **XXE** | XML, XInclude, JSON-to-XML, content-type forcing, and OOB entity resolution. |
| **Path traversal / LFI** | Unix and Windows targets, encoding variants, PHP wrappers, and multi-marker confirmation. |
| **GraphQL** | Introspection bypass, IDOR, injection, error disclosure, and configurable DoS checks. |
| **CORS** | Reflected origins, null origin trust, subdomain trust, downgrade cases, and credential combinations. |
| **Web cache poisoning** | Unkeyed headers and parameters with canary-based confirmation. |
| **Host header injection** | Reset poisoning, routing SSRF, duplicate Host behavior, and override headers. |
| **HTTP parameter pollution** | Duplicate-parameter precedence and parameter-splitting behavior. |
| **Prototype pollution** | Server-side <code>__proto__</code> and <code>constructor.prototype</code> probes with persistence canaries. |
| **Deserialization** | Format detection, active payloads, and language-specific gadget-chain workflows. |

### Technology-aware scanners

These scanners join **All Modules** only after the response indicates the relevant product or protocol:

<p align="center">
  <code>Dynamics 365 FetchXML</code>&nbsp;
  <code>SAP OData</code>&nbsp;
  <code>Salesforce SOQL</code>&nbsp;
  <code>Firebase / Firestore</code>&nbsp;
  <code>SharePoint CAML</code><br/>
  <code>ServiceNow GlideRecord</code>&nbsp;
  <code>Apache Solr</code>&nbsp;
  <code>Odoo Domain Filters</code>&nbsp;
  <code>Elasticsearch</code>&nbsp;
  <code>Spring Boot Actuator</code>
</p>

This response-gated design avoids firing product-specific payloads at unrelated targets.

### Passive analyzers

Passive modules inspect the request and response you explicitly send; they do not create additional traffic.

| Analyzer | Looks for |
|:--|:--|
| **Client-Side Analyzer** | DOM XSS flows, prototype-pollution sinks, and exposed secrets. |
| **Hidden Endpoint Finder** | Routes and endpoints embedded in HTML and JavaScript. |
| **Subdomain Collector** | Hostnames discovered in response content. |
| **Security Header Analyzer** | Missing or risky browser security controls. |
| **Technology Fingerprinter** | Frameworks, platforms, servers, and version disclosure. |
| **Sensitive Data Exposure** | JWTs, cloud identifiers, payment data, SSNs, IBANs, and other secrets. |
| **Error Disclosure Scanner** | Framework, runtime, database-driver, and stack-trace leakage. |

## 🧰 Framework toolbox

| Tool | Purpose |
|:--|:--|
| **AI Vulnerability Analyzer** | Optional LLM-guided analysis using Claude, Gemini, Codex, OpenCode, Kimi, Grok, or supported API providers. |
| **Deserialization Generator** | Copy-ready payloads from 137+ gadget chains across six languages. |
| **File Payload Generator** | PDF, SVG, DOCX, XLSX, XXE, web-shell, polyglot, EICAR, and inline test payloads. |
| **Wordlist Generator** | Domain-scoped passive word harvesting for fuzzing and discovery. |
| **TLS Analyzer** | Protocol probes, cipher classification, and certificate-chain inspection. |

## 🧭 Scanning workflow

The primary context-menu entry opens a single parameter-and-module picker.

| Context-menu action | Result |
|:--|:--|
| **Send to OmniStrike (All Modules)** | Opens the parameter and module picker. |
| **Send to OmniStrike ▸** | Runs one selected module in Normal or AI mode. |
| **Set as Session Login Request** | Keeps a login/refresh request in memory for Session Keep-Alive. |
| **Send to Stepper** | Adds the request to a prerequisite chain. |

OmniStrike can target:

- Query, form, cookie, and JSON parameters
- Embedded parameters in <code>Referer</code> and <code>Origin</code>
- Security-relevant injectable headers
- Individual URL path segments

Each active scanner runs once per selected parameter. Passive analyzers run alongside the chosen workflow without sending extra requests.

## 🔐 Session Keep-Alive

Use Session Keep-Alive when a reusable session expires during testing:

1. Right-click the login or refresh request.
2. Select **Set as Session Login Request**.
3. Enable **Session Keep-Alive** in the OmniStrike tab.
4. Choose the refresh interval.

OmniStrike replays the request, captures fresh cookies, and injects a cookie only when its Domain, Path, and Secure scope matches the outbound request.

> [!NOTE]
> The credential-bearing login request is memory-only and must be selected again after Burp restarts. OmniStrike persists the refresh interval, not the raw login request.

## 🔄 Stepper

Stepper prepares stateful requests by replaying their prerequisites. It is designed for login flows, CSRF tokens, session refreshes, chained API calls, and single-use values.

~~~mermaid
sequenceDiagram
    participant B as Burp / Scanner
    participant S as Stepper
    participant T as Target
    B->>S: Final request with {{itemId}}
    S->>T: POST /login
    T-->>S: Set-Cookie + {{token}}
    S->>T: GET /me using {{token}}
    T-->>S: {{userId}}
    S->>T: GET /users/{{userId}}/items
    T-->>S: {{itemId}}
    S->>T: Final request with fresh state
    T-->>B: Response
~~~

### What it handles

| Capability | Behavior |
|:--|:--|
| **Two-pass matching** | Exact matching distinguishes steps by method, service, path, query, and body; a looser pass still recognizes scanner-mutated target requests. |
| **Automatic variables** | A placeholder such as <code>{{token}}</code> is resolved from earlier headers, cookies, nested JSON, or response bodies. |
| **Scoped cookie jar** | Cookies follow host/domain, path, and Secure rules across steps and into the final request. |
| **Pinned values** | Manually supplied variables and cookies survive chain runs and override extracted values. |
| **Cached mode** | Reuses successful chain state for a configurable TTL. |
| **Per-request mode** | Runs a fresh isolated chain for every request that consumes a single-use token. |
| **Failure handling** | Failed or aborted chains do not mark stale state as fresh; optional Stop on Failure prevents incomplete downstream requests. |
| **Pause / resume** | Stops new chains and halts active chains at the next step boundary. |
| **Recursion protection** | Chain traffic cannot trigger another copy of the same chain. |

<details>
<summary><strong>Open the Stepper setup guide</strong></summary>

### 1. Enable Stepper

Open the **Stepper** tab and tick **Stepper Enabled**.

### 2. Capture prerequisite requests

Right-click each request and choose **Send to Stepper**. Add them in execution order, then use the toolbar to reorder, disable, edit, or remove steps.

### 3. Add placeholders

Edit a later step or final request and replace changing values with placeholders:

~~~http
Authorization: Bearer {{access_token}}
GET /api/users/{{userId}}/items/{{itemId}}
~~~

Stepper searches the newest earlier responses in this order:

1. Header with the requested name
2. <code>Set-Cookie</code> with the requested name
3. Matching JSON key, including nested objects and arrays
4. A body fallback for common JSON and <code>name=value</code> forms

Use an explicit extraction rule when a response contains duplicate names, when the variable should have a different name, or when a value lives in unusual markup.

### 4. Choose the execution mode

| | Cached mode | Per-request mode |
|:--|:--|:--|
| **Chain runs** | Once per successful TTL window | Once for every matched outgoing request |
| **Best for** | Reusable login sessions and cookies | Single-use CSRF tokens and one-time nonces |
| **Throughput** | Higher | Limited by chain duration and concurrency |
| **Auth-server load** | Lower | Higher |

### 5. Verify

Click **Run Chain** and inspect **Current Variables**, **Cookie Jar**, and **Activity Log**. Use **Invalidate Cache** to force the next request to prepare fresh state.

</details>

## 📡 Out-of-band testing

OmniStrike exposes one callback abstraction with three backends:

- **Burp Collaborator** when available
- **Custom OOB** with built-in HTTP and DNS listeners
- **Interactsh / External OAST** using a ProjectDiscovery public or self-hosted server, with optional token authentication

The custom listener makes blind testing possible without Burp Professional, but it must be reachable from the target. Bind and expose listener ports only on networks you trust, and stop the listeners when the assessment ends.

Interactsh mode registers an isolated session, generates a fresh correlated subdomain for every probe, decrypts polled interactions locally, and forwards confirmed DNS, HTTP, SMTP, and LDAP events through the same finding pipeline. The server address is remembered; the optional authentication token is held in memory only and is never persisted.

> [!WARNING]
> Use only an OOB service you trust. OOB payloads are sent by the target directly to that service and can include target-derived values for proof or correlation. This traffic does not pass through AI redaction. Disable OOB testing when assessment rules prohibit third-party callbacks or data egress.

## 🤖 AI analysis

The AI Vulnerability Analyzer is disabled by default. It supports:

- Local CLI workflows for Claude, Gemini, Codex, OpenCode, Kimi, and Grok
- API-key workflows for Anthropic, OpenAI, Google, xAI, Moonshot AI, DeepSeek, Mistral, Groq, OpenRouter, and Ollama
- Editable model identifiers so newer compatible models can be used without waiting for a UI update

### Client-data privacy

**Redact AI Data is enabled by default.** Every prompt crosses one shared privacy boundary immediately before it reaches an API or CLI backend. OmniStrike replaces sensitive values with stable, typed placeholders while retaining enough structure for useful analysis:

~~~http
POST https://[REDACTED_HOST_1]/api/orders?id=[REDACTED_QUERY_VALUE_1]
Authorization: Bearer [REDACTED_AUTH_1]
Cookie: session=[REDACTED_COOKIE_1]
Content-Type: application/json

{"email":"[REDACTED_EMAIL_1]","action":"view"}
~~~

The original Burp request is never modified. Authentication cookies and headers remain available to OmniStrike's local probe engine, so the scanner can still test an authenticated endpoint; only the AI-facing copy is sanitized.

Redaction covers authorization headers, every cookie value, private/custom headers, URL credentials and hosts, query and form values, sensitive JSON/XML fields, emails, payment cards, phone numbers, national IDs, SSNs, IBANs, IP/MAC addresses, UUIDs, private keys, known provider tokens, and unknown high-entropy secrets. Repeated values receive the same placeholder within a prompt so the model can reason about data flow.

**Mask UI Data** is a separate option for shoulder-surfing and screen sharing. It masks captured values in findings, HTTP viewers, logs, Stepper state, attack-surface hosts, tables, clipboard copies, and exports without changing the stored evidence.

> [!CAUTION]
> Redaction is defense in depth, not a mathematical guarantee: an unusual client-specific value can evade any local detector. For engagements that prohibit third-party disclosure, use a locally hosted model/CLI or leave AI disabled. CLI backends also process attacker-controlled response text and may expose local tool capabilities depending on the CLI's own configuration; use them only in an isolated environment.

## 🎛️ Scan controls

| Control | Description |
|:--|:--|
| **Threads** | Shared active-scan pool from 1 to 100 workers. |
| **Throttle** | None, adaptive backoff, or a fixed delay. |
| **Time-based testing** | Separately gates slower blind timing checks. |
| **Static-resource skip** | Avoids active injection against common asset extensions. |
| **Redact AI Data** | Sanitizes the AI-facing prompt at the shared provider boundary; enabled by default. |
| **Mask UI Data** | Optionally masks captured target data across views, copies, and exports. |
| **Themes** | Burp's native theme by default, plus 29 optional palettes scoped to OmniStrike or applied globally. |

## 🏗️ Build from source

### Requirements

- JDK 17 or newer
- Git

### Build

~~~bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew test shadowJar
~~~

Windows users can run the wrapper from Git Bash or WSL.

The ready-to-load extension is written to:

~~~text
build/libs/omnistrike.jar
~~~

The shadow JAR:

- Leaves the Montoya API out because Burp provides it at runtime
- Relocates OmniStrike's Gson dependency to prevent extension classpath conflicts
- Keeps gadget-chain package names intact so generated serialized payloads remain valid

## 🤝 Contributing

1. Fork the repository and create a focused branch.
2. Add tests for behavioral changes where practical.
3. Run <code>./gradlew test shadowJar</code>.
4. Validate scanning changes only against systems you own or are authorized to test.
5. Open a pull request with the problem, approach, and verification notes.

Bug reports and feature ideas are welcome in [GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues).

## 🌟 Contributors

<table>
  <tr>
    <td align="center"><strong><a href="https://github.com/worldtreeboy">worldtreeboy</a></strong><br/>Author &amp; maintainer</td>
    <td align="center"><strong>Claude</strong><br/>AI pair programmer</td>
    <td align="center"><strong>Codex</strong><br/>AI pair programmer</td>
    <td align="center"><strong>Kimi</strong><br/>AI pair programmer</td>
  </tr>
</table>

## 🗒️ Release notes

<details open>
<summary><strong>v1.84 — Burp-native theme by default</strong></summary>

- Restored Burp's native look as the default for fresh installs.
- Added a one-time migration from the v1.82 forced Omni Pro default while preserving other saved theme choices.
- Invalid or missing theme preferences now fall back to Burp Default instead of Omni Pro.
- Native startup no longer rewrites Burp-wide Swing defaults, removing the UI stall introduced by the original v1.84 build.
- The suite tab now registers immediately with a loading state and shows initialization failures instead of disappearing silently.

</details>

<details>
<summary><strong>v1.83 — Full scanner hardening and verified release</strong></summary>

- Audited every active scanner, passive analyzer, OOB path, session workflow, and shared scan primitive; added regression coverage for the confirmed failure modes.
- Corrected structured JSON/XML mutation, endpoint-scoped OOB confirmation, baseline-aware SSRF evidence, CORS authentication semantics, SQLi/SSTI/command-injection verification, and deserialization payload reliability on Java 17.
- Made high-impact scanners explicit/manual-only where appropriate and disabled destructive, state-changing, data-exfiltration, and timing-heavy probes by default.
- Added Burp Collaborator, Interactsh, and custom OOB backends with safer placeholder expansion, bounded parsing, absolute connection deadlines, and per-payload correlation.
- Hardened Session Keep-Alive and Stepper origin, redirect, cookie, cache, framing, persistence, and shutdown behavior.
- Bounded scan queues, subprocess/API output, passive discovery stores, deduplication caches, response parsing, and AI state; rejected work is now visible instead of silently disappearing.
- Kept AI redaction default-on, removed API-key persistence, reduced CLI prompt exposure, and preserved authenticated local scanning while sanitizing only the AI-facing copy.
- Confirmed all scanning remains explicitly right-click-driven; no active or passive module runs automatically on proxy traffic.

</details>

<details>
<summary><strong>v1.82 — Privacy boundary and visual redesign</strong></summary>

- Added default-on, structure-preserving redaction before every API-key and CLI AI backend.
- Added optional UI privacy masking across evidence viewers, findings, logs, Stepper state, attack-surface data, copies, and exports.
- Introduced the Omni Pro design system with a branded header, collapsible command controls, modern tables and tabs, painted rounded controls, redesigned workspace navigation, and a responsive welcome state.
- Preserved Burp's native theme as a permanent option and kept global theming explicitly opt-in.
- Added adversarial regression tests for credentials, cookies, structured bodies, PII, payment data, infrastructure identifiers, provider tokens, private keys, high-entropy secrets, stability, and false positives.

</details>

<details>
<summary><strong>v1.81 — Security hardening and scanner reliability</strong></summary>

- Scoped Session Keep-Alive redirects and cookies to their intended origins, paths, and transport security requirements; login requests now remain memory-only.
- Hardened the custom DNS OOB parser and Stepper's cross-origin cookie handling and successful-chain cache semantics.
- Preserved distinct findings during deduplication and made Dashboard finding bundling race-safe.
- Restored JSON payload injection across six scanners, including nested XXE targeting, and made rejected AI scan jobs visible and recoverable.
- Added regression tests for findings deduplication, session origin/cookie rules, and Stepper cookie matching.

</details>

<details>
<summary><strong>v1.80 — Provider expansion and scanner reliability</strong></summary>

- Added API-key mode for ten providers: Anthropic, OpenAI, Google Gemini, xAI, Moonshot AI, DeepSeek, Mistral, Groq, OpenRouter, and Ollama.
- Added structured CLI output handling for Grok and Kimi.
- Fixed GraphQL scans without a captured response and guarded the deep-nesting check against null bodies.
- Corrected bundled Dashboard severity and confidence aggregation.

</details>

<details>
<summary><strong>v1.79 — Kimi, Grok, and unattended CLI workflows</strong></summary>

- Added Kimi CLI and Grok CLI backends.
- Added backend-specific structured-output and prompt-delivery handling.
- Enabled headless approval modes for supported CLI backends.
- Added clear handling for oversized Kimi argv prompts.

</details>

<details>
<summary><strong>v1.78 — SQL injection reporting</strong></summary>

- Promoted confirmed multi-marker error-based SQL injection to a real HIGH/FIRM finding.
- Made manual SQLi rescans bypass the module's internal tested-parameter cache.
- Removed an unimplemented boolean-blind claim from the module description.

</details>

<details>
<summary><strong>v1.77 — Stability and hot-path performance</strong></summary>

- Prevented a latent AI CLI subprocess pipe deadlock.
- Fixed SQLi UNION and Dynamics FetchXML array-index edge cases.
- Hoisted frequently compiled scanner regular expressions into reusable constants.

</details>

<details>
<summary><strong>v1.76 — Explicit scanning and false-positive reduction</strong></summary>

- Made passive analyzers right-click-only.
- Reworked SSTI fingerprints around evaluated, engine-specific evidence.
- Hardened path-traversal baseline and marker logic.
- Converted Dashboard finding details to plain text.

</details>

<details>
<summary><strong>v1.75 and earlier</strong></summary>

- Forwarded findings without native HTTP exchanges to Burp using synthetic requests.
- Added persistence for non-secret settings while keeping API keys out of storage.
- Reduced JAR conflicts by excluding Montoya and relocating Gson.
- Added the parameter/module picker, manual dedup bypass, and Session Keep-Alive integration.
- Moved deserialization tooling into Framework Tools and removed the noisy LDAP injection scanner.

</details>

## 🛡️ Responsible use

OmniStrike is built for **authorized penetration testing and security research**. Use it only against systems you own or have explicit written permission to test. Active probes can change application state, trigger defenses, or affect availability.

See the [MIT License](LICENSE) for the software license. The authors are not responsible for misuse.

---

<div align="center">

Built on Burp's Montoya API.<br/>
**One request. The right probes. Fresh state. Clear evidence.**

[Download](https://github.com/worldtreeboy/OmniStrike/releases/latest) ·
[Report a bug](https://github.com/worldtreeboy/OmniStrike/issues) ·
[Back to top](#-omnistrike)

</div>

<div align="center">

<img src="https://img.shields.io/badge/OmniStrike-v1.65-blueviolet?style=for-the-badge&labelColor=1a1a2e" alt="Version"/>

# OmniStrike

**The last Burp extension you'll ever install.**

17 active scanners. 6 passive analyzers. 11 auto-triggered technology scanners. SQL exploitation engine. AI-powered fuzzing.<br/>
Technology profiling. Session automation. Custom OOB server. File payload generator. Zero false positives.<br/>
**One JAR. One click. Everything.**

<br/>

[![Java](https://img.shields.io/badge/Java_17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Montoya API](https://img.shields.io/badge/Montoya_API-E8350E?style=flat-square)](https://portswigger.net/burp)
[![License](https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square&color=blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=flat-square&color=yellow)](https://github.com/worldtreeboy/OmniStrike/stargazers)
[![Downloads](https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=brightgreen)](https://github.com/worldtreeboy/OmniStrike/releases)
[![Last Commit](https://img.shields.io/github/last-commit/worldtreeboy/OmniStrike?style=flat-square)](https://github.com/worldtreeboy/OmniStrike/commits/main)

<br/>

[**Download JAR**](https://github.com/worldtreeboy/OmniStrike/releases/latest)&ensp;&ensp;|&ensp;&ensp;[Quick Start](#-quick-start)&ensp;&ensp;|&ensp;&ensp;[Modules](#-what-it-scans)&ensp;&ensp;|&ensp;&ensp;[OmniMap](#-omnimap--sql-exploitation-engine)&ensp;&ensp;|&ensp;&ensp;[Build](#-build-from-source)

</div>

---

## The Problem

You install Burp Suite. Then you install 15 extensions. They fight for threads, duplicate requests, miss the gaps between them, and half of them haven't been updated since 2021. Your Burp is slow, your findings are fragmented, and you're still missing bugs.

## The Solution

**OmniStrike replaces your entire extension stack with a single JAR.** Every scanner shares one thread pool, one deduplication engine, one findings database, and one Collaborator pipeline. No conflicts. No duplicates. No gaps.

```
Extensions tab  -->  Add  -->  Java  -->  omnistrike.jar  -->  Done.
```

---

## What It Scans

### 17 Active Injection Scanners + 11 Auto-Triggered Technology Scanners

| Scanner | What It Does |
|:--------|:-------------|
| **SQL Injection** | 6-phase detection: error-based + UNION + boolean-blind (2-round) + time-blind (3-step) + OOB (64 payloads) + auth bypass. ~375 payloads/param across 10 DBMS. REST path segment injection. |
| **Command Injection** | 3-step time verification, structural regex output matching, 140 payloads/param (Unix + Windows), `$IFS`/backtick/encoding bypasses. |
| **SSRF** | Collaborator OOB, DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads (file/gopher/dict/ftp/ldap/tftp). |
| **SSTI** | 20 template engines, large-number canaries, template syntax consumption verification, 32 OOB payloads. |
| **XSS** | *(Removed in v1.63 — use Burp's built-in scanner for XSS)* |
| **XXE** | 4-phase: XML body + XInclude + JSON-to-XML + Content-Type forcing. UTF-16 bypass, SAML detection, 14 OOB payloads. |
| **Deserialization** | 6 languages, 137+ gadget chains (Java/PHP/.NET/Python/Ruby/Node.js). Jackson Tier 2 gadgets with PTV bypass probes. Passive fingerprinting + OOB-first detection. |
| **Path Traversal** | 24 Unix + 9 Windows targets, 26 encoding bypasses, PHP wrappers, structural content validation with multi-marker confirmation. |
| **GraphQL** | 7-phase: introspection (4 bypasses), schema analysis, injection testing, IDOR, DoS config, HTTP-level, error disclosure. |
| **CORS** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials, preflight bypass. |
| **Cache Poisoning** | 30 unkeyed header vectors, 29 unkeyed query params, cacheability analysis, canary-based poison confirmation. |
| **Host Header** | Password reset poisoning via Collaborator, routing SSRF, duplicate Host, override headers. |
| **HTTP Param Pollution** | Duplicate param precedence, privilege escalation patterns, WAF bypass via splitting. |
| **Prototype Pollution** | Server-side `__proto__`/`constructor.prototype` with canary persistence verification, behavioral gadgets. |
| **LDAP Injection** | 4-phase: error-based (2+ signature requirement), boolean differential (2-round), auth bypass (multi-signal), wildcard amplification. Zero FP design. |
| **Bypass URL Parser** | 13 modes for 403/401 bypass: path manipulation, encoding variants, method override, IP spoofing, rewrite headers, user-agent rotation. |
| **CSRF Manipulator** | 11 token manipulation tests: remove, empty, random, truncated, char flip, case swap, nonce reuse, Referer/Origin removal. |
| **WebSocket** | *(Removed in v1.63)* |
| **OmniMap** | Post-detection SQL exploitation engine. [Details below](#-omnimap--sql-exploitation-engine). |

### 11 Auto-Triggered Technology Scanners

These scanners **cannot be manually triggered**. They passively detect specific technologies in responses and automatically launch targeted attacks when confirmed. Zero noise on non-target systems. Each scanner's detection gate uses only technology-exclusive patterns — no generic error strings.

| Scanner | Trigger | Attack |
|:--------|:--------|:-------|
| **Dynamics 365 FetchXML** | D365 error patterns (`Microsoft.Xrm.Sdk`, `OrganizationServiceFault`, CRM-context error codes) + D365 headers | FetchXML injection: data exposure via `<all-attributes/>`, filter bypass tautologies, `<link-entity>` cross-entity joins, sensitive entity enumeration. Encoding-preserving (base64/URL/raw). |
| **SAP OData Injection** | SAP error patterns (`SAP-ABAP`, `CX_SY_`, `/IWBEP/`) + SAP-specific headers | OData `$filter` injection, entity enumeration (S/4HANA `A_` prefix + legacy naming), `$expand` cross-entity access, `$metadata` exposure. |
| **Salesforce SOQL Injection** | Salesforce-exclusive patterns (`System.QueryException`, `System.SObjectException`, `Visualforce`) + SF headers | SOQL filter tautology (`OR Id != null`), object enumeration (12 sensitive objects), `FIELDS(ALL)` field enumeration, SOSL search injection. |
| **Firebase Misconfiguration** | Firebase URL patterns (`.firebaseio.com`, `firestore.googleapis.com`) + config triple-check (`projectId`+`storageBucket`+`apiKey`) | Unauthenticated read (`.json` suffix), write test with automatic cleanup, Firestore collection enumeration with differential probe, Firebase Auth enumeration (signInWithPassword + createAuthUri). |
| **SharePoint CAML Injection** | SP error patterns (`Microsoft.SharePoint`, `\bSPWeb\b`, `Invalid CAML`) + SP-specific headers (`sprequestguid`, `x-sharepointhealthscore`) | CAML filter injection (tautology), ViewFields expansion (JSON key format), REST list enumeration (mandatory `odata.metadata` marker), cross-list joins with `<ProjectedFields>` verification. |
| **ServiceNow GlideRecord** | SN error patterns (`GlideRecord`, `GlideSystem`, `com.glide.(db\|script\|processors)`) + `x-is-logged-in` header | Encoded query injection (tautology/wildcard), table enumeration with differential probe, field exposure filtered to `SENSITIVE_FIELDS` set, ACL bypass via dot-walking with password value validation. |
| **Apache Solr Query** | Solr error patterns (`SolrException`, `org.apache.solr`) + `/solr/` URL + body markers (`responseHeader`, `numFound`) | `*:*` query injection with `numFound` differential, `fl=*` field enumeration, admin endpoint probes (`_cat/indices` equivalent) with differential, streaming expression detection, SSRF via shards (connection-error only). |
| **Odoo Domain Filter** | Odoo-exclusive patterns (`odoo.exceptions.*`, `openerp.exceptions`) + 3-signal URL gate (Odoo URL + JSON-RPC body + `odoo.` body marker) | Domain filter tautology (correct Polish-notation OR for multi-clause domains), admin-only model enumeration (7 restricted models), field exposure with non-trivial value validation, `fields_get` schema probing at INFO severity. |
| **Elasticsearch Query** | ES-exclusive patterns (`ElasticsearchException`, `org.elasticsearch.`, `SearchPhaseExecutionException`) + URL/body dual-signal | `*:*` query injection with `total_hits` differential (anchored to `hits` context, ES 6.x/7.x+), index enumeration (`_cat/indices`, `_cluster/health`, `_nodes`), `_source=*` field exposure, `_exists_` query syntax confirmation. |
| **Spring Boot Actuator** | Spring-exclusive patterns (`Whitelabel Error Page`, `org.springframework.`, `DispatcherServlet`) + actuator URL/HAL JSON dual-signal | Actuator root discovery with differential, 15 sensitive endpoint probes with per-endpoint JSON validation (`env`/`configprops`/`heapdump`/`mappings`/`httptrace`/`sessions`/etc.), legacy Spring Boot 1.x paths with differential probes. Binary Content-Type validation for heapdump. Per-host dedup. |
| **WordPress REST API** | *(Coming soon)* | User enumeration, exposed drafts, plugin enumeration. |

### 6 Passive Analyzers

| Analyzer | What It Finds |
|:---------|:--------------|
| **Client-Side** | DOM XSS source-to-sink, prototype pollution, hardcoded secrets (entropy-validated), postMessage, open redirects. Auto-skips minified libraries. |
| **Endpoint Finder** | Extracts API endpoints and paths from JS/HTML/JSON via 13+ regex patterns. |
| **Subdomain Collector** | Discovers subdomains from CSP, CORS, redirects, and response bodies. |
| **Security Headers** | HSTS, CSP, CORS, cookie flags, X-Frame-Options, server version disclosure. Consolidated per host. |
| **Tech Fingerprinter** | Detects servers, languages, frameworks, CMS, JS libraries, WAF/CDN, caches, cloud platforms. |
| **Sensitive Data** | Credit cards (Luhn), SSNs (range-validated), emails, phones, internal IPs, JWTs, DB connection strings, AWS ARNs, crypto addresses, IBANs. All values redacted. |

### 3 Framework Tools

| Tool | What It Does |
|:-----|:-------------|
| **AI Vulnerability Analyzer** | LLM-powered security analysis with smart fuzzing, WAF bypass generation, and adaptive multi-round scanning. Supports Claude Code, Gemini CLI, Codex CLI, OpenCode CLI. No API keys needed. Disabled by default. |
| **File Payload Generator** | 39 file payloads (PDF XSS, SVG XXE, DOCX/XLSX XXE, PHP/JSP/ASPX/Python/Ruby/Perl/Node.js/Bash/PowerShell POC, 11 template engine injections, .htaccess/.user.ini/web.config hijack, CSV injection, LaTeX RCE, polyglot GIF/JS, EICAR) + 31 inline copy-paste payloads (SSTI probes for 8 engines, XXE, Log4j, EL/SpEL, OGNL, LFI/RFI, CRLF, polyglot). Collaborator URL support. |
| **Wordlist Generator** | Passive word harvester from proxied traffic. Builds domain-specific wordlists for fuzzing/brute-forcing. |

---

## Quick Start

```
1.  Download omnistrike.jar from Releases (or build from source)
2.  Burp Suite  -->  Extensions  -->  Add  -->  Java  -->  select omnistrike.jar
3.  Enter target domain in "Target Scope"
4.  Click "Start Auto-Scan" and browse normally
5.  Or right-click any request  -->  "Send to OmniStrike"
```

That's it. OmniStrike handles the rest.

---

## Zero False Positives

This is the design principle behind every detection method in OmniStrike. We'd rather miss a real bug than report a fake one.

**How it works:**

| Layer | Method |
|:------|:-------|
| **OOB-First** | Collaborator/Custom OOB payloads fire before everything else. HTTP callback = CERTAIN. DNS callback = FIRM (continues scanning). |
| **Multi-Step Verification** | Time-based: 3-step (baseline + true delay + false must NOT delay). Boolean-blind: 2-round with benign variation pre-check. Error-based: requires 2+ DBMS-specific patterns when baseline is empty. |
| **Structural Evidence** | Path traversal requires multi-marker file signatures (`[fonts]` AND `[extensions]`, not just one). Passwd requires non-null baseline comparison. |
| **WAF Filtering** | `ResponseGuard` rejects 429, 503, 406, 413, 502, 504, Cloudflare 520-530, and WAF block pages (Cloudflare, Imperva, Sucuri, AWS WAF, ModSecurity) before any module analyzes the response. |
| **Auto-Throttle** | Detects rate limiting in real-time and backs off automatically (500ms to 15s exponential). Cools down when traffic flows normally. |

---

## OmniMap -- SQL Exploitation Engine

Found a SQL injection? OmniMap extracts the data. It's sqlmap built into your Burp tab.

| Technique | Speed | How |
|:----------|:------|:----|
| **UNION** | Fastest | Full row per request. DBMS-aware hex markers. |
| **Error-Based** | Fast | Data inside error messages. MySQL EXTRACTVALUE/UPDATEXML, PostgreSQL CAST, MSSQL CONVERT, Oracle XMLType. |
| **Boolean Blind** | Medium | Parallel multi-threaded bisection. Adaptive character tiers. |
| **Time-Based** | Slowest | DBMS-agnostic sleep probing with zero-sleep validation. |

**5 DBMS dialects** (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) with auto-detection, boundary analysis, 11 WAF tamper transforms, database tree view, and CSV export.

---

## Technology Profiling Engine

Every HTTP response is passively analyzed for technology signals. Evidence accumulates per host with calibrated weights:

| Signal | Weight | Example |
|:-------|:-------|:--------|
| Stack trace | 100 | `at com.example.App(App.java:42)` |
| DBMS error | 100 | `You have an error in your SQL syntax` |
| OS path leak | 90 | `/var/www/html/index.php` |
| Default error page | 80 | Spring Whitelabel, IIS Detailed Error |
| Version header | 60 | `X-AspNet-Version: 4.0` |
| Cookie name | 50 | `JSESSIONID`, `PHPSESSID` |
| X-Powered-By | 40 | `X-Powered-By: Express` |
| Server header | 10 | `Server: nginx` (easily spoofed) |
| ICMP TTL | 15 | `TTL=64` (Linux), `TTL=128` (Windows) |

When two technologies are neck-and-neck, **tie-breaker probes** fire automatically. Liar-proxy detection resolves contradictions (e.g., `Server: nginx` but `X-AspNet-Version` present).

All scanner modules receive the host's tech profile and **prioritize payloads accordingly** -- matching payloads first, generic second, non-matching last.

---

## Stepper -- Session Automation

Multi-step auth flows (login, CSRF token, session refresh) produce single-use tokens. Testing the final request requires replaying the entire chain first.

**Stepper automates this.** Define the chain once, and every outgoing request -- Repeater, Intruder, OmniStrike scans -- automatically replays the prerequisites, extracts fresh tokens, and patches them in.

- Automatic cookie jar from chain responses
- `{{variable}}` placeholder substitution in headers/body
- 4 extraction types: Body Regex, Header, Cookie, JSON Path
- Token cache with TTL (prevents redundant re-runs)
- Recursion-safe and serialized execution

---

## Custom OOB Server

No Burp Professional? No internet? No problem.

OmniStrike includes a built-in Out-of-Band callback server with HTTP and DNS listeners. Works on air-gapped networks.

All modules use it transparently through the same `CollaboratorManager` API -- switch between Burp Collaborator and Custom OOB with one click.

---

## Scope Control

| Feature | Description |
|:--------|:------------|
| **Target Scope** | Comma-separated domains. Only in-scope traffic is processed. |
| **Include / Exclude Lists** | Add specific URLs or endpoints. Mutual exclusion -- only one list active at a time. Supports both `/api/v1/users` paths and full `https://target.com/admin` URLs. Query params ignored. |
| **Static Resource Skip** | Active scanners skip `.js`, `.css`, `.png`, etc. Passive analyzers still run. |
| **Throttle Modes** | None (fastest), Auto (backs off on WAF), Manual (fixed ms delay). |

---

## 29 UI Themes

CyberPunk, Dracula, Monokai, Nord, Solarized, One Dark, Gruvbox, and more. Scoped to OmniStrike only by default -- or apply globally to the entire Burp Suite.

---

## Build From Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
# Output: build/libs/omnistrike.jar
```

Requires **JDK 17+**. Dependencies: Montoya API 2026.2, Gson 2.11.0, gadget chain libraries (Commons Collections, Javassist, ROME, Groovy, C3P0, BeanShell).

---

## Contributing

1. Fork and create a feature branch
2. `./gradlew shadowJar` must compile with zero errors
3. Test against [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Academy](https://portswigger.net/web-security)
4. Open a PR

[Issues](https://github.com/worldtreeboy/OmniStrike/issues) for bugs and feature requests.

---

## Legal

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively on systems you have written permission to test. The authors are not responsible for misuse.

---

<div align="center">
<sub>Built on the Montoya API. No legacy interfaces. No external servers. No API keys. Just one JAR.</sub>
</div>

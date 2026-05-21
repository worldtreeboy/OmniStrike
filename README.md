<div align="center">

<img src="https://img.shields.io/badge/OmniStrike-v1.74-blueviolet?style=for-the-badge&labelColor=1a1a2e" alt="Version"/>

# OmniStrike

**The last Burp extension you'll ever install.**

12 active injection scanners. 7 passive analyzers. 11 auto-triggered technology scanners. AI-powered fuzzing.<br/>
Technology profiling. Session automation. Custom OOB server. File & deserialization payload generators. Zero false positives.<br/>
**One JAR. One click. Everything.**

<br/>

[![Java](https://img.shields.io/badge/Java_17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Montoya API](https://img.shields.io/badge/Montoya_API-E8350E?style=flat-square)](https://portswigger.net/burp)
[![License](https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square&color=blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=flat-square&color=yellow)](https://github.com/worldtreeboy/OmniStrike/stargazers)
[![Downloads](https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=brightgreen)](https://github.com/worldtreeboy/OmniStrike/releases)
[![Last Commit](https://img.shields.io/github/last-commit/worldtreeboy/OmniStrike?style=flat-square)](https://github.com/worldtreeboy/OmniStrike/commits/main)

<br/>

[**Download JAR**](https://github.com/worldtreeboy/OmniStrike/releases/latest)&ensp;&ensp;|&ensp;&ensp;[Quick Start](#-quick-start)&ensp;&ensp;|&ensp;&ensp;[Modules](#-what-it-scans)&ensp;&ensp;|&ensp;&ensp;[Build](#-build-from-source)

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

### 12 Active Injection Scanners + 11 Auto-Triggered Technology Scanners

> **Active scanners run on demand only.** As of v1.74 there is no auto-scan / target-scope mode — right-click any request → **Send to OmniStrike** and pick exactly which parameters and modules to test. See [Scanning Workflow](#-scanning-workflow).

| Scanner | What It Does |
|:--------|:-------------|
| **SQL Injection** | 3-phase active detection: UNION-based (dynamic column probing, 5 syntax variants) + time-blind (3-step verification, ~45 payloads across 5 DBMS) + OOB via Collaborator (~100 payloads across 6 DBMS groups). Error/boolean phases removed — covered by Burp's built-in scanner. REST path segment injection. |
| **Command Injection** | 3-step time verification, structural regex output matching, 140 payloads/param (Unix + Windows), `$IFS`/backtick/encoding bypasses. **Node.js SSJI** (JSON params): arithmetic math probe (`(A*B).toString()` with word-boundary FP guard), `execSync` OOB/output-based/time-based across 5 context-breaker prefixes, `global.process.mainModule.require` WAF bypass, IIFE obfuscation variant — 29 payloads total. |
| **SSRF** | Collaborator OOB, DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads (file/gopher/dict/ftp/ldap/tftp). |
| **SSTI** | 20 template engines, large-number canaries, template syntax consumption verification, 32 OOB payloads. |
| **XXE** | 4-phase: XML body + XInclude + JSON-to-XML + Content-Type forcing. UTF-16 bypass, SAML detection, 14 OOB payloads. |
| **Path Traversal** | 24 Unix + 9 Windows targets, 26 encoding bypasses, PHP wrappers, structural content validation with multi-marker confirmation. |
| **GraphQL** | 7-phase: introspection (4 bypasses), schema analysis, injection testing, IDOR, DoS config, HTTP-level, error disclosure. |
| **CORS** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials, preflight bypass. |
| **Cache Poisoning** | 30 unkeyed header vectors, 29 unkeyed query params, cacheability analysis, canary-based poison confirmation. |
| **Host Header** | Password reset poisoning via Collaborator, routing SSRF, duplicate Host, override headers. |
| **HTTP Param Pollution** | Duplicate param precedence, privilege escalation patterns, WAF bypass via splitting. |
| **Prototype Pollution** | Server-side `__proto__`/`constructor.prototype` with canary persistence verification, behavioral gadgets. |

> **Deserialization** is still a full active scanner (6 languages, 137+ gadget chains) but its UI now lives under **Framework Tools** as a payload generator — see below. Scan a request with it via right-click like any other module.
>
> Removed over time: XSS & WebSocket (v1.63), Bypass URL Parser / CSRF Manipulator / OmniMap (v1.70), LDAP Injection (v1.73). Use Burp's built-in scanner where noted.

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
| **Error Disclosure** | Java stack traces + reflection errors (ClassNotFoundException, NoSuchMethodException, InvocationTargetException) + native serialization (InvalidClassException, StreamCorruptedException) + JAXB. Jackson deserialization errors: 12 exception types, 13 error messages, and polymorphic type-id errors (flags DefaultTyping/@JsonTypeInfo — Jackson gadget-chain attack surface, CVE-2017-7525 family). Spring Whitelabel, Python tracebacks, Django debug, Werkzeug debugger, PHP errors, Laravel Whoops, ASP.NET yellow pages, Node.js/Go/Ruby stack frames, database driver exceptions (ORA-, SQLSTATE, PSQLException, Hibernate, Sequelize, Sybase, Informix, Firebird, CockroachDB). One finding per host/path/category. Skips all 4xx. |

### 5 Framework Tools

| Tool | What It Does |
|:-----|:-------------|
| **AI Vulnerability Analyzer** | LLM-powered security analysis with smart fuzzing, WAF bypass generation, and adaptive multi-round scanning. Supports Claude Code, Gemini CLI, Codex CLI, OpenCode CLI. No API keys needed. Disabled by default. |
| **Deserialization Generator** | Generates deserialization payloads (Java/PHP/.NET/Python/Ruby/Node.js, 137+ gadget chains) for copy-paste / upload testing. The same module also runs as an active scanner via right-click. |
| **File Payload Generator** | 39 file payloads (PDF XSS, SVG XXE, DOCX/XLSX XXE, PHP/JSP/ASPX/Python/Ruby/Perl/Node.js/Bash/PowerShell POC, 11 template engine injections, .htaccess/.user.ini/web.config hijack, CSV injection, LaTeX RCE, polyglot GIF/JS, EICAR) + 31 inline copy-paste payloads (SSTI probes for 8 engines, XXE, Log4j, EL/SpEL, OGNL, LFI/RFI, CRLF, polyglot). Collaborator URL support. |
| **Wordlist Generator** | Passive word harvester from proxied traffic. Builds domain-specific wordlists for fuzzing/brute-forcing. |
| **TLS Analyzer** | Out-of-band TLS / SSL inspection. Probes each protocol version individually (TLSv1.3 → SSLv3) so you see the full support matrix instead of just whichever version Burp happened to negotiate. Optional cipher-suite enumeration, certificate-chain inspection (subject/issuer/SANs/expiry/signature/key size), self-signed/expired/weak-signature detection, hostname-mismatch detection. Findings publish into the Dashboard. Enter a host:port in the TLS Analyzer panel and run. |

---

## Quick Start

```
1.  Download omnistrike.jar from Releases (or build from source)
2.  Burp Suite  -->  Extensions  -->  Add  -->  Java  -->  select omnistrike.jar
3.  Browse the target so requests land in Proxy / HTTP history
4.  Right-click any request  -->  "Send to OmniStrike (All Modules)"
5.  Tick the parameters and modules to test  -->  Scan
```

That's it. OmniStrike handles the rest.

---

## Scanning Workflow

OmniStrike is **right-click driven**. There is no auto-scan loop and no target-scope field — you scan exactly what you choose, when you choose it. Nothing is sent to a target until you ask for it.

### Send to OmniStrike (All Modules)

Right-click any request → **Send to OmniStrike (All Modules)** opens a picker dialog with two tick-lists:

- **Parameters** — every scannable target found in the request: query / body / cookie / JSON params, parameters embedded in `Referer`/`Origin`, injectable headers, and URL path segments.
- **Modules** — the active scanners and passive analyzers to run.

Everything is ticked by default. Untick what you don't want and hit **Scan**. Each selected active scanner runs once per ticked parameter (true per-parameter targeting for modules that support it); passive analyzers run once over the whole request. Static resources (`.js`, `.css`, images) skip active injection automatically.

### Other right-click entry points

| Menu item | Action |
|:----------|:-------|
| **Send to OmniStrike (All Modules)** | Opens the parameter + module picker dialog (above). |
| **Send to OmniStrike ▸** | Per-module submenu — run a single scanner (Normal or AI) on the whole request. |
| **Set as Session Login Request** | Saves this request for Session Keep-Alive replay (see below). |
| **Send to Stepper** | Adds the request as a prerequisite step (when Stepper is enabled). |

Manual scans **bypass the deduplication cache**, so re-scanning a request you've already tested actually re-runs — no more silent "nothing happened." Use **Stop Scans** in the OmniStrike tab to halt everything immediately.

### Session Keep-Alive

Long scans die when the session expires. Right-click your login/refresh request → **Set as Session Login Request**, then tick **Session Keep-Alive** in the OmniStrike tab. OmniStrike periodically replays that request, captures the fresh `Set-Cookie` values (following redirects), and injects them — domain-scoped — into **all** outbound traffic: Burp's own tools (Proxy/Repeater/Intruder/Scanner) *and* OmniStrike's own scan modules. Your session stays alive for the whole engagement.

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

**Stepper automates this.** Add all requests in the chain (A → B → C → D → E). When any step is sent from Repeater, Intruder, or the active scanner, Stepper automatically identifies which step it is and replays only the required prerequisites — then patches the fresh cookies and tokens into the outgoing request.

| Feature | Detail |
|:--------|:-------|
| **Two-pass step matching** | **Exact pass** compares method + host + port + path + query + body, so multiple steps that differ only by query/body params (e.g. `postId=1` vs `=2` vs `=3`) are distinguishable. **Loose pass** falls back to method + path-without-query, returning the highest matching index (target = last step) so scanner-mutated probes still match. |
| **No-match is a no-op** | If an outgoing request doesn't match any configured step, Stepper does nothing. Unrelated browser/extension traffic won't trigger the chain. |
| **Per-Request Mode** | Optional toggle: every matched outgoing request gets its own fresh chain run on its own thread (no cache, no global lock). Required when prereqs produce single-use tokens (CSRF nonces) that the target burns per request. |
| **Pause / Resume** | One-click "Pause Now" button halts new chains and aborts in-flight ones at the next step boundary. Auto-paused when OmniStrike's scan is stopped. |
| **Works with OmniStrike's own scanner** | A `StepperHttp` wrapper is used by every OmniStrike scan module so their `sendRequest()` calls also trigger Stepper, not just Burp's native tools. |
| **Automatic cookie jar** | Every `Set-Cookie` from each chain step is collected and forwarded to subsequent steps and the final request. Newest value wins. Pinned cookies survive chain re-runs. |
| **Auto-extraction (rule-free)** | Write `{{name}}` anywhere — URL path, header, cookie, body — and Stepper auto-finds the value in earlier responses (header / Set-Cookie / JSON key / regex fallback). No extraction rule needed. |
| **Pinned variables (manual override)** | Set or override any `{{name}}` from the UI. Pinned vars survive chain re-runs and win over auto-extracted values with the same name. |
| **Edit Request dialog** | Edit any captured step's raw HTTP request after the fact — useful for inserting `{{varName}}` placeholders into the URL/headers/body where literal values were captured. |
| **TTL cache** | Configurable cache window (default 10s, cached mode only) prevents re-running the chain for every scanner request. Invalidated automatically when the prerequisite set changes. |
| **Stop on Failure** | Optional: abort the chain immediately if any step returns no response, preventing downstream steps from running with incomplete state. |
| **Recursion-safe** | ThreadLocal guard prevents chain requests from re-triggering the chain. ReentrantLock serializes concurrent execution in cached mode. |

### Stepper Manual

#### 1. Enable Stepper

Open the **Stepper** tab in OmniStrike → tick **Stepper Enabled** at the top. The "Send to Stepper" right-click menu becomes available everywhere in Burp.

#### 2. Add prerequisite steps

Right-click any request in Proxy / HTTP history / Repeater → **Send to Stepper**. The request appears in the **Prerequisite Steps** table. Add as many steps as your auth flow needs, in order. Use the ▲ / ▼ buttons to reorder, **Toggle** to enable/disable a step, **Remove** to drop one.

#### 3. Reference values from earlier responses

Anywhere in a later step or in your final outgoing request, write `{{name}}`. Stepper auto-finds the value from earlier responses in this order:

1. Response **header** named `name`
2. **Set-Cookie** with cookie name `name`
3. **JSON key** named `name` (case-insensitive, walks nested objects + arrays)
4. Regex fallback: `"name":"value"`, `"name":number`, or `name=value` in the body

Most-recent response wins. Resolution is cached, so subsequent requests don't re-search.

**Substitution works in:** URL path, query string, headers, cookies, request body.

##### Example — single value

| Step | Response excerpt | Outgoing target request |
|:-----|:-----------------|:------------------------|
| Step 1: `POST /login` | `{"id":"abcef"}` | `GET /api/{{id}}/xyz` → sent as `GET /api/abcef/xyz` |

##### Example — multi-step chain

| Step | Response | What downstream steps reference |
|:-----|:---------|:--------------------------------|
| 1: `POST /login` | `{"token":"AAA"}` | header `Authorization: Bearer {{token}}` |
| 2: `GET /me` (uses `{{token}}`) | `{"userId":"u-42"}` | path `/api/users/{{userId}}/items` |
| 3: `GET /api/users/{{userId}}/items` | `{"itemId":"x99"}` | final request `DELETE /api/items/{{itemId}}` |

The final outgoing `DELETE /api/items/{{itemId}}` becomes `DELETE /api/items/x99`. Zero rules configured.

#### 4. Cookies are fully automatic

Every `Set-Cookie` from any chain response is collected into the **Cookie Jar** (bottom-left panel) and merged into the `Cookie:` header of every later step and your final request. Existing cookies in the request are preserved; jar values overwrite same-named cookies.

- Click **+ Add** to manually pin a cookie that's not set by any chain response (e.g., a static API-key cookie). Pinned cookies survive chain re-runs.
- Untick **Auto Cookie Jar** to disable.

#### 5. Edit captured requests after the fact

Right-click → **Send to Stepper** captures the request **as-is** — with literal values, not placeholders. If you want a step's URL/header/body to reference a value extracted from an earlier step, click **Edit Request** in the steps toolbar:

1. Select the step in the table.
2. Click **Edit Request**. A raw HTTP editor opens.
3. Replace the literal value with `{{varName}}`. Example: `/api/abcde/check` → `/api/{{token}}/check`.
4. Click **OK**. The step's request is updated; the original `HttpService` (host/port/scheme) is preserved.

Save errors (malformed HTTP) are reported in a dialog and the step is left untouched.

#### 6. Pinned variables (manual override / seed)

The **Current Variables** table at the bottom-right shows every variable Stepper currently has — both auto-extracted ones and manually pinned ones. The **Source** column tells them apart.

- **+ Add** opens a dialog to set `name` = `value`. Pinned vars survive every chain re-run, and **win over auto-extracted values with the same name**. Use this to test with a known-good token, or to seed a value the chain can't produce on its own.
- **- Remove** unpins the selected variable. The next chain run will re-extract it if the response still has it.
- **Clear Pinned** drops all pinned vars at once.

#### 7. Per-Request Mode (single-use tokens / fresh chain per probe)

Default ("cached") mode runs the chain once, then reuses the result for **Cache TTL** seconds. This is fast and right for *reusable* tokens (login session, persistent cookies).

If your prereqs produce **single-use tokens** (a CSRF nonce the server burns per request, a one-time `_token` field, etc.), tick **Per-Request Mode** at the top of the panel. Every matched outgoing request then triggers its **own** fresh chain run on its own thread. Multiple Burp scanner threads run their A→B→C→D pipelines in parallel without clobbering each other's state.

| | Cached mode (default) | Per-Request Mode |
|:--|:--|:--|
| Chain runs | Once per TTL window | Once per matched outgoing request |
| Throughput | Full Burp scanner speed | Capped at `(scanner_threads) × (1 / chain_duration)` |
| Auth-server load | Minimal | High — multiplied by scanner concurrency |
| Required for | Reusable tokens | Single-use / per-request tokens |

#### 8. Pause / Resume

- **Pause Now** halts new chains immediately and aborts in-flight chains at the next step boundary (the current step's HTTP send can't be cancelled mid-call, so you may see 1-2 stragglers per in-flight chain).
- **Auto-paused** when OmniStrike's scan is stopped (`Stop Scan` button) — and auto-resumed when a new scan starts.
- Use the button manually when pausing Burp's built-in scanner, since Burp doesn't notify extensions of pause/stop.

#### 9. Run, verify, debug

- Click **Run Chain** to execute the configured prereqs manually (against the displayContext). The **Current Variables** table populates and the **Activity Log** prints `Auto-resolved {{name}} = ...` for each placeholder filled in.
- **Cache TTL** (default 10s, cached mode only) is how long captured values are reused before the chain re-runs. Click **Invalidate Cache** to force one re-run. The field is disabled while Per-Request Mode is on.
- Tick **Stop on Failure** to abort the chain if a step gets no response.
- A placeholder that can't be resolved is left as literal `{{name}}` in the outgoing request — easy to spot in Logger, and the log shows nothing was found.

#### 10. (Optional) Explicit extraction rules

Auto-extraction is the default. Add an explicit rule only when:

| Situation | Rule type | Pattern example |
|:----------|:----------|:----------------|
| Same JSON key at multiple nesting levels — you want a specific one | `JSON_PATH` | `data.user.id` |
| You want the variable named differently from the actual key (`access_token` → `{{auth}}`) | `JSON_PATH` / `BODY_REGEX` | `access_token` |
| Value lives somewhere weird (meta tag, hidden input, JS variable) | `BODY_REGEX` | `name="csrf"\s+value="([^"]+)"` (capture group 1) |
| You want the value of a specific named header | `HEADER` | `X-CSRF-Token` |
| You want the value of a specific named cookie | `COOKIE` | `PHPSESSID` |

Select the step, click **+ Add Rule**, fill in name + type + pattern. The explicit rule wins over auto-extraction for that variable.

---

## Custom OOB Server

No Burp Professional? No internet? No problem.

OmniStrike includes a built-in Out-of-Band callback server with HTTP and DNS listeners. Works on air-gapped networks.

All modules use it transparently through the same `CollaboratorManager` API -- switch between Burp Collaborator and Custom OOB with one click.

---

## Scan Tuning

Scanning is right-click only (no target scope, no auto-scan loop), so the OmniStrike tab keeps just the controls that shape a manual scan:

| Control | Description |
|:--------|:------------|
| **Threads** | Size of the shared scan thread pool (1-100). Applied immediately. |
| **Throttle Modes** | None (fastest), Auto (backs off on WAF/rate-limit), Manual (fixed ms delay). |
| **Time-Based Testing** | Off by default. Gates all slow time-blind tests (SQLi `SLEEP`, CmdI sleep/ping). |
| **Static Resource Skip** | Active injection auto-skips `.js`, `.css`, `.png`, etc. Passive analyzers still run. |

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

## Changelog

### v1.74
- **Right-click-only scanning** — removed the auto-scan workflow entirely: no more **Target Scope** field, **Include / Exclude** lists, or **Start Auto-Scan** button. Nothing is sent to a target until you right-click → **Send to OmniStrike**. The top bar is trimmed to the controls that actually matter for manual scans (Threads, Throttle, Time-Based Testing).
- **Parameter + module picker dialog** — **Send to OmniStrike (All Modules)** now opens a dialog with tick-lists for every scannable parameter (query/body/cookie/JSON, `Referer`/`Origin`-embedded params, injectable headers, URL path segments) and every module. Each active scanner runs once per ticked parameter (reflection check skips redundant whole-request re-runs for modules without per-parameter targeting); passive analyzers run once. Replaces the old "Scan Parameter" / "Scan This Parameter" submenus.
- **Manual scans bypass dedup** — a right-click scan now re-tests targets even if automatic scanning already covered them, via a thread-local bypass in `DeduplicationStore`. Fixes "Scan Parameter does nothing."
- **Session Keep-Alive fixes** — fresh cookies are now injected into **all** outbound traffic, including OmniStrike's own scan modules (which bypass Burp's `HttpHandler` via `api.http().sendRequest()`); injection runs after Stepper so the two don't interfere, and a thread-local guard keeps the login replay itself untouched. Also fixed a wiring-order bug where the keep-alive object was handed to the interceptor as `null`, so cookie injection never ran at all.
- **Sidebar cleanup** — active scanners are no longer listed in the sidebar (they're right-click only). The sidebar now shows AI Analysis, Passive Analyzers, and Framework Tools.
- **Deserialization → Framework Tools** — its UI panel (payload generator) moved under Framework Tools. It still runs as an active scanner via right-click.
- **Removed menu items** — **Send to OmniStrike (Custom)** and the **Analyze TLS** right-click item (TLS analysis lives in the TLS Analyzer panel). Deleted the now-dead `ScanConfigDialog` and the unreachable per-module detail panels for active scanners.

### v1.73
- **LDAP Injection scanner removed** — net false-positive risk outweighed its value; use Burp's built-in checks / manual testing.
- **Anti-reflection guard** added to Command Injection and Path Traversal — payloads that are simply echoed back in the response no longer count as evidence, cutting reflected-input false positives.

### v1.72
- **Stepper — Per-Request Mode** — new concurrency model for single-use tokens. Each matched outgoing request gets its own fresh `ChainContext` and runs the chain in parallel on its own thread (no global lock, no cache). Required when prereqs produce nonces the target burns per request.
- **Stepper — Pause / Resume** — `paused` flag with inter-step abort check. New chains are blocked and in-flight chains exit at the next step boundary. Auto-paused when OmniStrike's `stopManualScans()` fires; auto-resumed on new scan start. Manual `Pause Now` / `Resume` button in the panel for Burp's built-in scan (Burp doesn't notify extensions of pause/stop).
- **Stepper — Pinned variables** — `+ Add` button in the Variables table to manually set or override any `{{name}}`. Pinned values survive chain re-runs and win over auto-extracted values with the same name. Mirrors the existing pinned-cookies UX.
- **Stepper — Edit Request dialog** — `Edit Request` button on the steps table opens a raw HTTP editor for the captured request. Insert `{{varName}}` placeholders into the URL / headers / body after capture; the original `HttpService` is preserved. Parse errors are reported and the step is left untouched.
- **Stepper — Two-pass step matching** — exact pass compares method + host + port + full path + body (so `postId=1` vs `=2` vs `=3` are distinguishable); loose pass falls back to method + path-without-query and returns the *highest* matching index (convention: target = last step). No-match now returns the request unchanged instead of running all steps — unrelated browser/extension traffic no longer triggers chains.
- **Stepper integration with OmniStrike's own scanner** — new `StepperHttp` wrapper around `api.http().sendRequest()`. Burp's `HttpHandler` is bypassed by `api.http().sendRequest()` (Montoya design), so OmniStrike's 32 scan modules (92 call sites) previously sent probes without Stepper preprocessing. They all now route through `StepperHttp.sendRequest()` which preprocesses via the engine before sending. Burp's built-in tools (Proxy/Repeater/Intruder/Scanner) continue to work through the existing `HttpHandler`.
- **TLS Analyzer — Cipher classification overhaul** — `Enumerate ciphers` is now ON by default so the full server-supported cipher list is collected without ticking a hidden option. `classifyCipher` overhauled: CBC suites are now marked `DANGEROUS (CBC padding-oracle)` instead of the misleading `OK (legacy CBC)`. New `DANGEROUS (MD5 MAC)`, `DANGEROUS (broken cipher)` (RC4/DES/3DES/RC2), and `WEAK (no forward secrecy)` (`TLS_RSA_WITH_*`) categories. GCM / ChaCha20 still `STRONG (AEAD)`.

### v1.71
- **TLS Analyzer (new framework tool)** — out-of-band TLS / SSL inspection.
  - Per-protocol probe matrix (TLSv1.3 → SSLv3) since Burp's Montoya API does not expose negotiated TLS metadata. Reports `BLOCKED_BY_JDK` for protocols the local JVM disables (so the user knows the server's posture is unknown rather than assumed-broken).
  - Optional cipher-suite enumeration (off by default — slow). Built-in classifier flags NULL/anon/EXPORT/RC4/3DES/DES/MD5 ciphers.
  - Certificate chain inspection: subject, issuer, SANs, signature algorithm, public-key algorithm + size, expiry. Self-signed / expired / SHA-1 / RSA <2048 / hostname-mismatch detection.
  - Right-click any HTTPS request → **Analyze TLS (host:port)** to auto-fill and run.
  - Findings publish into the Findings store + Burp Dashboard with severity-mapped remediations.
- **Dashboard rendering fix** — finding descriptions and remediations no longer show literal `<br>`, `<b>`, `<table>` tags. Stripped HTML markup from `FindingsBundler`, `SecurityHeaderAnalyzer`, `TechFingerprinter` and made `OmniStrikeScanCheck.buildDetailHtml` convert plain-text newlines to `<br>` so multi-line descriptions render correctly.

### v1.70
- **Stepper auto-extraction** — `{{name}}` placeholders now auto-resolve from earlier step responses without requiring an `ExtractionRule`. Resolution order: response header → Set-Cookie → JSON key (case-insensitive, nested objects + arrays) → regex fallback (`"name":"value"`, `name=value`). Most-recent response wins; resolved values cached for the chain run.
- **Stepper URL path substitution fixed** — `{{var}}` previously only substituted in headers and body. Now also substituted in the request line / URL path, so `/api/{{id}}/xyz` works.
- **Stepper docs** — full how-to manual added to the README (enable → add steps → reference values → cookies → debug → optional rules).
- **Removed modules**:
  - **CSRF Manipulator** — token-tampering scanner removed (manual fuzzing covers the same surface).
  - **Bypass URL Parser** — 403/401 path-bypass scanner removed.
  - **OmniMap Exploiter** — SQL extraction engine removed (use sqlmap directly).
- **Cleanup** — `MANUAL_ONLY_IDS`, context menu filters, traffic interceptor module-shutdown hooks, executor pause/resume comments, and stale class files all updated.

### v1.69
- **OOB LDAP Listener** added to the custom OOB server
  - TCP LDAP listener on a configurable port (default: random available port, 0 = disabled)
  - Scans raw bytes for the 24-char hex payload ID — no full BER/ASN.1 parsing needed
  - Responds with a minimal LDAP BindResponse (resultCode=0) so clients don't hang or retry
  - UI: LDAP port field + randomize button + live preview label; status shows HTTP / DNS / LDAP
  - Enables OOB detection for XXE → LDAP, Log4Shell → LDAP, SSRF → LDAP payloads
- **Deserialization Scanner: blind testing on right-clicked parameters**
  - Previously, right-clicking a parameter skipped active payloads if passive analysis found no serialization signature (no rO0/base64/ysoserial markers)
  - Now falls back to `buildBlindDeserPoints()` — tests the parameter against all 6 supported languages (Java, .NET, PHP, Python, Ruby, Node.js) regardless of signature match
  - Respects user intent: explicit right-click = test it
- **ErrorDisclosureScanner** registered in the extension (was built but not wired into the module registry)
- **SSTI Scanner: dead code cleanup (5 fixes)**
  - Removed `polyglotCaused500` flag — declared and set but never used downstream; stale comment removed
  - Removed `confirmedEngine` variable — set to `"Spring EL"` in one branch but never read
  - Removed 2 POLYGLOT_PROBES with empty `expected` fields — Java `String.contains("")` always returns `true`, so `!baseline.contains("")` is always `false`; these probes could never produce a finding
  - Removed Django `{{settings.SECRET_KEY}}` ENGINE_PROBE with empty `expected` — same `String.contains("")` trap
  - Added `oobConfirmedParams` early-exit check inside the `testOobSsti` loop — stops sending OOB payloads as soon as a callback fires (consistent with CommandInjectionScanner)

### v1.68
- **Node.js SSJI detection** added to Command Injection scanner (JSON body parameters only)
  - JS arithmetic math probe: injects `(A*B).toString()` and checks for the product in the response; word-boundary guard prevents false positives from large numbers containing the product as a substring
  - `execSync` OOB payloads (14 variants): `require()`, `global.process.mainModule.require()`, IIFE obfuscation; `curl`/`wget`/`nslookup`/`ping` — fires in Phase 1 alongside standard OOB
  - `execSync` output-based payloads (8 variants): `id` (regex-matched) + `cat /etc/passwd` (marker-matched)
  - `execSync` time-based payloads (7 variants): gated by the Time-Based Testing UI toggle, serialized via `TimingLock`
  - 5 context-breaker prefixes per payload family: `'`, `')`, `'})`, `'))`, `'}}))` — covers the most common Node.js eval idioms

### v1.67
- Passive Tech Fingerprinter: per-host dedup, new framework signal categories
- LDAP Injection: zero FP redesign (2+ signature requirement for error-based, 2-round boolean differential)
- Auto-Throttle: exponential backoff on rate-limit detection

---

## Legal

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively on systems you have written permission to test. The authors are not responsible for misuse.

---

<div align="center">
<sub>Built on the Montoya API. No legacy interfaces. No external servers. No API keys. Just one JAR.</sub>
</div>

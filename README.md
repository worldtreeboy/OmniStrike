<div align="center">

<img src="https://img.shields.io/badge/OmniStrike-v1.77-blueviolet?style=for-the-badge&labelColor=1a1a2e" alt="Version"/>

# OmniStrike

**One Burp extension. 12 active injection scanners. 11 auto-triggered technology scanners. 7 passive analyzers. AI-powered fuzzing. Session automation. Custom OOB server. One JAR.**

[![Java](https://img.shields.io/badge/Java_17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Montoya API](https://img.shields.io/badge/Montoya_API-E8350E?style=flat-square)](https://portswigger.net/burp)
[![License](https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square&color=blue)](LICENSE)
[![Downloads](https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=brightgreen)](https://github.com/worldtreeboy/OmniStrike/releases)

[**Download JAR**](https://github.com/worldtreeboy/OmniStrike/releases/latest) · [Quick Start](#quick-start) · [Modules](#what-it-scans) · [Stepper](#stepper--session-automation) · [Build](#build-from-source)

</div>

---

## Quick Start

```
1.  Download omnistrike.jar from Releases (or build from source)
2.  Burp Suite → Extensions → Add → Java → omnistrike.jar
3.  Right-click any request → "Send to OmniStrike (All Modules)"
4.  Tick parameters + modules → Scan
```

**Every scan is right-click driven.** Nothing runs automatically on proxy traffic — neither active nor passive. Both passive analyzers and active scanners only run on requests you explicitly send via the right-click menu. No auto-scan loop, no target-scope field, no background analysis.

---

## What It Scans

### 12 Active Injection Scanners

| Scanner | Summary |
|:--------|:--------|
| **SQL Injection** | UNION + time-blind + OOB across 6 DBMS groups, ~100 OOB payloads, REST path injection. |
| **Command Injection** | Time + output + OOB, Unix & Windows, `$IFS`/backtick bypasses, Node.js SSJI with 5 context-breakers. |
| **SSRF** | Collaborator OOB, DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads. |
| **SSTI** | 20 template engines, large-number canaries, payload-reflection guard. |
| **XXE** | XML + XInclude + JSON-to-XML + Content-Type forcing, 14 OOB payloads. |
| **Path Traversal** | 24 Unix + 9 Windows targets, 26 encoding bypasses, PHP wrappers, multi-marker confirmation. |
| **GraphQL** | Introspection bypass, IDOR, DoS config, injection, error disclosure. |
| **CORS** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials. |
| **Cache Poisoning** | Unkeyed headers + query params, canary confirmation. |
| **Host Header** | Password reset poisoning, routing SSRF, duplicate Host, override headers. |
| **HTTP Param Pollution** | Duplicate-param precedence, WAF splitting bypass. |
| **Prototype Pollution** | `__proto__`/`constructor.prototype` with canary persistence. |

**Deserialization** runs as an active scanner via right-click; its UI lives under *Framework Tools* as a payload generator (6 languages, 137+ gadget chains).

### 11 Auto-Triggered Technology Scanners

These ride along with **Send to OmniStrike ▸ All Modules** and only fire if the target technology is confirmed in the response. Zero noise on non-target systems.

Dynamics 365 FetchXML · SAP OData · Salesforce SOQL · Firebase Misconfig · SharePoint CAML · ServiceNow GlideRecord · Apache Solr · Odoo Domain Filter · Elasticsearch Query · Spring Boot Actuator · *(WordPress REST API — coming soon)*

### 7 Passive Analyzers

Run on right-click → Send to OmniStrike alongside the active scanners — read-only, send nothing:

Client-Side (DOM XSS, prototype pollution, secrets) · Endpoint Finder · Subdomain Collector · Security Headers · Tech Fingerprinter · Sensitive Data (Luhn-validated CCs, SSNs, JWTs, ARNs, IBANs) · Error Disclosure (Java/Jackson/Spring/.NET/Python/Node.js/Go/Ruby + DB driver exceptions)

### 5 Framework Tools

| Tool | What It Does |
|:-----|:-------------|
| **AI Vulnerability Analyzer** | LLM-powered fuzzing via Claude/Gemini/Codex/OpenCode CLI. No API keys. Off by default. |
| **Deserialization Generator** | 137+ gadget chains across 6 languages, copy-paste-ready. |
| **File Payload Generator** | 39 file payloads (PDF/SVG/DOCX/XLSX XXE, web shells, polyglots, EICAR) + 31 inline payloads. |
| **Wordlist Generator** | Passive word harvester for fuzzing/brute-forcing. |
| **TLS Analyzer** | Per-protocol probe matrix (TLSv1.3 → SSLv3), cipher classification, cert chain inspection. |

---

## Scanning Workflow

Right-click any request → **Send to OmniStrike (All Modules)** opens a picker with tick-lists for every scannable parameter (query/body/cookie/JSON, embedded params in `Referer`/`Origin`, injectable headers, URL path segments) and every module. Each active scanner runs once per ticked parameter. Static resources (`.js`, `.css`, images) skip active injection automatically. Manual scans bypass the dedup cache so re-scanning actually re-runs.

| Menu item | Action |
|:----------|:-------|
| **Send to OmniStrike (All Modules)** | Picker dialog (above). |
| **Send to OmniStrike ▸** | Per-module submenu — single scanner (Normal or AI). |
| **Set as Session Login Request** | Saves the request for Session Keep-Alive replay. |
| **Send to Stepper** | Adds the request as a prerequisite step (when Stepper is enabled). |

### Session Keep-Alive

Right-click your login/refresh request → **Set as Session Login Request**, then tick **Session Keep-Alive** in the OmniStrike tab. OmniStrike periodically replays it, captures the fresh `Set-Cookie` values, and injects them — domain-scoped — into **all** outbound traffic (Burp's tools *and* OmniStrike's own scan modules).

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

No Burp Professional? No internet? OmniStrike includes a built-in OOB callback server with HTTP and DNS listeners. Switch between Burp Collaborator and Custom OOB with one click — same `CollaboratorManager` API behind both.

---

## Scan Tuning

| Control | Description |
|:--------|:------------|
| **Threads** | Shared scan thread pool size (1-100), applied immediately. |
| **Throttle Modes** | None / Auto (backs off on WAF/rate-limit) / Manual (fixed ms). |
| **Time-Based Testing** | Off by default. Gates slow time-blind tests. |
| **Static Resource Skip** | Auto-skip `.js`/`.css`/images for active injection. |

29 UI themes — scoped to OmniStrike only, or apply globally.

---

## Build From Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
# Output: build/libs/omnistrike.jar
```

Requires **JDK 17+**. Dependencies: Montoya API 2026.2, Gson 2.11.0, gadget chain libraries (Commons Collections, Javassist, ROME, Groovy, C3P0, BeanShell).

Contributing: fork → branch → `./gradlew shadowJar` must compile clean → test against DVWA / Juice Shop / PortSwigger Academy → open PR. [Issues](https://github.com/worldtreeboy/OmniStrike/issues) for bugs and feature requests.

---

## Changelog

### v1.77
- **Stability fixes.** Guarded a latent subprocess deadlock in the AI CLI backend (stdout is now drained before the prompt is piped to stdin, so a large prompt can't fill the pipe buffer and hang); fixed two array-index edge cases that could throw mid-scan (the SQLi UNION builder's Oracle `FROM` guard now matches the delimiter it splits on, and the Dynamics 365 FetchXML alias parse tolerates a trailing `alias='`).
- **Faster hot-path scanners.** Hoisted 27 regexes out of per-call method bodies into compile-once `static final` fields across Path Traversal, XXE, SSTI, Client-Side, Security Header, and Tech Fingerprinter — including five that were being recompiled twice per probe (response + baseline). No behavior change; less CPU/GC churn on large scans.
- Removed a stale leftover source snapshot from the tree.

### v1.76
- **Passive analyzers are now right-click only too.** Nothing runs automatically on proxy traffic. Both passive analyzers and active scanners only execute on requests you explicitly send via right-click → Send to OmniStrike. The previous auto-passive-on-in-scope behavior, the Burp Target → Scope fallback gate, and the dead OmniStrike include/exclude path checks are all gone. Findings list now contains exactly what you asked for, nothing else.
- **SSTI engine identification — false-positive overhaul.** Rewrote the engine probe table to use unique fingerprints only an evaluated template can produce — Flask `<Config '`, Python class reprs (`<class 'subprocess.Popen'>`), Java `Process[pid=`, Twig `object(Twig\TwigFilter)`, unique math products (`131803`) — instead of common words (`function`, `Process`, `Runtime`, `20`, `[`, `test|list`, `3.|4.|5.`). Probes that couldn't be made unambiguous (`@DateTime.Now`, `{{#list}}test{{/list}}`, `{$smarty.version}`, ERB `Dir.entries`, the Mustache section probe) were dropped rather than tightened. Hardened the matching loop: empty baselines short-circuit; raw payload reflected in the body always rejects (the old keyword-based skip-list let RCE/version/config/class/globals probes through, the main FP source); the matched token must not be a substring of the payload itself.
- **Path Traversal — baseline-marker fixes.** Marker-count detections (`UNIX_OSRELEASE`, `UNIX_ENVIRON`, `UNIX_APACHE`, `UNIX_SSHD`, `UNIX_REDIS`, `UNIX_OPENSSL`) now compare full marker counts between response and baseline; a baseline that happens to contain a different subset of markers no longer leaves the count check unguarded. `UNIX_OSRELEASE` uses line-anchored regex (was tripping on bare `ID=` in HTML/JSON). `UNIX_ENVIRON` adds a NUL-byte signal (the real `/proc/self/environ` format). Fixed an AND/OR logic bug in `WIN_BOOTINI` / `WIN_SYSTEMINI` / `WIN_PHPINI` / `WIN_WEBCONFIG` that passed whenever baseline lacked *either* marker.
- **Dashboard findings: plain text.** Finding details no longer emit HTML (`<h3>`, `<p>`, `<b>`, `<pre>`, `<br>`). Plain-text labels with blank-line separators throughout `DashboardReporter` and `OmniStrikeScanCheck`.

### v1.75
- **Every finding now reaches the Burp Dashboard** — findings with no underlying HTTP exchange (TLS Analyzer, async/Collaborator findings) get a minimal synthetic request built from the finding's URL.
- **Passive analyzers run automatically again** on in-scope proxy traffic. Active scanning stays right-click only.
- **Settings persistence** — thread count, throttle, theme, OOB config, Stepper chain (incl. rules/pinned vars/cookies), Session Keep-Alive login, and AI CLI backend choice all survive a Burp restart. API keys are never persisted.
- **Leaner JAR** — Montoya API no longer bundled (Burp provides it); Gson relocated. Deserialization gadget libs intentionally un-relocated so payloads keep their real class names.
- Removed dedup global lock; gated noisy per-request proxy logging behind a debug flag.

### v1.74
- **Right-click-only scanning** — removed auto-scan / target-scope entirely. Nothing is sent to a target until you right-click → **Send to OmniStrike**.
- **Parameter + module picker dialog** for **Send to OmniStrike (All Modules)** with tick-lists for every scannable param and module.
- **Manual scans bypass dedup** so re-scanning actually re-runs.
- **Session Keep-Alive** fresh cookies now inject into OmniStrike's own scan modules too (not just Burp's native tools).
- Deserialization UI moved under Framework Tools.

### v1.73
- LDAP Injection scanner removed (net FP risk outweighed value).
- Anti-reflection guard added to Command Injection and Path Traversal.

---

## Legal

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively on systems you have written permission to test. The authors are not responsible for misuse.

---

<div align="center">
<sub>Built on the Montoya API. No legacy interfaces. No external servers. No API keys. Just one JAR.</sub>
</div>

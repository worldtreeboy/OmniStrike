<h1 align="center">OmniStrike</h1>

<p align="center">
  <strong>One extension to replace them all.</strong><br>
  14 active scanners, 4 passive analyzers, AI-powered analysis — single JAR.
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/badge/version-1.30-blue?style=flat-square" alt="Version"></a>
  <img src="https://img.shields.io/badge/Java-17+-orange?style=flat-square&logo=openjdk" alt="Java 17+">
  <img src="https://img.shields.io/badge/Burp_Suite-Montoya_API-E8350E?style=flat-square" alt="Montoya API">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/worldtreeboy/OmniStrike?style=flat-square" alt="License"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/stargazers"><img src="https://img.shields.io/github/stars/worldtreeboy/OmniStrike?style=flat-square&color=yellow" alt="Stars"></a>
  <a href="https://github.com/worldtreeboy/OmniStrike/releases"><img src="https://img.shields.io/github/downloads/worldtreeboy/OmniStrike/total?style=flat-square&color=green" alt="Downloads"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#modules">Modules</a> &bull;
  <a href="#deserialization-payload-generator">Deser Generator</a> &bull;
  <a href="#ai-scanning">AI Scanning</a> &bull;
  <a href="#building-from-source">Build</a>
</p>

---

## Quick Start

```
1. Download omnistrike.jar from Releases
2. Burp Suite → Extensions → Add → Java → select omnistrike.jar
3. Set target scope, click Start — scan while you browse
4. Or right-click any request → Send to OmniStrike
```

---

## Modules

### Active Scanners (14)

| Module | What it does |
|---|---|
| **SQLi Detector** | Auth bypass, error-based, UNION, time-based blind (3-step verification), boolean-blind (2-round), 64 OOB payloads. ~375 payloads/param across 10 database engines. |
| **XSS Scanner** | 6 reflection contexts, smart filter probing (only sends viable payloads), adaptive evasion generation, DOM XSS flow analysis, CSTI, framework-specific payloads (AngularJS/Angular/Vue/React/jQuery), blind XSS via Collaborator. |
| **SSRF Scanner** | Collaborator OOB, cloud metadata with multi-marker validation (AWS/Azure/GCP/Oracle), DNS rebinding, 49 localhost bypasses, 31 protocol smuggling payloads (gopher, LDAP, etc). |
| **SSTI Scanner** | 20 template engines, large-number canaries (131803 not 49), template syntax consumption verification, 32 OOB payloads. |
| **Command Injection** | 3-step time-based, structural regex output matching, 140 payloads/param (Unix + Windows), `$IFS`/`%0a`/backtick/double-encoding bypasses. |
| **XXE Scanner** | 4-phase: XML body, XInclude, JSON→XML, Content-Type forcing. UTF-16 bypass, SAML detection, 14 OOB payloads. |
| **Deserialization** | 6 languages, 137+ gadget chains, passive fingerprinting, OOB-first Collaborator detection, blind spray mode. [Details below](#deserialization-scanner). |
| **GraphQL** | 7-phase: introspection (4 bypasses), schema analysis, injection (SQLi/NoSQLi/CMDi/SSTI/traversal), IDOR, DoS config, HTTP-level, error disclosure. Auto-generates queries from schema. |
| **CORS** | Reflected origin, null trust, subdomain trust, scheme downgrade, wildcard+credentials, preflight bypass. |
| **Cache Poisoning** | 30 unkeyed header vectors, 29 unkeyed query params, cacheability analysis, poison confirmation. |
| **Host Header Injection** | Password reset poisoning via Collaborator, routing SSRF, duplicate Host, override headers. |
| **HTTP Parameter Pollution** | Duplicate param precedence, privilege escalation patterns, WAF bypass via splitting. |
| **Prototype Pollution** | Server-side `__proto__`/`constructor.prototype` with canary persistence verification, behavioral gadgets. |
| **Path Traversal / LFI** | Absolute path + traversal, 24 Unix / 9 Windows targets with structural content validation, 26 encoding bypasses, PHP wrappers (filter/data/iconv). |

### Passive Analyzers (4)

| Module | What it does |
|---|---|
| **Client-Side Analyzer** | DOM XSS source-to-sink, prototype pollution, hardcoded secrets with entropy validation, postMessage, open redirects, endpoint extraction. Auto-skips minified libraries. |
| **Hidden Endpoint Finder** | Extracts API endpoints and paths from JS/HTML/JSON via 13+ regex patterns. |
| **Subdomain Collector** | Discovers subdomains from CSP, CORS, redirects, and response bodies. |
| **Security Header Analyzer** | HSTS, CSP, CORS, cookie flags, X-Frame-Options, Referrer-Policy, server version disclosure. |

---

## Deserialization Scanner

**6-language coverage** with passive fingerprinting, active injection, and OOB-first Collaborator detection:

| Language | Chains | Highlights |
|---|---|---|
| **Java** | 34 | Full ysoserial coverage (CommonsCollections 1-7, Spring, Hibernate, Groovy, C3P0, ROME, etc), 19 OOB payloads |
| **.NET** | 32 gadgets × 9 formatters | ysoserial.net-style Gadget + Formatter dropdowns, 9 OOB payloads |
| **PHP** | 47 | phpggc port — Laravel, Symfony, Monolog, Guzzle, WordPress, Doctrine, CodeIgniter4, ThinkPHP + 8 more frameworks. Configurable function dropdown (system/exec/passthru/etc). 3 OOB payloads |
| **Python** | 26 | Pickle protocol 0/2/4, PyYAML, jsonpickle, reverse shell. 12 OOB payloads |
| **Ruby** | 13 | Gem gadgets, Rails ActiveSupport, YAML/Psych, Oj library. Proper Marshal binary encoding. 5 OOB payloads |
| **Node.js** | 17 | node-serialize, serialize-javascript, js-yaml, cryo, funcster, prototype pollution. 12 OOB payloads |

38 suspect cookie patterns. Blind spray mode when no serialized data detected. OOB-first: if Collaborator confirms, remaining phases skipped.

---

## Deserialization Payload Generator

Standalone tool for generating deserialization payloads — no external tools needed (replaces ysoserial, ysoserial.net, phpggc).

- **137+ chains** across Java, .NET, PHP, Python, Ruby, Node.js
- **.NET**: Gadget + Formatter two-dropdown UX (32 gadgets × 9 formatters)
- **PHP**: Function dropdown (system, exec, passthru, shell_exec, popen, etc) — phpggc-style
- **Encodings**: Raw, Base64, URL-encoded, Base64+URL-encoded
- **Preview**: Terminal-style dark preview with selectable text color
- **Copy**: One-click Base64 or raw clipboard copy
- **Context menu**: Right-click in Proxy/Repeater to open directly

---

## AI Scanning

Right-click any request to trigger AI analysis. Never auto-fires — zero wasted tokens.

**Capabilities**: Smart fuzzing, WAF fingerprinting + bypass, adaptive multi-round scanning (up to 5 rounds with full response feedback), cross-file batch analysis, payload learning from confirmed findings, Collaborator data exfiltration, fuzz history (remembers every payload per URL/param/vuln type), multi-step exploitation of confirmed vulns.

**Providers**:

| Provider | Models |
|---|---|
| Anthropic (Claude) | claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001 |
| OpenAI | gpt-5.2, gpt-4o, o3-mini |
| Google Gemini | gemini-3.1-pro, gemini-3-flash-preview, gemini-2.5-flash |

Also supports CLI tools: Claude Code, Gemini CLI, Codex CLI, OpenCode CLI.

> API keys stored in memory only — never persisted to disk.

---

## Usage

**Scope-based (hands-free)**: Set target scope → toggle modules → click Start → browse normally. All in-scope traffic scanned automatically.

**Right-click**: Right-click any request → Send to OmniStrike (All Modules), or pick a specific module. Per-parameter targeting available via Scan Parameter submenu.

**Time-based testing**: Disabled by default (slow, heavy traffic). Enable via checkbox in UI.

**Session keep-alive**: Right-click login request → Set as Session Login Request. Extension replays it periodically to keep cookies fresh.

---

## Detection Philosophy

- **Zero false positives**: Every finding requires structural proof — not just response differences
- **OOB-first**: Collaborator payloads fire before time-based/error-based; if OOB confirms, remaining phases skipped
- **Smart filter probing**: Probes which characters survive filtering, then sends only viable payloads
- **3-step timing**: Baseline → true delay → false must NOT delay
- **Deduplication**: Cross-module, normalized URL dedup
- **Request/response highlighting**: All 19 modules annotate findings with byte-range markers in Burp Dashboard

---

## Building from Source

```bash
git clone https://github.com/worldtreeboy/OmniStrike.git
cd OmniStrike
./gradlew shadowJar
# Output: build/libs/omnistrike.jar
```

Requires JDK 17+. Dependencies: montoya-api 2026.2, gson 2.11.0.

---

## Contributing

1. Fork and create a feature branch
2. `./gradlew shadowJar` must compile cleanly
3. Test against [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop), or [PortSwigger Academy](https://portswigger.net/web-security)
4. Open a PR

[GitHub Issues](https://github.com/worldtreeboy/OmniStrike/issues) for bugs and feature requests.

---

## Changelog

### v1.30 (2026-02-27)
- **Deserialization payload expansion**: 137+ chains (47 PHP from phpggc, 26 Python with Pickle v0/v2/v4, 17 Node.js, 13 Ruby)
- **PHP Function dropdown**: configurable callable (system/exec/passthru/etc)
- **Encoding-aware preview**: Base64 section only shows for RAW encoding

---

## Security Notice

OmniStrike is for **authorized penetration testing** and **security research** only. Use exclusively against systems you have written permission to test.

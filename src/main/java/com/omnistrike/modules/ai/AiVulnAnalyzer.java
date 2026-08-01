package com.omnistrike.modules.ai;
import com.omnistrike.framework.stepper.StepperHttp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.JsonScanSupport;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.PersistenceManager;
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
 * AI-Powered Vulnerability Analyzer with passive review and bounded,
 * module-specific active testing.
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

    // AI-generated traffic must always be bounded. Targeted module scans use an
    // additional hard ceiling even when the general user setting is higher.
    static final int DEFAULT_AI_PAYLOAD_LIMIT = 12;
    static final int MAX_AI_PAYLOAD_LIMIT = 50;
    static final int MAX_TARGETED_PAYLOAD_LIMIT = 12;
    private volatile int maxPayloadsPerRequest = DEFAULT_AI_PAYLOAD_LIMIT;

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
    // No token budget — let the model's context window be the only limit.
    // CSS is still stripped (useless for vuln analysis) but everything else passes through.

    // ==================== Improvement 9: Structured Output Enforcement ====================
    private static final int MAX_JSON_RETRIES = 1;

    // ==================== Improvement 12: Fuzz History (per URL+param+vuln) ====================
    // Tracks every payload already sent for a given URL path + parameter + vuln type.
    // Injected into AI prompts so the LLM never regenerates payloads already tested.
    private final ConcurrentHashMap<String, FuzzHistoryEntry> fuzzHistory = new ConcurrentHashMap<>();
    private static final int MAX_HISTORY_ENTRIES = 5000;
    private static final int MAX_PAYLOADS_IN_PROMPT = 50; // cap history shown to AI per key

    // ==================== Improvement 10: Cost Tracking ====================
    private final AtomicLong totalInputTokens = new AtomicLong(0);
    private final AtomicLong totalOutputTokens = new AtomicLong(0);
    private final AtomicInteger totalApiCalls = new AtomicInteger(0);
    // estimatedCostUsd removed — now computed on-the-fly from atomic token counters
    // to avoid non-atomic read-compute-write race on volatile double.

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
    private static final Pattern SAFE_NOSQL_REGEX = Pattern.compile(
            "(?:\\.\\*|\\^\\.\\*\\$|\\^[A-Za-z0-9_.-]{1,128}\\$)");


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
            Map.entry("nosqli-scanner", new ModuleFocus("NoSQL Operator Injection",
                    "SCOPE: MongoDB-style NoSQL operator injection ONLY. Generate paired, non-destructive "
                    + "JSON operator objects using only $eq, $ne, and $regex. Use a unique impossible value "
                    + "for the narrow control and a broad value for the comparison.\n"
                    + "JSON TARGETS ONLY: set injection_point to \"json\" or \"body\" and identify the "
                    + "existing scalar with its JSON Pointer when possible. If the request is not JSON, "
                    + "return no payloads; the built-in scanner handles query/form bracket syntax.\n"
                    + "STRICTLY FORBIDDEN: $where, $function, JavaScript, timing payloads, destructive/update "
                    + "operators, SQL syntax, command injection, SSRF, SSTI, XSS, or any unrelated type. "
                    + "Every payload MUST have attack_type set to exactly \"nosqli\". Unsafe payloads are discarded.")),
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
                    "SCOPE: OS Command Injection ONLY (Linux and Windows).\n"
                    + "Use non-destructive confirmation probes and prioritize likely parameters. Cover distinct separator families: "
                    + "pipe, semicolon, backtick, $() substitution, && and || chaining.\n"
                    + "OOB TESTING IS MANDATORY: include fixed-canary DNS callbacks for every likely injectable parameter "
                    + "using the callback domain or placeholder provided below. Also include a small number of 5-second "
                    + "sleep/ping timing probes. Never exfiltrate target data.\n"
                    + "STRICTLY FORBIDDEN: Do NOT generate ANY payloads for SQLi, XSS, SSTI, SSRF, or any other vulnerability type. "
                    + "Every payload MUST have attack_type set to \"cmdi\". Any non-cmdi payload will be discarded.")),
            Map.entry("ssrf-scanner", new ModuleFocus("Server-Side Request Forgery (SSRF)",
                    "SCOPE: SSRF ONLY — internal network access, protocol smuggling, "
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
        return AiPrompts.ANALYSIS_PROMPT;
    }

    String buildFuzzPrompt(String targetModuleId) {
        int limit = getEffectivePayloadLimit(targetModuleId);
        String limitLine = "Generate at most " + limit + " total payloads. Prioritize distinct, high-signal tests; "
                + "do not produce cosmetic variations of the same payload.\n\n";

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
                    + "{\"payloads\": [{\"parameter\": \"param_name_or_json_pointer\", \"injection_point\": \"query|body|json|header|cookie|xml\", "
                    + "\"payload\": \"the_actual_payload_string\", \"attack_type\": \"" + attackType + "\", "
                    + "\"description\": \"brief explanation\"}]}\n\n"
                    + "HTTP Request:\n";
        }

        // Generic prompt — inject the limit and collaborator info dynamically
        String base = AiPrompts.SMART_FUZZ_PROMPT.replace(
                "PAYLOAD_LIMIT_INSTRUCTION", limitLine.trim());
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
        // OOB confirmation uses fixed canaries only; target-derived callback data
        // would bypass the outbound AI redaction boundary.
        return "OUT-OF-BAND (OOB) TESTING: You have access to a Burp Collaborator server at: " + serverAddr + "\n"
                + "For any blind/OOB payloads (blind SQLi, blind XXE, blind SSRF, blind command injection, etc.), "
                + "use the literal placeholder {COLLAB} wherever you need a unique Collaborator subdomain.\n"
                + "Example: For blind XXE, use <!ENTITY xxe SYSTEM \"http://{COLLAB}\">\n"
                + "Example: For blind SSRF, use http://{COLLAB}/test\n"
                + "Example: For blind SQLi DNS exfil, use LOAD_FILE('\\\\\\\\{COLLAB}\\\\a')\n"
                + "The {COLLAB} placeholder will be automatically replaced with a real tracked Collaborator URL.\n"
                + "PRIVACY RULE: use only fixed canary labels and paths. Never embed database values, "
                + "file contents, usernames, hostnames, tokens, or other target-derived data in an OOB request.\n\n";
    }

    private static String getAttackType(String moduleId) {
        return switch (moduleId) {
            case "sqli-detector" -> "sqli";
            case "nosqli-scanner" -> "nosqli";
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
            case "nosqli" -> p.contains("nosqli") || p.contains("nosql")
                    || p.contains("mongodb") && p.contains("operator");
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

    /**
     * Checks if an AI analysis finding's title+description matches the expected vulnerability type.
     * Used to drop off-target findings when the user asked for a specific vuln type.
     */
    private static boolean isFindingMatchingType(String combined, String expectedType) {
        return switch (expectedType) {
            case "sqli" -> combined.contains("sql") || combined.contains("sqli") || combined.contains("injection")
                    && (combined.contains("database") || combined.contains("query"));
            case "nosqli" -> (combined.contains("nosql") || combined.contains("mongodb"))
                    && (combined.contains("operator") || combined.contains("injection"));
            case "xss" -> combined.contains("xss") || combined.contains("cross-site scripting")
                    || combined.contains("reflected") && combined.contains("script");
            case "ssti" -> combined.contains("ssti") || combined.contains("template")
                    || combined.contains("server-side template");
            case "cmdi" -> combined.contains("command") || combined.contains("cmdi") || combined.contains("rce")
                    || combined.contains("os injection") || combined.contains("code execution");
            case "ssrf" -> combined.contains("ssrf") || combined.contains("server-side request")
                    || combined.contains("internal") && combined.contains("request");
            case "xxe" -> combined.contains("xxe") || combined.contains("xml external")
                    || combined.contains("xml entity");
            case "deserialization" -> combined.contains("deseriali") || combined.contains("gadget")
                    || combined.contains("marshalling");
            case "client-side" -> combined.contains("dom") || combined.contains("client-side")
                    || combined.contains("prototype pollution") || combined.contains("open redirect")
                    || combined.contains("postmessage") || combined.contains("hardcoded")
                    || combined.contains("secret") || combined.contains("cwe-79");
            default -> true; // unknown type — accept all
        };
    }

    // ==================== ScanModule interface ====================

    @Override
    public String getId() { return "ai-vuln-analyzer"; }

    @Override
    public String getName() { return "AI Vulnerability Analyzer"; }

    @Override
    public String getDescription() {
        return "AI-powered passive analysis and bounded, module-specific active testing.";
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
                new ThreadPoolExecutor.AbortPolicy());

        // Separate single-threaded executor for active fuzzing
        BlockingQueue<Runnable> fuzzQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        fuzzExecutor = new ThreadPoolExecutor(1, 1,
                0L, TimeUnit.MILLISECONDS, fuzzQueue,
                r -> {
                    Thread t = new Thread(r, "OmniStrike-AI-Fuzzer");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        // AI scanning is MANUAL ONLY — triggered via right-click context menu.
        // Automatic scanning from proxy traffic is disabled to prevent massive
        // token waste when every request in target scope hits the LLM.
        // The manualScan() method is the only entry point for AI analysis/fuzzing.
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

            promptBuilder.append(exchange.toPromptText());

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

            // Filter off-target findings when a specific module is requested.
            // The prompt tells the AI to only report X, but LLMs don't always listen.
            String expectedType = targetModuleId != null ? getAttackType(targetModuleId) : null;
            int droppedFindings = 0;

            for (LlmAnalysisResult.LlmFinding llmFinding : result.getFindings()) {
                // Post-processing filter: drop findings that don't match the target vuln type
                if (expectedType != null && !"unknown".equals(expectedType)) {
                    String titleLower = (llmFinding.getTitle() != null ? llmFinding.getTitle() : "").toLowerCase();
                    String descLower = (llmFinding.getDescription() != null ? llmFinding.getDescription() : "").toLowerCase();
                    String cweLower = (llmFinding.getCweId() != null ? llmFinding.getCweId() : "").toLowerCase();
                    String combined = titleLower + " " + descLower + " " + cweLower;
                    if (!isFindingMatchingType(combined, expectedType)) {
                        droppedFindings++;
                        continue;
                    }
                }

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
            if (droppedFindings > 0) {
                logInfo("AI Analysis: Filtered out " + droppedFindings + " off-target finding(s) for " + exchange.getUrl());
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
        String scanLabel = targetModuleId != null ? "Targeted AI Test" : "Smart Fuzzing";
        try {
            logInfo(scanLabel + ": Requesting payloads for " + exchange.getUrl()
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

            // Improvement 12: Fuzz history — tell AI what payloads were already tested
            String historyContext = buildFuzzHistoryContext(exchange.getUrl(), targetParameter, targetModuleId);

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
            if (!historyContext.isEmpty()) enrichedPrompt.append(historyContext);
            enrichedPrompt.append(paramConstraint);

            enrichedPrompt.append(exchange.toPromptText());

            String prompt = enrichedPrompt.toString();
            trackInputTokens(prompt);
            String requestKind = targetModuleId != null ? "targeted payload request" : "payload request";
            logInfo(">>> Sending " + requestKind + " to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") | prompt size: " + prompt.length() + " chars"
                    + " | est. cost: " + getCostSummary()
                    + (targetModuleId != null ? " | module: " + targetModuleId : ""));
            long startMs = System.currentTimeMillis();

            // Improvement 9: Structured output enforcement with retry
            String rawResponse = callWithRetry(prompt);
            long elapsedMs = System.currentTimeMillis() - startMs;
            logInfo("<<< AI payload response received in " + elapsedMs + "ms | response size: "
                    + (rawResponse != null ? rawResponse.length() : 0) + " chars");

            if (cancelled) { logInfo(scanLabel + ": Cancelled."); return; }

            List<FuzzPayload> payloads = parseFuzzPayloads(rawResponse);

            // When scanning for a specific module, drop any payloads the AI generated
            // for the wrong vulnerability type (e.g., XSS payloads during SSRF scan)
            if (targetModuleId != null) {
                String expectedType = getAttackType(targetModuleId);
                int beforeFilter = payloads.size();
                payloads.removeIf(p -> !isMatchingAttackType(p.attackType, expectedType)
                        || "nosqli".equals(expectedType)
                        && !isSafeNoSqlJsonPayload(p.injectionPoint, p.payload));
                int dropped = beforeFilter - payloads.size();
                if (dropped > 0) {
                    logInfo(scanLabel + ": Filtered out " + dropped + " off-target payload(s) "
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
                    logInfo(scanLabel + ": Filtered out " + dropped + " off-parameter payload(s) "
                            + "(expected: " + targetParameter + ")");
                }
            }

            // Improvement 12: Filter out payloads already tested (fuzz history dedup)
            payloads = filterAlreadyTested(payloads, exchange.getUrl());

            if (requiresOobForTargetedScan(targetModuleId)
                    && payloads.stream().noneMatch(this::containsConfiguredOobTarget)) {
                logError(scanLabel + ": AI returned no OOB callback payloads. "
                        + "The scan was stopped because OOB verification is mandatory for Command Injection.");
                return;
            }

            // Enforce the cap after all filtering as well as during JSON parsing. This is
            // deliberately redundant: one targeted click must never become hundreds of
            // active requests after a setting change or future parser refactor.
            int effectiveLimit = getEffectivePayloadLimit(targetModuleId);
            if (payloads.size() > effectiveLimit) {
                int discarded = payloads.size() - effectiveLimit;
                payloads = new ArrayList<>(payloads.subList(0, effectiveLimit));
                logInfo(scanLabel + ": Discarded " + discarded
                        + " payload(s) above the safety limit of " + effectiveLimit);
            }

            if (payloads.isEmpty()) {
                logInfo(scanLabel + ": No new payloads generated for " + exchange.getUrl()
                        + " (all were already tested — attack vectors may be exhausted)");
                return;
            }

            logInfo(scanLabel + ": Testing " + payloads.size() + " payloads against " + exchange.getUrl());

            String baselineBody = "";
            if (originalReqResp.response() != null) {
                String originalBody = originalReqResp.response().bodyToString();
                if (originalBody != null) baselineBody = originalBody;
            }

            // Step 2: Send each payload and collect results
            List<FuzzResult> allResults = new ArrayList<>();
            for (FuzzPayload payload : payloads) {
                if (cancelled) { logInfo(scanLabel + ": Cancelled mid-scan."); return; }

                // Improvement 6: Rate limit check before each request
                if (!waitForRateLimit(exchange.getUrl())) {
                    logInfo(scanLabel + ": Halted due to rate limiting/IP block.");
                    break;
                }

                try {
                    // AtomicReference lets the OOB callback access the response after sendRequest
                    AtomicReference<HttpRequestResponse> reqRespRef = new AtomicReference<>();
                    // Replace {COLLAB} placeholders with real tracked Collaborator payloads
                    FuzzPayload resolvedPayload = resolveCollaboratorPlaceholders(payload, exchange.getUrl(), reqRespRef, targetModuleId);
                    HttpRequest modified = injectPayload(originalReqResp.request(), resolvedPayload);
                    if ("nosqli-scanner".equals(targetModuleId)
                            && sameRequest(originalReqResp.request(), modified)) {
                        logInfo(scanLabel + ": Skipped a NoSQL payload that did not safely modify the JSON target");
                        continue;
                    }
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = StepperHttp.sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response); // Now OOB callback can read the request/response
                    fuzzRequestsSent.incrementAndGet();

                    // Improvement 6: Track response for rate limiting
                    trackRateLimit(exchange.getUrl(), response);

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolvedPayload, response, wafDetected, elapsed);
                    allResults.add(result);

                    // Check for immediate vulnerability indicators
                    boolean vulnFound = checkForVulnIndicators(
                            result, exchange.getUrl(), targetModuleId, baselineBody);

                    // Improvement 12: Record this payload in fuzz history
                    recordTestedPayload(exchange.getUrl(), resolvedPayload, response,
                            wafDetected, elapsed, vulnFound);

                    // Step 3: WAF bypass if blocked
                    if (wafBypass && wafDetected && !cancelled) {
                        logInfo(scanLabel + ": WAF detected for payload [" + resolvedPayload.attackType + "], attempting bypass");
                        List<FuzzResult> bypassResults = performWafBypass(
                                originalReqResp.request(), resolvedPayload, response,
                                targetModuleId, baselineBody);
                        allResults.addAll(bypassResults);
                    }
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                    logError(scanLabel + ": Error sending payload - " + e.getMessage());
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
                            originalReqResp.request(), allResults, round,
                            targetModuleId, baselineBody);
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

            if (cancelled) { logInfo(scanLabel + ": Cancelled."); return; }

            // Step 5: Final analysis — ask LLM to analyze all results
            analyzeFuzzResults(exchange.getUrl(), allResults, originalReqResp, targetModuleId);

            analyzedCount.incrementAndGet();
            logInfo(scanLabel + ": Completed for " + exchange.getUrl()
                    + " (" + allResults.size() + " total test requests)");

        } catch (LlmException e) {
            errorCount.incrementAndGet();
            logError(scanLabel + ": LLM error - " + e.getErrorType() + " - " + e.getMessage());
        } catch (Exception e) {
            errorCount.incrementAndGet();
            logError(scanLabel + ": Unexpected error - " + e.getMessage());
        }
    }

    // ==================== WAF Bypass ====================

    private List<FuzzResult> performWafBypass(HttpRequest originalRequest,
                                               FuzzPayload blockedPayload,
                                               HttpRequestResponse wafResponse,
                                               String targetModuleId,
                                               String baselineBody) {
        List<FuzzResult> results = new ArrayList<>();
        if (cancelled) return results;
        try {
            String wafSnippet = "";
            if (wafResponse.response() != null) {
                String body = wafResponse.response().bodyToString();
                wafSnippet = body != null ? truncate(body, 500) : "";
            }

            String prompt = String.format(AiPrompts.WAF_BYPASS_PROMPT,
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
                    if ("nosqli-scanner".equals(targetModuleId)
                            && sameRequest(originalRequest, modified)) continue;
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = StepperHttp.sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();

                    boolean stillBlocked = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(bypassPayload, response, stillBlocked, elapsed);
                    results.add(result);

                    boolean vulnFound = false;
                    if (!stillBlocked) {
                        logInfo("WAF Bypass: Successfully bypassed with [" + bypass.technique + "]");
                        vulnFound = checkForVulnIndicators(
                                result, originalRequest.url(), targetModuleId, baselineBody);
                    }

                    // Improvement 12: Record WAF bypass payloads in fuzz history
                    recordTestedPayload(originalRequest.url(), bypassPayload, response,
                            stillBlocked, elapsed, vulnFound);
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
                                                    String targetModuleId,
                                                    String baselineBody) {
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

            String prompt = String.format(AiPrompts.ADAPTIVE_PROMPT, resultsSummary) + rateLimitNote;
            trackInputTokens(prompt);

            // Improvement 9: Structured output enforcement
            String rawResponse = callWithRetry(prompt);
            List<FuzzPayload> payloads = parseFuzzPayloads(rawResponse);

            // Filter off-target payloads in adaptive rounds too
            if (targetModuleId != null) {
                String expectedType = getAttackType(targetModuleId);
                payloads.removeIf(p -> !isMatchingAttackType(p.attackType, expectedType)
                        || "nosqli".equals(expectedType)
                        && !isSafeNoSqlJsonPayload(p.injectionPoint, p.payload));
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
                    if ("nosqli-scanner".equals(targetModuleId)
                            && sameRequest(originalRequest, modified)) continue;
                    long startTime = System.currentTimeMillis();
                    HttpRequestResponse response = StepperHttp.sendRequest(modified);
                    long elapsed = System.currentTimeMillis() - startTime;
                    reqRespRef.set(response);
                    fuzzRequestsSent.incrementAndGet();
                    trackRateLimit(originalRequest.url(), response);

                    boolean wafDetected = isWafBlocked(response);
                    FuzzResult result = new FuzzResult(resolved, response, wafDetected, elapsed);
                    results.add(result);
                    boolean vulnFound = checkForVulnIndicators(
                            result, originalRequest.url(), targetModuleId, baselineBody);

                    // Improvement 12: Record adaptive payloads in fuzz history
                    recordTestedPayload(originalRequest.url(), resolved, response,
                            wafDetected, elapsed, vulnFound);
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
    private boolean checkForVulnIndicators(FuzzResult result, String url, String targetModuleId,
                                            String baselineBody) {
        if (result.response == null || result.response.response() == null) return false;

        String body = result.response.response().bodyToString();
        if (body == null) return false;
        String payloadText = result.payload.payload == null ? "" : result.payload.payload;
        String evidenceBody = payloadText.isEmpty() ? body : body.replace(payloadText, "");
        String bodyLower = evidenceBody.toLowerCase(Locale.ROOT);
        String baselineLower = baselineBody == null ? "" : baselineBody.toLowerCase(Locale.ROOT);
        int status = result.response.response().statusCode();

        // SQL error indicators
        if (result.payload.attackType.equals("sqli")) {
            for (String indicator : List.of("you have an error in your sql", "sqlstate[",
                    "warning: mysql_", "pg_query", "ora-", "unclosed quotation mark",
                    "quoted string not properly terminated", "unterminated quoted string at or near",
                    "syntax error at or near", "sqliteexception", "sqlexception")) {
                if (bodyLower.contains(indicator) && !baselineLower.contains(indicator)) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                            "SQL Injection — database error triggered",
                            "Database error '" + indicator + "' found in response after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return true;
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
                    return true;
                }
            }
        }

        // Reflection alone is not executable XSS. Require an HTML response and an
        // active payload, then keep the result tentative pending browser-context review.
        if (result.payload.attackType.equals("xss")) {
            String contentType = responseContentType(result.response);
            String payloadLower = payloadText.toLowerCase(Locale.ROOT);
            boolean activePayload = payloadLower.contains("<script") || payloadLower.contains("<svg")
                    || payloadLower.contains("<img") || payloadLower.contains("onerror")
                    || payloadLower.contains("onload") || payloadLower.contains("javascript:");
            if (contentType.contains("text/html") && activePayload
                    && !payloadText.isEmpty() && body.contains(payloadText)
                    && (baselineBody == null || !baselineBody.contains(payloadText))) {
                reportFuzzFinding(result, url, targetModuleId, Severity.MEDIUM, Confidence.TENTATIVE,
                        "Possible Reflected XSS — active payload reflected in HTML",
                        "Injected payload reflected verbatim in response body: "
                                + truncate(payloadText, 200));
                return true;
            }
        }

        // Command injection indicators — use specific OS output patterns, not generic words
        if (result.payload.attackType.equals("cmdi")) {
            for (String indicator : List.of("root:x:0:0:", "uid=0(root)", "uid=",
                    "volume serial number", "/bin/bash", "/bin/sh")) {
                if (bodyLower.contains(indicator) && !baselineLower.contains(indicator)) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                            "Command Injection — OS command output detected",
                            "OS-level output '" + indicator + "' detected after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return true;
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
                    return true;
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
                if (payloadText.contains(entry.getKey()) && evidenceBody.contains(entry.getValue())
                        && (baselineBody == null || !baselineBody.contains(entry.getValue()))) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.CRITICAL, Confidence.FIRM,
                            "Server-Side Template Injection — math expression evaluated",
                            "Template expression '" + entry.getKey() + "' evaluated to '"
                                    + entry.getValue() + "' in response. Payload: "
                                    + truncate(result.payload.payload, 200));
                    return true;
                }
            }
        }

        // Path traversal indicators — use specific file content patterns, not generic XML/HTML
        if (result.payload.attackType.equals("path_traversal")) {
            for (String indicator : List.of("root:x:0:0:", "[boot loader]",
                    "[extensions]", "[fonts]", "PATH=", "HOME=")) {
                if (bodyLower.contains(indicator) && !baselineLower.contains(indicator) && status == 200) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.FIRM,
                            "Path Traversal — file content leaked",
                            "File content indicator '" + indicator + "' found after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return true;
                }
            }
        }

        // SSRF indicators
        if (result.payload.attackType.equals("ssrf")) {
            for (String indicator : List.of("ami-", "instance-id", "metadata",
                    "169.254.169.254", "127.0.0.1", "localhost")) {
                if (bodyLower.contains(indicator) && !baselineLower.contains(indicator)
                        && !result.wafDetected) {
                    reportFuzzFinding(result, url, targetModuleId, Severity.HIGH, Confidence.TENTATIVE,
                            "Possible SSRF — internal resource indicator in response",
                            "Internal indicator '" + indicator + "' found after injecting: "
                                    + truncate(result.payload.payload, 200));
                    return true;
                }
            }
        }

        return false;
    }

    private static String responseContentType(HttpRequestResponse response) {
        if (response == null || response.response() == null) return "";
        for (var header : response.response().headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                return header.value() == null ? "" : header.value().toLowerCase(Locale.ROOT);
            }
        }
        return "";
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
            ModuleFocus focus = targetModuleId != null ? MODULE_FOCUS.get(targetModuleId) : null;
            String focusRule = focus != null
                    ? "\nSCOPE: Review these results ONLY for " + focus.displayName()
                    + ". Do not report any other vulnerability class.\n"
                    + ("nosqli-scanner".equals(targetModuleId)
                    ? "For NoSQL, require matching behavior from both a $ne/$eq control pair and an "
                    + "$regex broad/impossible pair. Reflection, WAF rejection, response-length-only "
                    + "changes, or one unconfirmed response are not proof.\n"
                    : "")
                    : "";
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
                    """ + focusRule + summary;

            logInfo("Targeted AI Test: Reviewing " + results.size()
                    + " response(s) for confirmed evidence");
            String rawResponse = callWithRetry(prompt);
            LlmAnalysisResult result = llmClient.parseResponse(rawResponse);
            String expectedType = targetModuleId != null ? getAttackType(targetModuleId) : null;
            int droppedFindings = 0;
            int acceptedFindings = 0;

            for (LlmAnalysisResult.LlmFinding llmFinding : result.getFindings()) {
                if (expectedType != null && !"unknown".equals(expectedType)) {
                    String combined = (llmFinding.getTitle() != null ? llmFinding.getTitle() : "")
                            + " " + (llmFinding.getDescription() != null ? llmFinding.getDescription() : "")
                            + " " + (llmFinding.getCweId() != null ? llmFinding.getCweId() : "");
                    if (!isFindingMatchingType(combined.toLowerCase(), expectedType)) {
                        droppedFindings++;
                        continue;
                    }
                }
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
                        .description("[AI Targeted Test] " + llmFinding.getDescription())
                        .remediation(llmFinding.getRemediation())
                        .requestResponse(originalReqResp)
                        .build();

                findingsStore.addFinding(finding);
                findingsCount.incrementAndGet();
                acceptedFindings++;
            }
            if (droppedFindings > 0) {
                logInfo("Targeted AI Test: Filtered out " + droppedFindings
                        + " off-target final finding(s) for " + url);
            }
            logInfo("Targeted AI Test: Evidence review completed with "
                    + acceptedFindings + " confirmed finding(s)");
        } catch (Exception e) {
            errorCount.incrementAndGet();
            logError("Targeted AI Test: Error analyzing results - " + e.getMessage());
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
                .description("[AI Targeted Test] " + result.payload.description)
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

            logInfo("Targeted AI Test: Tracked OOB callback armed | host=" + collabPayload
                    + " | param=" + payload.parameter);

            // Replace only the first occurrence per iteration
            resolvedPayload = resolvedPayload.replaceFirst(
                    java.util.regex.Pattern.quote(COLLAB_PLACEHOLDER),
                    java.util.regex.Matcher.quoteReplacement(collabPayload));
        }

        return new FuzzPayload(payload.parameter, payload.injectionPoint,
                resolvedPayload, payload.attackType, payload.description);
    }

    // ==================== Request modification ====================

    private HttpRequest injectPayload(HttpRequest original, FuzzPayload payload) {
        String injectionPoint = payload.injectionPoint == null ? "" : payload.injectionPoint.toLowerCase(Locale.ROOT);
        boolean noSqlOperator = isMatchingAttackType(payload.attackType, "nosqli");
        if (noSqlOperator && !isSafeNoSqlJsonPayload(injectionPoint, payload.payload)) {
            return original;
        }
        return switch (injectionPoint) {
            case "query", "url" -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.URL));
            case "body" -> {
                if (isJsonRequest(original)) {
                    String originalBody = original.bodyToString();
                    String modifiedBody = noSqlOperator
                            ? injectNoSqlJsonPayload(originalBody, payload.parameter, payload.payload)
                            : injectJsonValue(originalBody, payload.parameter, payload.payload);
                    yield modifiedBody.equals(originalBody) ? original : original.withBody(modifiedBody);
                }
                if (noSqlOperator) yield original;
                yield original.withParameter(
                        HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.BODY));
            }
            case "json" -> {
                String originalBody = original.bodyToString();
                String modifiedBody = noSqlOperator
                        ? injectNoSqlJsonPayload(originalBody, payload.parameter, payload.payload)
                        : injectJsonValue(originalBody, payload.parameter, payload.payload);
                yield modifiedBody.equals(originalBody) ? original : original.withBody(modifiedBody);
            }
            // "xml" explicitly means a complete replacement document. This avoids
            // accidentally appending an XML payload as a URL parameter.
            case "xml" -> original.withBody(payload.payload);
            case "header" -> original
                    .withRemovedHeader(payload.parameter)
                    .withAddedHeader(payload.parameter, payload.payload);
            case "cookie" -> PayloadEncoder.injectCookie(
                    original, payload.parameter, payload.payload);
            default -> original.withParameter(
                    HttpParameter.parameter(payload.parameter, PayloadEncoder.encode(payload.payload), HttpParameterType.URL));
        };
    }

    private static boolean sameRequest(HttpRequest first, HttpRequest second) {
        if (first == second) return true;
        if (first == null || second == null) return false;
        try {
            return Arrays.equals(first.toByteArray().getBytes(), second.toByteArray().getBytes());
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static boolean isJsonRequest(HttpRequest request) {
        for (var header : request.headers()) {
            if ("Content-Type".equalsIgnoreCase(header.name())) {
                String value = header.value().toLowerCase(Locale.ROOT);
                return value.contains("application/json") || value.contains("+json");
            }
        }
        return false;
    }

    /**
     * Structurally replaces one JSON primitive. JSON Pointer is preferred; a
     * display/leaf name is accepted only when it identifies exactly one target.
     */
    static String injectJsonValue(String body, String requestedParameter, String payload) {
        return injectJsonElement(body, requestedParameter, new JsonPrimitive(payload));
    }

    /**
     * NoSQL AI payloads are deliberately limited to non-executable operator
     * objects. This prevents an LLM from turning targeted testing into $where
     * JavaScript execution or an unrelated generic fuzzing pass.
     */
    static boolean isSafeNoSqlJsonPayload(String injectionPoint, String payload) {
        if (injectionPoint == null || payload == null || payload.length() > 1_024) return false;
        String point = injectionPoint.trim().toLowerCase(Locale.ROOT);
        if (!point.equals("json") && !point.equals("body")) return false;
        if (!hasBoundedJsonNesting(payload, 2)) return false;
        try {
            JsonElement parsed = JsonParser.parseString(payload);
            if (!parsed.isJsonObject()) return false;
            JsonObject object = parsed.getAsJsonObject();
            if (object.size() != 1) return false;
            Map.Entry<String, JsonElement> entry = object.entrySet().iterator().next();
            if (!Set.of("$eq", "$ne", "$regex").contains(entry.getKey())) return false;
            JsonElement value = entry.getValue();
            if (!(value.isJsonNull() || value.isJsonPrimitive())) return false;
            if ("$regex".equals(entry.getKey())) {
                return value.isJsonPrimitive()
                        && value.getAsJsonPrimitive().isString()
                        && SAFE_NOSQL_REGEX.matcher(value.getAsString()).matches();
            }
            return !value.isJsonPrimitive()
                    || !value.getAsJsonPrimitive().isString()
                    || value.getAsString().length() <= 512;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static boolean hasBoundedJsonNesting(String value, int limit) {
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quoted) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') quoted = false;
            } else if (c == '"') {
                quoted = true;
            } else if (c == '{' || c == '[') {
                if (++depth > limit) return false;
            } else if (c == '}' || c == ']') {
                if (--depth < 0) return false;
            }
        }
        return depth == 0 && !quoted;
    }

    static String injectNoSqlJsonPayload(String body, String requestedParameter, String payload) {
        if (!isSafeNoSqlJsonPayload("json", payload)) return body;
        try {
            return injectJsonElement(body, requestedParameter, JsonParser.parseString(payload));
        } catch (JsonParseException ignored) {
            return body;
        }
    }

    private static String injectJsonElement(
            String body, String requestedParameter, JsonElement replacement) {
        if (body == null || requestedParameter == null || requestedParameter.isBlank()) return body;
        try {
            List<JsonScanSupport.Target> targets = JsonScanSupport.extractTargets(body);
            String requested = requestedParameter.trim();

            for (JsonScanSupport.Target target : targets) {
                if (target.identityName().equals(requested)) {
                    return JsonScanSupport.replaceElement(body, target.path(), replacement);
                }
            }

            List<JsonScanSupport.Target> matches = targets.stream()
                    .filter(target -> target.matchesParameterName(requested))
                    .toList();
            if (matches.size() != 1) return body;
            return JsonScanSupport.replaceElement(body, matches.get(0).path(), replacement);
        } catch (RuntimeException ignored) {
            return body;
        }
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
            "' OR 1=1-- -",
            "{{7*7}}",
            "; cat /etc/passwd",
            "../../../../etc/passwd"
    };
    private static final String[] WAF_PROBE_LABELS = {
            "SQLi OR", "SSTI {{7*7}}", "CMDi cat", "Path traversal"
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
                HttpRequestResponse response = StepperHttp.sendRequest(modified);
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
        com.omnistrike.framework.BoundedDeduplication.trimToSize(wafFingerprints, 10_000);
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
        com.omnistrike.framework.BoundedDeduplication.trimToSize(rateLimitTrackers, 10_000);

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
        com.omnistrike.framework.BoundedDeduplication.trimToSize(rateLimitTrackers, 10_000);

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
     * Strips boilerplate from an HTTP response body for inclusion in prompts.
     */
    private String stripResponseBoilerplate(String body) {
        if (body == null) return "";
        // Remove CSS blocks only — keep <script> content for DOM XSS, reflected XSS, secrets analysis
        body = body.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "");
        body = body.replaceAll("<(?!/?script)[^>]+>", " "); // Strip non-script HTML tags
        body = body.replaceAll("\\s+", " ");
        return body.trim();
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
        // No-op: cost is now computed on-the-fly in getEstimatedCostUsd()
        // from the atomic token counters, eliminating the race condition.
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
                entry.append("Response Body: ").append(stripResponseBoilerplate(body)).append("\n");
            }
            entry.append("\n");
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

    // ==================== Fuzz History Data Classes (Improvement 12) ====================

    /** A single payload that was already sent, with its result. */
    private record TestedPayload(String payload, String attackType, int statusCode,
                                  long responseTimeMs, boolean wafBlocked, boolean vulnFound) {
        String toPromptLine() {
            StringBuilder sb = new StringBuilder();
            sb.append("  - ").append(truncateStatic(payload, 120));
            sb.append(" → status=").append(statusCode);
            sb.append(", time=").append(responseTimeMs).append("ms");
            if (wafBlocked) sb.append(", WAF_BLOCKED");
            if (vulnFound) sb.append(", VULN_FOUND");
            return sb.toString();
        }
    }

    /**
     * Per URL+param+vulnType history of all payloads already tested.
     * Thread-safe — all mutations go through synchronized methods.
     */
    static class FuzzHistoryEntry {
        private final String urlPath;
        private final String parameter;
        private final String vulnType;
        private final List<TestedPayload> payloads = new ArrayList<>();
        private int totalTested = 0;

        FuzzHistoryEntry(String urlPath, String parameter, String vulnType) {
            this.urlPath = urlPath;
            this.parameter = parameter;
            this.vulnType = vulnType;
        }

        synchronized void record(String payload, String attackType, int statusCode,
                                  long responseTimeMs, boolean wafBlocked, boolean vulnFound) {
            payloads.add(new TestedPayload(payload, attackType, statusCode,
                    responseTimeMs, wafBlocked, vulnFound));
            totalTested++;
        }

        synchronized int size() { return totalTested; }

        synchronized boolean hasPayload(String payload) {
            if (payload == null) return false;
            String normalized = payload.trim().toLowerCase();
            for (TestedPayload tp : payloads) {
                if (tp.payload != null && tp.payload.trim().toLowerCase().equals(normalized)) {
                    return true;
                }
            }
            return false;
        }

        /** Builds prompt text showing what was already tested — capped at MAX_PAYLOADS_IN_PROMPT. */
        synchronized String toPromptText(int maxEntries) {
            if (payloads.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(vulnType.toUpperCase()).append("] param='")
                    .append(parameter != null ? parameter : "*").append("' — ")
                    .append(totalTested).append(" payload(s) already tested");
            int wafCount = 0, vulnCount = 0;
            for (TestedPayload tp : payloads) {
                if (tp.wafBlocked) wafCount++;
                if (tp.vulnFound) vulnCount++;
            }
            if (wafCount > 0) sb.append(" (").append(wafCount).append(" WAF-blocked)");
            if (vulnCount > 0) sb.append(" (").append(vulnCount).append(" triggered vuln)");
            sb.append(":\n");

            int shown = 0;
            for (TestedPayload tp : payloads) {
                if (shown >= maxEntries) {
                    sb.append("  ... and ").append(totalTested - shown).append(" more\n");
                    break;
                }
                sb.append(tp.toPromptLine()).append("\n");
                shown++;
            }
            return sb.toString();
        }
    }

    /** Token usage from a single API call (Improvement 10). */
    private record TokenUsage(long inputTokens, long outputTokens) {}

    // ==================== Fuzz History Helpers (Improvement 12) ====================

    /** Builds a dedup key for fuzz history: normalized_path + param + vulnType */
    private String fuzzHistoryKey(String url, String parameter, String vulnType) {
        String path = normalizePath(url);
        String param = (parameter != null && !parameter.isEmpty()) ? parameter : "*";
        String vuln = (vulnType != null && !vulnType.isEmpty()) ? vulnType.toLowerCase() : "all";
        return path + "|" + param + "|" + vuln;
    }

    /** Records a tested payload in fuzz history. */
    private void recordTestedPayload(String url, FuzzPayload payload, HttpRequestResponse response,
                                      boolean wafBlocked, long responseTimeMs, boolean vulnFound) {
        if (fuzzHistory.size() >= MAX_HISTORY_ENTRIES) return; // prevent unbounded growth
        String key = fuzzHistoryKey(url, payload.parameter(), payload.attackType());
        FuzzHistoryEntry entry = fuzzHistory.computeIfAbsent(key,
                k -> new FuzzHistoryEntry(normalizePath(url), payload.parameter(), payload.attackType()));
        int statusCode = (response != null && response.response() != null) ? response.response().statusCode() : 0;
        entry.record(payload.payload(), payload.attackType(), statusCode, responseTimeMs, wafBlocked, vulnFound);
    }

    /**
     * Builds a prompt section telling the AI what payloads have already been tested
     * for this URL and (optionally) specific parameter and vuln type.
     * This prevents the AI from regenerating the same payloads.
     */
    private String buildFuzzHistoryContext(String url, String targetParameter, String targetModuleId) {
        String normalizedPath = normalizePath(url);
        List<FuzzHistoryEntry> relevantEntries = new ArrayList<>();

        for (Map.Entry<String, FuzzHistoryEntry> e : fuzzHistory.entrySet()) {
            FuzzHistoryEntry entry = e.getValue();
            // Match URL path
            if (!normalizedPath.equals(entry.urlPath)) continue;
            // If targeting a specific parameter, only show history for that param (and wildcard)
            if (targetParameter != null && entry.parameter != null
                    && !"*".equals(entry.parameter)
                    && !entry.parameter.equalsIgnoreCase(targetParameter)) continue;
            // If targeting a specific module/vuln type, only show that vuln's history
            if (targetModuleId != null) {
                String expectedVuln = getAttackType(targetModuleId);
                if (!"unknown".equals(expectedVuln) && !"all".equals(entry.vulnType)
                        && !entry.vulnType.equals(expectedVuln)) continue;
            }
            relevantEntries.add(entry);
        }

        if (relevantEntries.isEmpty()) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("ALREADY TESTED — The following payloads have ALREADY been sent to this endpoint. ")
                .append("Do NOT regenerate these. Generate DIFFERENT, NOVEL payloads that explore ")
                .append("techniques not yet tried. If all reasonable attack vectors have been exhausted, ")
                .append("return an empty payload list.\n\n");

        for (FuzzHistoryEntry entry : relevantEntries) {
            sb.append(entry.toPromptText(MAX_PAYLOADS_IN_PROMPT));
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Filters out payloads the AI regenerated despite being told not to.
     * Compares against fuzz history using normalized payload string matching.
     */
    private List<FuzzPayload> filterAlreadyTested(List<FuzzPayload> payloads, String url) {
        if (payloads.isEmpty()) return payloads;
        List<FuzzPayload> novel = new ArrayList<>();
        int dupes = 0;
        for (FuzzPayload p : payloads) {
            String key = fuzzHistoryKey(url, p.parameter(), p.attackType());
            FuzzHistoryEntry entry = fuzzHistory.get(key);
            if (entry != null && entry.hasPayload(p.payload())) {
                dupes++;
            } else {
                novel.add(p);
            }
        }
        if (dupes > 0) {
            logInfo("Fuzz History: Filtered out " + dupes + " duplicate payload(s) already tested");
        }
        return novel;
    }

    /** Clears the fuzz history. */
    public void clearFuzzHistory() { fuzzHistory.clear(); }

    /** Returns the total number of tracked fuzz history entries. */
    public int getFuzzHistorySize() { return fuzzHistory.size(); }

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

    // ── Persistence (AI backend choice) ──────────────────────────────────────
    // Only the CLI provider + binary path are persisted — never API keys, and
    // never the connection mode (AI stays Off after a restart until the user
    // re-selects a mode, so no LLM calls happen automatically).
    private volatile PersistenceManager persistence;
    private static final String K_CLI_PROVIDER = "ai.cliProvider";
    private static final String K_CLI_BINARY = "ai.cliBinary";

    public void setPersistence(PersistenceManager persistence) {
        this.persistence = persistence;
    }

    /** Saved CLI provider enum name, or null if none saved. */
    public String getPersistedCliProviderName() {
        PersistenceManager pm = persistence;
        return pm != null ? pm.getString(K_CLI_PROVIDER, null) : null;
    }

    /** Saved CLI binary path, or null if none saved. */
    public String getPersistedCliBinary() {
        PersistenceManager pm = persistence;
        return pm != null ? pm.getString(K_CLI_BINARY, null) : null;
    }

    /** Persist the user's CLI backend choice (called when CLI settings are applied). */
    public void persistCliChoice(LlmProvider provider, String binary) {
        PersistenceManager pm = persistence;
        if (pm == null || provider == null) return;
        pm.setString(K_CLI_PROVIDER, provider.name());
        if (binary != null) pm.setString(K_CLI_BINARY, binary);
    }

    /**
     * Restores the saved CLI provider + binary into the LlmClient so the choice
     * is ready when the user re-enables AI. Does NOT change the connection mode,
     * so the module stays disabled and no LLM calls fire on startup.
     */
    public void loadPersistedConfig() {
        String provName = getPersistedCliProviderName();
        String binary = getPersistedCliBinary();
        if (provName == null || binary == null || binary.isBlank()) return;
        try {
            LlmProvider provider = LlmProvider.valueOf(provName);
            llmClient.configureCli(provider, binary);
        } catch (Exception e) {
            // Unknown provider name or client error — ignore; AI just stays unconfigured.
        }
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

    /** Set max payloads per AI request. Values are clamped to a safe range. */
    public void setMaxPayloadsPerRequest(int max) {
        this.maxPayloadsPerRequest = max <= 0
                ? DEFAULT_AI_PAYLOAD_LIMIT
                : Math.min(max, MAX_AI_PAYLOAD_LIMIT);
    }
    public int getMaxPayloadsPerRequest() { return maxPayloadsPerRequest; }

    int getEffectivePayloadLimit(String targetModuleId) {
        return targetModuleId == null
                ? maxPayloadsPerRequest
                : Math.min(maxPayloadsPerRequest, MAX_TARGETED_PAYLOAD_LIMIT);
    }

    boolean hasOobCapability() {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return false;
        String address = collaboratorManager.getServerAddress();
        return address != null && !address.isBlank();
    }

    private static boolean requiresOobForTargetedScan(String targetModuleId) {
        return "cmdi-scanner".equals(targetModuleId);
    }

    private boolean containsConfiguredOobTarget(FuzzPayload payload) {
        return payload != null && payload.payload != null
                && payload.payload.contains(COLLAB_PLACEHOLDER);
    }

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

        // Run everything off the EDT — Burp blocks StepperHttp.sendRequest() on Swing thread.
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

    /**
     * Manual scan with a user-supplied custom prompt.
     * The user's prompt is prepended to the standard JSON output format instructions
     * and the HTTP exchange, then sent to the LLM for analysis.
     */
    public void manualScanCustomPrompt(HttpRequestResponse reqResp, String customPrompt) {
        cancelled = false;

        try {
            llmExecutor.submit(() -> {
                activeScansRunning.incrementAndGet();
                try {
                    doCustomPromptScan(reqResp, customPrompt);
                } finally {
                    activeScansRunning.decrementAndGet();
                }
            });
        } catch (RejectedExecutionException e) {
            logError("Custom prompt scan: Queue full, scan rejected for " + reqResp.request().url());
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
        if (fuzz && requiresOobForTargetedScan(targetModuleId) && !hasOobCapability()) {
            logError("Targeted AI Test: Command Injection requires an active OOB source. "
                    + "Enable Burp Collaborator or connect Interactsh in OOB Configuration.");
            return;
        }

        // Passive-only scan (no fuzzing) = analyzing response content (e.g., Client-Side Analyzer).
        // Always send a fresh request to get the latest JS/HTML, bypassing cache.
        // Also re-fetch for any scan where response is missing, empty, or 304.
        boolean passiveOnly = passive && !fuzz;
        boolean needsRefresh = passiveOnly || needsFreshResponse(reqResp);

        logInfo("Manual scan: target=" + (targetModuleId != null ? targetModuleId : "all")
                + " passive=" + passive + " activeTest=" + fuzz
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
                effectiveReqResp = StepperHttp.sendRequest(freshReq);
                if (effectiveReqResp.response() != null) {
                    String aiBody = effectiveReqResp.response().bodyToString();
                    logInfo("Manual scan: Got response — status " + effectiveReqResp.response().statusCode()
                            + ", body size: " + (aiBody != null ? aiBody.length() : 0) + " chars");
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
            } catch (RejectedExecutionException e) {
                logError("Targeted AI Test: Queue full, request rejected for " + finalReqResp.request().url());
            }
        }
    }

    /**
     * Executes a scan using a user-supplied custom prompt.
     * Re-fetches the response if needed, builds the prompt from the user's text
     * plus JSON format instructions and the HTTP exchange, then parses findings.
     */
    private void doCustomPromptScan(HttpRequestResponse reqResp, String customPrompt) {
        boolean needsRefresh = needsFreshResponse(reqResp);

        logInfo("Custom prompt scan: needsRefresh=" + needsRefresh + " url=" + reqResp.request().url());

        HttpRequestResponse effectiveReqResp = reqResp;
        if (needsRefresh) {
            logInfo("Custom prompt scan: Sending fresh request to " + reqResp.request().url());
            try {
                HttpRequest freshReq = reqResp.request()
                        .withRemovedHeader("If-Modified-Since")
                        .withRemovedHeader("If-None-Match")
                        .withRemovedHeader("If-Unmodified-Since")
                        .withRemovedHeader("Cache-Control")
                        .withRemovedHeader("Pragma")
                        .withAddedHeader("Cache-Control", "no-cache")
                        .withAddedHeader("Pragma", "no-cache");
                effectiveReqResp = StepperHttp.sendRequest(freshReq);
            } catch (Exception e) {
                logError("Custom prompt scan: Failed to fetch response - " + e.getMessage());
            }
        }

        final HttpRequestResponse finalReqResp = effectiveReqResp;
        CapturedHttpExchange exchange;
        try {
            exchange = CapturedHttpExchange.from(finalReqResp, maxBodySize);
        } catch (Exception e) {
            logError("Custom prompt scan: Failed to capture exchange - " + e.getMessage());
            return;
        }

        analyzeWithCustomPrompt(exchange, finalReqResp, customPrompt);
    }

    /**
     * Sends the user's custom prompt + HTTP exchange to the LLM and parses findings.
     * The custom prompt is wrapped with JSON output format instructions so findings
     * are reported as structured data (same as standard analysis).
     */
    private void analyzeWithCustomPrompt(CapturedHttpExchange exchange, HttpRequestResponse reqResp,
                                          String customPrompt) {
        if (cancelled) return;
        queuedCount.set(getQueueSize());
        try {
            StringBuilder promptBuilder = new StringBuilder();
            promptBuilder.append("You are a senior penetration tester. The user has given you the following instructions:\n\n");
            promptBuilder.append(customPrompt);
            promptBuilder.append("\n\n");
            promptBuilder.append("Analyze the HTTP exchange below according to the user's instructions.\n\n");
            promptBuilder.append("IMPORTANT: Respond ONLY with valid JSON:\n");
            promptBuilder.append("{\"findings\": [{\"title\": \"Brief title\", \"severity\": \"HIGH|MEDIUM|LOW|INFO\", ");
            promptBuilder.append("\"description\": \"What the issue is\", \"evidence\": \"Exact text from the request/response\", ");
            promptBuilder.append("\"poc\": \"Copy-paste-ready PoC\", ");
            promptBuilder.append("\"remediation\": \"How to fix\", \"cwe\": \"CWE-XXX\"}]}\n\n");
            promptBuilder.append("If no issues found, return {\"findings\": []}.\n\n");

            // Enrich with tech stack context
            String techContext = buildTechStackContext(reqResp);
            if (!techContext.isEmpty()) promptBuilder.append(techContext);

            String sessionContext = buildSessionFindingsContext();
            if (!sessionContext.isEmpty()) promptBuilder.append(sessionContext);

            promptBuilder.append("HTTP Exchange:\n");
            promptBuilder.append(exchange.toPromptText());

            String prompt = promptBuilder.toString();
            trackInputTokens(prompt);
            logInfo(">>> Sending custom prompt scan to " + llmClient.getProvider().getDisplayName()
                    + " (model: " + llmClient.getModel() + ") for " + exchange.getUrl()
                    + " | prompt size: " + prompt.length() + " chars");
            long startMs = System.currentTimeMillis();

            String rawResponse = callWithRetry(prompt);
            long elapsedMs = System.currentTimeMillis() - startMs;
            logInfo("<<< AI response received in " + elapsedMs + "ms | response size: "
                    + (rawResponse != null ? rawResponse.length() : 0) + " chars");
            LlmAnalysisResult result = llmClient.parseResponse(rawResponse);

            logInfo("Parsed " + result.getFindings().size() + " findings from custom prompt scan for " + exchange.getUrl());
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
                        .url(exchange.getUrl())
                        .evidence(ev)
                        .responseEvidence(llmFinding.getEvidence())
                        .description("[AI Custom Prompt] " + llmFinding.getDescription())
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
            logError("Custom prompt scan error - " + e.getMessage());
        }
        queuedCount.set(getQueueSize());
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
        // Note: fuzz history is NOT cleared here — it persists across dedup resets
        // so the AI still knows what was already tested. Call clearFuzzHistory() separately.
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
                    HttpRequestResponse freshResp = StepperHttp.sendRequest(freshReq);

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

                String prompt = AiPrompts.BATCH_ANALYSIS_PROMPT + buildBatchFileBlock(files, 0, files.size());
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
                        prompt = AiPrompts.BATCH_ANALYSIS_PROMPT + buildBatchFileBlock(files, batchStart, fileIdx);
                    } else {
                        prompt = String.format(AiPrompts.BATCH_CONTINUATION_PROMPT, previousSummary)
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

                    // Accumulate summary across passes so later passes retain full context
                    String passSummary = buildPassSummary(rawResponse, files, batchStart, fileIdx);
                    previousSummary = previousSummary.isEmpty() ? passSummary : previousSummary + "\n" + passSummary;
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
                String prompt = String.format(AiPrompts.EXPLOIT_PROMPT,
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
                        HttpRequestResponse response = StepperHttp.sendRequest(modified);
                        long elapsed = System.currentTimeMillis() - start;
                        ref.set(response);
                        fuzzRequestsSent.incrementAndGet();
                        trackRateLimit(url, response);

                        FuzzResult result = new FuzzResult(resolved, response, isWafBlocked(response), elapsed);
                        allResults.add(result);

                        // Report exploitation results — only if concrete evidence found
                        reportExploitResult(ep, response, url, attackType);
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

    /**
     * Reports an exploitation result with evidence-based confidence.
     * FIRM = concrete exploitation evidence found in response (file contents, DB data, command output).
     * TENTATIVE = 200 OK but no concrete evidence matched.
     * Skipped entirely if response is error/WAF/empty.
     */
    private void reportExploitResult(FuzzPayload ep, HttpRequestResponse response,
                                      String url, String attackType) {
        if (response == null || response.response() == null) return;

        String body = response.response().bodyToString();
        if (body == null || body.isEmpty()) return;
        int status = response.response().statusCode();

        // Skip error/WAF responses — nothing was exploited
        if (status >= 400) return;
        if (isWafBlocked(response)) return;

        String bodyLower = body.toLowerCase();

        // Try to find concrete exploitation evidence based on attack type
        ExploitEvidence evidence = detectExploitEvidence(ep, body, bodyLower, attackType);

        if (evidence.found) {
            // FIRM — concrete evidence of successful exploitation
            findingsStore.addFinding(Finding.builder("ai-vuln-analyzer",
                            "Exploitation Result — " + truncate(ep.description(), 60),
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .parameter(ep.parameter())
                    .payload(ep.payload())
                    .evidence("Exploitation payload: " + truncate(ep.payload(), 200)
                            + "\n\nEvidence: " + evidence.description
                            + "\n\nResponse (status " + status + "):\n"
                            + truncate(body, 1000))
                    .responseEvidence(evidence.matchedText)
                    .description("[AI Exploit] " + ep.description())
                    .requestResponse(response)
                    .build());
            findingsCount.incrementAndGet();
            logInfo("Exploit: FIRM evidence — " + evidence.description);
        }
        // No evidence matched — don't report. The AI final analysis round will
        // review all results anyway. Avoids flooding findings with noise.
    }

    /** Evidence detection result. */
    private record ExploitEvidence(boolean found, String description, String matchedText) {
        static ExploitEvidence none() { return new ExploitEvidence(false, "", ""); }
        static ExploitEvidence of(String desc, String matched) { return new ExploitEvidence(true, desc, matched); }
    }

    /**
     * Detects concrete exploitation evidence in the response body.
     * Returns the matched evidence string for response highlighting.
     */
    private ExploitEvidence detectExploitEvidence(FuzzPayload payload, String body,
                                                   String bodyLower, String attackType) {
        // === Deserialization / Path Traversal / LFI: File content indicators ===
        if ("deserialization".equals(attackType) || "path_traversal".equals(attackType)
                || attackType == null || "unknown".equals(attackType)) {
            // /etc/passwd
            if (bodyLower.contains("root:x:0:0:")) {
                int idx = bodyLower.indexOf("root:x:0:0:");
                return ExploitEvidence.of("/etc/passwd content extracted",
                        body.substring(idx, Math.min(idx + 100, body.length())));
            }
            // /etc/shadow
            if (bodyLower.contains("root:$") || bodyLower.contains("root:!")) {
                int idx = Math.max(bodyLower.indexOf("root:$"), bodyLower.indexOf("root:!"));
                return ExploitEvidence.of("/etc/shadow content extracted",
                        body.substring(idx, Math.min(idx + 80, body.length())));
            }
            // /etc/hostname or command output
            if (bodyLower.contains("/bin/bash") || bodyLower.contains("/bin/sh")
                    || bodyLower.contains("/usr/sbin/nologin")) {
                int idx = bodyLower.indexOf("/bin/");
                if (idx < 0) idx = bodyLower.indexOf("/usr/sbin/nologin");
                return ExploitEvidence.of("Unix system file content extracted",
                        body.substring(Math.max(0, idx - 30), Math.min(idx + 60, body.length())));
            }
            // Windows files
            if (bodyLower.contains("[boot loader]") || bodyLower.contains("[extensions]")) {
                String marker = bodyLower.contains("[boot loader]") ? "[boot loader]" : "[extensions]";
                int idx = bodyLower.indexOf(marker);
                return ExploitEvidence.of("Windows system file content extracted",
                        body.substring(idx, Math.min(idx + 100, body.length())));
            }
            // PHP source code leaked
            if (body.contains("<?php")) {
                int idx = body.indexOf("<?php");
                return ExploitEvidence.of("PHP source code extracted",
                        body.substring(idx, Math.min(idx + 200, body.length())));
            }
        }

        // === SQLi: Database content indicators ===
        if ("sqli".equals(attackType) || attackType == null || "unknown".equals(attackType)) {
            // Table/column data dumps
            for (String indicator : List.of("information_schema", "table_name", "column_name",
                    "mysql.user", "pg_catalog", "sqlite_master", "sys.objects",
                    "CREATE TABLE", "INSERT INTO")) {
                if (bodyLower.contains(indicator.toLowerCase())) {
                    int idx = bodyLower.indexOf(indicator.toLowerCase());
                    return ExploitEvidence.of("Database schema/data extracted (" + indicator + ")",
                            body.substring(idx, Math.min(idx + 150, body.length())));
                }
            }
            // Password hashes in response
            if (bodyLower.contains("$2y$") || bodyLower.contains("$2a$")
                    || bodyLower.contains("$6$") || bodyLower.contains("$5$")) {
                for (String hash : List.of("$2y$", "$2a$", "$6$", "$5$")) {
                    if (body.contains(hash)) {
                        int idx = body.indexOf(hash);
                        return ExploitEvidence.of("Password hash extracted",
                                body.substring(Math.max(0, idx - 20), Math.min(idx + 80, body.length())));
                    }
                }
            }
        }

        // === Command Injection / RCE: OS output ===
        if ("cmdi".equals(attackType) || "rce".equals(attackType)
                || attackType == null || "unknown".equals(attackType)) {
            for (String indicator : List.of("uid=0(root)", "uid=", "root:x:0:0:",
                    "volume serial number", "windows_nt", "linux version",
                    "total ", "drwx")) {
                if (bodyLower.contains(indicator)) {
                    int idx = bodyLower.indexOf(indicator);
                    return ExploitEvidence.of("OS command output detected (" + indicator + ")",
                            body.substring(idx, Math.min(idx + 120, body.length())));
                }
            }
        }

        // === SSTI: Template evaluation ===
        if ("ssti".equals(attackType) || attackType == null || "unknown".equals(attackType)) {
            var mathCanaries = Map.of(
                    "133*991", "131803", "7739*397", "3072383",
                    "9281*473", "4389913", "8123*547", "4443281", "3571*661", "2360431");
            for (var entry : mathCanaries.entrySet()) {
                if (payload.payload() != null && payload.payload().contains(entry.getKey())
                        && body.contains(entry.getValue())) {
                    int idx = body.indexOf(entry.getValue());
                    return ExploitEvidence.of("SSTI expression evaluated: " + entry.getKey() + "=" + entry.getValue(),
                            body.substring(Math.max(0, idx - 10), Math.min(idx + 30, body.length())));
                }
            }
            // Config/env dump
            if (bodyLower.contains("secret_key") || bodyLower.contains("database_url")
                    || bodyLower.contains("aws_access_key")) {
                for (String s : List.of("SECRET_KEY", "DATABASE_URL", "AWS_ACCESS_KEY")) {
                    if (body.contains(s)) {
                        int idx = body.indexOf(s);
                        return ExploitEvidence.of("Sensitive config leaked via SSTI (" + s + ")",
                                body.substring(idx, Math.min(idx + 100, body.length())));
                    }
                }
            }
        }

        // === SSRF: Internal resource content ===
        if ("ssrf".equals(attackType) || attackType == null || "unknown".equals(attackType)) {
            for (String indicator : List.of("ami-", "instance-id", "iam/security-credentials",
                    "computeMetadata", "169.254.169.254", "metadata/v1")) {
                if (bodyLower.contains(indicator.toLowerCase())) {
                    int idx = bodyLower.indexOf(indicator.toLowerCase());
                    return ExploitEvidence.of("Internal/cloud metadata extracted (" + indicator + ")",
                            body.substring(idx, Math.min(idx + 150, body.length())));
                }
            }
        }

        // === XXE: File content or error ===
        if ("xxe".equals(attackType) || attackType == null || "unknown".equals(attackType)) {
            if (bodyLower.contains("root:x:0:0:")) {
                int idx = bodyLower.indexOf("root:x:0:0:");
                return ExploitEvidence.of("XXE file exfiltration — /etc/passwd",
                        body.substring(idx, Math.min(idx + 100, body.length())));
            }
        }

        // === XSS: Payload reflected verbatim ===
        if ("xss".equals(attackType) && payload.payload() != null) {
            if (body.contains(payload.payload())) {
                int idx = body.indexOf(payload.payload());
                return ExploitEvidence.of("XSS payload reflected verbatim",
                        body.substring(idx, Math.min(idx + payload.payload().length() + 20, body.length())));
            }
        }

        // No concrete evidence found
        return ExploitEvidence.none();
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
    /** Computes cost on-the-fly from atomic token counters — no stored field, no race. */
    public double getEstimatedCostUsd() {
        double inputCost = (totalInputTokens.get() / 1_000_000.0) * 3.0;
        double outputCost = (totalOutputTokens.get() / 1_000_000.0) * 15.0;
        return inputCost + outputCost;
    }

    /** Returns a formatted cost summary string for display in the UI. */
    public String getCostSummary() {
        long inTok = totalInputTokens.get();
        long outTok = totalOutputTokens.get();
        int calls = totalApiCalls.get();
        if (calls == 0) return "No API calls yet";
        return String.format("%d calls | %,dK input / %,dK output tokens | est. $%.4f",
                calls, inTok / 1000, outTok / 1000, getEstimatedCostUsd());
    }

    /** Resets cost tracking counters. */
    public void resetCostTracking() {
        totalInputTokens.set(0);
        totalOutputTokens.set(0);
        totalApiCalls.set(0);
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
        llmClient.clearSensitiveConfiguration();
        analyzed.clear();
        batchQueue.clear();
        wafFingerprints.clear();
        rateLimitTrackers.clear();
        fuzzHistory.clear();
        sessionFindings.clear();
        batchScanRunning = false;
        connectionMode = AiConnectionMode.NONE;
    }
}

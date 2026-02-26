package com.omnistrike.modules.recon;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client-Side Response Analyzer
 *
 * Passive module that analyzes JavaScript/HTML response bodies for client-side
 * vulnerabilities: DOM XSS, prototype pollution, hardcoded secrets, insecure
 * postMessage, open redirects, info disclosure, dangerous eval, storage issues.
 *
 * Self-contained — does NOT share patterns with XssScanner.
 */
public class ClientSideAnalyzer implements ScanModule {

    private MontoyaApi api;

    // Dedup: only analyze each response body hash once per host+path
    private final ConcurrentHashMap<String, Boolean> analyzed = new ConcurrentHashMap<>();

    // Max response body size to analyze (500KB)
    private static final int MAX_BODY_SIZE = 512_000;

    // ==================== Content-Type Filtering ====================

    private static final Set<String> ANALYZABLE_CONTENT_TYPES = Set.of(
            "text/html", "text/javascript", "application/javascript",
            "application/x-javascript", "application/json"
    );

    // ==================== Sub-Analyzer 1: DOM XSS Source-Sink ====================

    private static final List<String> DOM_XSS_SOURCES = List.of(
            "location.href", "location.search", "location.hash", "location.pathname",
            "document.URL", "document.documentURI", "document.referrer",
            "window.name", "event.data", "postMessage",
            "URLSearchParams", "localStorage.getItem", "sessionStorage.getItem",
            "document.cookie", "location.assign", "location.replace"
    );

    private static final Map<String, Severity> DOM_XSS_SINKS = Map.ofEntries(
            // High severity: code execution and HTML injection
            Map.entry("eval(", Severity.HIGH),
            Map.entry("innerHTML", Severity.HIGH),
            Map.entry("outerHTML", Severity.HIGH),
            Map.entry("document.write(", Severity.HIGH),
            Map.entry("document.writeln(", Severity.HIGH),
            Map.entry("insertAdjacentHTML(", Severity.HIGH),
            Map.entry("Function(", Severity.HIGH),
            Map.entry("$.globalEval(", Severity.HIGH),
            Map.entry("$.parseHTML(", Severity.HIGH),
            // Framework-specific sinks
            Map.entry("dangerouslySetInnerHTML", Severity.HIGH),
            Map.entry("v-html", Severity.HIGH),
            Map.entry("bypassSecurityTrustHtml", Severity.HIGH),
            Map.entry("[innerHTML]", Severity.HIGH),
            // Medium severity: URL/jQuery sinks
            Map.entry("setTimeout(", Severity.MEDIUM),
            Map.entry("setInterval(", Severity.MEDIUM),
            Map.entry(".html(", Severity.MEDIUM),
            Map.entry(".append(", Severity.MEDIUM),
            Map.entry("window.open(", Severity.MEDIUM),
            Map.entry("location.assign(", Severity.MEDIUM),
            Map.entry("location.replace(", Severity.MEDIUM),
            Map.entry("$.html(", Severity.MEDIUM)
    );

    // ==================== Sub-Analyzer 2: Prototype Pollution ====================

    private static final List<PatternWithSeverity> PROTO_POLLUTION_PATTERNS = List.of(
            new PatternWithSeverity(Pattern.compile("__proto__"), Severity.HIGH,
                    "Direct __proto__ access — prototype pollution vector"),
            new PatternWithSeverity(Pattern.compile("constructor\\.prototype"), Severity.HIGH,
                    "constructor.prototype access — prototype pollution vector"),
            new PatternWithSeverity(Pattern.compile("constructor\\s*\\["), Severity.HIGH,
                    "constructor bracket notation — potential prototype pollution"),
            new PatternWithSeverity(Pattern.compile("Object\\.assign\\s*\\("), Severity.MEDIUM,
                    "Object.assign with potentially user-controlled input"),
            new PatternWithSeverity(Pattern.compile("\\$\\.extend\\s*\\("), Severity.MEDIUM,
                    "jQuery $.extend — may allow prototype pollution with deep=true"),
            new PatternWithSeverity(Pattern.compile("_\\.merge\\s*\\("), Severity.MEDIUM,
                    "lodash _.merge — known prototype pollution sink"),
            new PatternWithSeverity(Pattern.compile("_\\.extend\\s*\\("), Severity.MEDIUM,
                    "lodash _.extend — potential prototype pollution"),
            new PatternWithSeverity(Pattern.compile("_\\.defaultsDeep\\s*\\("), Severity.MEDIUM,
                    "lodash _.defaultsDeep — known prototype pollution sink (CVE-2019-10744)")
    );

    // ==================== Sub-Analyzer 3: Hardcoded Secrets ====================

    private static final List<SecretPattern> SECRET_PATTERNS = List.of(
            // AWS
            new SecretPattern(Pattern.compile("AKIA[A-Z0-9]{16}"), Severity.HIGH,
                    "AWS Access Key ID", "CWE-798"),
            new SecretPattern(Pattern.compile("(?i)aws_secret_access_key\\s*[=:]\\s*['\"][A-Za-z0-9/+=]{40}"), Severity.HIGH,
                    "AWS Secret Access Key", "CWE-798"),
            // Google
            new SecretPattern(Pattern.compile("AIza[0-9A-Za-z_-]{35}"), Severity.MEDIUM,
                    "Google API Key", "CWE-798"),
            // Slack
            new SecretPattern(Pattern.compile("xox[baprs]-[0-9a-zA-Z-]{10,}"), Severity.MEDIUM,
                    "Slack Token", "CWE-798"),
            // GitHub
            new SecretPattern(Pattern.compile("gh[pousr]_[A-Za-z0-9_]{36,}"), Severity.MEDIUM,
                    "GitHub Token", "CWE-798"),
            // Stripe
            new SecretPattern(Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"), Severity.HIGH,
                    "Stripe Secret Key (Live)", "CWE-798"),
            new SecretPattern(Pattern.compile("pk_live_[0-9a-zA-Z]{24,}"), Severity.MEDIUM,
                    "Stripe Publishable Key (Live)", "CWE-798"),
            // Private keys
            new SecretPattern(Pattern.compile("-----BEGIN[A-Z ]*PRIVATE KEY-----"), Severity.HIGH,
                    "Private Key exposed in response", "CWE-321"),
            // Generic API keys/secrets
            new SecretPattern(Pattern.compile("(?i)api[_-]?key\\s*[=:]\\s*['\"][A-Za-z0-9_-]{16,}['\"]"), Severity.MEDIUM,
                    "Hardcoded API Key", "CWE-798"),
            new SecretPattern(Pattern.compile("(?i)api[_-]?secret\\s*[=:]\\s*['\"][A-Za-z0-9_-]{16,}['\"]"), Severity.MEDIUM,
                    "Hardcoded API Secret", "CWE-798"),
            new SecretPattern(Pattern.compile("(?i)jwt[_-]?secret\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"), Severity.HIGH,
                    "Hardcoded JWT Secret", "CWE-798"),
            new SecretPattern(Pattern.compile("(?i)token[_-]?secret\\s*[=:]\\s*['\"][^'\"]{8,}['\"]"), Severity.MEDIUM,
                    "Hardcoded Token Secret", "CWE-798"),
            // Passwords
            new SecretPattern(Pattern.compile("(?i)password\\s*[=:]\\s*['\"][^'\"]{4,}['\"]"), Severity.LOW,
                    "Hardcoded password in JavaScript", "CWE-798"),
            // Firebase
            new SecretPattern(Pattern.compile("(?i)firebase[a-zA-Z]*\\s*[=:]\\s*['\"][A-Za-z0-9_-]{20,}['\"]"), Severity.MEDIUM,
                    "Firebase configuration value", "CWE-798"),
            // Twilio
            new SecretPattern(Pattern.compile("SK[0-9a-fA-F]{32}"), Severity.MEDIUM,
                    "Twilio API Key", "CWE-798"),
            // SendGrid
            new SecretPattern(Pattern.compile("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"), Severity.HIGH,
                    "SendGrid API Key", "CWE-798")
    );

    // ==================== Sub-Analyzer 4: Insecure postMessage ====================

    private static final Pattern POST_MESSAGE_LISTENER = Pattern.compile(
            "addEventListener\\s*\\(\\s*['\"]message['\"]\\s*,\\s*(function\\s*\\([^)]*\\)\\s*\\{[^}]{0,2000}\\}|\\([^)]*\\)\\s*=>\\s*\\{[^}]{0,2000}\\})",
            Pattern.DOTALL);

    private static final Pattern ORIGIN_CHECK = Pattern.compile(
            "\\.(origin|source)\\b|event\\.origin|e\\.origin|msg\\.origin");

    // ==================== Sub-Analyzer 5: Open Redirect ====================

    private static final List<Pattern> OPEN_REDIRECT_PATTERNS = List.of(
            Pattern.compile("location\\s*=\\s*location\\.(hash|search|href)"),
            Pattern.compile("location\\.href\\s*=\\s*(location\\.(search|hash)|document\\.URL|document\\.referrer|window\\.name)"),
            Pattern.compile("location\\.assign\\s*\\(\\s*(location\\.|document\\.(URL|referrer)|window\\.name)"),
            Pattern.compile("location\\.replace\\s*\\(\\s*(location\\.|document\\.(URL|referrer)|window\\.name)"),
            Pattern.compile("window\\.open\\s*\\(\\s*(location\\.(hash|search)|document\\.(URL|referrer)|window\\.name)"),
            Pattern.compile("(?i)window\\.location\\s*=\\s*[a-zA-Z_$][a-zA-Z0-9_$]*\\s*[;\\n]")
    );

    // ==================== Sub-Analyzer 6: Information Disclosure ====================

    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile(
            "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b");

    private static final Pattern INTERNAL_HOST_PATTERN = Pattern.compile(
            "(?i)['\"]https?://(localhost|127\\.0\\.0\\.1|[a-z0-9-]+\\.(internal|local|staging|dev|test|qa|uat))[:/'\"]");

    private static final Pattern DEBUG_ENDPOINT_PATTERN = Pattern.compile(
            "(?i)['\"]/?(?:debug|admin|actuator|swagger|graphiql|graphql|phpinfo|server-status|elmah|trace|_profiler|metrics)[/'\"]");

    private static final Pattern SOURCE_MAP_PATTERN = Pattern.compile(
            "sourceMappingURL\\s*=\\s*\\S+");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");

    // ==================== Sub-Analyzer 7: Dangerous eval/Function ====================

    // eval() with a variable (not a string literal)
    private static final Pattern EVAL_VARIABLE = Pattern.compile(
            "\\beval\\s*\\(\\s*(?!['\"`])([a-zA-Z_$][a-zA-Z0-9_$.]*)\\s*\\)");

    // setTimeout/setInterval with string first arg
    private static final Pattern TIMEOUT_STRING = Pattern.compile(
            "\\b(setTimeout|setInterval)\\s*\\(\\s*['\"]");

    // new Function() with variable
    private static final Pattern NEW_FUNCTION_VAR = Pattern.compile(
            "\\bnew\\s+Function\\s*\\(\\s*(?!['\"`])([a-zA-Z_$])");

    // ==================== Sub-Analyzer 8: Client-Side Storage ====================

    private static final Pattern LOCALSTORAGE_SENSITIVE = Pattern.compile(
            "(?i)localStorage\\.setItem\\s*\\(\\s*['\"](?:token|jwt|auth|session|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|credential)['\"]");

    private static final Pattern SESSIONSTORAGE_SENSITIVE = Pattern.compile(
            "(?i)sessionStorage\\.setItem\\s*\\(\\s*['\"](?:token|jwt|auth|session|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|credential)['\"]");

    // ==================== Sub-Analyzer 9: Path Traversal Patterns ====================

    // Exposed server file paths in responses (no ../ — too generic in JS)
    private static final Pattern SERVER_PATH_PATTERN = Pattern.compile(
            "(?:/var/www/|/var/log/|/etc/(?:passwd|shadow|hosts|nginx|apache|httpd)|/home/[a-z_][a-z0-9_-]*/|"
            + "/usr/(?:local/|share/)|/opt/[a-z]+/|/tmp/[a-z]+|"
            + "C:\\\\(?:Users|Windows|inetpub|Program Files)\\\\|"
            + "WEB-INF/|META-INF/)");

    // Dynamic import/require with variables
    private static final Pattern DYNAMIC_IMPORT = Pattern.compile(
            "(?:import\\s*\\(\\s*(?!['\"`/])([a-zA-Z_$])|require\\s*\\(\\s*(?!['\"`])([a-zA-Z_$]))");

    // File/path related parameter names in fetch/XHR
    private static final Pattern FILE_PARAM_FETCH = Pattern.compile(
            "(?i)[?&](file|path|dir|folder|doc|document|template|page|include|require|load|read|fetch|url|src|resource|download|attachment|name|filename)"
            + "\\s*=\\s*[^&\\s]{1,100}");

    // ==================== Sub-Analyzer 10: Endpoint Extractor ====================

    // Full URLs
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?<=['\"`\\s(,=])(?:https?://[a-zA-Z0-9._-]+(?::[0-9]{1,5})?(?:/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=%{}-]*)?)(?=['\"`\\s),;])");

    // Relative API paths like /api/v1/users, /graphql, /auth/login
    private static final Pattern API_PATH_PATTERN = Pattern.compile(
            "(?<=['\"`])(/(?:api|v[0-9]+|auth|oauth|login|logout|register|signup|admin|user|account|profile|"
            + "dashboard|settings|config|upload|download|export|import|search|graphql|webhook|callback|"
            + "internal|debug|test|health|status|metrics|monitor|proxy|redirect|reset|verify|confirm|token|"
            + "session|refresh|revoke|delete|update|create|read|list|get|post|put|patch|ws|socket|stream|"
            + "feed|notify|event|log|audit|report|billing|payment|checkout|cart|order|invoice|subscription)"
            + "(?:/[a-zA-Z0-9._~:@!$&'()*+,;=%{}-]*)*)(?=['\"`])");

    // ==================== ScanModule Interface ====================

    @Override
    public String getId() { return "client-side-analyzer"; }

    @Override
    public String getName() { return "Client-Side Analyzer"; }

    @Override
    public String getDescription() {
        return "Analyzes JS/HTML responses for DOM XSS, prototype pollution, hardcoded secrets, "
                + "insecure postMessage, open redirects, info disclosure, and dangerous eval usage.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        String url = requestResponse.request().url();

        // Check content type — only analyze JS/HTML/JSON responses
        if (!isAnalyzableResponse(response)) return findings;

        // Get response body, cap at MAX_BODY_SIZE
        String body = response.bodyToString();
        if (body == null || body.length() < 20) return findings;
        if (body.length() > MAX_BODY_SIZE) {
            body = body.substring(0, MAX_BODY_SIZE);
        }

        // Dedup by host+path+hash
        String dedupKey = requestResponse.request().httpService().host()
                + requestResponse.request().path()
                + "|" + body.hashCode();
        if (analyzed.putIfAbsent(dedupKey, Boolean.TRUE) != null) {
            return findings;
        }

        // Detect minified/bundled libraries — skip most analyzers to avoid FPs
        boolean isLibrary = isMinifiedLibrary(body);

        if (isLibrary) {
            // Only run high-confidence secrets (AWS keys, private keys) and endpoint extraction
            findings.addAll(analyzeHardcodedSecrets(body, url));
            findings.addAll(analyzeEndpoints(body, url));
        } else {
            // Run all 10 sub-analyzers
            findings.addAll(analyzeDomXss(body, url));
            findings.addAll(analyzePrototypePollution(body, url));
            findings.addAll(analyzeHardcodedSecrets(body, url));
            findings.addAll(analyzePostMessage(body, url));
            findings.addAll(analyzeOpenRedirects(body, url));
            findings.addAll(analyzeInfoDisclosure(body, url));
            findings.addAll(analyzeDangerousEval(body, url));
            findings.addAll(analyzeClientSideStorage(body, url));
            findings.addAll(analyzePathTraversal(body, url));
            findings.addAll(analyzeEndpoints(body, url));
        }

        if (!findings.isEmpty() && api != null) {
            api.logging().logToOutput("[ClientSideAnalyzer] Found " + findings.size()
                    + " issue(s) in: " + truncate(url, 80));
        }

        return findings;
    }

    // ==================== Content-Type Check ====================

    private boolean isAnalyzableResponse(HttpResponse response) {
        String contentType = "";
        for (var h : response.headers()) {
            if ("content-type".equalsIgnoreCase(h.name())) {
                contentType = h.value().toLowerCase();
                break;
            }
        }

        for (String type : ANALYZABLE_CONTENT_TYPES) {
            if (contentType.contains(type)) return true;
        }

        // Fallback: check if body starts with HTML or contains JS-like content
        String body = response.bodyToString();
        if (body == null || body.length() < 20) return false;
        String trimmed = body.trim();
        if (trimmed.startsWith("<") || trimmed.startsWith("<!") || trimmed.startsWith("<?")) return true;
        if (trimmed.contains("function ") || trimmed.contains("function(")
                || trimmed.contains("=>") || trimmed.contains("var ")
                || trimmed.contains("const ") || trimmed.contains("let ")) return true;

        return false;
    }

    // ==================== Sub-Analyzer 1: DOM XSS Source-Sink ====================

    private List<Finding> analyzeDomXss(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        // Find which sources and sinks are present
        List<String> foundSources = new ArrayList<>();
        for (String source : DOM_XSS_SOURCES) {
            if (body.contains(source)) {
                foundSources.add(source);
            }
        }

        if (foundSources.isEmpty()) return findings;

        Map<String, Severity> foundSinks = new LinkedHashMap<>();
        for (Map.Entry<String, Severity> entry : DOM_XSS_SINKS.entrySet()) {
            if (body.contains(entry.getKey())) {
                foundSinks.put(entry.getKey(), entry.getValue());
            }
        }

        if (foundSinks.isEmpty()) return findings;

        // Check for source→sink proximity within script blocks
        // Extract script blocks and inline JS
        List<String> scriptBlocks = extractScriptBlocks(body);
        // Also treat the full body if it's a JS file
        if (isLikelyJsFile(body)) {
            scriptBlocks.add(body);
        }

        // Sanitizer functions that neutralize XSS between source and sink
        List<String> sanitizers = List.of(
                "DOMPurify.sanitize", "escapeHtml", "encodeURIComponent",
                "textContent", "sanitize(", "encode(", "encodeURI(",
                "createTextNode", "innerText");

        Set<String> reportedPairs = new HashSet<>();
        for (String script : scriptBlocks) {
            for (String source : foundSources) {
                int sourceIdx = script.indexOf(source);
                if (sourceIdx < 0) continue;
                // Discard if source is inside a comment
                if (isInsideComment(script, sourceIdx)) continue;

                for (Map.Entry<String, Severity> sinkEntry : foundSinks.entrySet()) {
                    String sink = sinkEntry.getKey();
                    int sinkIdx = script.indexOf(sink);
                    if (sinkIdx < 0) continue;
                    // Discard if sink is inside a comment
                    if (isInsideComment(script, sinkIdx)) continue;

                    String pairKey = source + "→" + sink;
                    if (reportedPairs.contains(pairKey)) continue;

                    // Check if a sanitizer call exists between source and sink positions
                    int regionStart = Math.min(sourceIdx, sinkIdx);
                    int regionEnd = Math.max(sourceIdx + source.length(), sinkIdx + sink.length());
                    String between = script.substring(regionStart, Math.min(regionEnd, script.length()));
                    boolean hasSanitizer = false;
                    for (String san : sanitizers) {
                        if (between.contains(san)) { hasSanitizer = true; break; }
                    }
                    if (hasSanitizer) continue; // Sanitizer present — discard

                    reportedPairs.add(pairKey);

                    // Extract evidence: surrounding context
                    String sourceEvidence = extractContext(script, source, 60);
                    String sinkEvidence = extractContext(script, sink, 60);

                    findings.add(Finding.builder("client-side-analyzer",
                                    "DOM XSS: " + source + " → " + sink,
                                    sinkEntry.getValue(), Confidence.TENTATIVE)
                            .url(url)
                            .evidence("Source: " + sourceEvidence + "\nSink: " + sinkEvidence)
                            .responseEvidence(sink)
                            .description("Potential DOM XSS: user-controllable source '" + source
                                    + "' found in same script block as dangerous sink '" + sink
                                    + "'. If user input flows from the source to the sink without "
                                    + "sanitization, this is a DOM-based XSS vulnerability.")
                            .remediation("Sanitize all user-controllable input before passing to DOM sinks. "
                                    + "Use textContent instead of innerHTML. Implement Content Security Policy. "
                                    + "Use DOMPurify for HTML sanitization.")
                            .build());
                }
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 2: Prototype Pollution ====================

    private List<Finding> analyzePrototypePollution(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        for (PatternWithSeverity pws : PROTO_POLLUTION_PATTERNS) {
            Matcher m = pws.pattern.matcher(body);
            if (m.find()) {
                int matchStart = m.start();

                // Discard if inside a comment
                if (isInsideComment(body, matchStart)) continue;

                // Check if this is a defensive check (guarding against proto pollution, not vulnerable)
                int contextStart = Math.max(0, matchStart - 50);
                int contextEnd = Math.min(body.length(), matchStart + m.group().length() + 50);
                String surroundingContext = body.substring(contextStart, contextEnd);
                if (surroundingContext.contains("===") || surroundingContext.contains("!==")
                        || surroundingContext.contains("indexOf") || surroundingContext.contains("hasOwnProperty")
                        || surroundingContext.contains("Object.keys") || surroundingContext.contains("propertyIsEnumerable")) {
                    continue; // Defensive check — not a vulnerability
                }

                String matchedText = m.group();
                String evidence = extractContext(body, matchStart, 80);
                findings.add(Finding.builder("client-side-analyzer",
                                "Prototype Pollution: " + pws.description,
                                pws.severity, Confidence.TENTATIVE)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(matchedText)
                        .description("Potential prototype pollution vector detected. " + pws.description
                                + ". An attacker may be able to modify Object.prototype and affect "
                                + "application behavior, potentially leading to XSS or privilege escalation.")
                        .remediation("Use Object.create(null) for dictionaries. Validate and sanitize "
                                + "user-controlled keys. Use Map instead of plain objects. "
                                + "Freeze Object.prototype in critical code paths.")
                        .build());
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 3: Hardcoded Secrets ====================

    // Generic secret pattern names that require entropy validation
    private static final Set<String> GENERIC_SECRET_NAMES = Set.of(
            "Hardcoded API Key", "Hardcoded API Secret", "Hardcoded JWT Secret",
            "Hardcoded Token Secret", "Hardcoded password in JavaScript",
            "Firebase configuration value"
    );

    private List<Finding> analyzeHardcodedSecrets(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        for (SecretPattern sp : SECRET_PATTERNS) {
            Matcher m = sp.pattern.matcher(body);
            while (m.find()) {
                String matched = m.group();
                int matchStart = m.start();

                // Discard if inside a comment
                if (isInsideComment(body, matchStart)) { continue; }

                // Discard if value is a placeholder/dummy
                if (isDummyOrPlaceholder(matched)) { continue; }

                // For generic patterns, require sufficient entropy
                if (GENERIC_SECRET_NAMES.contains(sp.name) && hasLowEntropy(matched)) { continue; }

                // Determine severity — downgrade certain public-facing keys
                Severity effectiveSeverity = sp.severity;
                Confidence effectiveConfidence = Confidence.FIRM;
                if (sp.name.contains("Stripe Publishable Key")) {
                    effectiveSeverity = Severity.INFO; // Publishable keys are meant to be public
                } else if (sp.name.contains("Google API Key")) {
                    effectiveSeverity = Severity.LOW;  // Often intentionally client-side
                }

                // Redact part of the secret for safety
                String redacted = redactSecret(matched);
                String evidence = extractContext(body, matchStart, 100);

                findings.add(Finding.builder("client-side-analyzer",
                                sp.name + " found in response",
                                effectiveSeverity, effectiveConfidence)
                        .url(url)
                        .evidence("Matched: " + redacted + "\nContext: " + evidence)
                        .responseEvidence(matched)
                        .description("A " + sp.name + " was found exposed in the response body. "
                                + "Hardcoded secrets in client-side code are accessible to anyone "
                                + "who views the page source. (" + sp.cwe + ")")
                        .remediation("Remove secrets from client-side code. Use server-side environment "
                                + "variables. Rotate the exposed credential immediately. "
                                + "Implement API gateways or backend proxies for sensitive operations.")
                        .build());
                break; // One finding per pattern per response
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 4: Insecure postMessage ====================

    private List<Finding> analyzePostMessage(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        Matcher m = POST_MESSAGE_LISTENER.matcher(body);
        while (m.find()) {
            String handlerBody = m.group();

            // Check if the handler validates origin
            boolean hasOriginCheck = ORIGIN_CHECK.matcher(handlerBody).find();

            if (!hasOriginCheck) {
                // Check if handler body contains a dangerous sink
                boolean hasSink = false;
                String sinkFound = "";
                for (String sink : List.of("eval(", "innerHTML", "document.write(",
                        "Function(", ".html(", "location")) {
                    if (handlerBody.contains(sink)) {
                        hasSink = true;
                        sinkFound = sink;
                        break;
                    }
                }

                Severity severity = hasSink ? Severity.HIGH : Severity.MEDIUM;
                String desc = hasSink
                        ? "postMessage handler has no origin validation AND data flows to dangerous sink '"
                        + sinkFound + "'. Any origin can send messages to trigger this code."
                        : "postMessage handler has no origin validation. Any origin can send messages "
                        + "to this handler, though no immediate dangerous sink was detected.";

                findings.add(Finding.builder("client-side-analyzer",
                                "Insecure postMessage handler" + (hasSink ? " → " + sinkFound : " (no origin check)"),
                                severity, Confidence.TENTATIVE)
                        .url(url)
                        .evidence(truncate(handlerBody, 300))
                        .responseEvidence(handlerBody)
                        .description(desc)
                        .remediation("Always validate event.origin against expected origins before "
                                + "processing message data. Example: if (event.origin !== 'https://trusted.com') return;")
                        .build());
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 5: Open Redirects ====================

    private List<Finding> analyzeOpenRedirects(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        for (Pattern pattern : OPEN_REDIRECT_PATTERNS) {
            Matcher m = pattern.matcher(body);
            if (m.find()) {
                int matchStart = m.start();

                // Discard if inside a comment
                if (isInsideComment(body, matchStart)) continue;

                // Check if there's URL validation before the redirect (within 200 chars before)
                int lookbackStart = Math.max(0, matchStart - 200);
                String before = body.substring(lookbackStart, matchStart);
                if (before.contains("indexOf") || before.contains("startsWith")
                        || before.contains(".match(") || before.contains(".test(")
                        || before.contains(".includes(") || before.contains("whitelist")
                        || before.contains("allowedUrl") || before.contains("safeUrl")) {
                    continue; // URL validation present — discard
                }

                String matchedRedirect = m.group();
                String evidence = extractContext(body, matchStart, 80);

                findings.add(Finding.builder("client-side-analyzer",
                                "Client-Side Open Redirect: " + truncate(matchedRedirect, 60),
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(matchedRedirect)
                        .description("JavaScript code redirects to a URL derived from user-controllable "
                                + "input (location.hash, location.search, etc.). An attacker could craft "
                                + "a URL that redirects victims to a malicious site for phishing.")
                        .remediation("Validate redirect targets against a whitelist of allowed URLs. "
                                + "Use relative URLs instead of absolute. Never use user input directly "
                                + "as a redirect target.")
                        .build());
                break; // One redirect finding per response is enough
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 6: Information Disclosure ====================

    private List<Finding> analyzeInfoDisclosure(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        // Extract target domain from URL for email filtering
        String targetDomain = "";
        try {
            String host = url.contains("://") ? url.split("://")[1].split("[:/]")[0] : url.split("[:/]")[0];
            int dot = host.indexOf('.');
            targetDomain = dot >= 0 ? host.substring(dot + 1) : host;
        } catch (Exception ignored) {}

        // Internal IPs
        Matcher ipMatcher = INTERNAL_IP_PATTERN.matcher(body);
        Set<String> seenIps = new HashSet<>();
        while (ipMatcher.find()) {
            String ip = ipMatcher.group();
            int matchStart = ipMatcher.start();

            // Discard if inside a comment
            if (isInsideComment(body, matchStart)) continue;

            // Skip IPs that look like version strings (preceded by 'v' or 'version' immediately before IP)
            int lookback = Math.max(0, matchStart - 15);
            String before = body.substring(lookback, matchStart).toLowerCase();
            if (before.matches(".*\\bv(ersion)?\\s*[.:=]?\\s*$")) continue;

            // Skip IPs inside src= or href= pointing to CDN resources
            int attrLookback = Math.max(0, matchStart - 30);
            String attrBefore = body.substring(attrLookback, matchStart).toLowerCase();
            if (attrBefore.contains("src=") || attrBefore.contains("href=")) continue;

            // Skip common version-like patterns: 10.0.0.0 and 10.0.0.1 (often used as examples/defaults)
            if (ip.equals("10.0.0.0") || ip.equals("10.0.0.1")) continue;

            if (seenIps.add(ip)) {
                String evidence = extractContext(body, matchStart, 60);
                findings.add(Finding.builder("client-side-analyzer",
                                "Internal IP address disclosed: " + ip,
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(ip)
                        .description("An internal/private IP address (" + ip + ") was found in the "
                                + "response. This reveals internal network structure.")
                        .remediation("Remove internal IP addresses from client-side code and responses.")
                        .build());
            }
            if (seenIps.size() >= 5) break; // Cap to avoid noise
        }

        // Internal hosts
        Matcher hostMatcher = INTERNAL_HOST_PATTERN.matcher(body);
        if (hostMatcher.find()) {
            int matchStart = hostMatcher.start();
            // Discard if inside a comment
            if (!isInsideComment(body, matchStart)) {
                String hostMatch = hostMatcher.group();
                String evidence = extractContext(body, matchStart, 80);
                findings.add(Finding.builder("client-side-analyzer",
                                "Internal/staging host URL disclosed",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(hostMatch)
                        .description("A reference to an internal, staging, or development host was found. "
                                + "This may expose internal infrastructure or non-production environments.")
                        .remediation("Remove internal host references from production code.")
                        .build());
            }
        }

        // Debug endpoints — REMOVED: too FP-heavy. Strings like /admin, /graphql, /swagger
        // in JS are extremely common and almost never actionable. The endpoint extractor
        // already captures these.

        // Source maps
        Matcher sourceMapMatcher = SOURCE_MAP_PATTERN.matcher(body);
        if (sourceMapMatcher.find()) {
            String sourceMapMatch = sourceMapMatcher.group();
            findings.add(Finding.builder("client-side-analyzer",
                            "Source map reference found",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(sourceMapMatch)
                    .responseEvidence(sourceMapMatch)
                    .description("A sourceMappingURL was found, which can expose original source code "
                            + "including comments, variable names, and application logic.")
                    .remediation("Remove source map references from production builds. "
                            + "Configure build tools to exclude sourceMappingURL in production.")
                    .build());
        }

        // Email addresses (only in JS-like content, skip HTML body text)
        if (isLikelyJsFile(body)) {
            Matcher emailMatcher = EMAIL_PATTERN.matcher(body);
            Set<String> seenEmails = new HashSet<>();
            while (emailMatcher.find() && seenEmails.size() < 3) {
                String email = emailMatcher.group();
                // Skip common false positives and noise domains
                if (email.contains("example.com") || email.contains("test.com")
                        || email.endsWith(".png") || email.endsWith(".js")
                        || email.contains("@localhost") || email.contains("@0.0.0.0")
                        || email.contains("@sentry.io") || email.contains("@w3.org")
                        || (!targetDomain.isEmpty() && email.contains("@" + targetDomain))) continue;
                if (seenEmails.add(email)) {
                    findings.add(Finding.builder("client-side-analyzer",
                                    "Email address disclosed in JS: " + email,
                                    Severity.LOW, Confidence.FIRM)
                            .url(url)
                            .evidence(email)
                            .responseEvidence(email)
                            .description("An email address was found in JavaScript code. "
                                    + "This could be used for social engineering or targeted phishing.")
                            .remediation("Remove hardcoded email addresses from client-side code.")
                            .build());
                }
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 7: Dangerous eval/Function ====================

    private List<Finding> analyzeDangerousEval(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        // eval(variable)
        Matcher evalMatcher = EVAL_VARIABLE.matcher(body);
        if (evalMatcher.find()) {
            int matchStart = evalMatcher.start();
            // Discard if inside a comment
            if (!isInsideComment(body, matchStart)) {
                String evalMatch = evalMatcher.group();
                String evidence = extractContext(body, matchStart, 80);
                findings.add(Finding.builder("client-side-analyzer",
                                "Dangerous eval() with variable: eval(" + evalMatcher.group(1) + ")",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(evalMatch)
                        .description("eval() is called with a variable argument rather than a string literal. "
                                + "If the variable can be influenced by user input, this leads to arbitrary "
                                + "JavaScript execution.")
                        .remediation("Avoid eval() entirely. Use JSON.parse() for JSON data. "
                                + "Use safer alternatives like Function constructors with proper validation.")
                        .build());
            }
        }

        // setTimeout/setInterval with string — REMOVED: extremely FP-heavy.
        // The actual exploit scenario (user controls the string passed to setTimeout) is
        // vanishingly rare in passive analysis. Common safe pattern: setTimeout('myFunc()', 1000).

        // new Function(variable)
        Matcher funcMatcher = NEW_FUNCTION_VAR.matcher(body);
        if (funcMatcher.find()) {
            int matchStart = funcMatcher.start();
            // Discard if inside a comment
            if (!isInsideComment(body, matchStart)) {
                String funcMatch = funcMatcher.group();
                String evidence = extractContext(body, matchStart, 80);
                findings.add(Finding.builder("client-side-analyzer",
                                "Dangerous new Function() with variable argument",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(funcMatch)
                        .description("new Function() is called with a variable argument. Like eval(), "
                                + "this compiles and executes arbitrary code if the argument is user-controllable.")
                        .remediation("Avoid new Function() with dynamic input. Use safer alternatives.")
                        .build());
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 8: Client-Side Storage ====================

    private List<Finding> analyzeClientSideStorage(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        Matcher localMatcher = LOCALSTORAGE_SENSITIVE.matcher(body);
        if (localMatcher.find()) {
            // Discard if inside a comment
            if (!isInsideComment(body, localMatcher.start())) {
                String localMatch = localMatcher.group();
                String evidence = extractContext(body, localMatcher.start(), 100);
                findings.add(Finding.builder("client-side-analyzer",
                                "Sensitive data stored in localStorage",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(localMatch)
                        .description("Sensitive data (tokens, passwords, keys) is being stored in localStorage. "
                                + "localStorage is accessible via JavaScript and persists across sessions, "
                                + "making it vulnerable to XSS-based token theft.")
                        .remediation("Use HttpOnly cookies for session tokens instead of localStorage. "
                                + "If client-side storage is necessary, use sessionStorage for short-lived data "
                                + "and encrypt sensitive values.")
                        .build());
            }
        }

        Matcher sessionMatcher = SESSIONSTORAGE_SENSITIVE.matcher(body);
        if (sessionMatcher.find()) {
            // Discard if inside a comment
            if (!isInsideComment(body, sessionMatcher.start())) {
                String sessionMatch = sessionMatcher.group();
                String evidence = extractContext(body, sessionMatcher.start(), 100);
                findings.add(Finding.builder("client-side-analyzer",
                                "Sensitive data stored in sessionStorage",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(sessionMatch)
                        .description("Sensitive data is being stored in sessionStorage. While sessionStorage "
                                + "does not persist across tabs/sessions, it is still accessible via JavaScript "
                                + "and vulnerable to XSS attacks.")
                        .remediation("Prefer HttpOnly cookies for sensitive tokens. "
                                + "Minimize the sensitivity of data stored in sessionStorage.")
                        .build());
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 9: Path Traversal ====================

    private List<Finding> analyzePathTraversal(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        // Exposed server file paths
        Matcher serverPathMatcher = SERVER_PATH_PATTERN.matcher(body);
        Set<String> seenPaths = new HashSet<>();
        while (serverPathMatcher.find() && seenPaths.size() < 5) {
            String path = serverPathMatcher.group();
            int matchStart = serverPathMatcher.start();

            // Discard if inside a comment
            if (isInsideComment(body, matchStart)) continue;

            // Discard if inside <code>, <pre>, <tt> tags or documentation-like context
            int tagLookback = Math.max(0, matchStart - 100);
            String tagBefore = body.substring(tagLookback, matchStart).toLowerCase();
            if (tagBefore.contains("<code") || tagBefore.contains("<pre")
                    || tagBefore.contains("<tt") || tagBefore.contains("class=\"doc")
                    || tagBefore.contains("class=\"help")) continue;

            if (seenPaths.add(path)) {
                String evidence = extractContext(body, matchStart, 80);
                findings.add(Finding.builder("client-side-analyzer",
                                "Server file path exposed: " + truncate(path, 50),
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(path)
                        .description("A server-side file path was found in the response body. "
                                + "This reveals internal directory structure and may help an attacker "
                                + "craft path traversal payloads.")
                        .remediation("Remove server file paths from client-side responses. "
                                + "Use generic error messages that don't expose file system details.")
                        .build());
            }
        }

        // PATH_FROM_USER_INPUT — REMOVED: pattern is too broad (matches any fetch/url near any
        // location/params). Almost 100% FP rate.

        // Dynamic import/require with variables — lowered to INFO/TENTATIVE
        Matcher dynImportMatcher = DYNAMIC_IMPORT.matcher(body);
        if (dynImportMatcher.find()) {
            String dynImportMatch = dynImportMatcher.group();
            String evidence = extractContext(body, dynImportMatcher.start(), 80);
            findings.add(Finding.builder("client-side-analyzer",
                            "Dynamic import()/require() with variable argument",
                            Severity.INFO, Confidence.TENTATIVE)
                    .url(url)
                    .evidence(evidence)
                    .responseEvidence(dynImportMatch)
                    .description("Dynamic import() or require() is called with a variable argument. "
                            + "If the variable is user-controllable, an attacker may be able to load "
                            + "arbitrary modules or files.")
                    .remediation("Avoid dynamic imports with user input. Use a whitelist of allowed modules.")
                    .build());
        }

        // File-related parameters in URLs (suggest traversal testing)
        Matcher fileParamMatcher = FILE_PARAM_FETCH.matcher(body);
        Set<String> seenParams = new HashSet<>();
        while (fileParamMatcher.find() && seenParams.size() < 3) {
            String paramName = fileParamMatcher.group(1);
            if (seenParams.add(paramName.toLowerCase())) {
                String fileParamMatch = fileParamMatcher.group();
                String evidence = extractContext(body, fileParamMatcher.start(), 100);
                findings.add(Finding.builder("client-side-analyzer",
                                "File/path parameter found: " + paramName,
                                Severity.INFO, Confidence.FIRM)
                        .url(url)
                        .evidence(evidence)
                        .responseEvidence(fileParamMatch)
                        .description("A URL parameter named '" + paramName + "' suggests the server "
                                + "handles file paths. This parameter is a strong candidate for path "
                                + "traversal testing (e.g., ../../etc/passwd, ..\\..\\windows\\win.ini).")
                        .remediation("Ensure server-side validation rejects path traversal sequences. "
                                + "Use a whitelist approach for file access. Never use raw user input in file operations.")
                        .build());
            }
        }

        return findings;
    }

    // ==================== Sub-Analyzer 10: Endpoint Extractor ====================

    private List<Finding> analyzeEndpoints(String body, String url) {
        List<Finding> findings = new ArrayList<>();

        // Collect all URLs and API paths
        Set<String> foundEndpoints = new LinkedHashSet<>();

        // Full URLs
        Matcher urlMatcher = URL_PATTERN.matcher(body);
        while (urlMatcher.find() && foundEndpoints.size() < 50) {
            String endpoint = urlMatcher.group().trim();
            // Skip common noise: same-page anchors, data URIs, very short
            if (endpoint.length() < 10) continue;
            if (endpoint.contains("w3.org") || endpoint.contains("schema.org")
                    || endpoint.contains("xmlns") || endpoint.contains("example.com")) continue;
            foundEndpoints.add(endpoint);
        }

        // Relative API paths
        Matcher apiMatcher = API_PATH_PATTERN.matcher(body);
        while (apiMatcher.find() && foundEndpoints.size() < 50) {
            String path = apiMatcher.group().trim();
            if (path.length() < 4) continue;
            foundEndpoints.add(path);
        }

        if (foundEndpoints.isEmpty()) return findings;

        // Build a table of all discovered endpoints
        StringBuilder table = new StringBuilder();
        table.append("Endpoints discovered in response body:\n\n");
        int idx = 1;
        for (String endpoint : foundEndpoints) {
            table.append(String.format("  %2d. %s\n", idx++, endpoint));
        }

        findings.add(Finding.builder("client-side-analyzer",
                        "Discovered " + foundEndpoints.size() + " endpoint(s) in JS/HTML",
                        Severity.INFO, Confidence.CERTAIN)
                .url(url)
                .evidence(table.toString())
                .description("The following URLs and API paths were extracted from the response body. "
                        + "These may include hidden or undocumented endpoints worth testing for "
                        + "authentication bypass, IDOR, or other vulnerabilities.")
                .remediation("Review all exposed endpoints. Remove references to internal or "
                        + "debug endpoints from production code. Ensure all endpoints enforce "
                        + "proper authentication and authorization.")
                .build());

        return findings;
    }

    // ==================== Disqualification Helpers ====================

    /**
     * Returns true if matchStart falls inside an HTML comment, JS block comment, or JS line comment.
     */
    private boolean isInsideComment(String body, int matchStart) {
        // Check HTML comments: <!-- ... -->
        int htmlOpen = body.lastIndexOf("<!--", matchStart);
        if (htmlOpen >= 0) {
            int htmlClose = body.indexOf("-->", htmlOpen + 4);
            if (htmlClose < 0 || htmlClose > matchStart) return true;
        }
        // Check JS block comments: /* ... */
        int blockOpen = body.lastIndexOf("/*", matchStart);
        if (blockOpen >= 0) {
            int blockClose = body.indexOf("*/", blockOpen + 2);
            if (blockClose < 0 || blockClose > matchStart) return true;
        }
        // Check JS line comments: // ... \n
        int lineStart = body.lastIndexOf("//", matchStart);
        if (lineStart >= 0) {
            // Make sure the // is not inside a string (rough: no quote between // and matchStart)
            int newline = body.indexOf('\n', lineStart);
            if (newline < 0 || newline > matchStart) {
                // Verify no quote char between lineStart and the // that would indicate a URL like http://
                if (lineStart >= 1 && body.charAt(lineStart - 1) == ':') {
                    // Likely a URL scheme (http://), not a comment
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns true if the response looks like a bundled/minified library.
     */
    private boolean isMinifiedLibrary(String body) {
        // Check average line length (minified code has very long lines)
        String[] lines = body.split("\n", 20); // Sample first 20 lines
        if (lines.length > 0) {
            long totalLen = 0;
            for (String line : lines) totalLen += line.length();
            if (totalLen / lines.length > 500) return true;
        }
        // Check known library signatures
        String[] librarySignatures = {
            "jQuery v", "Lodash", "angular.module", "React.createElement",
            "Vue.config", "/*! Bootstrap", "/*! normalize.css", "Underscore.js",
            "Backbone.js", "Ember.", "Handlebars.", "Mustache.", "moment.js",
            "/*!", "* jQuery", "* Bootstrap", "* Vue.js", "* React"
        };
        for (String sig : librarySignatures) {
            if (body.contains(sig)) return true;
        }
        return false;
    }

    /**
     * Returns true if the matched value is a placeholder/dummy (not a real secret).
     */
    private boolean isDummyOrPlaceholder(String value) {
        if (value == null || value.isEmpty()) return true;
        String lower = value.toLowerCase();

        // Contains placeholder keywords
        String[] placeholderKeywords = {
            "test", "example", "todo", "placeholder", "changeme", "xxx", "fake",
            "sample", "default", "dummy", "temp", "mock", "demo", "replace_me",
            "your_", "change", "insert", "enter", "replace", "<your", "{your",
            "aaaa", "0000", "1234", "abcd", "xxxx", "none", "null", "undefined",
            "fixme", "put_", "add_", "set_", "fill"
        };
        for (String kw : placeholderKeywords) {
            if (lower.contains(kw)) return true;
        }

        // All same characters
        if (value.length() > 3) {
            char first = value.charAt(0);
            boolean allSame = true;
            for (int i = 1; i < value.length(); i++) {
                if (value.charAt(i) != first) { allSame = false; break; }
            }
            if (allSame) return true;
        }

        // Sequential patterns
        if (lower.contains("1234567890") || lower.contains("abcdefg")
                || lower.contains("0123456789")) return true;

        return false;
    }

    /**
     * Returns true if the secret value has low entropy (likely not a real key).
     * Requires at least 16 chars, not all lowercase, not all digits.
     */
    private boolean hasLowEntropy(String value) {
        if (value == null) return true;
        // Extract just the value part (after = or : and quotes)
        String cleaned = value.replaceAll("(?i)^.*?[=:]\\s*['\"]?", "").replaceAll("['\"]$", "");
        if (cleaned.length() < 16) return true;
        if (cleaned.matches("[a-z]+")) return true;   // all lowercase alpha
        if (cleaned.matches("[0-9]+")) return true;    // all digits
        if (cleaned.matches("[A-Z]+")) return true;    // all uppercase alpha

        // Check Shannon entropy
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : cleaned.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / cleaned.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy < 2.5; // Very low entropy threshold
    }

    // ==================== Helper Methods ====================

    private List<String> extractScriptBlocks(String html) {
        List<String> blocks = new ArrayList<>();
        Pattern scriptTag = Pattern.compile("<script[^>]*>(.*?)</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        Matcher m = scriptTag.matcher(html);
        while (m.find()) {
            String content = m.group(1).trim();
            if (!content.isEmpty() && content.length() > 10) {
                blocks.add(content);
            }
        }
        // Also extract inline event handlers (onclick, onerror, etc.)
        Pattern eventHandler = Pattern.compile("\\bon\\w+\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher em = eventHandler.matcher(html);
        while (em.find()) {
            blocks.add(em.group(1));
        }
        return blocks;
    }

    private boolean isLikelyJsFile(String body) {
        if (body == null || body.length() < 20) return false;
        String trimmed = body.trim();
        // Doesn't start with HTML
        if (trimmed.startsWith("<")) return false;
        // Contains JS-like constructs
        return trimmed.contains("function ") || trimmed.contains("function(")
                || trimmed.contains("var ") || trimmed.contains("const ")
                || trimmed.contains("let ") || trimmed.contains("=>");
    }

    private String extractContext(String body, String needle, int contextSize) {
        int idx = body.indexOf(needle);
        if (idx < 0) return needle;
        return extractContext(body, idx, contextSize);
    }

    private String extractContext(String body, int matchStart, int contextSize) {
        int start = Math.max(0, matchStart - contextSize / 2);
        int end = Math.min(body.length(), matchStart + contextSize);
        String context = body.substring(start, end).replaceAll("\\s+", " ").trim();
        if (start > 0) context = "..." + context;
        if (end < body.length()) context = context + "...";
        return context;
    }

    private String redactSecret(String secret) {
        if (secret.length() <= 8) return secret.substring(0, 2) + "***";
        int showChars = Math.min(8, secret.length() / 3);
        return secret.substring(0, showChars) + "..." + secret.substring(secret.length() - 4);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    @Override
    public void destroy() {
        analyzed.clear();
    }

    public void clearAll() {
        analyzed.clear();
    }

    // ==================== Inner Record Types ====================

    private record PatternWithSeverity(Pattern pattern, Severity severity, String description) {}

    private record SecretPattern(Pattern pattern, Severity severity, String name, String cwe) {}
}

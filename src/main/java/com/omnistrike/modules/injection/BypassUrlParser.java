package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;
import com.omnistrike.ui.modules.BypassUrlParserPanel;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bypass URL Parser — comprehensive 403/401 bypass scanner.
 *
 * Given a target URL, generates hundreds of mutated HTTP requests using 13 bypass
 * strategies, sends them all via Burp's HTTP client, and reports which ones returned
 * a different (ideally 200) status code. Results are saved to a JSON file in /tmp.
 *
 * Inspired by laluka/bypass-url-parser.
 *
 * Bypass modes implemented:
 *   1. mid_paths         — insert path tricks between segments
 *   2. end_paths         — append suffixes to the path
 *   3. case_substitution — uppercase/lowercase variations of path segments
 *   4. char_encode       — URL-encode characters (single, double, triple, unicode overlong)
 *   5. http_methods      — try alternate HTTP verbs
 *   6. http_versions     — try HTTP/1.0, HTTP/1.1
 *   7. http_headers_method  — method override headers (X-HTTP-Method-Override, etc.)
 *   8. http_headers_scheme  — scheme spoofing (X-Forwarded-Proto, etc.)
 *   9. http_headers_ip      — IP spoofing (X-Forwarded-For, X-Real-IP, etc.)
 *  10. http_headers_port    — port spoofing (X-Forwarded-Port)
 *  11. http_headers_url     — URL rewrite headers (X-Original-URL, X-Rewrite-URL)
 *  12. user_agent           — rotate User-Agent strings
 *  13. combined_headers     — combined IP + method override + scheme in single request
 */
public class BypassUrlParser implements ScanModule {

    // ═══════════════════════════════════════════════════════════════
    //  MODULE IDENTITY
    // ═══════════════════════════════════════════════════════════════

    @Override public String getId() { return "bypass-url-parser"; }
    @Override public String getName() { return "Bypass URL Parser"; }

    @Override
    public String getDescription() {
        return "Comprehensive 403/401 bypass scanner — generates hundreds of mutated requests "
                + "using path manipulation, header spoofing, method override, encoding tricks, "
                + "and more. Inspired by laluka/bypass-url-parser.";
    }

    @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
    @Override public boolean isPassive() { return false; }

    // ═══════════════════════════════════════════════════════════════
    //  STATE & DEPENDENCIES
    // ═══════════════════════════════════════════════════════════════

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    private volatile BypassUrlParserPanel panel;

    private volatile boolean running;
    private volatile ExecutorService scanExecutor;
    private final AtomicInteger completedCount = new AtomicInteger(0);
    private final AtomicInteger totalCount = new AtomicInteger(0);
    private final AtomicInteger bypassCount = new AtomicInteger(0);

    // Results collected during a scan (thread-safe for concurrent writer threads)
    private final CopyOnWriteArrayList<BypassResult> results = new CopyOnWriteArrayList<>();

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    public void setPanel(BypassUrlParserPanel panel) {
        this.panel = panel;
    }

    /** Called from context menu — populates the panel with the URL and switches to it. */
    public void populatePanel(String url) {
        BypassUrlParserPanel p = panel;
        if (p != null) {
            javax.swing.SwingUtilities.invokeLater(() -> p.setTargetUrl(url));
        }
    }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public void destroy() {
        stopScan();
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        // Manual trigger only — not auto-scanned from traffic flow
        return Collections.emptyList();
    }

    // ═══════════════════════════════════════════════════════════════
    //  BYPASS MODE NAMES
    // ═══════════════════════════════════════════════════════════════

    public static final String MODE_MID_PATHS          = "mid_paths";
    public static final String MODE_END_PATHS          = "end_paths";
    public static final String MODE_CASE_SUBSTITUTION  = "case_substitution";
    public static final String MODE_CHAR_ENCODE        = "char_encode";
    public static final String MODE_HTTP_METHODS       = "http_methods";
    public static final String MODE_HTTP_VERSIONS      = "http_versions";
    public static final String MODE_HEADERS_METHOD     = "http_headers_method";
    public static final String MODE_HEADERS_SCHEME     = "http_headers_scheme";
    public static final String MODE_HEADERS_IP         = "http_headers_ip";
    public static final String MODE_HEADERS_PORT       = "http_headers_port";
    public static final String MODE_HEADERS_URL        = "http_headers_url";
    public static final String MODE_USER_AGENT         = "user_agent";
    public static final String MODE_COMBINED_HEADERS   = "combined_headers";

    public static final List<String> ALL_MODES = List.of(
            MODE_MID_PATHS, MODE_END_PATHS, MODE_CASE_SUBSTITUTION, MODE_CHAR_ENCODE,
            MODE_HTTP_METHODS, MODE_HTTP_VERSIONS, MODE_HEADERS_METHOD, MODE_HEADERS_SCHEME,
            MODE_HEADERS_IP, MODE_HEADERS_PORT, MODE_HEADERS_URL, MODE_USER_AGENT,
            MODE_COMBINED_HEADERS
    );

    // ═══════════════════════════════════════════════════════════════
    //  PAYLOAD CONSTANTS
    // ═══════════════════════════════════════════════════════════════

    /** Path tricks to insert between URL segments */
    private static final String[] MID_PATH_PAYLOADS = {
            "/./", "//", "/../", "/..;/", "/.;/", "/..;/..;/",
            "/%2f/", "/%2e/", "/%2e%2e/", "/%2e%2e;/",
            "/..%00/", "/.%00/", "/%00/",
            "/..%0d/", "/..%0a/", "/..%0d%0a/",
            "/.%2e/", "/%252e%252e/", "/%252e/",
            "/%c0%af/", "/%c0%ae/", "/%c1%9c/",
            "/%ef%bc%8f/",   // fullwidth solidus
            "/..%5c/", "/..%255c/", "/..\\/"
    };

    /** Suffixes to append to the end of the path */
    private static final String[] END_PATH_PAYLOADS = {
            "/", "//", "/./", "/../", "/.", "/..",
            "/.html", "/.json", "/.css", "/.js", "/.txt", "/.xml",
            "/.php", "/.asp", "/.aspx", "/.jsp",
            "/..;/", "/;/", "/%20", "/%09", "/%00",
            "/#", "/?", "/?anything", "/#anything",
            "/~", "/;", "/...", "/....",
            "%20", "%09", "%00", ".", ".html", ".json", ".css",
            ";", ";.json", ";.css", ";.html", ";/",
            "#", "?", "?x=", "%23", "%3f", "%26",
            "..;", "..;/", ";foo=bar",
            "\\", "\\..\\", "..\\", ".\\", "%5c", "%5c..%5c",
            "%ef%bc%8f",     // fullwidth solidus
            "%e5%98%8a%e5%98%8d",  // CRLF in unicode
            "/.randomext", "/.;x=y", "..%c0%af", "..%c1%9c"
    };

    /** HTTP methods to test */
    private static final String[] HTTP_METHODS = {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
            "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "SEARCH", "PURGE", "BPROPFIND", "MERGE",
            "MKACTIVITY", "CHECKOUT", "REPORT", "ACL"
    };

    /** Method override header names */
    private static final String[] METHOD_OVERRIDE_HEADERS = {
            "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"
    };

    /** Method values for override headers */
    private static final String[] OVERRIDE_METHODS = {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    };

    /** Scheme/protocol spoofing header names */
    private static final String[] SCHEME_HEADERS = {
            "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Scheme",
            "Front-End-Https", "X-URL-Scheme", "X-Forwarded-Ssl",
            "X-Forwarded-Protocol"
    };

    /** Scheme values */
    private static final String[] SCHEME_VALUES = { "http", "https" };

    /** IP address spoofing header names */
    private static final String[] IP_HEADERS = {
            "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
            "X-Client-IP", "True-Client-IP", "CF-Connecting-IP",
            "Fastly-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-Ip",
            "X-Azure-ClientIP", "X-Original-Forwarded-For", "X-Backend-Host",
            "X-Host", "Forwarded"
    };

    /** Internal / localhost IP values */
    private static final String[] IP_VALUES = {
            "127.0.0.1", "0.0.0.0", "localhost", "::1", "::", "0",
            "10.0.0.1", "10.0.0.0", "172.16.0.1", "192.168.1.1",
            "192.168.0.1", "127.0.0.0", "2130706433", "0x7f000001",
            "0177.0.0.1", "127.1"
    };

    /** Port spoofing header names */
    private static final String[] PORT_HEADERS = { "X-Forwarded-Port" };

    /** Common port values */
    private static final String[] PORT_VALUES = {
            "80", "443", "8080", "8443", "4443", "8000", "8888", "9090", "9443"
    };

    /** URL rewrite / spoofing header names */
    private static final String[] URL_HEADERS = {
            "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
            "Referer", "X-Forwarded-Host", "X-Host"
    };

    /** User-Agent strings */
    private static final String[] USER_AGENTS = {
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Twitterbot/1.0",
            "curl/7.68.0",
            "wget/1.20",
            "python-requests/2.28.0",
            "Java/17.0.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "internal-service/1.0",
            "health-check/1.0",
            "AdsBot-Google (+http://www.google.com/adsbot.html)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)"
    };

    // ═══════════════════════════════════════════════════════════════
    //  DATA STRUCTURES
    // ═══════════════════════════════════════════════════════════════

    /** A single bypass attempt to be executed */
    public static class BypassAttempt {
        public final String mode;
        public final String description;
        public final String path;              // mutated path (raw, may include encoded chars)
        public final String method;            // HTTP method (default GET)
        public final String httpVersion;       // HTTP/1.0 or HTTP/1.1
        public final Map<String, String> extraHeaders; // additional headers to inject

        public BypassAttempt(String mode, String description, String path, String method,
                             String httpVersion, Map<String, String> extraHeaders) {
            this.mode = mode;
            this.description = description;
            this.path = path;
            this.method = method != null ? method : "GET";
            this.httpVersion = httpVersion != null ? httpVersion : "HTTP/1.1";
            this.extraHeaders = extraHeaders != null ? extraHeaders : Collections.emptyMap();
        }
    }

    /** Result of executing a single bypass attempt */
    public static class BypassResult {
        public final String mode;
        public final String description;
        public final String payloadUrl;
        public final String method;
        public final int statusCode;
        public final int contentLength;
        public final String contentType;
        public final int wordCount;
        public final int lineCount;
        public final String classification; // "BYPASS", "POTENTIAL", "DIFFERENT", "SAME", "ERROR"
        public final HttpRequestResponse requestResponse;
        public final String extraHeaders;

        public BypassResult(String mode, String description, String payloadUrl, String method,
                            int statusCode, int contentLength, String contentType,
                            int wordCount, int lineCount, String classification,
                            HttpRequestResponse requestResponse, String extraHeaders) {
            this.mode = mode;
            this.description = description;
            this.payloadUrl = payloadUrl;
            this.method = method;
            this.statusCode = statusCode;
            this.contentLength = contentLength;
            this.contentType = contentType;
            this.wordCount = wordCount;
            this.lineCount = lineCount;
            this.classification = classification;
            this.requestResponse = requestResponse;
            this.extraHeaders = extraHeaders;
        }
    }

    /** Baseline response metrics for comparison */
    private static class BaselineResult {
        final int statusCode;
        final int contentLength;
        final String contentType;
        final int wordCount;
        final int lineCount;
        final String body;

        BaselineResult(int statusCode, int contentLength, String contentType,
                       int wordCount, int lineCount, String body) {
            this.statusCode = statusCode;
            this.contentLength = contentLength;
            this.contentType = contentType;
            this.wordCount = wordCount;
            this.lineCount = lineCount;
            this.body = body;
        }
    }

    /** Parsed URL components */
    private static class UrlParts {
        final String scheme;
        final String host;
        final int port;
        final String path;
        final String query;
        final boolean useHttps;

        UrlParts(String scheme, String host, int port, String path, String query) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = (path == null || path.isEmpty()) ? "/" : path;
            this.query = query;
            this.useHttps = "https".equalsIgnoreCase(scheme);
        }

        /** Returns the host header value (includes port if non-default) */
        String hostHeader() {
            if ((useHttps && port == 443) || (!useHttps && port == 80)) return host;
            return host + ":" + port;
        }

        /** Returns the full URL for a given path */
        String fullUrl(String p) {
            return scheme + "://" + hostHeader() + p;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  MAIN ENTRY POINT
    // ═══════════════════════════════════════════════════════════════

    /** Returns true if a scan is currently running */
    public boolean isRunning() { return running; }

    /** Stop the current scan */
    public void stopScan() {
        running = false;
        ExecutorService ex = scanExecutor;
        if (ex != null && !ex.isShutdown()) {
            ex.shutdownNow();
        }
    }

    /**
     * Runs the bypass scan against the given target URL.
     * Called from the BypassUrlParserPanel when the user clicks "Run".
     *
     * @param targetUrl      target URL (e.g., http://target.com/admin)
     * @param selectedModes  set of bypass mode names to run
     * @param threads        number of concurrent threads
     * @param timeoutSeconds per-request timeout in seconds
     */
    public void runBypassScan(String targetUrl, Set<String> selectedModes,
                              int threads, int timeoutSeconds) {
        if (running) {
            log("Scan already running — stop it first.");
            return;
        }
        if (targetUrl == null || targetUrl.isBlank()) {
            log("No target URL specified.");
            return;
        }
        if (selectedModes.isEmpty()) {
            log("No bypass modes selected.");
            return;
        }

        // Parse URL
        UrlParts url;
        try {
            url = parseUrl(targetUrl.trim());
        } catch (Exception e) {
            log("Invalid URL: " + e.getMessage());
            return;
        }

        // Reset state
        running = true;
        results.clear();
        completedCount.set(0);
        bypassCount.set(0);
        totalCount.set(0);

        // Run on a background thread so the UI stays responsive
        Thread scanThread = new Thread(() -> {
            try {
                executeScan(url, selectedModes, threads, timeoutSeconds);
            } catch (Throwable t) {
                log("Scan error: " + t.getClass().getName() + ": " + t.getMessage());
            } finally {
                running = false;
                updatePanel();
            }
        }, "OmniStrike-BUP-Main");
        scanThread.setDaemon(true);
        scanThread.start();
    }

    /** Core scan execution (runs on background thread) */
    private void executeScan(UrlParts url, Set<String> modes, int threads, int timeoutSec) {
        log("Starting bypass scan against: " + url.fullUrl(url.path));
        log("Modes: " + String.join(", ", modes));
        log("Threads: " + threads + " | Timeout: " + timeoutSec + "s");

        // Step 1: Send baseline request
        log("Sending baseline request...");
        HttpService service = HttpService.httpService(url.host, url.port, url.useHttps);
        BaselineResult baseline = sendBaseline(service, url.path, url.hostHeader(), timeoutSec);
        if (baseline == null) {
            log("Failed to get baseline response — aborting scan.");
            return;
        }
        log("Baseline: HTTP " + baseline.statusCode + " | "
                + baseline.contentLength + " bytes | " + baseline.contentType);

        BypassUrlParserPanel p = panel;
        if (p != null) {
            javax.swing.SwingUtilities.invokeLater(() ->
                    p.setBaselineInfo(baseline.statusCode, baseline.contentLength));
        }

        // Step 2: Generate all bypass payloads
        log("Generating bypass payloads...");
        List<BypassAttempt> attempts = generateAll(url, modes);
        totalCount.set(attempts.size());
        log("Generated " + attempts.size() + " payloads across " + modes.size() + " modes.");

        if (!running) return;

        // Step 3: Execute all attempts in parallel
        scanExecutor = new ThreadPoolExecutor(
                threads, threads, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                r -> { Thread t = new Thread(r, "OmniStrike-BUP-Worker"); t.setDaemon(true); return t; }
        );

        List<Future<?>> futures = new ArrayList<>();
        for (BypassAttempt attempt : attempts) {
            if (!running) break;
            futures.add(scanExecutor.submit(() -> {
                if (!running) return;
                try {
                    BypassResult result = executeAttempt(attempt, service, url, baseline, timeoutSec);
                    if (result != null) {
                        results.add(result);
                        if ("BYPASS".equals(result.classification)
                                || "POTENTIAL".equals(result.classification)) {
                            bypassCount.incrementAndGet();
                            reportFinding(result, url);
                        }
                    }
                } catch (Throwable t) {
                    // Swallow individual request errors
                } finally {
                    completedCount.incrementAndGet();
                    // Update panel periodically (every 10 requests to avoid UI flood)
                    if (completedCount.get() % 10 == 0 || completedCount.get() == totalCount.get()) {
                        updatePanel();
                    }
                }
            }));
        }

        // Wait for completion
        for (Future<?> f : futures) {
            if (!running) break;
            try {
                f.get(timeoutSec + 10, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                f.cancel(true);
            } catch (CancellationException | InterruptedException | ExecutionException ignored) {
            }
        }

        scanExecutor.shutdown();

        // Step 4: Export results to JSON
        String jsonPath = exportResults(url);

        log("Scan complete: " + completedCount.get() + "/" + totalCount.get()
                + " requests | " + bypassCount.get() + " bypasses found");
        if (jsonPath != null) {
            log("Results saved to: " + jsonPath);
        }
        updatePanel();
    }

    // ═══════════════════════════════════════════════════════════════
    //  PAYLOAD GENERATION
    // ═══════════════════════════════════════════════════════════════

    /** Generates all bypass attempts for the selected modes */
    private List<BypassAttempt> generateAll(UrlParts url, Set<String> modes) {
        List<BypassAttempt> all = new ArrayList<>();
        if (modes.contains(MODE_MID_PATHS))         all.addAll(generateMidPaths(url));
        if (modes.contains(MODE_END_PATHS))          all.addAll(generateEndPaths(url));
        if (modes.contains(MODE_CASE_SUBSTITUTION))  all.addAll(generateCaseSubstitution(url));
        if (modes.contains(MODE_CHAR_ENCODE))        all.addAll(generateCharEncode(url));
        if (modes.contains(MODE_HTTP_METHODS))       all.addAll(generateHttpMethods(url));
        if (modes.contains(MODE_HTTP_VERSIONS))      all.addAll(generateHttpVersions(url));
        if (modes.contains(MODE_HEADERS_METHOD))     all.addAll(generateHeadersMethod(url));
        if (modes.contains(MODE_HEADERS_SCHEME))     all.addAll(generateHeadersScheme(url));
        if (modes.contains(MODE_HEADERS_IP))         all.addAll(generateHeadersIp(url));
        if (modes.contains(MODE_HEADERS_PORT))       all.addAll(generateHeadersPort(url));
        if (modes.contains(MODE_HEADERS_URL))        all.addAll(generateHeadersUrl(url));
        if (modes.contains(MODE_USER_AGENT))         all.addAll(generateUserAgent(url));
        if (modes.contains(MODE_COMBINED_HEADERS))   all.addAll(generateCombinedHeaders(url));
        // Deduplicate identical payloads (same path + method + headers)
        return deduplicateAttempts(all);
    }

    /** Remove duplicate attempts that would produce identical requests */
    private List<BypassAttempt> deduplicateAttempts(List<BypassAttempt> attempts) {
        Set<String> seen = new LinkedHashSet<>();
        List<BypassAttempt> unique = new ArrayList<>();
        for (BypassAttempt a : attempts) {
            String key = a.method + "|" + a.path + "|" + a.httpVersion + "|" + a.extraHeaders;
            if (seen.add(key)) {
                unique.add(a);
            }
        }
        return unique;
    }

    // ── mid_paths ────────────────────────────────────────────────────

    private List<BypassAttempt> generateMidPaths(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        String path = url.path;

        // Split path into segments: /admin/panel → ["admin", "panel"]
        String[] segments = path.split("/");
        List<String> parts = new ArrayList<>();
        for (String s : segments) {
            if (!s.isEmpty()) parts.add(s);
        }

        if (parts.isEmpty()) return attempts; // root path, nothing to manipulate

        // For each insertion point between segments
        for (int insertIdx = 0; insertIdx <= parts.size(); insertIdx++) {
            for (String mid : MID_PATH_PAYLOADS) {
                StringBuilder mutated = new StringBuilder();
                for (int i = 0; i < parts.size(); i++) {
                    if (i == insertIdx) {
                        // Trim leading slash from mid if we already have one
                        String m = mid;
                        if (mutated.length() > 0 && mutated.charAt(mutated.length() - 1) == '/'
                                && m.startsWith("/")) {
                            m = m.substring(1);
                        }
                        mutated.append(m);
                    }
                    if (mutated.length() == 0 || mutated.charAt(mutated.length() - 1) != '/') {
                        mutated.append("/");
                    }
                    mutated.append(parts.get(i));
                }
                if (insertIdx == parts.size()) {
                    // Append after last segment
                    String m = mid;
                    if (mutated.length() > 0 && mutated.charAt(mutated.length() - 1) != '/'
                            && !m.startsWith("/")) {
                        mutated.append("/");
                    }
                    mutated.append(m);
                }
                String mutatedPath = mutated.toString();
                if (!mutatedPath.startsWith("/")) mutatedPath = "/" + mutatedPath;

                attempts.add(new BypassAttempt(
                        MODE_MID_PATHS,
                        "Insert " + mid.replace("\n", "\\n") + " at position " + insertIdx,
                        mutatedPath, "GET", "HTTP/1.1", null
                ));
            }
        }

        // Also add direct path traversal variants
        for (String mid : MID_PATH_PAYLOADS) {
            // Prepend traversal before the entire path
            String variant = mid + path.substring(1); // remove leading /
            if (!variant.startsWith("/")) variant = "/" + variant;
            attempts.add(new BypassAttempt(MODE_MID_PATHS,
                    "Prepend " + mid + " before path", variant, "GET", "HTTP/1.1", null));
        }

        return attempts;
    }

    // ── end_paths ────────────────────────────────────────────────────

    private List<BypassAttempt> generateEndPaths(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        String path = url.path;

        for (String suffix : END_PATH_PAYLOADS) {
            String mutated = path + suffix;
            attempts.add(new BypassAttempt(MODE_END_PATHS,
                    "Append " + suffix, mutated, "GET", "HTTP/1.1", null));
        }

        // Also try removing trailing slash if present, or adding one
        if (path.endsWith("/") && path.length() > 1) {
            attempts.add(new BypassAttempt(MODE_END_PATHS,
                    "Remove trailing slash", path.substring(0, path.length() - 1),
                    "GET", "HTTP/1.1", null));
        }

        return attempts;
    }

    // ── case_substitution ────────────────────────────────────────────

    private List<BypassAttempt> generateCaseSubstitution(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        String path = url.path;

        String[] segments = path.split("/");
        List<String> parts = new ArrayList<>();
        for (String s : segments) {
            if (!s.isEmpty()) parts.add(s);
        }

        if (parts.isEmpty()) return attempts;

        // For each segment, generate case variations
        for (int segIdx = 0; segIdx < parts.size(); segIdx++) {
            String segment = parts.get(segIdx);
            List<String> variations = generateCaseVariations(segment);

            for (String variation : variations) {
                if (variation.equals(segment)) continue; // skip original
                StringBuilder mutated = new StringBuilder("/");
                for (int i = 0; i < parts.size(); i++) {
                    if (i > 0) mutated.append("/");
                    mutated.append(i == segIdx ? variation : parts.get(i));
                }
                attempts.add(new BypassAttempt(MODE_CASE_SUBSTITUTION,
                        "Case variant: " + variation + " (segment " + segIdx + ")",
                        mutated.toString(), "GET", "HTTP/1.1", null));
            }
        }

        // All uppercase / all lowercase full path
        String upper = path.toUpperCase();
        String lower = path.toLowerCase();
        if (!upper.equals(path)) {
            attempts.add(new BypassAttempt(MODE_CASE_SUBSTITUTION,
                    "Full path uppercase", upper, "GET", "HTTP/1.1", null));
        }
        if (!lower.equals(path)) {
            attempts.add(new BypassAttempt(MODE_CASE_SUBSTITUTION,
                    "Full path lowercase", lower, "GET", "HTTP/1.1", null));
        }

        return attempts;
    }

    /** Generate case variations for a segment (up to 64 variations) */
    private List<String> generateCaseVariations(String segment) {
        List<String> variations = new ArrayList<>();
        int len = segment.length();

        if (len > 10) {
            // For long segments, generate key variations only
            variations.add(segment.toUpperCase());
            variations.add(segment.toLowerCase());
            variations.add(Character.toUpperCase(segment.charAt(0)) + segment.substring(1).toLowerCase());
            // Alternating case
            StringBuilder alt1 = new StringBuilder();
            StringBuilder alt2 = new StringBuilder();
            for (int i = 0; i < len; i++) {
                char c = segment.charAt(i);
                alt1.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
                alt2.append(i % 2 == 0 ? Character.toLowerCase(c) : Character.toUpperCase(c));
            }
            variations.add(alt1.toString());
            variations.add(alt2.toString());
        } else {
            // Generate all 2^n combinations (capped at 64)
            int combos = Math.min(1 << len, 64);
            for (int mask = 0; mask < combos; mask++) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < len; i++) {
                    char c = segment.charAt(i);
                    if (Character.isLetter(c)) {
                        sb.append((mask & (1 << i)) != 0
                                ? Character.toUpperCase(c) : Character.toLowerCase(c));
                    } else {
                        sb.append(c);
                    }
                }
                variations.add(sb.toString());
            }
        }
        return variations;
    }

    // ── char_encode ──────────────────────────────────────────────────

    private List<BypassAttempt> generateCharEncode(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        String path = url.path;

        String[] segments = path.split("/");
        List<String> parts = new ArrayList<>();
        for (String s : segments) {
            if (!s.isEmpty()) parts.add(s);
        }

        if (parts.isEmpty()) return attempts;

        // For each segment, encode each character
        for (int segIdx = 0; segIdx < parts.size(); segIdx++) {
            String segment = parts.get(segIdx);
            for (int charIdx = 0; charIdx < segment.length(); charIdx++) {
                char c = segment.charAt(charIdx);
                String hex = String.format("%02x", (int) c);

                // Single URL encode
                String singleEnc = replaceCharAt(segment, charIdx, "%" + hex);
                // Double URL encode
                String doubleEnc = replaceCharAt(segment, charIdx, "%25" + hex);
                // Triple URL encode
                String tripleEnc = replaceCharAt(segment, charIdx, "%2525" + hex);
                // Unicode overlong UTF-8 (2-byte for ASCII)
                // Overlong UTF-8 2-byte encoding: first byte = 0xC0|(c>>6), second = 0x80|(c&0x3F)
                String unicodeEnc = replaceCharAt(segment, charIdx,
                        String.format("%%%02x%%%02x", 0xC0 | (c >> 6), 0x80 | (c & 0x3F)));

                for (String[] enc : new String[][]{
                        {singleEnc, "Single URL-encode '" + c + "'"},
                        {doubleEnc, "Double URL-encode '" + c + "'"},
                        {tripleEnc, "Triple URL-encode '" + c + "'"},
                        {unicodeEnc, "Unicode overlong '" + c + "'"}
                }) {
                    StringBuilder mutated = new StringBuilder("/");
                    for (int i = 0; i < parts.size(); i++) {
                        if (i > 0) mutated.append("/");
                        mutated.append(i == segIdx ? enc[0] : parts.get(i));
                    }
                    attempts.add(new BypassAttempt(MODE_CHAR_ENCODE, enc[1],
                            mutated.toString(), "GET", "HTTP/1.1", null));
                }
            }
        }

        // Also encode the path separator /
        String fullEncoded = path.replace("/", "%2f");
        if (!fullEncoded.startsWith("/") && !fullEncoded.startsWith("%2f")) {
            fullEncoded = "/" + fullEncoded;
        }
        attempts.add(new BypassAttempt(MODE_CHAR_ENCODE,
                "Encode all slashes as %2f", fullEncoded, "GET", "HTTP/1.1", null));

        String doubleSlash = path.replace("/", "%252f");
        if (!doubleSlash.startsWith("/") && !doubleSlash.startsWith("%252f")) {
            doubleSlash = "/" + doubleSlash;
        }
        attempts.add(new BypassAttempt(MODE_CHAR_ENCODE,
                "Double-encode all slashes as %252f", doubleSlash, "GET", "HTTP/1.1", null));

        return attempts;
    }

    /** Replace character at index with a replacement string */
    private static String replaceCharAt(String s, int idx, String replacement) {
        return s.substring(0, idx) + replacement + s.substring(idx + 1);
    }

    // ── http_methods ─────────────────────────────────────────────────

    private List<BypassAttempt> generateHttpMethods(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String method : HTTP_METHODS) {
            attempts.add(new BypassAttempt(MODE_HTTP_METHODS,
                    "Method: " + method, url.path, method, "HTTP/1.1", null));
        }
        return attempts;
    }

    // ── http_versions ────────────────────────────────────────────────

    private List<BypassAttempt> generateHttpVersions(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String version : new String[]{"HTTP/1.0", "HTTP/1.1"}) {
            attempts.add(new BypassAttempt(MODE_HTTP_VERSIONS,
                    "Version: " + version, url.path, "GET", version, null));
        }
        // HTTP/0.9 — no headers, just the path
        attempts.add(new BypassAttempt(MODE_HTTP_VERSIONS,
                "Version: HTTP/0.9 (path only)", url.path, "GET", "HTTP/0.9", null));
        return attempts;
    }

    // ── http_headers_method ──────────────────────────────────────────

    private List<BypassAttempt> generateHeadersMethod(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String header : METHOD_OVERRIDE_HEADERS) {
            for (String method : OVERRIDE_METHODS) {
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put(header, method);
                attempts.add(new BypassAttempt(MODE_HEADERS_METHOD,
                        header + ": " + method, url.path, "GET", "HTTP/1.1", headers));
                // Also try with POST as the actual method
                attempts.add(new BypassAttempt(MODE_HEADERS_METHOD,
                        "POST + " + header + ": " + method, url.path, "POST", "HTTP/1.1", headers));
            }
        }
        return attempts;
    }

    // ── http_headers_scheme ──────────────────────────────────────────

    private List<BypassAttempt> generateHeadersScheme(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String header : SCHEME_HEADERS) {
            for (String value : SCHEME_VALUES) {
                Map<String, String> headers = new LinkedHashMap<>();
                // X-Forwarded-Ssl uses "on" instead of scheme names
                if ("X-Forwarded-Ssl".equals(header)) {
                    headers.put(header, "https".equals(value) ? "on" : "off");
                } else if ("Front-End-Https".equals(header)) {
                    headers.put(header, "https".equals(value) ? "on" : "off");
                } else {
                    headers.put(header, value);
                }
                attempts.add(new BypassAttempt(MODE_HEADERS_SCHEME,
                        header + ": " + headers.get(header), url.path, "GET", "HTTP/1.1", headers));
            }
        }
        return attempts;
    }

    // ── http_headers_ip ──────────────────────────────────────────────

    private List<BypassAttempt> generateHeadersIp(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String header : IP_HEADERS) {
            for (String ip : IP_VALUES) {
                Map<String, String> headers = new LinkedHashMap<>();
                if ("Forwarded".equals(header)) {
                    headers.put(header, "for=" + ip);
                } else {
                    headers.put(header, ip);
                }
                attempts.add(new BypassAttempt(MODE_HEADERS_IP,
                        header + ": " + ip, url.path, "GET", "HTTP/1.1", headers));
            }
        }
        return attempts;
    }

    // ── http_headers_port ────────────────────────────────────────────

    private List<BypassAttempt> generateHeadersPort(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String header : PORT_HEADERS) {
            for (String port : PORT_VALUES) {
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put(header, port);
                attempts.add(new BypassAttempt(MODE_HEADERS_PORT,
                        header + ": " + port, url.path, "GET", "HTTP/1.1", headers));
            }
        }
        return attempts;
    }

    // ── http_headers_url ─────────────────────────────────────────────

    private List<BypassAttempt> generateHeadersUrl(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();

        // URL values to try in rewrite headers
        String[] urlValues = {
                url.path,
                "/",
                url.path + "/",
                "http://127.0.0.1" + url.path,
                "https://127.0.0.1" + url.path,
                "http://localhost" + url.path,
                url.path + "?",
                url.path + "#",
                url.path + "%00",
                "/." + url.path
        };

        for (String header : URL_HEADERS) {
            for (String value : urlValues) {
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put(header, value);
                String actualPath = url.path;
                // For X-Original-URL and X-Rewrite-URL, the actual request goes to /
                // because the server uses the header value as the real path
                if ("X-Original-URL".equals(header) || "X-Rewrite-URL".equals(header)) {
                    actualPath = "/";
                }
                attempts.add(new BypassAttempt(MODE_HEADERS_URL,
                        header + ": " + value, actualPath, "GET", "HTTP/1.1", headers));
            }
        }

        return attempts;
    }

    // ── user_agent ───────────────────────────────────────────────────

    private List<BypassAttempt> generateUserAgent(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();
        for (String ua : USER_AGENTS) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("User-Agent", ua);
            String desc = ua.length() > 50 ? ua.substring(0, 50) + "..." : ua;
            attempts.add(new BypassAttempt(MODE_USER_AGENT,
                    "UA: " + desc, url.path, "GET", "HTTP/1.1", headers));
        }
        return attempts;
    }

    // ── combined_headers ─────────────────────────────────────────────

    /** Combine multiple header techniques in single requests for deeper bypass */
    private List<BypassAttempt> generateCombinedHeaders(UrlParts url) {
        List<BypassAttempt> attempts = new ArrayList<>();

        // Combine IP + method override + scheme spoofing
        String[] topIps = {"127.0.0.1", "0.0.0.0", "localhost", "::1"};
        String[] topMethods = {"GET", "POST", "PUT"};
        String[] topSchemes = {"http", "https"};

        for (String ip : topIps) {
            for (String method : topMethods) {
                for (String scheme : topSchemes) {
                    Map<String, String> headers = new LinkedHashMap<>();
                    headers.put("X-Forwarded-For", ip);
                    headers.put("X-HTTP-Method-Override", method);
                    headers.put("X-Forwarded-Proto", scheme);
                    attempts.add(new BypassAttempt(MODE_COMBINED_HEADERS,
                            "Combined: XFF=" + ip + " + Method=" + method + " + Proto=" + scheme,
                            url.path, "GET", "HTTP/1.1", headers));
                }
            }
        }

        // IP + rewrite URL
        for (String ip : topIps) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("X-Forwarded-For", ip);
            headers.put("X-Original-URL", url.path);
            attempts.add(new BypassAttempt(MODE_COMBINED_HEADERS,
                    "Combined: XFF=" + ip + " + X-Original-URL=" + url.path,
                    "/", "GET", "HTTP/1.1", headers));
        }

        // Googlebot UA + IP spoofing
        Map<String, String> googleBot = new LinkedHashMap<>();
        googleBot.put("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        googleBot.put("X-Forwarded-For", "66.249.66.1"); // Google's IP range
        attempts.add(new BypassAttempt(MODE_COMBINED_HEADERS,
                "Combined: Googlebot UA + Google IP", url.path, "GET", "HTTP/1.1", googleBot));

        return attempts;
    }

    // ═══════════════════════════════════════════════════════════════
    //  REQUEST EXECUTION
    // ═══════════════════════════════════════════════════════════════

    /** Send the baseline request to establish the original response */
    private BaselineResult sendBaseline(HttpService service, String path, String hostHeader, int timeout) {
        try {
            byte[] rawReq = buildRawRequest("GET", path, hostHeader, "HTTP/1.1", Collections.emptyMap());
            HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(rawReq));
            HttpRequestResponse rr = api.http().sendRequest(request);

            if (rr.response() == null) return null;

            String body = rr.response().bodyToString();
            String ct = getHeader(rr.response().headers(), "Content-Type");

            return new BaselineResult(
                    rr.response().statusCode(),
                    body != null ? body.length() : 0,
                    ct != null ? ct : "",
                    countWords(body),
                    countLines(body),
                    body
            );
        } catch (Exception e) {
            log("Baseline request failed: " + e.getMessage());
            return null;
        }
    }

    /** Execute a single bypass attempt and compare to baseline */
    private BypassResult executeAttempt(BypassAttempt attempt, HttpService service,
                                        UrlParts url, BaselineResult baseline, int timeout) {
        try {
            // Build extra headers (merge attempt headers with defaults)
            Map<String, String> headers = new LinkedHashMap<>();
            if (attempt.extraHeaders != null) {
                headers.putAll(attempt.extraHeaders);
            }

            byte[] rawReq = buildRawRequest(
                    attempt.method, attempt.path, url.hostHeader(),
                    attempt.httpVersion, headers);

            HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(rawReq));
            HttpRequestResponse rr = api.http().sendRequest(request);

            if (rr.response() == null) {
                return new BypassResult(attempt.mode, attempt.description,
                        url.fullUrl(attempt.path), attempt.method,
                        0, 0, "", 0, 0, "ERROR", null,
                        formatHeaders(attempt.extraHeaders));
            }

            String body = rr.response().bodyToString();
            String ct = getHeader(rr.response().headers(), "Content-Type");
            String locationHeader = getHeader(rr.response().headers(), "Location");
            int status = rr.response().statusCode();
            int cl = body != null ? body.length() : 0;
            int words = countWords(body);
            int lines = countLines(body);

            String classification = classifyResult(status, baseline.statusCode, cl,
                    baseline.contentLength, body, baseline.body, locationHeader);

            return new BypassResult(
                    attempt.mode, attempt.description,
                    url.fullUrl(attempt.path), attempt.method,
                    status, cl, ct != null ? ct : "", words, lines,
                    classification, rr,
                    formatHeaders(attempt.extraHeaders)
            );
        } catch (Exception e) {
            return new BypassResult(attempt.mode, attempt.description,
                    url.fullUrl(attempt.path), attempt.method,
                    0, 0, "", 0, 0, "ERROR", null,
                    formatHeaders(attempt.extraHeaders));
        }
    }

    /** Build a raw HTTP request as bytes to preserve path without normalization */
    private byte[] buildRawRequest(String method, String path, String hostHeader,
                                    String httpVersion, Map<String, String> extraHeaders) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path).append(" ").append(httpVersion).append("\r\n");
        sb.append("Host: ").append(hostHeader).append("\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");

        // Track which standard headers are overridden
        boolean hasUserAgent = false;
        if (extraHeaders != null) {
            for (Map.Entry<String, String> h : extraHeaders.entrySet()) {
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                if ("User-Agent".equalsIgnoreCase(h.getKey())) hasUserAgent = true;
            }
        }
        if (!hasUserAgent) {
            sb.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
        }
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════
    //  RESULT CLASSIFICATION
    // ═══════════════════════════════════════════════════════════════

    // ── Body rejection phrases (case-insensitive, checked in 200 responses) ──

    private static final String[] BODY_REJECTION_PHRASES = {
            "access denied", "forbidden", "403 forbidden", "401 unauthorized",
            "not authorized", "unauthorized access", "authentication required",
            "permission denied", "you do not have permission", "please log in",
            "login required", "session expired", "invalid session",
            "not found", "404 not found", "page not found",
            "request rejected", "request blocked", "waf", "web application firewall",
            "you are not allowed", "insufficient privileges"
    };

    /** Login/auth redirect pattern in Location header */
    private static final java.util.regex.Pattern LOGIN_REDIRECT =
            java.util.regex.Pattern.compile(
                    "(?i)/(login|signin|sign-in|sign_in|sso|auth|cas|saml|oauth|session|account|logout)"
                            + "|[?&](error|expired|redirect|return|next|continue|denied)=");

    /**
     * Classify the result by comparing response to baseline.
     * BYPASS:     status changed from 4xx/5xx → 2xx (with real content, not a denial page)
     * POTENTIAL:  status changed from 4xx → 3xx (redirect to non-login destination)
     * DIFFERENT:  status or content significantly differs
     * SAME:       no meaningful change
     */
    private String classifyResult(int status, int baselineStatus, int contentLength,
                                   int baselineContentLength, String body,
                                   String baselineBody, String locationHeader) {

        // --- Body similarity check: if result body matches baseline error body, it's the same ---
        if (baselineBody != null && body != null && bodySimilar(body, baselineBody)) {
            return "SAME";
        }

        // --- Baseline was already 2xx — can't "bypass" something already accessible ---
        if (baselineStatus >= 200 && baselineStatus < 300) {
            if (status != baselineStatus) return "DIFFERENT";
            // Use percentage-based tolerance for dynamic pages (20%)
            if (baselineContentLength > 0 && percentDiff(contentLength, baselineContentLength) > 20) return "DIFFERENT";
            if (baselineContentLength == 0 && contentLength > 100) return "DIFFERENT";
            return "SAME";
        }

        // --- Baseline was 4xx or 5xx — look for bypasses ---

        // 2xx response: potential bypass, but validate body content
        if (status >= 200 && status < 300) {
            // If body is small (< 10KB) and contains rejection/denial language,
            // the server returned 200 but actually denied access (soft error page)
            if (bodyContainsRejection(body)) {
                return "DIFFERENT";
            }
            return "BYPASS";
        }

        // 3xx redirect: check if it's to a login page (not a real bypass)
        if (status >= 300 && status < 400 && baselineStatus >= 400) {
            if (isLoginRedirect(locationHeader)) {
                return "SAME";
            }
            return "POTENTIAL";
        }

        // Different status codes
        if (status != baselineStatus) return "DIFFERENT";

        // Same status but significantly different content length (20% tolerance)
        if (baselineContentLength > 0 && percentDiff(contentLength, baselineContentLength) > 20) {
            return "DIFFERENT";
        }

        return "SAME";
    }

    /** Check if body contains rejection/denial language (only for bodies < 10KB) */
    private static boolean bodyContainsRejection(String body) {
        if (body == null || body.isEmpty()) return false;
        // Only check small bodies — large pages with real content that
        // happen to mention "forbidden" in a footer are likely real bypasses
        if (body.length() > 10_000) return false;
        String lower = body.toLowerCase();
        for (String phrase : BODY_REJECTION_PHRASES) {
            if (lower.contains(phrase)) return true;
        }
        return false;
    }

    /** Check if a redirect Location header points to a login/auth page */
    private static boolean isLoginRedirect(String location) {
        if (location == null || location.isEmpty()) return false;
        return LOGIN_REDIRECT.matcher(location).find();
    }

    /** Check if two bodies are similar enough to be the same page */
    private static boolean bodySimilar(String a, String b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        if (a.isEmpty() || b.isEmpty()) return false;
        // If lengths differ by > 20%, not similar
        double lengthRatio = (double) Math.min(a.length(), b.length()) / Math.max(a.length(), b.length());
        if (lengthRatio < 0.80) return false;
        // Compare first N characters for similarity
        int compareLen = Math.min(Math.min(a.length(), b.length()), 500);
        int matches = 0;
        for (int i = 0; i < compareLen; i++) {
            if (a.charAt(i) == b.charAt(i)) matches++;
        }
        return (double) matches / compareLen > 0.90;
    }

    /** Percentage difference between two integer values */
    private static double percentDiff(int a, int b) {
        if (b == 0) return a > 0 ? 100 : 0;
        return Math.abs(a - b) * 100.0 / b;
    }

    // ═══════════════════════════════════════════════════════════════
    //  FINDINGS & EXPORT
    // ═══════════════════════════════════════════════════════════════

    /** Report a successful bypass as a Finding to the framework */
    private void reportFinding(BypassResult result, UrlParts url) {
        Severity sev = "BYPASS".equals(result.classification) ? Severity.HIGH : Severity.MEDIUM;
        Confidence conf = "BYPASS".equals(result.classification) ? Confidence.FIRM : Confidence.TENTATIVE;

        StringBuilder desc = new StringBuilder();
        desc.append("A 403/401 bypass was detected using the '").append(result.mode).append("' technique.\n\n");
        desc.append("Baseline response: HTTP ").append("4xx/5xx").append("\n");
        desc.append("Bypass response: HTTP ").append(result.statusCode).append("\n");
        desc.append("Technique: ").append(result.description).append("\n");
        desc.append("Payload URL: ").append(result.payloadUrl).append("\n");
        desc.append("Method: ").append(result.method).append("\n");
        if (result.extraHeaders != null && !result.extraHeaders.isEmpty()) {
            desc.append("Extra Headers: ").append(result.extraHeaders).append("\n");
        }

        String evidence = "HTTP " + result.statusCode + " (Content-Length: " + result.contentLength + ")";

        Finding finding = Finding.builder(getId(),
                        "403 Bypass: " + result.mode + " → HTTP " + result.statusCode, sev, conf)
                .url(url.fullUrl(url.path))
                .description(desc.toString())
                .evidence(evidence)
                .payload(result.payloadUrl)
                .responseEvidence("HTTP/" + result.statusCode)
                .requestResponse(result.requestResponse)
                .remediation("Review access control configuration. Ensure URL normalization is "
                        + "applied consistently before authorization checks. Consider using "
                        + "a WAF or reverse proxy that canonicalizes paths.")
                .build();

        findingsStore.addFinding(finding);
    }

    /** Export all results to a JSON file in /tmp */
    private String exportResults(UrlParts url) {
        try {
            String timestamp = Instant.now().toString().replace(":", "-");
            String filename = "/tmp/bup-" + url.host + "-" + timestamp + ".json";

            Map<String, Object> export = new LinkedHashMap<>();
            export.put("target", url.fullUrl(url.path));
            export.put("scanTime", Instant.now().toString());
            export.put("totalPayloads", totalCount.get());
            export.put("completedPayloads", completedCount.get());
            export.put("totalBypasses", bypassCount.get());

            List<Map<String, Object>> resultList = new ArrayList<>();
            for (BypassResult r : results) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("mode", r.mode);
                item.put("description", r.description);
                item.put("payloadUrl", r.payloadUrl);
                item.put("method", r.method);
                item.put("statusCode", r.statusCode);
                item.put("contentLength", r.contentLength);
                item.put("contentType", r.contentType);
                item.put("wordCount", r.wordCount);
                item.put("lineCount", r.lineCount);
                item.put("classification", r.classification);
                item.put("extraHeaders", r.extraHeaders);
                resultList.add(item);
            }
            export.put("results", resultList);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
                pw.print(gson.toJson(export));
            }

            return filename;
        } catch (Exception e) {
            log("Failed to export results: " + e.getMessage());
            return null;
        }
    }

    /** Export results to a user-selected file path */
    public String exportResultsToFile(String filePath) {
        try {
            Map<String, Object> export = new LinkedHashMap<>();
            export.put("scanTime", Instant.now().toString());
            export.put("totalPayloads", totalCount.get());
            export.put("completedPayloads", completedCount.get());
            export.put("totalBypasses", bypassCount.get());

            List<Map<String, Object>> resultList = new ArrayList<>();
            for (BypassResult r : results) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("mode", r.mode);
                item.put("description", r.description);
                item.put("payloadUrl", r.payloadUrl);
                item.put("method", r.method);
                item.put("statusCode", r.statusCode);
                item.put("contentLength", r.contentLength);
                item.put("contentType", r.contentType);
                item.put("wordCount", r.wordCount);
                item.put("lineCount", r.lineCount);
                item.put("classification", r.classification);
                item.put("extraHeaders", r.extraHeaders);
                resultList.add(item);
            }
            export.put("results", resultList);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (PrintWriter pw = new PrintWriter(new FileWriter(filePath))) {
                pw.print(gson.toJson(export));
            }
            return filePath;
        } catch (Exception e) {
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════

    /** Get current results (for panel table display) */
    public List<BypassResult> getResults() {
        return Collections.unmodifiableList(new ArrayList<>(results));
    }

    public int getCompletedCount() { return completedCount.get(); }
    public int getTotalCount() { return totalCount.get(); }
    public int getBypassCount() { return bypassCount.get(); }

    /** Parse a URL string into components */
    private UrlParts parseUrl(String urlStr) throws Exception {
        // Ensure scheme is present
        if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
            urlStr = "http://" + urlStr;
        }
        URI uri = new URI(urlStr);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();
        String path = uri.getRawPath();
        String query = uri.getRawQuery();

        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("No host in URL: " + urlStr);
        }
        if (port < 0) {
            port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
        }
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        return new UrlParts(scheme, host, port, path, query);
    }

    private static int countWords(String body) {
        if (body == null || body.isEmpty()) return 0;
        return body.split("\\s+").length;
    }

    private static int countLines(String body) {
        if (body == null || body.isEmpty()) return 0;
        return body.split("\n", -1).length;
    }

    private static String getHeader(List<? extends burp.api.montoya.http.message.HttpHeader> headers,
                                    String name) {
        for (var h : headers) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    private static String formatHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getKey()).append(": ").append(e.getValue());
        }
        return sb.toString();
    }

    /** Log a message to Burp's output and the panel */
    private void log(String message) {
        if (api != null) {
            try {
                api.logging().logToOutput("[BUP] " + message);
            } catch (Exception ignored) {}
        }
        BypassUrlParserPanel p = panel;
        if (p != null) {
            javax.swing.SwingUtilities.invokeLater(() -> p.appendLog(message));
        }
    }

    /** Notify the panel to refresh its display */
    private void updatePanel() {
        BypassUrlParserPanel p = panel;
        if (p != null) {
            javax.swing.SwingUtilities.invokeLater(() -> p.refresh());
        }
    }
}

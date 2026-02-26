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
 * MODULE 4: Security Header Analyzer
 * Checks for missing security headers, CORS misconfigurations, CSP weaknesses,
 * cookie flag analysis, and server info disclosure.
 */
public class SecurityHeaderAnalyzer implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;

    // Track which hosts have already been analyzed to avoid duplicate findings per host
    private final ConcurrentHashMap<String, Boolean> analyzedHosts = new ConcurrentHashMap<>();

    // Track per-host+path dedup for endpoint-specific checks (CORS, CSP, cookies)
    private final ConcurrentHashMap<String, Boolean> analyzedPaths = new ConcurrentHashMap<>();

    // Store all header findings per host
    private final ConcurrentHashMap<String, List<HeaderFinding>> headerFindings = new ConcurrentHashMap<>();

    // CDN domains commonly allowed in CSP that can host arbitrary JS
    private static final Set<String> CSP_BYPASS_CDNS = Set.of(
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
            "raw.githubusercontent.com", "ajax.googleapis.com", "code.jquery.com",
            "stackpath.bootstrapcdn.com", "cdn.bootcss.com", "lib.baomitu.com",
            "cdn.bootcdn.net", "accounts.google.com", "*.googleusercontent.com",
            "storage.googleapis.com", "firebasestorage.googleapis.com"
    );

    // Required security headers
    private static final Map<String, String> REQUIRED_HEADERS = Map.ofEntries(
            Map.entry("Strict-Transport-Security", "Prevents MITM downgrade attacks. Recommended: max-age=31536000; includeSubDomains"),
            Map.entry("X-Content-Type-Options", "Prevents MIME-sniffing. Should be 'nosniff'"),
            Map.entry("X-Frame-Options", "Prevents clickjacking. Should be 'DENY' or 'SAMEORIGIN'. Supplement with CSP frame-ancestors"),
            Map.entry("Content-Security-Policy", "Prevents XSS and injection attacks"),
            Map.entry("Referrer-Policy", "Controls information leakage via Referer header"),
            Map.entry("Permissions-Policy", "Controls browser feature access (camera, microphone, geolocation, etc.)"),
            Map.entry("Cross-Origin-Opener-Policy", "Prevents cross-origin window access. Recommended: same-origin"),
            Map.entry("Cross-Origin-Resource-Policy", "Controls cross-origin resource loading"),
            Map.entry("Cross-Origin-Embedder-Policy", "Required for SharedArrayBuffer/high-res timers")
    );

    // Server/technology headers that disclose info
    private static final Set<String> INFO_DISCLOSURE_HEADERS = Set.of(
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "x-generator", "x-drupal-cache", "x-varnish", "via",
            "x-backend-server", "x-debug-token", "x-debug-token-link"
    );

    public static class HeaderFinding {
        public final String header;
        public final String issue;
        public final Severity severity;
        public final String detail;

        public HeaderFinding(String header, String issue, Severity severity, String detail) {
            this.header = header;
            this.issue = issue;
            this.severity = severity;
            this.detail = detail;
        }
    }

    @Override
    public String getId() { return "header-analyzer"; }

    @Override
    public String getName() { return "Security Header Analyzer"; }

    @Override
    public String getDescription() {
        return "Analyzes security headers, CORS, CSP, cookie flags, and server info disclosure.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        String url = requestResponse.request().url();
        String host = requestResponse.request().httpService().host();

        // Only do full header analysis once per host
        boolean firstTimeHost = analyzedHosts.putIfAbsent(host, Boolean.TRUE) == null;

        // Use merge to preserve ALL values for multi-valued headers (e.g., multiple
        // Content-Security-Policy or Set-Cookie headers). Values are joined with \n
        // so downstream checks analyze every header, not just the last one.
        Map<String, String> responseHeaderMap = new LinkedHashMap<>();
        for (var h : response.headers()) {
            responseHeaderMap.merge(h.name().toLowerCase(), h.value(),
                    (existing, newVal) -> existing + "\n" + newVal);
        }

        List<HeaderFinding> hostFindings = headerFindings.computeIfAbsent(host,
                k -> Collections.synchronizedList(new ArrayList<>()));

        if (firstTimeHost) {
            // Check missing security headers
            checkMissingHeaders(responseHeaderMap, url, host, findings, hostFindings);

            // Check server info disclosure
            checkInfoDisclosure(responseHeaderMap, url, host, findings, hostFindings);
        }

        // Per-path dedup for endpoint-specific checks — strip query params for normalization
        String path = url;
        int qIdx = path.indexOf('?');
        if (qIdx > 0) path = path.substring(0, qIdx);
        String pathKey = host + "|" + path;
        boolean firstTimePath = analyzedPaths.putIfAbsent(pathKey, Boolean.TRUE) == null;

        if (firstTimePath) {
            // CORS, CSP, cookies, HSTS — only check once per host+path
            checkCors(responseHeaderMap, url, host, findings, hostFindings);
            checkCsp(responseHeaderMap, url, host, findings, hostFindings);
            checkCookieFlags(response, url, host, findings, hostFindings);
            checkHsts(responseHeaderMap, url, host, findings, hostFindings);
        }

        return findings;
    }

    private void checkMissingHeaders(Map<String, String> headers, String url, String host,
                                      List<Finding> findings, List<HeaderFinding> hostFindings) {
        for (Map.Entry<String, String> required : REQUIRED_HEADERS.entrySet()) {
            String headerName = required.getKey();
            if (!headers.containsKey(headerName.toLowerCase())) {
                HeaderFinding hf = new HeaderFinding(headerName, "Missing", Severity.LOW, required.getValue());
                hostFindings.add(hf);
                findings.add(Finding.builder("header-analyzer",
                                "Missing security header: " + headerName,
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Header '" + headerName + "' not present in response")
                        .description(required.getValue())
                        .build());
            }
        }
    }

    private void checkInfoDisclosure(Map<String, String> headers, String url, String host,
                                      List<Finding> findings, List<HeaderFinding> hostFindings) {
        for (String infoHeader : INFO_DISCLOSURE_HEADERS) {
            String value = headers.get(infoHeader);
            if (value != null && !value.isBlank()) {
                HeaderFinding hf = new HeaderFinding(infoHeader, "Info disclosure", Severity.INFO, value);
                hostFindings.add(hf);
                findings.add(Finding.builder("header-analyzer",
                                "Server info disclosure: " + infoHeader + ": " + value,
                                Severity.INFO, Confidence.CERTAIN)
                        .url(url)
                        .evidence(infoHeader + ": " + value)
                        .responseEvidence(infoHeader + ": " + value)
                        .description("Server/technology version disclosed via response header. "
                                + "Attackers can use this to identify known vulnerabilities.")
                        .build());
            }
        }
    }

    private void checkCors(Map<String, String> headers, String url, String host,
                            List<Finding> findings, List<HeaderFinding> hostFindings) {
        String acao = headers.get("access-control-allow-origin");
        if (acao == null) return;

        String acac = headers.get("access-control-allow-credentials");
        boolean allowsCreds = "true".equalsIgnoreCase(acac);

        if ("*".equals(acao) && allowsCreds) {
            HeaderFinding hf = new HeaderFinding("CORS", "Wildcard origin with credentials",
                    Severity.HIGH, "Access-Control-Allow-Origin: * with Allow-Credentials: true");
            hostFindings.add(hf);
            findings.add(Finding.builder("header-analyzer",
                            "CORS misconfiguration: wildcard origin with credentials",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true")
                    .responseEvidence(acao)
                    .description("Dangerous CORS config. Any origin can make credentialed requests. "
                            + "Browsers actually block this combo, but it indicates a misconfigured server.")
                    .build());
        } else if ("*".equals(acao)) {
            findings.add(Finding.builder("header-analyzer",
                            "CORS: wildcard origin (no credentials)",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Access-Control-Allow-Origin: *")
                    .responseEvidence(acao)
                    .description("Wildcard origin without credentials is often acceptable for public APIs.")
                    .build());
        } else if (acao.equalsIgnoreCase("null") && allowsCreds) {
            findings.add(Finding.builder("header-analyzer",
                            "CORS misconfiguration: null origin with credentials",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Access-Control-Allow-Origin: null with credentials")
                    .responseEvidence(acao)
                    .description("Reflects 'null' origin with credentials. Sandboxed iframes can exploit this.")
                    .build());
        }
    }

    private void checkCsp(Map<String, String> headers, String url, String host,
                           List<Finding> findings, List<HeaderFinding> hostFindings) {
        String csp = headers.get("content-security-policy");
        if (csp == null) return;

        // Check for unsafe directives
        if (csp.contains("'unsafe-inline'")) {
            findings.add(Finding.builder("header-analyzer",
                            "CSP allows unsafe-inline",
                            Severity.MEDIUM, Confidence.CERTAIN)
                    .url(url)
                    .evidence("CSP contains 'unsafe-inline'")
                    .responseEvidence("'unsafe-inline'")
                    .description("unsafe-inline allows inline scripts/styles, significantly weakening XSS protection.")
                    .build());
        }

        if (csp.contains("'unsafe-eval'")) {
            findings.add(Finding.builder("header-analyzer",
                            "CSP allows unsafe-eval",
                            Severity.MEDIUM, Confidence.CERTAIN)
                    .url(url)
                    .evidence("CSP contains 'unsafe-eval'")
                    .responseEvidence("'unsafe-eval'")
                    .description("unsafe-eval allows eval(), new Function(), etc. Can be used to execute injected code.")
                    .build());
        }

        // Check for wildcard sources
        Pattern wildcardSrc = Pattern.compile("(\\w+-src\\s+[^;]*\\*)");
        Matcher wm = wildcardSrc.matcher(csp);
        while (wm.find()) {
            String directive = wm.group(1);
            if (!directive.contains("*.") && directive.contains(" *")) {
                findings.add(Finding.builder("header-analyzer",
                                "CSP wildcard source in: " + directive.split("\\s+")[0],
                                Severity.MEDIUM, Confidence.CERTAIN)
                        .url(url)
                        .evidence(directive)
                        .responseEvidence(directive)
                        .description("Wildcard (*) source allows loading resources from any origin.")
                        .build());
            }
        }

        // CDN bypass detection -- check directive values with word boundary matching,
        // excluding report-uri/report-to directives where CDN hostnames are harmless
        String[] cspDirectives = csp.split(";");
        for (String cdn : CSP_BYPASS_CDNS) {
            String cdnBare = cdn.startsWith("*.") ? cdn.substring(2) : cdn;
            Pattern cdnPattern = Pattern.compile("\\b" + Pattern.quote(cdnBare) + "\\b");
            for (String directive : cspDirectives) {
                String trimmed = directive.trim().toLowerCase();
                // Skip report-uri and report-to directives -- CDN references there are not bypasses
                if (trimmed.startsWith("report-uri") || trimmed.startsWith("report-to")) continue;
                if (cdnPattern.matcher(trimmed).find()) {
                    findings.add(Finding.builder("header-analyzer",
                                    "CSP CDN bypass: " + cdn,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("CSP directive '" + trimmed.split("\\s+")[0]
                                    + "' allows " + cdn + " which can host arbitrary JavaScript")
                            .responseEvidence(cdn)
                            .description("CDN " + cdn + " allows arbitrary file hosting. Attackers can host "
                                    + "malicious JS on this CDN to bypass CSP.")
                            .build());
                    break; // One finding per CDN is enough
                }
            }
        }

        // Check for data: or blob: specifically within script-src directive
        String scriptSrcDirective = extractDirective(csp, "script-src");
        if (scriptSrcDirective != null && (scriptSrcDirective.contains("data:") || scriptSrcDirective.contains("blob:"))) {
            findings.add(Finding.builder("header-analyzer",
                            "CSP script-src allows data: or blob: URIs",
                            Severity.MEDIUM, Confidence.CERTAIN)
                    .url(url)
                    .evidence("script-src includes data: or blob: scheme")
                    .responseEvidence(csp)
                    .description("data: and blob: URIs in script-src can be used to bypass CSP via injection.")
                    .build());
        }
    }

    private void checkCookieFlags(HttpResponse response, String url, String host,
                                   List<Finding> findings, List<HeaderFinding> hostFindings) {
        for (var header : response.headers()) {
            if (!header.name().equalsIgnoreCase("Set-Cookie")) continue;

            String value = header.value();
            String cookieName = extractCookieName(value);
            if (cookieName == null) continue;

            boolean isSession = Pattern.compile(
                    "\\b(session|sess|sid|token|auth|jwt|csrf|xsrf)\\b",
                    Pattern.CASE_INSENSITIVE).matcher(cookieName).find();
            String flagLower = value.toLowerCase();

            if (isSession) {
                if (!flagLower.contains("secure")) {
                    findings.add(Finding.builder("header-analyzer",
                                    "Session cookie missing Secure flag: " + cookieName,
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Set-Cookie: " + value)
                            .responseEvidence(value)
                            .description("Cookie '" + cookieName + "' appears session-related but lacks Secure flag. "
                                    + "May be sent over unencrypted HTTP.")
                            .build());
                }

                if (!flagLower.contains("httponly")) {
                    findings.add(Finding.builder("header-analyzer",
                                    "Session cookie missing HttpOnly flag: " + cookieName,
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Set-Cookie: " + value)
                            .responseEvidence(value)
                            .description("Cookie '" + cookieName + "' appears session-related but lacks HttpOnly flag. "
                                    + "Accessible to JavaScript, increasing XSS impact.")
                            .build());
                }

                if (!flagLower.contains("samesite")) {
                    findings.add(Finding.builder("header-analyzer",
                                    "Session cookie missing SameSite attribute: " + cookieName,
                                    Severity.LOW, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Set-Cookie: " + value)
                            .responseEvidence(value)
                            .description("Cookie '" + cookieName + "' lacks SameSite attribute. "
                                    + "May be vulnerable to CSRF attacks in older browsers.")
                            .build());
                } else if (flagLower.contains("samesite=none") && !flagLower.contains("secure")) {
                    findings.add(Finding.builder("header-analyzer",
                                    "SameSite=None without Secure: " + cookieName,
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Set-Cookie: " + value)
                            .responseEvidence(value)
                            .description("SameSite=None requires Secure flag. Without it, the cookie will be rejected by modern browsers.")
                            .build());
                }
            }
        }
    }

    private void checkHsts(Map<String, String> headers, String url, String host,
                            List<Finding> findings, List<HeaderFinding> hostFindings) {
        String hsts = headers.get("strict-transport-security");
        if (hsts == null) return;

        // Check max-age
        Matcher maxAgeMatcher = Pattern.compile("max-age=(\\d+)").matcher(hsts.toLowerCase());
        if (maxAgeMatcher.find()) {
            long maxAge = Long.parseLong(maxAgeMatcher.group(1));
            if (maxAge < 15768000) { // Less than 6 months
                findings.add(Finding.builder("header-analyzer",
                                "HSTS max-age too low: " + maxAge + "s",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Strict-Transport-Security: " + hsts)
                        .responseEvidence(hsts)
                        .description("HSTS max-age is " + maxAge + " seconds (< 6 months). "
                                + "Recommended: at least 31536000 (1 year).")
                        .build());
            }
        }

        // Check for includeSubDomains
        if (!hsts.toLowerCase().contains("includesubdomains")) {
            findings.add(Finding.builder("header-analyzer",
                            "HSTS missing includeSubDomains",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Strict-Transport-Security: " + hsts)
                    .responseEvidence(hsts)
                    .description("HSTS does not include subdomains. Subdomains may be accessed over HTTP.")
                    .build());
        }
    }

    /**
     * Extracts a specific CSP directive's value from a full CSP string.
     * Returns null if the directive is not present.
     * E.g., extractDirective("default-src 'self'; script-src cdn.example.com data:", "script-src")
     *   → "script-src cdn.example.com data:"
     */
    private static String extractDirective(String csp, String directiveName) {
        if (csp == null) return null;
        // CSP directives are separated by ';'
        for (String directive : csp.split(";")) {
            String trimmed = directive.trim();
            if (trimmed.toLowerCase().startsWith(directiveName.toLowerCase())) {
                return trimmed;
            }
        }
        return null;
    }

    private String extractCookieName(String setCookieValue) {
        if (setCookieValue == null) return null;
        int eqIdx = setCookieValue.indexOf('=');
        if (eqIdx > 0) return setCookieValue.substring(0, eqIdx).trim();
        return null;
    }

    @Override
    public void destroy() {}

    public ConcurrentHashMap<String, List<HeaderFinding>> getHeaderFindings() { return headerFindings; }
    public void clearAll() { analyzedHosts.clear(); analyzedPaths.clear(); headerFindings.clear(); }
}

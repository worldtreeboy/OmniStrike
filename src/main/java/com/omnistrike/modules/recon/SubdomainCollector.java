package com.omnistrike.modules.recon;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.SharedDataBus;
import com.omnistrike.model.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 3: Subdomain Collector
 * Passively extracts subdomains from CSP headers, response bodies,
 * CORS headers, redirects, and other sources.
 */
public class SubdomainCollector implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private SharedDataBus dataBus;

    // Thread-safe date formatter (replaces SimpleDateFormat which is not thread-safe)
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Discovered subdomains: subdomain -> SubdomainInfo
    private final ConcurrentHashMap<String, SubdomainInfo> subdomains = new ConcurrentHashMap<>();

    // Private/internal IP ranges for flagging
    private static final Pattern PRIVATE_IP = Pattern.compile(
            "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)"
    );

    public static class SubdomainInfo {
        public final String subdomain;
        public volatile String sourceType;
        public volatile String foundInUrl;
        public volatile String firstSeen;
        public volatile String resolvedIp;
        public volatile boolean isWildcard;

        public SubdomainInfo(String subdomain, String sourceType, String foundInUrl) {
            this.subdomain = subdomain;
            this.sourceType = sourceType;
            this.foundInUrl = foundInUrl;
            this.firstSeen = LocalDateTime.now().format(DATE_FORMATTER);
            this.isWildcard = false;
        }
    }

    @Override
    public String getId() { return "subdomain-collector"; }

    @Override
    public String getName() { return "Subdomain Collector"; }

    @Override
    public String getDescription() {
        return "Passively extracts subdomains from CSP, CORS, response bodies, and headers.";
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

    /**
     * Set the shared data bus for inter-module communication.
     * Discovered subdomains will be published to the "discovered-subdomains" channel.
     */
    public void setSharedDataBus(SharedDataBus dataBus) {
        this.dataBus = dataBus;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        String url = requestResponse.request().url();
        String host = requestResponse.request().httpService().host();
        String rootDomain = extractRootDomain(host);
        if (rootDomain == null) return findings;

        // Build dynamic pattern for subdomains of the target
        Pattern subdomainPattern = Pattern.compile(
                "([a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\.)*"
                        + Pattern.quote(rootDomain) + ")",
                Pattern.CASE_INSENSITIVE
        );

        // CSP headers
        for (var header : response.headers()) {
            String name = header.name().toLowerCase();
            if (name.equals("content-security-policy") || name.equals("content-security-policy-report-only")) {
                extractFromCsp(header.value(), rootDomain, url, findings, subdomainPattern);
            }
            // CORS
            if (name.equals("access-control-allow-origin")) {
                extractSubdomains(header.value(), "CORS header", url, rootDomain, findings, subdomainPattern);
            }
            // Redirect
            if (name.equals("location")) {
                extractSubdomains(header.value(), "Redirect header", url, rootDomain, findings, subdomainPattern);
            }
            // Link header
            if (name.equals("link")) {
                extractSubdomains(header.value(), "Link header", url, rootDomain, findings, subdomainPattern);
            }
            // Internal headers that may leak hosts
            if (name.equals("x-forwarded-host") || name.equals("x-original-url") || name.equals("x-backend-server")) {
                extractSubdomains(header.value(), "Internal header (" + header.name() + ")", url, rootDomain, findings, subdomainPattern);
            }
        }

        // Response body
        try {
            String body = response.bodyToString();
            if (body != null && !body.isBlank()) {
                extractSubdomains(body, "Response body", url, rootDomain, findings, subdomainPattern);
            }
        } catch (Exception ignored) {
        }

        return findings;
    }

    private void extractFromCsp(String cspValue, String rootDomain, String url,
                                 List<Finding> findings, Pattern subdomainPattern) {
        // Split CSP into directives
        String[] directives = cspValue.split(";");
        for (String directive : directives) {
            directive = directive.trim();
            // Extract domains from directive values
            String[] parts = directive.split("\\s+");
            for (String part : parts) {
                // Handle wildcards: *.example.com
                if (part.startsWith("*.")) {
                    String domain = part.substring(2);
                    if (domain.endsWith(rootDomain) || domain.equals(rootDomain)) {
                        trackSubdomain("*." + domain, "CSP (wildcard)", url, findings, true);
                    }
                }
                // Strip scheme and port
                String cleaned = part.replaceAll("^https?://", "").replaceAll(":[0-9]+$", "");
                Matcher m = subdomainPattern.matcher(cleaned);
                while (m.find()) {
                    trackSubdomain(m.group(1).toLowerCase(), "CSP header", url, findings, false);
                }
            }
        }
    }

    private void extractSubdomains(String text, String sourceType, String url,
                                    String rootDomain, List<Finding> findings, Pattern pattern) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String sub = m.group(1).toLowerCase();
            if (!sub.equals(rootDomain)) {
                trackSubdomain(sub, sourceType, url, findings, false);
            }
        }
    }

    private void trackSubdomain(String subdomain, String sourceType, String url,
                                 List<Finding> findings, boolean isWildcard) {
        if (subdomains.putIfAbsent(subdomain, new SubdomainInfo(subdomain, sourceType, url)) == null) {
            if (isWildcard) {
                subdomains.get(subdomain).isWildcard = true;
            }
            // Publish discovered subdomain to SharedDataBus for other modules
            if (dataBus != null) {
                dataBus.addToSet("discovered-subdomains", subdomain);
            }
            Severity severity = Severity.INFO;
            findings.add(Finding.builder("subdomain-collector",
                            "New subdomain: " + subdomain,
                            severity, Confidence.CERTAIN)
                    .url(url)
                    .evidence(subdomain + " (source: " + sourceType + ")")
                    .responseEvidence(subdomain)
                    .description("Subdomain discovered via " + sourceType)
                    .build());
        }
    }

    private static final Set<String> MULTI_PART_TLDS = Set.of(
        "co.uk", "com.au", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
        "com.br", "com.cn", "com.sg", "com.tw", "com.hk", "com.mx",
        "org.uk", "net.au", "ac.uk", "gov.uk", "edu.au", "or.jp",
        "ne.jp", "ac.jp", "go.jp", "com.ar", "com.co", "com.tr",
        "web-security-academy.net" // PortSwigger lab domains
    );

    /**
     * Extract root domain from a host (e.g., "api.test.example.com" -> "example.com")
     * Handles multi-part TLDs like .co.uk, .com.au, etc.
     */
    private String extractRootDomain(String host) {
        if (host == null) return null;
        String lower = host.toLowerCase();
        String[] parts = lower.split("\\.");
        if (parts.length < 2) return lower;

        // Check for multi-part TLDs
        if (parts.length >= 3) {
            String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (MULTI_PART_TLDS.contains(lastTwo)) {
                if (parts.length >= 4) {
                    return parts[parts.length - 3] + "." + lastTwo;
                }
                return lastTwo;
            }
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    @Override
    public void destroy() {}

    public ConcurrentHashMap<String, SubdomainInfo> getSubdomains() { return subdomains; }

    public void clearAll() { subdomains.clear(); }
}

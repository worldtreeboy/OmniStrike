package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * CORS Misconfiguration Scanner — 16-phase comprehensive test suite.
 *
 *  1. Reflected arbitrary origin         9. Duplicate Origin header confusion
 *  2. Null origin                       10. Trusted cloud/SaaS platform origins
 *  3. Subdomain / prefix trust          11. Internal / private network origins
 *  4. Scheme downgrade (HTTP on HTTPS)  12. Wildcard subdomain trust
 *  5. Wildcard + credentials            13. Missing Vary: Origin (cache poisoning)
 *  6. Preflight bypass                  14. JSONP coexistence
 *  7. Parser differential bypasses      15. Per-method policy divergence
 *  8. Port-based bypass                 16. Collaborator blind CORS (OOB DNS)
 */
public class CorsMisconfScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    @Override
    public String getId() { return "cors-scanner"; }

    @Override
    public String getName() { return "CORS Misconfiguration Scanner"; }

    @Override
    public String getDescription() {
        return "16-phase CORS scanner: reflected origin, null origin, subdomain trust, scheme downgrade, "
                + "wildcard+credentials, preflight bypass, parser differentials, port bypass, duplicate headers, "
                + "cloud origins, internal origins, wildcard subdomains, cache poisoning, JSONP, "
                + "per-method divergence, OOB collaborator.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());

        if (!dedup.markIfNew("cors-scanner", urlPath, "Origin")) return Collections.emptyList();

        try {
            testCors(requestResponse);
        } catch (Exception e) {
            api.logging().logToError("CORS test error on " + urlPath + ": " + e.getMessage());
        }

        return Collections.emptyList();
    }

    // ==================== ORCHESTRATOR ====================

    private void testCors(HttpRequestResponse original) throws InterruptedException {
        String url = original.request().url();
        String targetDomain = extractDomain(url);

        // Phase 1: Reflected arbitrary origin
        boolean reflectedArbitrary = testReflectedOrigin(original, url);

        // Phase 2: Null origin
        testNullOrigin(original, url);

        // Phase 3: Subdomain / prefix trust
        testSubdomainTrust(original, url, targetDomain);

        // Phase 4: Scheme downgrade
        if (url.startsWith("https://")) {
            testSchemeDowngrade(original, url, targetDomain);
        }

        // Phase 5: Wildcard with credentials
        testWildcardWithCredentials(original, url);

        // Phase 6: Preflight bypass
        if (config.getBool("cors.preflight.enabled", true) && !reflectedArbitrary) {
            testPreflightBypass(original, url);
        }

        // --- Novel techniques (phases 7–16) ---
        // Bypass-oriented phases are skipped if arbitrary origin already reflects

        // Phase 7: Parser differential bypasses
        if (!reflectedArbitrary) {
            testParserDifferentialBypasses(original, url, targetDomain);
        }

        // Phase 8: Port-based bypass
        if (!reflectedArbitrary) {
            testPortBypass(original, url, targetDomain);
        }

        // Phase 9: Duplicate Origin header confusion
        if (!reflectedArbitrary) {
            testDuplicateOriginHeaders(original, url, targetDomain);
        }

        // Phase 10: Trusted cloud/SaaS platform origins
        if (!reflectedArbitrary) {
            testTrustedCloudOrigins(original, url);
        }

        // Phase 11: Internal/private network origins
        if (!reflectedArbitrary) {
            testInternalNetworkOrigins(original, url);
        }

        // Phase 12: Wildcard subdomain trust (*.target.com)
        testWildcardSubdomainTrust(original, url, targetDomain);

        // Phase 13: Missing Vary: Origin (cache poisoning)
        testVaryOriginCachePoisoning(original, url);

        // Phase 14: JSONP coexistence (bypasses CORS entirely)
        testJsonpCoexistence(original, url);

        // Phase 15: Per-method CORS policy divergence
        if (!reflectedArbitrary) {
            testPerMethodDivergence(original, url);
        }

        // Phase 16: Collaborator-based blind CORS (OOB DNS)
        if (!reflectedArbitrary) {
            testCollaboratorBlindCors(original, url);
        }
    }

    // ==================== PHASE 1: REFLECTED ORIGIN ====================

    /**
     * @return true if the server reflects an arbitrary attacker origin
     */
    private boolean testReflectedOrigin(HttpRequestResponse original, String url) throws InterruptedException {
        String attackerOrigin = "https://attacker.com";
        HttpRequestResponse result = sendWithOrigin(original, attackerOrigin);
        if (result == null || result.response() == null) { perHostDelay(); return false; }

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);
        boolean reflected = attackerOrigin.equals(acao);

        if (reflected) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            acac ? "CORS: Reflected Origin with Credentials"
                                 : "CORS: Reflected Origin (no credentials)",
                            acac ? Severity.HIGH : Severity.INFO,
                            acac ? Confidence.CERTAIN : Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: " + attackerOrigin + " | ACAO: " + acao + " | ACAC: " + acac
                            + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                    .description(acac
                            ? "The server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true. "
                              + "An attacker page at any domain can steal authenticated cross-origin data."
                            : "The server reflects arbitrary Origin headers but without Access-Control-Allow-Credentials: true. "
                              + "Cross-origin reads are limited to public data — browser will not attach cookies.")
                    .remediation("Whitelist specific trusted origins. Never reflect the Origin header directly.")
                    .requestResponse(result)
                    .payload(attackerOrigin)
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
        return reflected;
    }

    // ==================== PHASE 2: NULL ORIGIN ====================

    private void testNullOrigin(HttpRequestResponse original, String url) throws InterruptedException {
        HttpRequestResponse result = sendWithOrigin(original, "null");
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);

        if ("null".equals(acao)) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            acac ? "CORS: Null Origin Trusted with Credentials"
                                 : "CORS: Null Origin Trusted",
                            acac ? Severity.HIGH : Severity.INFO,
                            acac ? Confidence.CERTAIN : Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: null | ACAO: null | ACAC: " + acac
                            + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                    .description("The server trusts the 'null' origin" + (acac ? " with credentials" : "")
                            + ". Sandboxed iframes (data: URIs, file:// pages) and cross-scheme redirects "
                            + "send Origin: null. An attacker can exploit this via a sandboxed iframe"
                            + (acac ? " to steal authenticated data." : " for cross-origin reads of public data."))
                    .remediation("Never whitelist the null origin. Reject requests with Origin: null.")
                    .requestResponse(result)
                    .payload("null")
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 3: SUBDOMAIN TRUST ====================

    private void testSubdomainTrust(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        String[] evilOrigins = {
                "https://evil-" + targetDomain,
                "https://" + targetDomain + ".evil.com",
                "https://evil." + targetDomain,
        };

        for (String evilOrigin : evilOrigins) {
            HttpRequestResponse result = sendWithOrigin(original, evilOrigin);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String acao = extractAcao(result);
            if (evilOrigin.equals(acao)) {
                boolean acac = hasAcac(result);
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS: Subdomain/Prefix Trust Bypass",
                                acac ? Severity.HIGH : Severity.INFO, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + evilOrigin + " | ACAO: " + acao + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description("Origin '" + evilOrigin + "' was accepted. An attacker who registers "
                                + "this domain can perform cross-origin data theft"
                                + (acac ? " including authenticated data." : " of public data only (no credentials)."))
                        .remediation("Use strict exact-match origin validation. Do not use substring/prefix/suffix matching.")
                        .requestResponse(result)
                        .payload(evilOrigin)
                        .responseEvidence(acao)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 4: SCHEME DOWNGRADE ====================

    private void testSchemeDowngrade(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        String httpOrigin = "http://" + targetDomain;
        HttpRequestResponse result = sendWithOrigin(original, httpOrigin);
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        if (httpOrigin.equals(acao)) {
            boolean acac = hasAcac(result);
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS: HTTP Origin Trusted on HTTPS Endpoint",
                            acac ? Severity.HIGH : Severity.INFO, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: " + httpOrigin + " | ACAO: " + acao + " | ACAC: " + acac
                            + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                    .description("The HTTPS endpoint trusts HTTP origins. A man-in-the-middle attacker can "
                            + "hijack the HTTP origin to " + (acac ? "steal authenticated data" : "read public data")
                            + " from the HTTPS endpoint via CORS.")
                    .remediation("Only allow HTTPS origins on HTTPS endpoints.")
                    .requestResponse(result)
                    .payload(httpOrigin)
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 5: WILDCARD WITH CREDENTIALS ====================

    private void testWildcardWithCredentials(HttpRequestResponse original, String url) throws InterruptedException {
        HttpRequestResponse result = sendWithOrigin(original, "https://check.example.com");
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        boolean acac = hasAcac(result);

        if ("*".equals(acao) && acac) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS: Wildcard with Credentials",
                            Severity.LOW, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("ACAO: * | ACAC: true")
                    .description("ACAO: * with ACAC: true is spec-invalid. Browsers should reject this but "
                            + "older or misconfigured clients may not. Indicates a broken CORS policy.")
                    .remediation("Never use ACAO: * with ACAC: true. Reflect a specific whitelisted origin instead.")
                    .requestResponse(result)
                    .payload("https://check.example.com")
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 6: PREFLIGHT BYPASS ====================

    private void testPreflightBypass(HttpRequestResponse original, String url) throws InterruptedException {
        String attackerOrigin = "https://attacker.com";
        try {
            HttpRequest simpleGet = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader("Origin", attackerOrigin);

            HttpRequestResponse result = api.http().sendRequest(simpleGet);
            if (result == null || result.response() == null) { perHostDelay(); return; }

            String acao = extractAcao(result);
            if (attackerOrigin.equals(acao)) {
                boolean acac = hasAcac(result);
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS: Simple Request Reflects Origin (No Preflight Needed)",
                                acac ? Severity.MEDIUM : Severity.INFO, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Simple GET Origin: " + attackerOrigin + " | ACAO: " + acao + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description("A simple GET (no custom headers, no preflight) reflects the attacker's origin. "
                                + "CORS exploitation requires only a basic fetch()/XHR, no OPTIONS preflight."
                                + (acac ? "" : " Without credentials, only public data is accessible cross-origin."))
                        .remediation("Validate Origin on all request types, not just preflighted requests.")
                        .requestResponse(result)
                        .payload(attackerOrigin)
                        .responseEvidence(acao)
                        .build());
            }
        } catch (Exception e) {
            api.logging().logToError("CORS preflight test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 7: PARSER DIFFERENTIAL BYPASSES ====================

    private void testParserDifferentialBypasses(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        // Each payload: {label, origin, description, exploitability}
        // "direct" = attacker can register the domain and exploit via browser
        // "indirect" = requires request smuggling, proxy manipulation, or server-side parser flaw
        String[][] payloads = {
                // Unescaped regex dot: server regex uses target.com without escaping the dot,
                // so target-com matches because regex '.' accepts any char.
                // DIRECTLY EXPLOITABLE: attacker registers target-com.evil.com
                {"Unescaped Regex Dot (hyphen)",
                 "https://" + targetDomain.replace(".", "-") + ".evil.com",
                 "Server regex '" + targetDomain + "' without escaped dot — '.' matches '-'. "
                         + "Directly exploitable: attacker registers this domain.",
                 "direct"},

                // Same test with a different char to confirm regex dot behavior
                {"Unescaped Regex Dot (char)",
                 "https://" + targetDomain.replace(".", "x") + ".evil.com",
                 "Server regex dot matches 'x'. Directly exploitable: attacker registers this domain.",
                 "direct"},

                // URL authority confusion: userinfo@host parsing.
                // Server sees 'target.com' in the string but URL host is evil.com.
                // In a real attack, the browser sends Origin: https://evil.com (strips userinfo),
                // so this tests server-side URL parser bugs reachable via request smuggling.
                {"URL Authority Confusion",
                 "https://" + targetDomain + "@evil.com",
                 "URL userinfo@host confusion: server extracts '" + targetDomain
                         + "' from string but actual host is evil.com. "
                         + "Exploitable via request smuggling or proxy header injection.",
                 "indirect"},

                // Null byte truncation: C-based backends / PHP may truncate at %00.
                // Not directly exploitable via browser (browsers don't send %00 in Origin),
                // but proves validation logic is flawed.
                {"Null Byte Truncation",
                 "https://" + targetDomain + "%00.evil.com",
                 "C-based backends or PHP urldecode then truncate at null byte, "
                         + "seeing only '" + targetDomain + "'. Proves broken validation logic. "
                         + "Exploitable via request smuggling to inject crafted Origin.",
                 "indirect"},

                // Backtick: documented Safari parser differential (CVE-2016-9078 era).
                // Tests whether server accepts unusual chars that older browsers misparse.
                {"Backtick Parser Differential",
                 "https://" + targetDomain + "`.evil.com",
                 "Backtick character causes parser differentials in older Safari. "
                         + "Tests server-side acceptance of special characters in origin.",
                 "indirect"},

                // Curly brace: may break regex in some frameworks (Java Pattern, Python re)
                // if the origin string is used unsanitized in a regex pattern.
                {"Special Char Brace",
                 "https://" + targetDomain + "}.evil.com",
                 "Curly brace may break regex-based origin validation in server frameworks. "
                         + "Tests for regex injection in CORS config.",
                 "indirect"},
        };

        for (String[] payload : payloads) {
            String label = payload[0];
            String origin = payload[1];
            String mechanism = payload[2];
            boolean direct = "direct".equals(payload[3]);

            HttpRequestResponse result = sendWithOrigin(original, origin);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String acao = extractAcao(result);
            if (acao != null && (origin.equals(acao) || origin.trim().equals(acao.trim()))) {
                boolean acac = hasAcac(result);
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Bypass: " + label,
                                acac ? (direct ? Severity.HIGH : Severity.MEDIUM) : Severity.INFO,
                                direct ? Confidence.CERTAIN : Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description(mechanism)
                        .remediation("Use strict exact-match origin validation with a hardcoded allowlist. "
                                + "Escape all special characters if using regex. "
                                + "Validate the full origin string, never substrings.")
                        .requestResponse(result)
                        .payload(origin)
                        .responseEvidence(acao)
                        .build());
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 8: PORT-BASED BYPASS ====================

    private void testPortBypass(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        // Per Same-Origin Policy, different ports = different origins.
        // If the server trusts target.com on any port, a service on a non-standard port
        // (dev server, Jenkins, admin panel, CI) becomes a valid CORS attack origin.
        String scheme = url.startsWith("https") ? "https" : "http";
        String origin = scheme + "://" + targetDomain + ":9999";

        HttpRequestResponse result = sendWithOrigin(original, origin);
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        if (origin.equals(acao)) {
            boolean acac = hasAcac(result);
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS: Arbitrary Port Accepted on Target Domain",
                            acac ? Severity.MEDIUM : Severity.INFO, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac
                            + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                    .description("The server trusts " + targetDomain + " on arbitrary ports. "
                            + "Per Same-Origin Policy, different ports are different origins. "
                            + "A compromised or attacker-controlled service on a non-standard port "
                            + "(dev server, CI tool, admin panel) can be used as a CORS attack origin.")
                    .remediation("Validate the full origin including scheme, host, AND port.")
                    .requestResponse(result)
                    .payload(origin)
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 9: DUPLICATE ORIGIN HEADERS ====================

    private void testDuplicateOriginHeaders(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        // Some frameworks read the first Origin header, others the last.
        // Exploitable via HTTP request smuggling or reverse proxies that append headers.
        String scheme = url.startsWith("https") ? "https" : "http";
        String trustedOrigin = scheme + "://" + targetDomain;
        String attackerOrigin = "https://attacker.com";

        try {
            // Trusted first, attacker second — tests if server reads the last value
            HttpRequest modified = original.request()
                    .withRemovedHeader("Origin")
                    .withAddedHeader("Origin", trustedOrigin)
                    .withAddedHeader("Origin", attackerOrigin);

            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result == null || result.response() == null) { perHostDelay(); return; }

            String acao = extractAcao(result);
            if (attackerOrigin.equals(acao)) {
                boolean acac = hasAcac(result);
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS Bypass: Duplicate Origin Header Confusion",
                                acac ? Severity.HIGH : Severity.INFO, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin headers: [" + trustedOrigin + ", " + attackerOrigin + "] | ACAO: " + acao
                                + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description("With duplicate Origin headers, the server reflected the attacker value. "
                                + "The server reads the last Origin header while proxies/browsers send one. "
                                + "Exploitable via HTTP request smuggling or reverse proxy header injection.")
                        .remediation("Reject requests with multiple Origin headers. If parsing, use the first value only.")
                        .requestResponse(result)
                        .payload(attackerOrigin)
                        .responseEvidence(acao)
                        .build());
            }
        } catch (Exception e) {
            api.logging().logToError("CORS duplicate origin test failed: " + e.getMessage());
        }
        perHostDelay();
    }

    // ==================== PHASE 10: TRUSTED CLOUD/SAAS ORIGINS ====================

    private void testTrustedCloudOrigins(HttpRequestResponse original, String url) throws InterruptedException {
        // Platforms where anyone can register a free subdomain.
        // If the server whitelists *.platform.tld, any attacker can host an exploit page there.
        String[][] cloudOrigins = {
                {"https://evil.github.io",           "github.io (GitHub Pages)"},
                {"https://evil.netlify.app",         "netlify.app (Netlify)"},
                {"https://evil.vercel.app",          "vercel.app (Vercel)"},
                {"https://evil.pages.dev",           "pages.dev (Cloudflare Pages)"},
                {"https://evil.web.app",             "web.app (Firebase Hosting)"},
                {"https://evil.firebaseapp.com",     "firebaseapp.com (Firebase)"},
                {"https://evil.herokuapp.com",       "herokuapp.com (Heroku)"},
                {"https://evil.azurewebsites.net",   "azurewebsites.net (Azure)"},
                {"https://evil.s3.amazonaws.com",    "s3.amazonaws.com (AWS S3)"},
                {"https://evil.cloudfront.net",      "cloudfront.net (AWS CloudFront)"},
                {"https://evil.surge.sh",            "surge.sh (Surge)"},
                {"https://evil.onrender.com",        "onrender.com (Render)"},
        };

        for (String[] entry : cloudOrigins) {
            String origin = entry[0];
            String platform = entry[1];

            HttpRequestResponse result = sendWithOrigin(original, origin);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String acao = extractAcao(result);
            if (origin.equals(acao)) {
                boolean acac = hasAcac(result);
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS: Trusted Cloud Platform — " + platform,
                                acac ? Severity.HIGH : Severity.INFO, Confidence.CERTAIN)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description("The server trusts origins from " + platform + ". "
                                + "Anyone can register a free subdomain on this platform and host "
                                + "an attacker-controlled page to perform cross-origin data theft"
                                + (acac ? " including authenticated data." : " of public data only (no credentials)."))
                        .remediation("Do not whitelist entire cloud platform domains. "
                                + "Only trust specific, known production origins.")
                        .requestResponse(result)
                        .payload(origin)
                        .responseEvidence(acao)
                        .build());
                return; // One cloud hit proves the issue
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 11: INTERNAL/PRIVATE NETWORK ORIGINS ====================

    private void testInternalNetworkOrigins(HttpRequestResponse original, String url) throws InterruptedException {
        // If the server trusts internal origins, attackers with code execution on the
        // internal network (compromised Electron app, XSS in dev tool, local web server)
        // can read cross-origin responses.
        String[][] internalOrigins = {
                {"http://localhost",                 "localhost"},
                {"http://localhost:8080",            "localhost:8080 (common dev port)"},
                {"http://127.0.0.1",                "IPv4 loopback"},
                {"http://[::1]",                    "IPv6 loopback"},
                {"http://10.0.0.1",                 "10.x private range"},
                {"http://172.16.0.1",               "172.16.x private range"},
                {"http://192.168.1.1",              "192.168.x private range"},
                {"http://169.254.169.254",          "AWS EC2 instance metadata"},
                {"http://metadata.google.internal", "GCP instance metadata"},
        };

        for (String[] entry : internalOrigins) {
            String origin = entry[0];
            String label = entry[1];

            HttpRequestResponse result = sendWithOrigin(original, origin);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String acao = extractAcao(result);
            if (origin.equals(acao)) {
                boolean acac = hasAcac(result);
                boolean isMetadata = origin.contains("169.254") || origin.contains("metadata.google");
                Severity internalSev;
                if (acac) {
                    internalSev = isMetadata ? Severity.HIGH : Severity.MEDIUM;
                } else {
                    internalSev = Severity.INFO;
                }
                findingsStore.addFinding(Finding.builder("cors-scanner",
                                "CORS: Internal Network Origin Trusted — " + label,
                                internalSev, Confidence.FIRM)
                        .url(url).parameter("Origin")
                        .evidence("Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac
                                + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                        .description("The server trusts the internal origin '" + origin + "' (" + label + "). "
                                + "If an attacker can run JavaScript on the internal network "
                                + "(compromised Electron app, XSS in a dev tool, rogue local service), "
                                + "they can read cross-origin responses from this endpoint."
                                + (isMetadata ? " Trusting cloud metadata origins is especially dangerous — "
                                        + "enables SSRF-to-CORS chains for cloud credential theft." : ""))
                        .remediation("Do not whitelist internal or private network origins in production CORS configuration.")
                        .requestResponse(result)
                        .payload(origin)
                        .responseEvidence(acao)
                        .build());
                return; // One hit proves the issue
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 12: WILDCARD SUBDOMAIN TRUST ====================

    private void testWildcardSubdomainTrust(HttpRequestResponse original, String url, String targetDomain) throws InterruptedException {
        // Tests if *.targetDomain is whitelisted — any subdomain is trusted.
        // If any subdomain has XSS or is takeover-able, it chains into full CORS bypass.
        String scheme = url.startsWith("https") ? "https" : "http";
        String origin = scheme + "://xss-" + (System.currentTimeMillis() % 100000) + "." + targetDomain;

        HttpRequestResponse result = sendWithOrigin(original, origin);
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        if (origin.equals(acao)) {
            boolean acac = hasAcac(result);
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS: Wildcard Subdomain Trust (*." + targetDomain + ")",
                            acac ? Severity.MEDIUM : Severity.INFO, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("Origin: " + origin + " | ACAO: " + acao + " | ACAC: " + acac
                            + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                    .description("The server trusts any subdomain of " + targetDomain + ". "
                            + "If any subdomain has an XSS vulnerability, a dangling DNS record, "
                            + "or is available for subdomain takeover, it chains into a full CORS bypass"
                            + (acac ? " with credential access." : " for public data only (no credentials)."))
                    .remediation("Whitelist specific subdomains only. Do not use *." + targetDomain + ".")
                    .requestResponse(result)
                    .payload(origin)
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 13: VARY ORIGIN CACHE POISONING ====================

    private void testVaryOriginCachePoisoning(HttpRequestResponse original, String url) throws InterruptedException {
        // If the server reflects Origin in ACAO but doesn't set Vary: Origin,
        // CDN/proxy caches serve ACAO:attacker.com to all users = web cache poisoning.
        String probeOrigin = "https://cors-cache-probe-" + (System.currentTimeMillis() % 100000) + ".example.com";
        HttpRequestResponse result = sendWithOrigin(original, probeOrigin);
        if (result == null || result.response() == null) { perHostDelay(); return; }

        String acao = extractAcao(result);
        // Only relevant if ACAO is reflected (not static * and not absent)
        if (acao == null || "*".equals(acao) || !probeOrigin.equals(acao)) { perHostDelay(); return; }

        boolean hasVaryOrigin = false;
        boolean isCacheable = false;
        for (var h : result.response().headers()) {
            String hname = h.name().toLowerCase();
            String hval = h.value().toLowerCase();
            if ("vary".equals(hname) && hval.contains("origin")) {
                hasVaryOrigin = true;
            }
            if ("cache-control".equals(hname) && (hval.contains("public") || hval.contains("max-age") || hval.contains("s-maxage"))) {
                isCacheable = true;
            }
            if ("x-cache".equals(hname) && hval.contains("hit")) {
                isCacheable = true;
            }
            if ("age".equals(hname)) {
                isCacheable = true;
            }
        }

        // Only report missing Vary: Origin if the response is actually cacheable
        if (!hasVaryOrigin && isCacheable) {
            findingsStore.addFinding(Finding.builder("cors-scanner",
                            "CORS Cache Poisoning: Missing Vary: Origin",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url).parameter("Origin")
                    .evidence("ACAO reflected: " + acao + " | Vary header does NOT include 'Origin'")
                    .description("The server reflects the Origin in ACAO but omits 'Origin' from the Vary header. "
                            + "If a CDN or caching proxy sits in front, it will cache this response with "
                            + "ACAO set to the attacker's origin and serve it to all subsequent users. "
                            + "This enables cross-origin data theft at scale via web cache poisoning.")
                    .remediation("Always include 'Vary: Origin' when ACAO changes based on the request Origin.")
                    .requestResponse(result)
                    .payload(probeOrigin)
                    .responseEvidence(acao)
                    .build());
        }
        perHostDelay();
    }

    // ==================== PHASE 14: JSONP COEXISTENCE ====================

    private void testJsonpCoexistence(HttpRequestResponse original, String url) throws InterruptedException {
        // If an endpoint supports JSONP, it bypasses CORS entirely — attacker loads
        // the response via a <script> tag regardless of the CORS policy.
        String[] callbackParams = {"callback", "jsonp", "cb", "jsonpcallback", "_callback"};
        String marker = "omnistrikecb";

        for (String param : callbackParams) {
            String sep = url.contains("?") ? "&" : "?";
            String testUrl = url + sep + param + "=" + marker;

            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(testUrl);
                HttpRequestResponse result = api.http().sendRequest(req);
                if (result == null || result.response() == null) { perHostDelay(); continue; }

                int status = result.response().statusCode();
                if (status < 200 || status >= 400) { perHostDelay(); continue; }

                String body = result.response().bodyToString();
                if (body == null || body.isEmpty()) { perHostDelay(); continue; }
                body = body.trim();

                // Verify JSONP: response body starts with our callback name followed by (
                boolean isJsonp = body.startsWith(marker + "(")
                        || body.startsWith("/**/" + marker + "(")
                        || body.startsWith("/**/ " + marker + "(");

                if (isJsonp) {
                    findingsStore.addFinding(Finding.builder("cors-scanner",
                                    "CORS Bypass: JSONP Endpoint ('" + param + "' parameter)",
                                    Severity.HIGH, Confidence.CERTAIN)
                            .url(url).parameter(param)
                            .evidence("GET " + testUrl + " → "
                                    + body.substring(0, Math.min(body.length(), 150)))
                            .description("This endpoint supports JSONP via the '" + param + "' parameter. "
                                    + "JSONP responses are loaded via <script> tags and bypass CORS entirely. "
                                    + "Any website can steal this endpoint's response data cross-origin "
                                    + "regardless of how strict the CORS policy is.")
                            .remediation("Remove JSONP support. Use CORS with a strict origin whitelist. "
                                    + "If JSONP must remain, ensure the endpoint never returns sensitive "
                                    + "or user-specific data.")
                            .requestResponse(result)
                            .payload(marker)
                            .responseEvidence(marker + "(")
                            .build());
                    return; // One JSONP hit is enough
                }
            } catch (Exception e) {
                // skip
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 15: PER-METHOD POLICY DIVERGENCE ====================

    private void testPerMethodDivergence(HttpRequestResponse original, String url) throws InterruptedException {
        // Test if CORS policy differs by HTTP method. If GET rejects the origin but
        // POST or OPTIONS accepts it, the server has inconsistent CORS validation.
        String attackerOrigin = "https://attacker.com";
        String originalMethod = original.request().method();
        String[] methods = {"POST", "OPTIONS"};

        for (String method : methods) {
            // Skip if original request already used this method (already tested in Phase 1)
            if (method.equalsIgnoreCase(originalMethod)) continue;

            try {
                HttpRequest modified = original.request()
                        .withMethod(method)
                        .withRemovedHeader("Origin")
                        .withAddedHeader("Origin", attackerOrigin);

                // For OPTIONS, add preflight headers to simulate a real preflight request
                if ("OPTIONS".equals(method)) {
                    modified = modified.withAddedHeader("Access-Control-Request-Method", "GET");
                }

                HttpRequestResponse result = api.http().sendRequest(modified);
                if (result == null || result.response() == null) { perHostDelay(); continue; }

                String acao = extractAcao(result);
                if (attackerOrigin.equals(acao)) {
                    boolean acac = hasAcac(result);

                    // For OPTIONS, also extract Access-Control-Allow-Methods
                    String allowedMethods = null;
                    if ("OPTIONS".equals(method)) {
                        for (var h : result.response().headers()) {
                            if ("Access-Control-Allow-Methods".equalsIgnoreCase(h.name())) {
                                allowedMethods = h.value();
                                break;
                            }
                        }
                    }

                    findingsStore.addFinding(Finding.builder("cors-scanner",
                                    "CORS: " + method + " Reflects Origin (Per-Method Divergence)",
                                    acac ? Severity.HIGH : Severity.INFO, Confidence.FIRM)
                            .url(url).parameter("Origin")
                            .evidence(method + " Origin: " + attackerOrigin + " | ACAO: " + acao
                                    + " | ACAC: " + acac
                                    + (allowedMethods != null ? " | Allow-Methods: " + allowedMethods : "")
                                    + (acac ? "" : " | Origin reflected but credentials not allowed — cross-origin reads limited to public data"))
                            .description("While " + originalMethod + " requests reject the attacker origin, "
                                    + method + " requests reflect it. "
                                    + ("OPTIONS".equals(method)
                                            ? "The preflight response grants cross-origin access for the methods "
                                              + "listed in Access-Control-Allow-Methods."
                                            : "This per-method policy inconsistency may allow cross-origin "
                                              + "state changes or data reads via " + method + " requests."))
                            .remediation("Apply consistent CORS origin validation across all HTTP methods.")
                            .requestResponse(result)
                            .payload(attackerOrigin)
                            .responseEvidence(acao)
                            .build());
                    return; // One hit proves inconsistency
                }
            } catch (Exception e) {
                // skip
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 16: COLLABORATOR BLIND CORS ====================

    private void testCollaboratorBlindCors(HttpRequestResponse original, String url) throws InterruptedException {
        // Use Burp Collaborator as the Origin domain to detect if the server performs
        // DNS resolution on the Origin value — indicates server-side origin processing.
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return;

        AtomicReference<HttpRequestResponse> sentRr = new AtomicReference<>();
        AtomicReference<String> sentOrigin = new AtomicReference<>();

        String collabPayload = collaboratorManager.generatePayload(
                "cors-scanner", url, "Origin", "CORS Blind OOB DNS",
                interaction -> {
                    findingsStore.addFinding(Finding.builder("cors-scanner",
                                    "CORS: Server-Side Origin Resolution (OOB " + interaction.type().name() + ")",
                                    Severity.LOW, Confidence.CERTAIN)
                            .url(url).parameter("Origin")
                            .evidence("Collaborator " + interaction.type().name()
                                    + " interaction from " + interaction.clientIp()
                                    + " at " + interaction.timeStamp())
                            .description("The server performed a " + interaction.type().name()
                                    + " lookup on the Origin header value. This confirms server-side origin "
                                    + "processing that actively resolves domains. This is unusual behavior that "
                                    + "may indicate custom validation logic susceptible to DNS rebinding attacks "
                                    + "or SSRF via the Origin header.")
                            .remediation("Origin validation should be string-based comparison against an allowlist. "
                                    + "Never resolve the Origin header domain via DNS for validation purposes.")
                            .requestResponse(sentRr.get())
                            .payload(sentOrigin.get())
                            .build());
                });

        if (collabPayload == null) return;

        String origin = "https://" + collabPayload;
        sentOrigin.set(origin);
        HttpRequestResponse result = sendWithOrigin(original, origin);
        sentRr.set(result);
        perHostDelay();
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendWithOrigin(HttpRequestResponse original, String origin) {
        try {
            HttpRequest modified = original.request()
                    .withRemovedHeader("Origin")
                    .withAddedHeader("Origin", origin);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractAcao(HttpRequestResponse response) {
        for (var h : response.response().headers()) {
            if (h.name().equalsIgnoreCase("Access-Control-Allow-Origin")) {
                return h.value().trim();
            }
        }
        return null;
    }

    private boolean hasAcac(HttpRequestResponse response) {
        for (var h : response.response().headers()) {
            if (h.name().equalsIgnoreCase("Access-Control-Allow-Credentials")) {
                return "true".equalsIgnoreCase(h.value().trim());
            }
        }
        return false;
    }

    private String extractDomain(String url) {
        try {
            String noScheme = url.replaceFirst("^https?://", "");
            int slash = noScheme.indexOf('/');
            String hostPort = slash >= 0 ? noScheme.substring(0, slash) : noScheme;
            int colon = hostPort.indexOf(':');
            return colon >= 0 ? hostPort.substring(0, colon) : hostPort;
        } catch (Exception e) {
            return "";
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("cors.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }
}

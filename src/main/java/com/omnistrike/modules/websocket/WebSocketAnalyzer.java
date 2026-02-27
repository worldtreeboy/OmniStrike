package com.omnistrike.modules.websocket;

import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive analysis engine for WebSocket frames.
 * Called on every intercepted frame. All checks require concrete regex-matched evidence
 * to fire — no heuristics, no guessing. Prime directive: ZERO FALSE POSITIVES.
 */
public class WebSocketAnalyzer {

    private static final String MODULE_ID = "ws-scanner";

    private FindingsStore findingsStore;

    // ==================== Sensitive Data Patterns ====================

    // Credit card numbers (Visa, MasterCard, Amex, Discover) with optional separators
    private static final Pattern CC_PATTERN = Pattern.compile(
            "\\b(?:4[0-9]{3}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}" +   // Visa
            "|5[1-5][0-9]{2}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}" +     // MasterCard
            "|3[47][0-9]{2}[\\s-]?[0-9]{6}[\\s-]?[0-9]{5}" +                       // Amex
            "|6(?:011|5[0-9]{2})[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4})\\b" // Discover
    );

    // US Social Security Numbers
    private static final Pattern SSN_PATTERN = Pattern.compile(
            "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"
    );

    // API keys / secrets (common patterns: long hex, base64-ish with key prefixes)
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
            "(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|private[_-]?key)" +
            "[\"'\\s:=]+[\"']?([a-zA-Z0-9_\\-]{20,})[\"']?"
    );

    // Password fields in JSON/form data
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "(?i)(?:\"password\"|\"passwd\"|\"pass\"|\"pwd\"|\"secret\")" +
            "\\s*[:=]\\s*[\"']([^\"']{1,200})[\"']"
    );

    // JWT in message body (not in HTTP headers — those are caught elsewhere)
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
    );

    // Email addresses
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z]{2,}\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Phone numbers (US/international formats)
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\b(?:\\+?1[\\s.-]?)?\\(?[0-9]{3}\\)?[\\s.-]?[0-9]{3}[\\s.-]?[0-9]{4}\\b"
    );

    // SQL error strings (exact match list for zero false positives)
    private static final String[] SQL_ERROR_STRINGS = {
            "SQL syntax", "mysql_fetch", "ORA-0", "ORA-1",
            "PostgreSQL", "pg_query", "sqlite3.", "SQLite3::",
            "Microsoft OLE DB", "ODBC SQL Server", "Unclosed quotation mark",
            "java.sql.SQL", "JDBC", "SqlException",
            "near \"syntax\"", "syntax error at or near"
    };

    // Stack trace patterns
    private static final Pattern STACK_TRACE_PATTERN = Pattern.compile(
            "(?:at\\s+[a-zA-Z0-9$.]+\\([A-Za-z0-9]+\\.java:\\d+\\))" +          // Java
            "|(?:File\\s+\"[^\"]+\",\\s+line\\s+\\d+)" +                           // Python
            "|(?:at\\s+[A-Za-z0-9_$.]+\\s+\\([^)]+:\\d+:\\d+\\))" +               // Node.js
            "|(?:#\\d+\\s+[A-Za-z0-9_\\\\]+->)" +                                  // PHP
            "|(?:Traceback\\s+\\(most recent call last\\))"                          // Python traceback
    );

    // Auth token in URL query parameters
    private static final Pattern URL_TOKEN_PATTERN = Pattern.compile(
            "[?&](?:token|access_token|api_key|apikey|auth|session|jwt|key)=([^&\\s]{8,})",
            Pattern.CASE_INSENSITIVE
    );

    public void setFindingsStore(FindingsStore findingsStore) {
        this.findingsStore = findingsStore;
    }

    /**
     * Analyze a single WebSocket frame. Returns findings (may be empty).
     * Also adds findings directly to FindingsStore for async notification.
     */
    public List<Finding> analyzeMessage(WebSocketMessage message, WebSocketConnection connection) {
        List<Finding> findings = new ArrayList<>();

        if (message.isText() && message.getPayload() != null) {
            String payload = message.getPayload();
            String url = connection.getUpgradeUrl();

            // Sensitive data checks
            checkCreditCards(payload, url, findings);
            checkSSN(payload, url, findings);
            checkApiKeys(payload, url, findings);
            checkPasswords(payload, url, findings);
            checkJwt(payload, url, findings);
            checkPII(payload, url, findings);

            // Error message checks (server-to-client only)
            if (message.getDirection() == WebSocketMessage.Direction.SERVER_TO_CLIENT) {
                checkSqlErrors(payload, url, findings);
                checkStackTraces(payload, url, findings);
            }
        }

        // Add all findings to the store
        if (findingsStore != null) {
            for (Finding f : findings) {
                findingsStore.addFinding(f);
            }
        }

        return findings;
    }

    /**
     * Analyze the upgrade request itself for connection-level issues.
     * Called once when a new connection is established.
     */
    public List<Finding> analyzeConnection(WebSocketConnection connection) {
        List<Finding> findings = new ArrayList<>();
        String url = connection.getUpgradeUrl();

        // Check for unencrypted WebSocket (ws:// instead of wss://)
        if (url != null && url.startsWith("ws://")) {
            findings.add(Finding.builder(MODULE_ID, "Unencrypted WebSocket (ws://)", Severity.MEDIUM, Confidence.CERTAIN)
                    .url(url)
                    .evidence("WebSocket connection uses ws:// (unencrypted): " + url)
                    .description("The WebSocket connection uses the unencrypted ws:// protocol instead of wss://. " +
                            "All WebSocket frames including authentication tokens and sensitive data are transmitted in plaintext.")
                    .remediation("Use wss:// (WebSocket Secure) for all WebSocket connections.")
                    .build());
        }

        // Check for missing Origin header
        if (connection.getOriginHeader() == null) {
            findings.add(Finding.builder(MODULE_ID, "Missing Origin Header on WebSocket Upgrade", Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("No Origin header present in the WebSocket upgrade request")
                    .description("The WebSocket upgrade request does not include an Origin header. " +
                            "This may indicate the connection is not browser-initiated, or Origin validation cannot be performed server-side.")
                    .remediation("Ensure the server validates the Origin header on WebSocket upgrades to prevent Cross-Site WebSocket Hijacking.")
                    .build());
        }

        // Check for no cookies on upgrade (session-less WS)
        if (!connection.isCookiesPresent()) {
            findings.add(Finding.builder(MODULE_ID, "Session-less WebSocket Connection", Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("No cookies present in the WebSocket upgrade request")
                    .description("The WebSocket upgrade request does not contain any cookies. " +
                            "This may mean the connection lacks session binding, potentially allowing unauthorized access.")
                    .remediation("Ensure WebSocket connections are authenticated via cookies, tokens, or other mechanisms.")
                    .build());
        }

        // Check for auth tokens in URL
        if (url != null) {
            Matcher tokenMatcher = URL_TOKEN_PATTERN.matcher(url);
            if (tokenMatcher.find()) {
                findings.add(Finding.builder(MODULE_ID, "Auth Token in WebSocket Upgrade URL", Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence("Token parameter found in upgrade URL: " + tokenMatcher.group())
                        .description("The WebSocket upgrade URL contains an authentication token as a query parameter. " +
                                "This token may be logged in server access logs, browser history, proxy logs, and referrer headers.")
                        .remediation("Pass authentication tokens via headers (e.g., Cookie, Authorization) or the first WebSocket message instead of the URL.")
                        .build());
            }
        }

        // Add all findings to the store
        if (findingsStore != null) {
            for (Finding f : findings) {
                findingsStore.addFinding(f);
            }
        }

        return findings;
    }

    // ==================== Individual Checks ====================

    private void checkCreditCards(String payload, String url, List<Finding> findings) {
        Matcher m = CC_PATTERN.matcher(payload);
        if (m.find()) {
            String matched = m.group();
            // Luhn check to reduce false positives
            if (passesLuhn(matched.replaceAll("[\\s-]", ""))) {
                findings.add(Finding.builder(MODULE_ID, "Credit Card Number in WebSocket Message", Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .evidence("Credit card number detected: " + maskCC(matched))
                        .description("A credit card number was found in a WebSocket message payload. " +
                                "This data is transmitted over the WebSocket connection and may be visible to intermediaries.")
                        .remediation("Never transmit raw credit card numbers. Use tokenization or payment processor APIs.")
                        .build());
            }
        }
    }

    private void checkSSN(String payload, String url, List<Finding> findings) {
        Matcher m = SSN_PATTERN.matcher(payload);
        if (m.find()) {
            findings.add(Finding.builder(MODULE_ID, "SSN in WebSocket Message", Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Possible SSN detected: " + m.group().substring(0, 3) + "-XX-XXXX")
                    .description("A value matching US Social Security Number format was found in a WebSocket message.")
                    .remediation("Never transmit SSNs in plaintext. Use tokenization or mask the value.")
                    .build());
        }
    }

    private void checkApiKeys(String payload, String url, List<Finding> findings) {
        Matcher m = API_KEY_PATTERN.matcher(payload);
        if (m.find()) {
            String keyPreview = m.group(1);
            if (keyPreview.length() > 8) {
                keyPreview = keyPreview.substring(0, 8) + "...";
            }
            findings.add(Finding.builder(MODULE_ID, "API Key/Secret in WebSocket Message", Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("API key/secret detected: " + m.group().substring(0, Math.min(m.group().length(), 40)) + "...")
                    .description("An API key or secret was found in a WebSocket message. This credential could be " +
                            "intercepted and used to access protected resources.")
                    .remediation("Do not transmit API keys through WebSocket messages. Use server-side credential management.")
                    .build());
        }
    }

    private void checkPasswords(String payload, String url, List<Finding> findings) {
        Matcher m = PASSWORD_PATTERN.matcher(payload);
        if (m.find()) {
            findings.add(Finding.builder(MODULE_ID, "Password in WebSocket Message", Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Password field detected in message: " + m.group().replaceAll("(?<=[:=]\\s{0,2}[\"']?).*(?=[\"']?)", "****"))
                    .description("A password value was found in a WebSocket message payload.")
                    .remediation("Never transmit passwords in WebSocket messages. Use secure authentication flows.")
                    .build());
        }
    }

    private void checkJwt(String payload, String url, List<Finding> findings) {
        Matcher m = JWT_PATTERN.matcher(payload);
        if (m.find()) {
            String jwt = m.group();
            String preview = jwt.length() > 50 ? jwt.substring(0, 50) + "..." : jwt;
            findings.add(Finding.builder(MODULE_ID, "JWT in WebSocket Message", Severity.MEDIUM, Confidence.CERTAIN)
                    .url(url)
                    .evidence("JWT found in message body: " + preview)
                    .description("A JSON Web Token was detected in a WebSocket message payload. " +
                            "JWTs typically contain authentication claims and should be transmitted securely.")
                    .remediation("Ensure JWTs are transmitted over encrypted connections (wss://) and consider short expiration times.")
                    .build());
        }
    }

    private void checkPII(String payload, String url, List<Finding> findings) {
        // Email
        Matcher emailMatcher = EMAIL_PATTERN.matcher(payload);
        if (emailMatcher.find()) {
            findings.add(Finding.builder(MODULE_ID, "Email Address in WebSocket Message", Severity.MEDIUM, Confidence.FIRM)
                    .url(url)
                    .evidence("Email address found: " + emailMatcher.group())
                    .description("An email address was found in a WebSocket message, which may constitute PII exposure.")
                    .remediation("Review whether email addresses need to be transmitted via WebSocket. Consider data minimization.")
                    .build());
        }

        // Phone (only flag if not already flagging email from same message, to reduce noise)
        if (!emailMatcher.find()) {
            Matcher phoneMatcher = PHONE_PATTERN.matcher(payload);
            if (phoneMatcher.find()) {
                findings.add(Finding.builder(MODULE_ID, "Phone Number in WebSocket Message", Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Possible phone number found: " + phoneMatcher.group())
                        .description("A value matching phone number format was found in a WebSocket message.")
                        .remediation("Review whether phone numbers need to be transmitted via WebSocket. Consider data minimization.")
                        .build());
            }
        }
    }

    private void checkSqlErrors(String payload, String url, List<Finding> findings) {
        for (String errorStr : SQL_ERROR_STRINGS) {
            if (payload.contains(errorStr)) {
                findings.add(Finding.builder(MODULE_ID, "SQL Error in WebSocket Response", Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("SQL error string detected: " + errorStr)
                        .description("A SQL error message was found in a server-to-client WebSocket message. " +
                                "This may reveal database technology, query structure, or table/column names to an attacker.")
                        .remediation("Implement generic error handling for WebSocket responses. Never expose raw SQL errors to clients.")
                        .build());
                return; // One finding per message is enough
            }
        }
    }

    private void checkStackTraces(String payload, String url, List<Finding> findings) {
        Matcher m = STACK_TRACE_PATTERN.matcher(payload);
        if (m.find()) {
            findings.add(Finding.builder(MODULE_ID, "Stack Trace in WebSocket Response", Severity.LOW, Confidence.FIRM)
                    .url(url)
                    .evidence("Stack trace detected: " + m.group())
                    .description("A stack trace was found in a server-to-client WebSocket message. " +
                            "This reveals internal application structure, file paths, and technology stack.")
                    .remediation("Implement generic error handling. Never expose stack traces to clients in production.")
                    .build());
        }
    }

    // ==================== Utility Methods ====================

    /**
     * Luhn algorithm to validate credit card numbers and reduce false positives.
     */
    private boolean passesLuhn(String number) {
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            char c = number.charAt(i);
            if (!Character.isDigit(c)) return false;
            int n = c - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    /**
     * Masks a credit card number for safe logging (shows first 4 and last 4 digits).
     */
    private String maskCC(String cc) {
        String digits = cc.replaceAll("[\\s-]", "");
        if (digits.length() < 8) return "****";
        return digits.substring(0, 4) + " **** **** " + digits.substring(digits.length() - 4);
    }
}

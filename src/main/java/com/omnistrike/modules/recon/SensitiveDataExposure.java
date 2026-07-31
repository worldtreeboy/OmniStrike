package com.omnistrike.modules.recon;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.ScanTargetIdentity;
import com.omnistrike.framework.BoundedDeduplication;
import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SensitiveDataExposure — passive scanner for PII and sensitive data in responses.
 *
 * Detects credit cards (Luhn-validated), SSNs, bulk emails, phone numbers,
 * internal IPs, JWTs, database connection strings, AWS ARNs, cryptocurrency
 * addresses, and IBANs. All matched values are redacted in findings.
 */
public class SensitiveDataExposure implements ScanModule {

    private static final String MODULE_ID = "sensitive-data";
    private static final int MAX_BODY_SIZE = 512_000;

    private MontoyaApi api;
    private ModuleConfig config;

    // Dedup: "host|path|patternType" → true
    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    // Content types worth scanning
    private static final Set<String> SCANNABLE_TYPES = Set.of(
            "text/html", "text/plain", "text/xml", "text/csv",
            "application/json", "application/xml", "application/xhtml+xml",
            "application/javascript", "text/javascript"
    );

    // ── Pattern definitions ──

    private enum PatternType {
        CREDIT_CARD("Credit Card Number", Severity.HIGH),
        SSN("US Social Security Number", Severity.HIGH),
        EMAIL_BULK("Bulk Email Addresses", Severity.MEDIUM),
        PHONE_BULK("Bulk Phone Numbers", Severity.MEDIUM),
        INTERNAL_IP("Internal IP Address", Severity.LOW),
        JWT("JSON Web Token", Severity.MEDIUM),
        DB_CONNECTION_STRING("Database Connection String", Severity.HIGH),
        AWS_ARN("AWS ARN", Severity.LOW),
        CRYPTO_ADDRESS("Cryptocurrency Address", Severity.LOW),
        IBAN("IBAN Number", Severity.MEDIUM);

        final String displayName;
        final Severity severity;

        PatternType(String displayName, Severity severity) {
            this.displayName = displayName;
            this.severity = severity;
        }
    }

    // Compiled patterns
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b");

    private static final Pattern SSN_PATTERN = Pattern.compile(
            "\\b([0-9]{3})-([0-9]{2})-([0-9]{4})\\b");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b");

    private static final Pattern PHONE_US_PATTERN = Pattern.compile(
            "(?:\\+?1[\\s.-]?)?\\(?[2-9][0-9]{2}\\)?[\\s.-]?[2-9][0-9]{2}[\\s.-]?[0-9]{4}");

    private static final Pattern PHONE_INTL_PATTERN = Pattern.compile(
            "\\+[1-9][0-9]{6,14}");

    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile(
            "\\b(?:10\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}"
                    + "|172\\.(?:1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}"
                    + "|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})\\b");

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    private static final Pattern DB_CONN_PATTERN = Pattern.compile(
            "(?i)(?:jdbc:[a-z]+://[^\\s\"'<>]+|mongodb(?:\\+srv)?://[^\\s\"'<>]+"
                    + "|postgres(?:ql)?://[^\\s\"'<>]+|mysql://[^\\s\"'<>]+"
                    + "|redis://[^\\s\"'<>]+|mssql://[^\\s\"'<>]+)");

    private static final Pattern AWS_ARN_PATTERN = Pattern.compile(
            "arn:aws:[a-z0-9*-]+:[a-z0-9*-]*:[0-9]{0,12}:[a-zA-Z0-9/_+=.@-]+");

    private static final Pattern BTC_ADDRESS_PATTERN = Pattern.compile(
            "\\b(?:1[a-km-zA-HJ-NP-Z0-9]{25,34}|3[a-km-zA-HJ-NP-Z0-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\\b");

    private static final Pattern ETH_ADDRESS_PATTERN = Pattern.compile(
            "\\b0x[0-9a-fA-F]{40}\\b");

    private static final Pattern IBAN_PATTERN = Pattern.compile(
            "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,18})\\b");

    // Excluded email addresses (noise)
    private static final Set<String> EXCLUDED_EMAIL_DOMAINS = Set.of(
            "example.com", "example.org", "example.net", "test.com",
            "localhost", "sentry.io", "w3.org", "schema.org",
            "googleapis.com", "gravatar.com"
    );

    private static final Set<String> EXCLUDED_EMAIL_LOCALS = Set.of(
            "noreply", "no-reply", "admin", "webmaster", "postmaster",
            "hostmaster", "info", "support", "mailer-daemon", "root"
    );

    // ─── ScanModule interface ───

    @Override
    public String getId() { return MODULE_ID; }

    @Override
    public String getName() { return "Sensitive Data Exposure"; }

    @Override
    public String getDescription() {
        return "Detects PII and sensitive data (credit cards, SSNs, emails, JWTs, DB strings, etc.) leaking in HTTP responses.";
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
    public void destroy() { seen.clear(); }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        // Content-type filter
        if (!isScannableContentType(response)) return findings;

        String host;
        String path;
        try {
            host = ScanTargetIdentity.origin(requestResponse.request().url());
            path = requestResponse.request().pathWithoutQuery();
        } catch (Exception e) {
            return findings;
        }
        String url = requestResponse.request().url();

        String body;
        try {
            body = response.bodyToString();
        } catch (Exception e) {
            return findings;
        }
        if (body == null || body.isEmpty()) return findings;
        if (body.length() > MAX_BODY_SIZE) {
            body = body.substring(0, MAX_BODY_SIZE);
        }

        // Run all detectors
        detectCreditCards(body, host, path, url, requestResponse, findings);
        detectSSNs(body, host, path, url, requestResponse, findings);
        detectBulkEmails(body, host, path, url, requestResponse, findings);
        detectBulkPhones(body, host, path, url, requestResponse, findings);
        detectInternalIPs(body, host, path, url, requestResponse, findings);
        detectJWTs(body, host, path, url, requestResponse, findings);
        detectDBConnectionStrings(body, host, path, url, requestResponse, findings);
        detectAWSArns(body, host, path, url, requestResponse, findings);
        detectCryptoAddresses(body, host, path, url, requestResponse, findings);
        detectIBANs(body, host, path, url, requestResponse, findings);

        return findings;
    }

    // ─── Detectors ───

    private void detectCreditCards(String body, String host, String path, String url,
                                   HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.CREDIT_CARD)) return;

        Matcher m = CREDIT_CARD_PATTERN.matcher(body);
        List<String> validated = new ArrayList<>();
        while (m.find() && validated.size() < 10) {
            String num = m.group().replaceAll("[\\s-]", "");
            if (luhnCheck(num)) {
                validated.add(redact(num));
            }
        }
        if (validated.isEmpty()) { undedup(host, path, PatternType.CREDIT_CARD); return; }

        findings.add(buildFinding(PatternType.CREDIT_CARD, url, rr,
                "Found " + validated.size() + " credit card number(s) in response body.",
                String.join("\n", validated),
                "Remove credit card numbers from API responses. Use tokenization or masking."));
    }

    private void detectSSNs(String body, String host, String path, String url,
                            HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.SSN)) return;

        Matcher m = SSN_PATTERN.matcher(body);
        List<String> validated = new ArrayList<>();
        while (m.find() && validated.size() < 10) {
            int area = Integer.parseInt(m.group(1));
            int group = Integer.parseInt(m.group(2));
            int serial = Integer.parseInt(m.group(3));
            // SSN validation: area != 000, 666, 900-999; group != 00; serial != 0000
            if (area > 0 && area != 666 && area < 900 && group > 0 && serial > 0) {
                validated.add(redact(m.group()));
            }
        }
        if (validated.isEmpty()) { undedup(host, path, PatternType.SSN); return; }

        findings.add(buildFinding(PatternType.SSN, url, rr,
                "Found " + validated.size() + " US Social Security Number(s) in response body.",
                String.join("\n", validated),
                "Remove SSNs from responses. Mask or tokenize sensitive identifiers."));
    }

    private void detectBulkEmails(String body, String host, String path, String url,
                                  HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.EMAIL_BULK)) return;

        Matcher m = EMAIL_PATTERN.matcher(body);
        List<String> emails = new ArrayList<>();
        while (m.find() && emails.size() < 50) {
            String email = m.group();
            if (!isExcludedEmail(email)) {
                emails.add(email);
            }
        }
        // Only flag bulk exposure (5+)
        if (emails.size() < 5) { undedup(host, path, PatternType.EMAIL_BULK); return; }

        List<String> redacted = emails.stream().limit(10).map(this::redact).toList();
        findings.add(buildFinding(PatternType.EMAIL_BULK, url, rr,
                "Found " + emails.size() + " email addresses exposed in response body.",
                String.join("\n", redacted) + (emails.size() > 10 ? "\n... and " + (emails.size() - 10) + " more" : ""),
                "Avoid exposing user email addresses in bulk. Implement pagination and access controls."));
    }

    private void detectBulkPhones(String body, String host, String path, String url,
                                  HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.PHONE_BULK)) return;

        Set<String> phones = new LinkedHashSet<>();
        Matcher m1 = PHONE_US_PATTERN.matcher(body);
        while (m1.find() && phones.size() < 50) phones.add(m1.group());
        Matcher m2 = PHONE_INTL_PATTERN.matcher(body);
        while (m2.find() && phones.size() < 50) phones.add(m2.group());

        if (phones.size() < 5) { undedup(host, path, PatternType.PHONE_BULK); return; }

        List<String> redacted = phones.stream().limit(10).map(this::redact).toList();
        findings.add(buildFinding(PatternType.PHONE_BULK, url, rr,
                "Found " + phones.size() + " phone numbers exposed in response body.",
                String.join("\n", redacted) + (phones.size() > 10 ? "\n... and " + (phones.size() - 10) + " more" : ""),
                "Avoid exposing phone numbers in bulk. Implement access controls and data masking."));
    }

    private void detectInternalIPs(String body, String host, String path, String url,
                                   HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.INTERNAL_IP)) return;

        Matcher m = INTERNAL_IP_PATTERN.matcher(body);
        Set<String> ips = new LinkedHashSet<>();
        while (m.find() && ips.size() < 20) {
            String ip = m.group();
            // Validate octets are 0-255
            if (isValidIp(ip)) {
                ips.add(ip);
            }
        }
        if (ips.isEmpty()) { undedup(host, path, PatternType.INTERNAL_IP); return; }

        findings.add(buildFinding(PatternType.INTERNAL_IP, url, rr,
                "Found " + ips.size() + " internal (RFC 1918) IP address(es) in response body.",
                String.join("\n", ips),
                "Remove internal IP addresses from responses to prevent network topology disclosure."));
    }

    private void detectJWTs(String body, String host, String path, String url,
                            HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.JWT)) return;

        Matcher m = JWT_PATTERN.matcher(body);
        List<String> jwts = new ArrayList<>();
        while (m.find() && jwts.size() < 5) {
            jwts.add(redact(m.group()));
        }
        if (jwts.isEmpty()) { undedup(host, path, PatternType.JWT); return; }

        findings.add(buildFinding(PatternType.JWT, url, rr,
                "Found " + jwts.size() + " JWT token(s) exposed in response body.",
                String.join("\n", jwts),
                "Avoid exposing JWT tokens in response bodies. Deliver tokens only via secure headers or HttpOnly cookies."));
    }

    private void detectDBConnectionStrings(String body, String host, String path, String url,
                                           HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.DB_CONNECTION_STRING)) return;

        Matcher m = DB_CONN_PATTERN.matcher(body);
        List<String> conns = new ArrayList<>();
        while (m.find() && conns.size() < 5) {
            conns.add(redact(m.group()));
        }
        if (conns.isEmpty()) { undedup(host, path, PatternType.DB_CONNECTION_STRING); return; }

        findings.add(buildFinding(PatternType.DB_CONNECTION_STRING, url, rr,
                "Found " + conns.size() + " database connection string(s) in response body.",
                String.join("\n", conns),
                "Never expose database connection strings in responses. Use environment variables and server-side configuration."));
    }

    private void detectAWSArns(String body, String host, String path, String url,
                               HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.AWS_ARN)) return;

        Matcher m = AWS_ARN_PATTERN.matcher(body);
        List<String> arns = new ArrayList<>();
        while (m.find() && arns.size() < 5) {
            arns.add(redact(m.group()));
        }
        if (arns.isEmpty()) { undedup(host, path, PatternType.AWS_ARN); return; }

        findings.add(buildFinding(PatternType.AWS_ARN, url, rr,
                "Found " + arns.size() + " AWS ARN(s) in response body.",
                String.join("\n", arns),
                "Remove AWS ARNs from public responses to prevent cloud resource enumeration."));
    }

    private void detectCryptoAddresses(String body, String host, String path, String url,
                                       HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.CRYPTO_ADDRESS)) return;

        List<String> addrs = new ArrayList<>();
        Matcher btc = BTC_ADDRESS_PATTERN.matcher(body);
        while (btc.find() && addrs.size() < 5) addrs.add("BTC: " + redact(btc.group()));
        Matcher eth = ETH_ADDRESS_PATTERN.matcher(body);
        while (eth.find() && addrs.size() < 5) addrs.add("ETH: " + redact(eth.group()));

        if (addrs.isEmpty()) { undedup(host, path, PatternType.CRYPTO_ADDRESS); return; }

        findings.add(buildFinding(PatternType.CRYPTO_ADDRESS, url, rr,
                "Found " + addrs.size() + " cryptocurrency address(es) in response body.",
                String.join("\n", addrs),
                "Review whether cryptocurrency addresses should be exposed in responses."));
    }

    private void detectIBANs(String body, String host, String path, String url,
                             HttpRequestResponse rr, List<Finding> findings) {
        if (!dedup(host, path, PatternType.IBAN)) return;

        Matcher m = IBAN_PATTERN.matcher(body);
        List<String> validated = new ArrayList<>();
        while (m.find() && validated.size() < 10) {
            String iban = m.group();
            if (validateIbanCheckDigit(iban)) {
                validated.add(redact(iban));
            }
        }
        if (validated.isEmpty()) { undedup(host, path, PatternType.IBAN); return; }

        findings.add(buildFinding(PatternType.IBAN, url, rr,
                "Found " + validated.size() + " IBAN number(s) in response body.",
                String.join("\n", validated),
                "Remove IBAN numbers from responses. Mask or tokenize financial identifiers."));
    }

    // ─── Helpers ───

    private boolean isScannableContentType(HttpResponse response) {
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                String ct = header.value().toLowerCase();
                for (String type : SCANNABLE_TYPES) {
                    if (ct.contains(type)) return true;
                }
                return false;
            }
        }
        // No Content-Type header → scan it (might be useful)
        return true;
    }

    /**
     * Attempt dedup. Returns true if this is the first time seeing this combination.
     */
    private boolean dedup(String host, String path, PatternType type) {
        String key = host + "|" + path + "|" + type.name();
        return BoundedDeduplication.markIfNew(seen, key);
    }

    /**
     * Remove dedup entry if no match was found (allow re-scan on different response).
     */
    private void undedup(String host, String path, PatternType type) {
        String key = host + "|" + path + "|" + type.name();
        seen.remove(key);
    }

    private Finding buildFinding(PatternType type, String url, HttpRequestResponse rr,
                                 String description, String evidence, String remediation) {
        return Finding.builder(MODULE_ID, type.displayName, type.severity, Confidence.FIRM)
                .url(url)
                .description(description)
                .evidence(evidence)
                .remediation(remediation)
                .requestResponse(rr)
                .build();
    }

    /**
     * Redact a value to show only first 4 and last 4 characters.
     */
    private String redact(String value) {
        if (value == null) return "";
        if (value.length() <= 8) return "****";
        return value.substring(0, 4) + "..." + value.substring(value.length() - 4);
    }

    /**
     * Luhn algorithm for credit card validation.
     */
    private static boolean luhnCheck(String number) {
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            char c = number.charAt(i);
            if (c < '0' || c > '9') return false;
            int n = c - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum > 0 && sum % 10 == 0;
    }

    /**
     * Validate IP address octets are in 0-255 range.
     */
    private static boolean isValidIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private boolean isExcludedEmail(String email) {
        int atIdx = email.indexOf('@');
        if (atIdx < 0) return true;
        String local = email.substring(0, atIdx).toLowerCase();
        String domain = email.substring(atIdx + 1).toLowerCase();
        return EXCLUDED_EMAIL_DOMAINS.contains(domain) || EXCLUDED_EMAIL_LOCALS.contains(local);
    }

    /**
     * IBAN check digit validation (ISO 13616).
     * Move first 4 chars to end, convert letters A=10..Z=35, mod 97 == 1.
     */
    private static boolean validateIbanCheckDigit(String iban) {
        if (iban.length() < 5) return false;
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        StringBuilder numeric = new StringBuilder();
        for (char c : rearranged.toCharArray()) {
            if (Character.isLetter(c)) {
                numeric.append(Character.toUpperCase(c) - 'A' + 10);
            } else if (Character.isDigit(c)) {
                numeric.append(c);
            } else {
                return false;
            }
        }
        try {
            java.math.BigInteger value = new java.math.BigInteger(numeric.toString());
            return value.mod(java.math.BigInteger.valueOf(97)).intValue() == 1;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

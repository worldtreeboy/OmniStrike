package com.omnistrike.framework;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Best-effort, structure-preserving redaction for text that may leave the extension
 * or be displayed in privacy mode.
 *
 * <p>The redactor understands HTTP headers, cookies, authorization schemes, common
 * JSON/XML/form key-value shapes, and well-known secret/PII formats. Replacements
 * are deterministic within one call: repeated source values receive the same typed
 * placeholder so an AI can still reason about data flow without seeing the value.
 */
public final class SensitiveDataRedactor {

    private SensitiveDataRedactor() {}

    private static final Pattern HEADER_LINE = Pattern.compile(
            "(?m)^([A-Za-z][A-Za-z0-9-]{0,80})(:[ \\t]*)([^\\r\\n]*)$");
    private static final Pattern JSON_FIELD = Pattern.compile(
            "([\"'])([A-Za-z_][A-Za-z0-9_.-]{0,79})\\1(\\s*:\\s*)"
                    + "(\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|[^,}\\]\\r\\n]+)");
    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,79})(\\s*=\\s*)"
                    + "(\"[^\"]*\"|'[^']*'|[^&;\\s<>\"']+)");
    private static final Pattern TEMPLATE_VALUE = Pattern.compile(
            "(?m)(\\{\\{\\s*([A-Za-z_][A-Za-z0-9_.-]{0,79})\\s*}}\\s*=\\s*)([^\\r\\n]+)");
    private static final Pattern XML_ELEMENT = Pattern.compile(
            "(?is)(<([A-Za-z_][A-Za-z0-9_.:-]{0,79})(?:\\s[^>]*)?>)([^<]*)(</\\2\\s*>)");
    private static final Pattern XML_ATTRIBUTE = Pattern.compile(
            "(?is)(\\b([A-Za-z_][A-Za-z0-9_.:-]{0,79})\\s*=\\s*)([\"'])(.*?)\\3");
    private static final Pattern URL_USERINFO = Pattern.compile(
            "(?i)(\\b[a-z][a-z0-9+.-]*://)([^/@\\s:]+):([^/@\\s]+)@");
    private static final Pattern URL_HOST = Pattern.compile(
            "(?i)(\\b[a-z][a-z0-9+.-]*://(?:[^/@\\s]+@)?)(\\[[0-9a-f:]+]|(?:[a-z0-9-]+\\.)*[a-z0-9-]+)(:\\d{1,5})?");
    private static final Pattern URL_QUERY = Pattern.compile(
            "(?m)\\?[^\\s#\\r\\n]*");
    private static final Pattern QUERY_FIELD = Pattern.compile(
            "(?i)([?&])([A-Za-z_][A-Za-z0-9_.-]{0,79})=([^&#\\s]*)");
    private static final Pattern FORM_ENCODED_LINE = Pattern.compile(
            "(?m)^([A-Za-z_][A-Za-z0-9_.-]{0,79}=[^&\\r\\n]*(?:&[A-Za-z_][A-Za-z0-9_.-]{0,79}=[^&\\r\\n]*)+)$");
    private static final Pattern NAMED_VALUE_LINE = Pattern.compile(
            "(?m)^([A-Za-z_][A-Za-z0-9_.-]{0,79})(\\s*=\\s*)([^\\r\\n]*)$");

    private static final Pattern EMAIL = Pattern.compile(
            "(?i)\\b[A-Z0-9._%+\\-]+@[A-Z0-9.\\-]+\\.[A-Z]{2,}\\b");
    private static final Pattern JWT = Pattern.compile(
            "\\beyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b");
    private static final Pattern CREDIT_CARD_CANDIDATE = Pattern.compile(
            "(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)");
    private static final Pattern SSN = Pattern.compile(
            "\\b(?!000|666|9\\d\\d)(\\d{3})-(?!00)(\\d{2})-(?!0000)(\\d{4})\\b");
    private static final Pattern IBAN = Pattern.compile(
            "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b");
    private static final Pattern INTERNATIONAL_PHONE = Pattern.compile(
            "(?<![A-Za-z0-9])\\+[1-9]\\d{7,14}(?!\\d)");
    private static final Pattern SINGAPORE_NRIC_FIN = Pattern.compile(
            "(?i)\\b[STFGM]\\d{7}[A-Z]\\b");
    private static final Pattern UUID = Pattern.compile(
            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\b");
    private static final Pattern IPV4 = Pattern.compile(
            "(?<![A-Za-z0-9])(?:\\d{1,3}\\.){3}\\d{1,3}(?![A-Za-z0-9])");
    private static final Pattern MAC_ADDRESS = Pattern.compile(
            "(?i)\\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\\b");
    private static final Pattern ENTROPY_TOKEN = Pattern.compile(
            "(?<![A-Za-z0-9_])[A-Za-z0-9_+/=-]{24,512}(?![A-Za-z0-9_])");
    private static final Pattern PRIVATE_KEY = Pattern.compile(
            "(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \\1-----");

    private static final Pattern GITHUB_TOKEN = Pattern.compile(
            "\\b(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255})\\b");
    private static final Pattern AWS_ACCESS_KEY = Pattern.compile(
            "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b");
    private static final Pattern GOOGLE_API_KEY = Pattern.compile(
            "\\bAIza[0-9A-Za-z_-]{35}\\b");
    private static final Pattern OPENAI_KEY = Pattern.compile(
            "\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\\b");
    private static final Pattern STRIPE_SECRET = Pattern.compile(
            "\\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\\b");
    private static final Pattern SLACK_TOKEN = Pattern.compile(
            "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b");
    private static final Pattern REDACTED_PLACEHOLDER = Pattern.compile(
            "^\\[REDACTED_[A-Z0-9_]+(?:_\\d+)?]$");

    private static final Set<String> EXACT_SENSITIVE_NAMES = Set.of(
            "password", "passwd", "pwd", "passphrase", "pin", "secret",
            "token", "accesstoken", "refreshtoken", "idtoken", "authtoken",
            "bearertoken", "session", "sessionid", "sessionkey", "cookie",
            "authorization", "credential", "credentials", "apikey", "apisecret",
            "clientsecret", "privatekey", "secretkey", "accesskey", "signingkey",
            "encryptionkey", "csrf", "csrftoken", "xsrf", "xsrftoken",
            "card", "cardnumber", "creditcard", "creditcardnumber", "pan",
            "cvv", "cvc", "securitycode", "ssn", "socialsecuritynumber",
            "email", "emailaddress", "mail", "phone", "phonenumber", "mobile",
            "iban", "bankaccount", "accountnumber", "routingnumber",
            "username", "userid", "login", "dob", "dateofbirth",
            "address", "street", "postalcode", "zipcode",
            "firstname", "lastname", "fullname", "legalname", "customername",
            "contactname", "filename", "passport", "passportnumber", "nationalid",
            "nric", "fin", "patientid", "medicalrecordnumber", "mrn");

    private static final Set<String> PRIVATE_HEADERS = Set.of(
            "host", "origin", "referer", "location", "user-agent", "from",
            "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-server",
            "x-real-ip", "x-client-ip", "x-remote-addr", "x-original-url",
            "x-rewrite-url", "x-request-id", "x-correlation-id", "traceparent",
            "tracestate", "baggage", "cf-connecting-ip", "true-client-ip");

    /** Redacts sensitive values while retaining structural and type context. */
    public static String redact(String input) {
        if (input == null || input.isEmpty()) return input;

        Context context = new Context();
        String output = replaceMatches(input, PRIVATE_KEY,
                m -> context.placeholder("PRIVATE_KEY", m.group()));
        output = redactHeaders(output, context);
        output = redactUrlUserInfo(output, context);
        output = redactUrlHosts(output, context);
        output = redactUrlQueryValues(output, context);
        output = redactFormEncodedLines(output, context);
        output = redactNamedValueLines(output, context);
        output = redactTemplateValues(output, context);
        output = redactJsonFields(output, context);
        output = redactXmlElements(output, context);
        output = redactXmlAttributes(output, context);
        output = redactKeyValues(output, context);

        output = replaceTyped(output, JWT, "JWT", context);
        output = replaceTyped(output, GITHUB_TOKEN, "GITHUB_TOKEN", context);
        output = replaceTyped(output, AWS_ACCESS_KEY, "AWS_ACCESS_KEY", context);
        output = replaceTyped(output, GOOGLE_API_KEY, "GOOGLE_API_KEY", context);
        output = replaceTyped(output, OPENAI_KEY, "API_KEY", context);
        output = replaceTyped(output, STRIPE_SECRET, "STRIPE_KEY", context);
        output = replaceTyped(output, SLACK_TOKEN, "SLACK_TOKEN", context);
        output = replaceTyped(output, EMAIL, "EMAIL", context);
        output = redactCreditCards(output, context);
        output = replaceTyped(output, SSN, "SSN", context);
        output = replaceTyped(output, IBAN, "IBAN", context);
        output = replaceTyped(output, INTERNATIONAL_PHONE, "PHONE", context);
        output = replaceTyped(output, SINGAPORE_NRIC_FIN, "NATIONAL_ID", context);
        output = replaceTyped(output, UUID, "IDENTIFIER", context);
        output = replaceMatches(output, IPV4, matcher ->
                isValidIpv4(matcher.group())
                        ? context.placeholder("IP_ADDRESS", matcher.group())
                        : matcher.group());
        output = replaceTyped(output, MAC_ADDRESS, "MAC_ADDRESS", context);
        output = replaceMatches(output, ENTROPY_TOKEN, matcher ->
                looksLikeSecretToken(matcher.group())
                        ? context.placeholder("HIGH_ENTROPY", matcher.group())
                        : matcher.group());
        return output;
    }

    /** Returns a fixed display placeholder without retaining any part of the value. */
    public static String maskValue(String type, String value) {
        if (value == null || value.isEmpty()) return value;
        String normalizedType = normalizeType(type);
        return "[REDACTED_" + normalizedType + "]";
    }

    private static String redactHeaders(String input, Context context) {
        return replaceMatches(input, HEADER_LINE, matcher -> {
            String name = matcher.group(1);
            String separator = matcher.group(2);
            String value = matcher.group(3);
            String lower = name.toLowerCase(Locale.ROOT);

            if ("cookie".equals(lower)) {
                return name + separator + redactCookieHeader(value, context, "COOKIE", false);
            }
            if ("set-cookie".equals(lower)) {
                return name + separator + redactCookieHeader(value, context, "SET_COOKIE", true);
            }
            if ("authorization".equals(lower) || "proxy-authorization".equals(lower)) {
                return name + separator + redactAuthorization(value, context);
            }
            if (isSensitiveName(name)) {
                return name + separator + preserveOuterQuotes(
                        value, context.placeholder(categoryForName(name), stripOuterQuotes(value)));
            }
            if (isPrivateHeader(lower)) {
                // Let the URL pass redact its host/query components so equivalent
                // Host, Origin, Referer, Location and absolute-URL values share a
                // deterministic placeholder. This preserves same-origin reasoning.
                if ("origin".equals(lower) || "referer".equals(lower)
                        || "location".equals(lower)) {
                    return matcher.group();
                }
                String category = lower.contains("host") ? "HOST"
                        : lower.contains("ip") || "forwarded".equals(lower) ? "IP_ADDRESS"
                        : lower.contains("url") ? "URL"
                        : "HEADER_VALUE";
                return name + separator + preserveOuterQuotes(
                        value, context.placeholder(category, stripOuterQuotes(value)));
            }
            return matcher.group();
        });
    }

    private static boolean isPrivateHeader(String lowerName) {
        if (PRIVATE_HEADERS.contains(lowerName)) return true;
        if (!lowerName.startsWith("x-")) return false;
        return !Set.of("x-powered-by", "x-content-type-options", "x-frame-options",
                "x-xss-protection", "x-dns-prefetch-control", "x-download-options",
                "x-permitted-cross-domain-policies").contains(lowerName);
    }

    private static String redactCookieHeader(
            String value, Context context, String type, boolean setCookie) {
        if (value == null || value.isEmpty()) return value;
        String[] parts = value.split(";", -1);
        int limit = setCookie ? Math.min(parts.length, 1) : parts.length;
        for (int i = 0; i < limit; i++) {
            String part = parts[i];
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            String raw = part.substring(eq + 1).trim();
            if (raw.isEmpty() || isPlaceholder(stripOuterQuotes(raw))) continue;
            String masked = preserveOuterQuotes(
                    raw, context.placeholder(type, stripOuterQuotes(raw)));
            int valueStart = eq + 1;
            String spacing = part.substring(valueStart,
                    valueStart + (part.substring(valueStart).length()
                            - part.substring(valueStart).stripLeading().length()));
            parts[i] = part.substring(0, valueStart) + spacing + masked;
        }
        return String.join(";", parts);
    }

    private static String redactAuthorization(String value, Context context) {
        if (value == null || value.isBlank()) return value;
        String trimmed = value.trim();
        if (isPlaceholder(trimmed)) return value;
        int space = trimmed.indexOf(' ');
        if (space > 0) {
            String scheme = trimmed.substring(0, space);
            String credential = trimmed.substring(space + 1).trim();
            return scheme + " " + context.placeholder("AUTH", credential);
        }
        return context.placeholder("AUTH", trimmed);
    }

    private static String redactUrlUserInfo(String input, Context context) {
        return replaceMatches(input, URL_USERINFO, matcher ->
                matcher.group(1)
                        + context.placeholder("USERNAME", matcher.group(2))
                        + ":"
                        + context.placeholder("PASSWORD", matcher.group(3))
                        + "@");
    }

    private static String redactUrlHosts(String input, Context context) {
        return replaceMatches(input, URL_HOST, matcher ->
                matcher.group(1)
                        + context.placeholder("HOST", matcher.group(2))
                        + (matcher.group(3) != null ? matcher.group(3) : ""));
    }

    private static String redactUrlQueryValues(String input, Context context) {
        return replaceMatches(input, URL_QUERY, queryMatcher -> {
            String query = queryMatcher.group();
            return replaceMatches(query, QUERY_FIELD, fieldMatcher -> {
                String raw = fieldMatcher.group(3);
                if (raw == null || raw.isEmpty() || isPlaceholder(raw)) {
                    return fieldMatcher.group();
                }
                String key = fieldMatcher.group(2);
                String category = isSensitiveName(key) ? categoryForName(key) : "QUERY_VALUE";
                return fieldMatcher.group(1) + key + "=" + context.placeholder(category, raw);
            });
        });
    }

    private static String redactFormEncodedLines(String input, Context context) {
        return replaceMatches(input, FORM_ENCODED_LINE, matcher -> {
            String[] fields = matcher.group(1).split("&", -1);
            for (int i = 0; i < fields.length; i++) {
                int equals = fields[i].indexOf('=');
                if (equals <= 0 || equals == fields[i].length() - 1) continue;
                String key = fields[i].substring(0, equals);
                String raw = fields[i].substring(equals + 1);
                if (isPlaceholder(raw)) continue;
                String category = isSensitiveName(key) ? categoryForName(key) : "FORM_VALUE";
                fields[i] = key + "=" + context.placeholder(category, raw);
            }
            return String.join("&", fields);
        });
    }

    private static String redactNamedValueLines(String input, Context context) {
        return replaceMatches(input, NAMED_VALUE_LINE, matcher -> {
            String key = matcher.group(1);
            String raw = matcher.group(3);
            if (!isSensitiveName(key) || raw.isBlank() || raw.contains("&")
                    || isPlaceholder(stripOuterQuotes(raw))) {
                return matcher.group();
            }
            return key + matcher.group(2) + preserveOuterQuotes(
                    raw, context.placeholder(categoryForName(key), stripOuterQuotes(raw)));
        });
    }

    private static String redactTemplateValues(String input, Context context) {
        return replaceMatches(input, TEMPLATE_VALUE, matcher -> {
            String name = matcher.group(2);
            String raw = matcher.group(3).trim();
            if (raw.isEmpty() || isPlaceholder(stripOuterQuotes(raw))) return matcher.group();
            String type = isSensitiveName(name) ? categoryForName(name) : "VALUE";
            return matcher.group(1) + context.placeholder(type, stripOuterQuotes(raw));
        });
    }

    private static String redactJsonFields(String input, Context context) {
        return replaceMatches(input, JSON_FIELD, matcher -> {
            String key = matcher.group(2);
            if (!isSensitiveName(key)) return matcher.group();
            String raw = matcher.group(4);
            String trimmed = raw.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")
                    || "null".equalsIgnoreCase(trimmed)) {
                return matcher.group();
            }
            String masked = preserveOuterQuotes(
                    raw, context.placeholder(categoryForName(key), stripOuterQuotes(raw)));
            return matcher.group(1) + key + matcher.group(1) + matcher.group(3) + masked;
        });
    }

    private static String redactKeyValues(String input, Context context) {
        return replaceMatches(input, KEY_VALUE, matcher -> {
            String key = matcher.group(1);
            if (!isSensitiveName(key)) return matcher.group();
            String raw = matcher.group(3);
            if (isPlaceholder(stripOuterQuotes(raw))) return matcher.group();
            return key + matcher.group(2) + preserveOuterQuotes(
                    raw, context.placeholder(categoryForName(key), stripOuterQuotes(raw)));
        });
    }

    private static String redactXmlElements(String input, Context context) {
        return replaceMatches(input, XML_ELEMENT, matcher -> {
            String key = localName(matcher.group(2));
            String raw = matcher.group(3);
            if (!isSensitiveName(key) || raw.isBlank() || isPlaceholder(raw.trim())) {
                return matcher.group();
            }
            return matcher.group(1)
                    + context.placeholder(categoryForName(key), raw.trim())
                    + matcher.group(4);
        });
    }

    private static String redactXmlAttributes(String input, Context context) {
        return replaceMatches(input, XML_ATTRIBUTE, matcher -> {
            String key = localName(matcher.group(2));
            if (!isSensitiveName(key)) return matcher.group();
            String raw = matcher.group(4);
            if (raw.isEmpty() || isPlaceholder(raw)) return matcher.group();
            return matcher.group(1) + matcher.group(3)
                    + context.placeholder(categoryForName(key), raw)
                    + matcher.group(3);
        });
    }

    private static String redactCreditCards(String input, Context context) {
        return replaceMatches(input, CREDIT_CARD_CANDIDATE, matcher -> {
            String candidate = matcher.group();
            String digits = candidate.replace(" ", "").replace("-", "");
            if (digits.length() < 13 || digits.length() > 19 || !luhnCheck(digits)) {
                return candidate;
            }
            return context.placeholder("CARD", digits);
        });
    }

    private static String replaceTyped(
            String input, Pattern pattern, String type, Context context) {
        return replaceMatches(input, pattern,
                matcher -> context.placeholder(type, matcher.group()));
    }

    private static String replaceMatches(
            String input, Pattern pattern, Function<Matcher, String> replacement) {
        Matcher matcher = pattern.matcher(input);
        StringBuffer output = new StringBuffer(input.length());
        while (matcher.find()) {
            matcher.appendReplacement(output,
                    Matcher.quoteReplacement(replacement.apply(matcher)));
        }
        matcher.appendTail(output);
        return output.toString();
    }

    static boolean isSensitiveName(String rawName) {
        if (rawName == null || rawName.isBlank()) return false;
        String name = normalizeName(localName(rawName));
        if (EXACT_SENSITIVE_NAMES.contains(name)) return true;
        return name.endsWith("password")
                || name.endsWith("passwd")
                || name.endsWith("passphrase")
                || name.endsWith("token")
                || name.endsWith("secret")
                || name.endsWith("apikey")
                || name.endsWith("privatekey")
                || name.endsWith("sessionid")
                || name.endsWith("cookie")
                || name.endsWith("credential")
                || name.endsWith("cardnumber")
                || name.endsWith("email")
                || name.endsWith("phonenumber")
                || name.endsWith("accountnumber");
    }

    private static String categoryForName(String rawName) {
        String name = normalizeName(localName(rawName));
        if (name.contains("email") || "mail".equals(name)) return "EMAIL";
        if (name.contains("card") || "pan".equals(name)
                || name.contains("cvv") || name.contains("cvc")) return "CARD";
        if (name.contains("password") || name.contains("passwd")
                || "pwd".equals(name) || name.contains("passphrase")
                || "pin".equals(name)) return "PASSWORD";
        if (name.contains("cookie")) return "COOKIE";
        if (name.contains("session")) return "SESSION";
        if (name.contains("token") || name.contains("csrf") || name.contains("xsrf")) return "TOKEN";
        if (name.contains("authorization") || name.contains("bearer")) return "AUTH";
        if (name.contains("key") || name.contains("secret")) return "API_KEY";
        if (name.contains("ssn") || name.contains("socialsecurity")) return "SSN";
        if (name.contains("phone") || name.contains("mobile")) return "PHONE";
        if (name.contains("iban") || name.contains("bank")
                || name.contains("account") || name.contains("routing")) return "BANK";
        if (name.contains("passport") || name.contains("nationalid")
                || "nric".equals(name) || "fin".equals(name)) return "NATIONAL_ID";
        if (name.contains("user") || name.contains("login") || name.contains("name")) {
            return "IDENTITY";
        }
        if (name.contains("file")) return "FILE";
        if (name.contains("patient") || name.contains("medical") || "mrn".equals(name)) {
            return "HEALTH_ID";
        }
        if (name.contains("address") || name.contains("street")
                || name.contains("postal") || name.contains("zip")) return "ADDRESS";
        if (name.contains("dob") || name.contains("birth")) return "DOB";
        return "SECRET";
    }

    private static String normalizeName(String name) {
        return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static String normalizeType(String type) {
        String normalized = type == null ? "VALUE"
                : type.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
        normalized = normalized.replaceAll("^_+|_+$", "");
        return normalized.isEmpty() ? "VALUE" : normalized;
    }

    private static String localName(String name) {
        int colon = name == null ? -1 : name.lastIndexOf(':');
        return colon >= 0 ? name.substring(colon + 1) : name;
    }

    private static boolean isPlaceholder(String value) {
        return value != null && REDACTED_PLACEHOLDER.matcher(value.trim()).matches();
    }

    private static String stripOuterQuotes(String value) {
        if (value == null) return "";
        String trimmed = value.trim();
        if (trimmed.length() >= 2) {
            char first = trimmed.charAt(0);
            char last = trimmed.charAt(trimmed.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return trimmed.substring(1, trimmed.length() - 1);
            }
        }
        return trimmed;
    }

    private static String preserveOuterQuotes(String original, String replacement) {
        if (original == null) return replacement;
        String trimmed = original.trim();
        String leading = original.substring(0, original.indexOf(trimmed));
        String trailing = original.substring(original.indexOf(trimmed) + trimmed.length());
        if (trimmed.length() >= 2) {
            char first = trimmed.charAt(0);
            char last = trimmed.charAt(trimmed.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return leading + first + replacement + last + trailing;
            }
        }
        return leading + replacement + trailing;
    }

    private static boolean isValidIpv4(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) return false;
        for (String octet : octets) {
            try {
                if (octet.isEmpty() || Integer.parseInt(octet) > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static boolean looksLikeSecretToken(String value) {
        if (value == null || value.length() < 24 || value.startsWith("REDACTED_")) return false;
        boolean upper = false, lower = false, digit = false, symbol = false;
        boolean[] seen = new boolean[128];
        int distinct = 0;
        int[] frequency = new int[128];
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else symbol = true;
            if (c < 128) {
                frequency[c]++;
                if (!seen[c]) {
                    seen[c] = true;
                    distinct++;
                }
            }
        }
        if (distinct < 10 || !digit || !(upper || lower)) return false;
        double entropy = 0.0;
        for (int count : frequency) {
            if (count == 0) continue;
            double probability = (double) count / value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        boolean mixed = (upper && lower) || symbol;
        boolean longHex = value.length() >= 32 && value.matches("(?i)[0-9a-f]+") && distinct >= 12;
        return longHex || (mixed && entropy >= 3.6);
    }

    static boolean luhnCheck(String digits) {
        int sum = 0;
        boolean doubleDigit = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            char c = digits.charAt(i);
            if (!Character.isDigit(c)) return false;
            int value = c - '0';
            if (doubleDigit) {
                value *= 2;
                if (value > 9) value -= 9;
            }
            sum += value;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    private static final class Context {
        private final Map<String, String> placeholders = new LinkedHashMap<>();
        private final Map<String, Integer> counters = new HashMap<>();

        String placeholder(String type, String rawValue) {
            String raw = rawValue == null ? "" : rawValue;
            if (isPlaceholder(raw)) return raw;
            String existing = placeholders.get(raw);
            if (existing != null) return existing;
            String normalizedType = normalizeType(type);
            int number = counters.merge(normalizedType, 1, Integer::sum);
            String placeholder = "[REDACTED_" + normalizedType + "_" + number + "]";
            placeholders.put(raw, placeholder);
            return placeholder;
        }
    }
}

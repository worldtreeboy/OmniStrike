package com.omnistrike.framework;

/**
 * Smart URL encoder for scanner payloads.
 * Encodes only characters that break HTTP/URL syntax (space, &amp;, #, +)
 * while preserving existing percent-encoded sequences (%0a, %00, %252e, etc.).
 *
 * This prevents double-encoding of pre-encoded bypass payloads while still
 * producing valid HTTP requests.
 */
public final class PayloadEncoder {

    private PayloadEncoder() {}

    /**
     * Encode a payload value for use in a URL query string or form-encoded body.
     * Preserves existing %XX sequences, encodes only HTTP-breaking characters.
     *
     * @param payload The raw payload string (may contain pre-encoded sequences)
     * @return Encoded string safe for URL/body parameter values
     */
    public static String encode(String payload) {
        if (payload == null) return null;

        StringBuilder sb = new StringBuilder(payload.length() + 16);
        int len = payload.length();

        for (int i = 0; i < len; i++) {
            char c = payload.charAt(i);

            // Preserve existing %XX sequences (pre-encoded bypass payloads)
            if (c == '%' && i + 2 < len && isHex(payload.charAt(i + 1)) && isHex(payload.charAt(i + 2))) {
                sb.append(c);
                sb.append(payload.charAt(i + 1));
                sb.append(payload.charAt(i + 2));
                i += 2;
                continue;
            }

            // Encode characters that break HTTP request line or URL/body parameter parsing
            switch (c) {
                case ' ':  sb.append("%20"); break;
                case '"':  sb.append("%22"); break;  // Breaks parameter quoting
                case '&':  sb.append("%26"); break;
                case '#':  sb.append("%23"); break;
                case '+':  sb.append("%2B"); break;
                case ';':  sb.append("%3B"); break;  // Parameter separator in some servers
                case '{':  sb.append("%7B"); break;  // Breaks JSON/serialized payloads in params
                case '}':  sb.append("%7D"); break;
                case '\\': sb.append("%5C"); break;
                case '%':  sb.append("%25"); break;  // Bare % not followed by hex digits
                case '\r': sb.append("%0D"); break;
                case '\n': sb.append("%0A"); break;
                default:   sb.append(c);     break;
            }
        }

        return sb.toString();
    }

    /**
     * Inject a payload into a specific cookie within the Cookie header,
     * bypassing Burp's cookie parser which splits on ';' and corrupts
     * payloads containing semicolons (e.g., SQL injection with multiple statements).
     *
     * URL-encodes characters that break cookie syntax (quotes, braces, semicolons, etc.)
     * while preserving existing percent-encoded sequences.
     *
     * @param request     The original HTTP request
     * @param cookieName  The cookie name to replace
     * @param payload     The payload value (may contain '"', '{', ';', spaces, etc.)
     * @return Modified request with the cookie value replaced
     */
    public static burp.api.montoya.http.message.requests.HttpRequest injectCookie(
            burp.api.montoya.http.message.requests.HttpRequest request,
            String cookieName, String payload) {
        String safePayload = encodeCookieValue(payload);

        String cookieHeader = null;
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Cookie")) {
                cookieHeader = h.value();
                break;
            }
        }

        if (cookieHeader == null) {
            // No existing Cookie header — add one
            return request.withAddedHeader("Cookie", cookieName + "=" + safePayload);
        }

        // Replace the cookie value using regex that matches from '=' to next '; ' or end of string
        String escaped = java.util.regex.Pattern.quote(cookieName);
        String replaced = cookieHeader.replaceFirst(
                escaped + "=[^;]*",
                java.util.regex.Matcher.quoteReplacement(cookieName + "=" + safePayload));

        return request.withRemovedHeader("Cookie").withAddedHeader("Cookie", replaced);
    }

    /**
     * Encode characters that are unsafe in cookie values.
     * Per RFC 6265, cookie values should not contain: whitespace, double quotes,
     * comma, semicolon, or backslash. We also encode braces, brackets, and other
     * characters that break HTTP header parsing.
     *
     * Preserves existing %XX sequences to avoid double-encoding.
     * Preserves base64 characters (A-Z, a-z, 0-9, +, /, =) since many cookies
     * use base64-encoded values.
     */
    public static String encodeCookieValue(String value) {
        if (value == null) return null;

        StringBuilder sb = new StringBuilder(value.length() + 32);
        int len = value.length();

        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);

            // Preserve existing %XX sequences
            if (c == '%' && i + 2 < len && isHex(value.charAt(i + 1)) && isHex(value.charAt(i + 2))) {
                sb.append(c);
                sb.append(value.charAt(i + 1));
                sb.append(value.charAt(i + 2));
                i += 2;
                continue;
            }

            // Encode characters that break cookie/header syntax
            switch (c) {
                case ' ':  sb.append("%20"); break;
                case '"':  sb.append("%22"); break;
                case '{':  sb.append("%7B"); break;
                case '}':  sb.append("%7D"); break;
                case ';':  sb.append("%3B"); break;
                case ',':  sb.append("%2C"); break;
                case '\\': sb.append("%5C"); break;
                case '\t': sb.append("%09"); break;
                case '\r': sb.append("%0D"); break;
                case '\n': sb.append("%0A"); break;
                default:   sb.append(c);     break;
            }
        }
        return sb.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}

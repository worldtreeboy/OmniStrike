package com.omnistrike.modules.injection.deser;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * Central factory for deserialization payload generation.
 *
 * Handles language/chain selection, payload generation with encoding,
 * and auto-detection of serialized data signatures in HTTP traffic.
 */
public final class DeserPayloadGenerator {

    public enum Language {
        JAVA, DOTNET, PHP, PYTHON, RUBY, NODEJS
    }

    public enum Encoding {
        RAW, BASE64, URL_ENCODED, BASE64_URL_ENCODED
    }

    private DeserPayloadGenerator() {}

    // ── Chain discovery ───────────────────────────────────────────────────────

    public static Map<String, String> getAvailableChains(Language language) {
        return switch (language) {
            case JAVA   -> JavaPayloads.getChains();
            case DOTNET -> DotNetPayloads.getChains();
            case PHP    -> PhpPayloads.getChains();
            case PYTHON -> PythonPayloads.getChains();
            case RUBY   -> RubyPayloads.getChains();
            case NODEJS -> NodePayloads.getChains();
        };
    }

    // ── Payload generation ────────────────────────────────────────────────────

    public static byte[] generate(Language language, String chain, String command, Encoding encoding) {
        byte[] raw = generateRaw(language, chain, command);
        return applyEncoding(raw, encoding);
    }

    private static byte[] generateRaw(Language language, String chain, String command) {
        return switch (language) {
            case JAVA   -> JavaPayloads.generate(chain, command);
            case DOTNET -> DotNetPayloads.generate(chain, command);
            case PHP    -> PhpPayloads.generate(chain, command);
            case PYTHON -> PythonPayloads.generate(chain, command);
            case RUBY   -> RubyPayloads.generate(chain, command);
            case NODEJS -> NodePayloads.generate(chain, command);
        };
    }

    public static byte[] applyEncoding(byte[] raw, Encoding encoding) {
        return switch (encoding) {
            case RAW -> raw;
            case BASE64 -> Base64.getEncoder().encode(raw);
            case URL_ENCODED -> URLEncoder.encode(
                    new String(raw, StandardCharsets.UTF_8), StandardCharsets.UTF_8)
                    .getBytes(StandardCharsets.UTF_8);
            case BASE64_URL_ENCODED -> URLEncoder.encode(
                    Base64.getEncoder().encodeToString(raw), StandardCharsets.UTF_8)
                    .getBytes(StandardCharsets.UTF_8);
        };
    }

    // ── Auto-detection of serialized data ─────────────────────────────────────

    private static final Map<Language, List<Pattern>> SIGNATURES = new EnumMap<>(Language.class);
    static {
        SIGNATURES.put(Language.JAVA, List.of(
            Pattern.compile("rO0AB"),
            Pattern.compile("ACED0005", Pattern.CASE_INSENSITIVE)
        ));
        SIGNATURES.put(Language.PHP, List.of(
            Pattern.compile("O:\\d+:\""),
            Pattern.compile("a:\\d+:\\{"),
            Pattern.compile("s:\\d+:\"")
        ));
        SIGNATURES.put(Language.DOTNET, List.of(
            Pattern.compile("AAEAAAD"),
            Pattern.compile("/wEy"),
            Pattern.compile("/wFp"),
            Pattern.compile("__VIEWSTATE")
        ));
        SIGNATURES.put(Language.PYTHON, List.of(
            Pattern.compile("gASV"),
            Pattern.compile("gAM"),
            Pattern.compile("\\x80\\x04\\x95"),
            Pattern.compile("cos\\nsystem")
        ));
        SIGNATURES.put(Language.RUBY, List.of(
            Pattern.compile("BAh"),
            Pattern.compile("\\x04\\x08")
        ));
        SIGNATURES.put(Language.NODEJS, List.of(
            Pattern.compile("_\\$\\$ND_FUNC\\$\\$_"),
            Pattern.compile("__cryo_type__"),
            Pattern.compile("!!js/function")
        ));
    }

    public static Language detectSerialization(String data) {
        if (data == null || data.isEmpty()) return null;

        for (var entry : SIGNATURES.entrySet()) {
            for (Pattern p : entry.getValue()) {
                if (p.matcher(data).find()) return entry.getKey();
            }
        }

        // Try URL-decoded
        try {
            String decoded = URLDecoder.decode(data, StandardCharsets.UTF_8);
            if (!decoded.equals(data)) {
                for (var entry : SIGNATURES.entrySet()) {
                    for (Pattern p : entry.getValue()) {
                        if (p.matcher(decoded).find()) return entry.getKey();
                    }
                }
            }
        } catch (Exception ignored) {}

        // Try Base64-decoded
        try {
            if (data.matches("[A-Za-z0-9+/=_-]{8,}")) {
                byte[] decoded = Base64.getDecoder().decode(
                        data.replace('-', '+').replace('_', '/'));
                String decodedStr = new String(decoded, StandardCharsets.ISO_8859_1);

                if (decoded.length >= 4 &&
                    (decoded[0] & 0xFF) == 0xAC && (decoded[1] & 0xFF) == 0xED &&
                    (decoded[2] & 0xFF) == 0x00 && (decoded[3] & 0xFF) == 0x05) {
                    return Language.JAVA;
                }

                if (decoded.length >= 4 &&
                    decoded[0] == 0x00 && decoded[1] == 0x01 &&
                    decoded[2] == 0x00 && decoded[3] == 0x00) {
                    return Language.DOTNET;
                }

                if (decoded.length >= 2 &&
                    (decoded[0] & 0xFF) == 0x80 &&
                    ((decoded[1] & 0xFF) == 0x03 || (decoded[1] & 0xFF) == 0x04)) {
                    return Language.PYTHON;
                }

                if (decoded.length >= 2 &&
                    (decoded[0] & 0xFF) == 0x04 && (decoded[1] & 0xFF) == 0x08) {
                    return Language.RUBY;
                }

                for (var entry : SIGNATURES.entrySet()) {
                    for (Pattern p : entry.getValue()) {
                        if (p.matcher(decodedStr).find()) return entry.getKey();
                    }
                }
            }
        } catch (Exception ignored) {}

        return null;
    }

    public static List<SerializedDataLocation> findSerializedData(String requestStr, String responseStr) {
        List<SerializedDataLocation> locations = new ArrayList<>();
        if (requestStr == null || requestStr.isEmpty()) return locations;

        String[] parts = requestStr.split("\r\n\r\n", 2);
        String headerSection = parts[0];
        String body = parts.length > 1 ? parts[1] : "";
        String[] headerLines = headerSection.split("\r\n");

        // Check query parameters
        if (headerLines.length > 0) {
            String requestLine = headerLines[0];
            int qMark = requestLine.indexOf('?');
            int spaceAfter = requestLine.lastIndexOf(' ');
            if (qMark > 0 && spaceAfter > qMark) {
                String query = requestLine.substring(qMark + 1, spaceAfter);
                checkParams(query, SerializedDataLocation.LocationType.QUERY_PARAM,
                        qMark, locations);
            }
        }

        // Check Cookie header
        for (int i = 1; i < headerLines.length; i++) {
            String line = headerLines[i];
            if (line.toLowerCase().startsWith("cookie:")) {
                String cookieValue = line.substring(7).trim();
                int offset = requestStr.indexOf(cookieValue);
                String[] cookies = cookieValue.split(";\\s*");
                for (String cookie : cookies) {
                    int eq = cookie.indexOf('=');
                    if (eq > 0) {
                        String name = cookie.substring(0, eq).trim();
                        String value = cookie.substring(eq + 1).trim();
                        Language lang = detectSerialization(value);
                        if (lang != null) {
                            int valOffset = requestStr.indexOf(value, offset);
                            locations.add(new SerializedDataLocation(
                                    SerializedDataLocation.LocationType.COOKIE, name, value,
                                    lang, valOffset, valOffset + value.length()));
                        }
                    }
                }
            }

            // Check other headers
            if (line.contains(":") && !line.toLowerCase().startsWith("host:")) {
                int colonIdx = line.indexOf(':');
                String headerName = line.substring(0, colonIdx).trim();
                String headerValue = line.substring(colonIdx + 1).trim();
                Language lang = detectSerialization(headerValue);
                if (lang != null) {
                    int offset = requestStr.indexOf(headerValue);
                    locations.add(new SerializedDataLocation(
                            SerializedDataLocation.LocationType.HEADER, headerName, headerValue,
                            lang, offset, offset + headerValue.length()));
                }
            }
        }

        // Check body parameters (form-encoded)
        if (!body.isEmpty() && !body.trim().startsWith("{") && !body.trim().startsWith("<")) {
            checkParams(body, SerializedDataLocation.LocationType.BODY_PARAM,
                    requestStr.indexOf(body), locations);
        }

        // Check JSON fields
        if (!body.isEmpty() && body.trim().startsWith("{")) {
            checkJsonFields(body, requestStr.indexOf(body), locations);
        }

        // Check raw body
        if (!body.isEmpty() && locations.isEmpty()) {
            Language lang = detectSerialization(body);
            if (lang != null) {
                int offset = requestStr.indexOf(body);
                locations.add(new SerializedDataLocation(
                        SerializedDataLocation.LocationType.RAW_BODY, null, body,
                        lang, offset, offset + body.length()));
            }
        }

        return locations;
    }

    private static void checkParams(String paramStr, SerializedDataLocation.LocationType type,
                                     int baseOffset, List<SerializedDataLocation> locations) {
        String[] pairs = paramStr.split("&");
        int offset = 0;
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = pair.substring(0, eq);
                String value = pair.substring(eq + 1);
                String decoded = value;
                try {
                    decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
                } catch (Exception ignored) {}

                Language lang = detectSerialization(decoded);
                if (lang != null) {
                    int valStart = baseOffset + offset + eq + 1;
                    locations.add(new SerializedDataLocation(type, name, value,
                            lang, valStart, valStart + value.length()));
                }
            }
            offset += pair.length() + 1;
        }
    }

    private static void checkJsonFields(String jsonBody, int baseOffset,
                                          List<SerializedDataLocation> locations) {
        Pattern jsonPat = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = jsonPat.matcher(jsonBody);
        while (m.find()) {
            String key = m.group(1);
            String value = m.group(2);
            String unescaped = value.replace("\\\"", "\"").replace("\\\\", "\\")
                    .replace("\\n", "\n").replace("\\r", "\r");
            Language lang = detectSerialization(unescaped);
            if (lang != null) {
                int valStart = baseOffset + m.start(2);
                locations.add(new SerializedDataLocation(
                        SerializedDataLocation.LocationType.JSON_FIELD, key, value,
                        lang, valStart, valStart + value.length()));
            }
        }
    }

    // ── Utility: hex dump ─────────────────────────────────────────────────────

    public static String toHexDump(byte[] data, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(data.length, maxBytes);
        for (int i = 0; i < len; i += 16) {
            sb.append(String.format("%04x  ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < len) {
                    sb.append(String.format("%02x ", data[i + j] & 0xFF));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(' ');
            }
            sb.append(" |");
            for (int j = 0; j < 16 && i + j < len; j++) {
                byte b = data[i + j];
                sb.append(b >= 32 && b < 127 ? (char) b : '.');
            }
            sb.append("|\n");
        }
        if (data.length > maxBytes) {
            sb.append("... (").append(data.length - maxBytes).append(" more bytes)\n");
        }
        return sb.toString();
    }
}

package com.omnistrike.modules.injection.deser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Encoding;
import com.omnistrike.modules.injection.deser.DeserPayloadGenerator.Language;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Active deserialization testing engine for OmniStrike.
 *
 * Injects generated payloads at detected serialized data points,
 * sends modified requests, and analyzes responses for signs of exploitation.
 */
public class DeserEngine {

    private static final String MODULE_ID = "deser-scanner";

    private final MontoyaApi api;
    private final FindingsStore findingsStore;
    private final Consumer<String> logCallback;
    private final BiConsumer<String[], Long> resultCallback;
    private volatile boolean stopped;

    private static final String[] DESER_ERROR_PATTERNS = {
        "java.io.InvalidClassException", "java.io.StreamCorruptedException",
        "ClassNotFoundException", "java.lang.ClassCastException",
        "java.io.ObjectInputStream", "InvocationTargetException",
        "unserialize()", "Cannot unserialize", "__wakeup", "__destruct",
        "pickle.loads", "PickleError", "UnpicklingError",
        "SerializationException", "BinaryFormatter",
        "Marshal.load", "marshal data too short",
        "SyntaxError", "node-serialize", "deserialize"
    };

    private static final String[] EXECUTION_INDICATORS = {
        "uid=", "root:", "www-data", "COMPUTERNAME=", "USERDOMAIN=",
        "Volume Serial Number", "Directory of", "total "
    };

    public DeserEngine(MontoyaApi api, FindingsStore findingsStore,
                       Consumer<String> logCallback, BiConsumer<String[], Long> resultCallback) {
        this.api = api;
        this.findingsStore = findingsStore;
        this.logCallback = logCallback;
        this.resultCallback = resultCallback;
    }

    public void stop() { this.stopped = true; }

    /**
     * Test a single payload at a specific injection point.
     */
    public void test(String rawRequest, Language language, String chain,
                     String command, Encoding encoding, String injectParam) {
        stopped = false;
        log("[*] Generating " + language + "/" + chain + " payload...");

        byte[] payload;
        try {
            payload = DeserPayloadGenerator.generate(language, chain, command, encoding);
        } catch (Exception e) {
            log("[!] Payload generation failed: " + e.getMessage());
            return;
        }

        log("[+] Payload size: " + payload.length + " bytes (encoding: " + encoding + ")");

        String payloadStr = new String(payload, StandardCharsets.UTF_8);
        String modified = injectPayload(rawRequest, payloadStr, injectParam);

        sendAndAnalyze(modified, chain, injectParam != null ? injectParam : "auto", language);
    }

    /**
     * Auto-scan: detect serialized data locations, try all applicable chains.
     */
    public void autoScan(String rawRequest) {
        stopped = false;
        log("[*] ══════════════════════════════════════════════════════");
        log("[*]  OmniStrike Deserialization Auto-Scan");
        log("[*] ══════════════════════════════════════════════════════");

        if (!rawRequest.contains("\r\n")) {
            rawRequest = rawRequest.replace("\n", "\r\n");
        }
        if (!rawRequest.endsWith("\r\n\r\n")) {
            rawRequest = rawRequest.endsWith("\r\n") ? rawRequest + "\r\n" : rawRequest + "\r\n\r\n";
        }

        log("[*] Phase 1: Scanning request for serialized data...");
        List<SerializedDataLocation> locations = DeserPayloadGenerator.findSerializedData(rawRequest, null);

        if (locations.isEmpty()) {
            log("[!] No serialized data detected. Trying all parameters...");
            locations = getAllParams(rawRequest);
        }

        log("[+] Found " + locations.size() + " injection point(s)");
        for (SerializedDataLocation loc : locations) {
            log("    " + loc);
        }
        log("");

        int totalTests = 0;
        int findingsCount = 0;

        for (SerializedDataLocation loc : locations) {
            if (stopped) break;

            Language lang = loc.getLanguage();
            Map<String, String> chains = DeserPayloadGenerator.getAvailableChains(lang);

            log("[*] Testing " + loc.getLocationType() +
                    (loc.getParamName() != null ? " [" + loc.getParamName() + "]" : "") +
                    " with " + lang + " chains (" + chains.size() + ")...");

            List<Encoding> encodings = guessEncodings(loc.getRawValue());

            for (var chainEntry : chains.entrySet()) {
                if (stopped) break;
                String chainName = chainEntry.getKey();

                for (Encoding enc : encodings) {
                    if (stopped) break;
                    totalTests++;

                    try {
                        byte[] payload = DeserPayloadGenerator.generate(lang, chainName,
                                "echo omnistrike_" + chainName, enc);
                        String payloadStr = new String(payload, StandardCharsets.UTF_8);

                        String modified = replaceAt(rawRequest, loc, payloadStr);
                        boolean interesting = sendAndAnalyze(modified, chainName,
                                loc.getParamName() != null ? loc.getParamName() : loc.getLocationType().name(),
                                lang);

                        if (interesting) findingsCount++;
                    } catch (Exception e) {
                        log("    [!] " + chainName + "/" + enc + ": " + e.getMessage());
                    }
                }
            }
        }

        log("");
        log("[*] ══════════════════════════════════════════════════════");
        log("[*] Auto-scan complete: " + totalTests + " tests, " + findingsCount + " potential findings");
        log("[*] ══════════════════════════════════════════════════════");
    }

    // ── Request modification ─────────────────────────────────────────────────

    private String injectPayload(String rawRequest, String payload, String paramName) {
        if (!rawRequest.contains("\r\n")) rawRequest = rawRequest.replace("\n", "\r\n");
        if (!rawRequest.endsWith("\r\n\r\n")) {
            rawRequest = rawRequest.endsWith("\r\n") ? rawRequest + "\r\n" : rawRequest + "\r\n\r\n";
        }

        if (paramName == null || paramName.isEmpty() || "Auto-Detect".equals(paramName)) {
            List<SerializedDataLocation> locs = DeserPayloadGenerator.findSerializedData(rawRequest, null);
            if (!locs.isEmpty()) {
                return replaceAt(rawRequest, locs.get(0), payload);
            }
            log("    [!] No injection point found, appending to body");
            String[] parts = rawRequest.split("\r\n\r\n", 2);
            return parts[0] + "\r\n\r\n" + payload;
        }

        return replaceParamValue(rawRequest, paramName, payload);
    }

    private String replaceAt(String rawRequest, SerializedDataLocation loc, String payload) {
        int start = loc.getStartOffset();
        int end = loc.getEndOffset();
        if (start >= 0 && end > start && end <= rawRequest.length()) {
            return rawRequest.substring(0, start) + payload + rawRequest.substring(end);
        }
        String oldValue = loc.getRawValue();
        if (rawRequest.contains(oldValue)) {
            return rawRequest.replace(oldValue, payload);
        }
        return rawRequest;
    }

    private String replaceParamValue(String raw, String paramName, String payload) {
        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);

        String pattern = paramName + "=";
        int idx = raw.indexOf(pattern);
        if (idx >= 0) {
            int valueStart = idx + pattern.length();
            int valueEnd = raw.indexOf('&', valueStart);
            if (valueEnd < 0) {
                valueEnd = raw.indexOf(' ', valueStart);
                if (valueEnd < 0) valueEnd = raw.indexOf("\r\n", valueStart);
                if (valueEnd < 0) valueEnd = raw.length();
            }
            return raw.substring(0, valueStart) + encodedPayload + raw.substring(valueEnd);
        }

        // Check Cookie header
        String cookiePattern = paramName + "=";
        for (String line : raw.split("\r\n")) {
            if (line.toLowerCase().startsWith("cookie:") && line.contains(cookiePattern)) {
                int cookieIdx = raw.indexOf(line);
                int valStart = line.indexOf(cookiePattern) + cookiePattern.length();
                int valEnd = line.indexOf(';', valStart);
                if (valEnd < 0) valEnd = line.length();
                String newLine = line.substring(0, valStart) + payload + line.substring(valEnd);
                return raw.substring(0, cookieIdx) + newLine + raw.substring(cookieIdx + line.length());
            }
        }

        return raw;
    }

    // ── HTTP sending and analysis ────────────────────────────────────────────

    private boolean sendAndAnalyze(String modifiedRequest, String chainName,
                                    String injectPoint, Language language) {
        String[] lines = modifiedRequest.split("\r\n");
        String host = null;
        boolean useHttps = false;
        int port = 80;

        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:")) {
                host = line.substring(5).trim();
                break;
            }
        }
        if (host == null) {
            log("    [!] No Host header — cannot send");
            return false;
        }

        if (host.contains(":")) {
            String portStr = host.substring(host.indexOf(':') + 1);
            host = host.substring(0, host.indexOf(':'));
            try { port = Integer.parseInt(portStr); } catch (NumberFormatException ignored) {}
            if (port == 443) useHttps = true;
        } else {
            if (lines[0].contains("https://")) useHttps = true;
            port = useHttps ? 443 : 80;
        }

        long startMs = System.currentTimeMillis();
        try {
            HttpService service = HttpService.httpService(host, port, useHttps);
            HttpRequest req = HttpRequest.httpRequest(service, modifiedRequest);
            var rr = api.http().sendRequest(req);
            HttpResponse resp = rr.response();
            long elapsed = System.currentTimeMillis() - startMs;

            if (resp == null) {
                addResult(chainName, injectPoint, "No response", "0", String.valueOf(elapsed), "ERROR");
                return false;
            }

            int status = resp.statusCode();
            String body = resp.bodyToString() != null ? resp.bodyToString() : "";
            int bodyLen = body.length();

            String verdict = analyzeResponse(status, body, elapsed);

            addResult(chainName, injectPoint,
                    String.valueOf(status), String.valueOf(bodyLen),
                    String.valueOf(elapsed), verdict);

            if ("VULNERABLE".equals(verdict) || "INTERESTING".equals(verdict)) {
                String url = (useHttps ? "https://" : "http://") + host
                        + (port != 80 && port != 443 ? ":" + port : "");
                String detail = "[Deser:" + language + "/" + chainName + "] " +
                        injectPoint + " | HTTP " + status + " | " + bodyLen + "b | " + elapsed + "ms";

                Severity sev = "VULNERABLE".equals(verdict) ? Severity.CRITICAL : Severity.HIGH;
                Finding finding = Finding.builder(MODULE_ID,
                                "Insecure Deserialization: " + language + "/" + chainName, sev, Confidence.FIRM)
                        .url(url)
                        .parameter(injectPoint)
                        .evidence(detail)
                        .description("Potential insecure deserialization detected via " + language +
                                " " + chainName + " gadget chain. The application processed the " +
                                "serialized payload and showed signs of " +
                                ("VULNERABLE".equals(verdict) ? "code execution" : "payload processing") + ".")
                        .remediation("Avoid deserializing untrusted data. Use allowlists for " +
                                "permitted classes. Consider using safe serialization formats (JSON, XML).")
                        .requestResponse(rr)
                        .build();

                findingsStore.addFinding(finding);
                log("    [+] " + verdict + ": " + chainName + " at " + injectPoint);
                return true;
            }

            return false;

        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - startMs;
            addResult(chainName, injectPoint, "Error", "0", String.valueOf(elapsed), "ERROR");
            return false;
        }
    }

    private String analyzeResponse(int status, String body, long elapsed) {
        String bodyLower = body.toLowerCase();

        for (String indicator : EXECUTION_INDICATORS) {
            if (body.contains(indicator)) return "VULNERABLE";
        }

        int errorCount = 0;
        for (String pattern : DESER_ERROR_PATTERNS) {
            if (bodyLower.contains(pattern.toLowerCase())) errorCount++;
        }

        if (errorCount >= 2) return "INTERESTING";
        if (elapsed > 10000) return "INTERESTING";
        if (status == 500 && errorCount > 0) return "INTERESTING";

        if (status >= 200 && status < 300) return "OK";
        if (status == 400) return "REJECTED";
        if (status == 403 || status == 401) return "BLOCKED";
        if (status == 500) return "ERROR_500";

        return "UNKNOWN";
    }

    // ── Parameter extraction for blind testing ───────────────────────────────

    private List<SerializedDataLocation> getAllParams(String rawRequest) {
        List<SerializedDataLocation> locs = new ArrayList<>();

        String[] parts = rawRequest.split("\r\n\r\n", 2);
        String headerSection = parts[0];
        String body = parts.length > 1 ? parts[1] : "";
        String[] headerLines = headerSection.split("\r\n");

        // Query params
        if (headerLines.length > 0) {
            String reqLine = headerLines[0];
            int q = reqLine.indexOf('?');
            int sp = reqLine.lastIndexOf(' ');
            if (q > 0 && sp > q) {
                String query = reqLine.substring(q + 1, sp);
                for (String pair : query.split("&")) {
                    int eq = pair.indexOf('=');
                    if (eq > 0) {
                        String name = pair.substring(0, eq);
                        String value = pair.substring(eq + 1);
                        int offset = rawRequest.indexOf(value);
                        locs.add(new SerializedDataLocation(
                                SerializedDataLocation.LocationType.QUERY_PARAM,
                                name, value, Language.JAVA,
                                offset, offset + value.length()));
                    }
                }
            }
        }

        // Cookie values
        for (String line : headerLines) {
            if (line.toLowerCase().startsWith("cookie:")) {
                String cookies = line.substring(7).trim();
                for (String cookie : cookies.split(";\\s*")) {
                    int eq = cookie.indexOf('=');
                    if (eq > 0) {
                        String name = cookie.substring(0, eq).trim();
                        String value = cookie.substring(eq + 1).trim();
                        int offset = rawRequest.indexOf(value);
                        locs.add(new SerializedDataLocation(
                                SerializedDataLocation.LocationType.COOKIE,
                                name, value, Language.JAVA,
                                offset, offset + value.length()));
                    }
                }
            }
        }

        // Body params
        if (!body.isEmpty() && !body.trim().startsWith("{")) {
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    String name = pair.substring(0, eq);
                    String value = pair.substring(eq + 1);
                    int offset = rawRequest.indexOf(value, rawRequest.indexOf("\r\n\r\n"));
                    locs.add(new SerializedDataLocation(
                            SerializedDataLocation.LocationType.BODY_PARAM,
                            name, value, Language.JAVA,
                            offset, offset + value.length()));
                }
            }
        }

        return locs;
    }

    private List<Encoding> guessEncodings(String rawValue) {
        if (rawValue == null) return List.of(Encoding.RAW, Encoding.BASE64);

        List<Encoding> encodings = new ArrayList<>();

        if (rawValue.matches("[A-Za-z0-9+/=_-]{8,}")) {
            encodings.add(Encoding.BASE64);
            encodings.add(Encoding.BASE64_URL_ENCODED);
        }

        if (rawValue.contains("%")) {
            encodings.add(Encoding.URL_ENCODED);
        }

        encodings.add(Encoding.RAW);

        return encodings;
    }

    // ── Logging / callbacks ──────────────────────────────────────────────────

    private void log(String msg) {
        if (logCallback != null) logCallback.accept(msg);
        try { api.logging().logToOutput("[Deser] " + msg); }
        catch (Exception ignored) {}
    }

    private void addResult(String chain, String injectPoint, String status,
                            String length, String timeMs, String verdict) {
        if (resultCallback != null) {
            resultCallback.accept(
                    new String[]{chain, injectPoint, status, length, timeMs, verdict},
                    Long.parseLong(timeMs));
        }
    }
}

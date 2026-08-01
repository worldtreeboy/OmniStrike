package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.JsonScanSupport;
import com.omnistrike.framework.PrivacyManager;
import com.omnistrike.framework.ResponseGuard;
import com.omnistrike.framework.ScanState;
import com.omnistrike.framework.ScanTargetIdentity;
import com.omnistrike.framework.stepper.StepperHttp;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ModuleCategory;
import com.omnistrike.model.ModuleConfig;
import com.omnistrike.model.ScanModule;
import com.omnistrike.model.Severity;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conservative MongoDB-style NoSQL operator-injection scanner.
 *
 * <p>It deliberately omits $where, JavaScript, sleep and destructive operators.
 * A finding needs stable repeated true/false differentials plus confirmation by
 * an independent operator family. Response-length changes alone never confirm.
 */
public class NoSqlInjectionScanner implements ScanModule {

    static final String MODULE_ID = "nosqli-scanner";
    private static final int MAX_PROFILE_BODY = 2_000_000;
    private static final int MAX_JSON_DEPTH = 128;
    private static final int MAX_STRUCTURE_NODES = 5_000;

    private static final Set<String> RESULT_ARRAY_KEYS = Set.of(
            "results", "result", "data", "items", "records", "documents",
            "users", "rows", "hits", "entries", "objects");
    private static final Set<String> AUTH_VALUE_KEYS = Set.of(
            "token", "accesstoken", "idtoken", "refreshtoken", "jwt",
            "sessiontoken", "authtoken");
    private static final Set<String> AUTH_OBJECT_KEYS = Set.of(
            "user", "profile", "account", "principal");
    private static final Set<String> SKIPPED_PARAMETER_NAMES = Set.of(
            "csrf", "csrftoken", "xsrf", "xsrftoken", "nonce", "captcha",
            "recaptcha", "otp", "totp", "state");
    private static final Set<String> HIGH_PRIORITY_NAMES = Set.of(
            "username", "user", "email", "login", "password", "pass",
            "query", "filter", "search", "where", "selector", "id", "userid");
    private static final Set<String> MUTATING_ACTION_KEYS = Set.of(
            "action", "operation", "op", "method", "command", "task", "do");
    private static final Set<String> MUTATING_ACTION_VALUES = Set.of(
            "create", "register", "signup", "submit", "update", "edit", "delete",
            "remove", "upload", "payment", "checkout", "order", "transfer", "send",
            "destroy", "reset", "change", "publish", "approve", "revoke", "logout",
            "signout", "enable", "disable");

    private static final Pattern READ_ONLY_POST_PATH = Pattern.compile(
            "(?i)(?:^|/)(?:login|signin|sign-in|authenticate|auth|session|token|"
                    + "search|query|filter|find|lookup)(?:[./]|$)");
    private static final Pattern MUTATING_PATH = Pattern.compile(
            "(?i)(?:^|/)(?:create|register|signup|sign-up|submit|update|edit|delete|"
                    + "remove|upload|payment|checkout|order|transfer|send|destroy|reset|"
                    + "change|publish|approve|revoke|logout|signout|sign-out|enable|disable)(?:[._/-]|$)");
    private static final Pattern HTML_TAG = Pattern.compile("(?i)<([a-z][a-z0-9:-]*)\\b");
    private static final Pattern LONG_DYNAMIC_TOKEN = Pattern.compile(
            "(?i)\\b(?:[a-f0-9]{16,}|[a-z0-9_-]{24,})\\b");
    private static final Pattern NUMBER = Pattern.compile("\\b\\d+\\b");

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "NoSQL Operator Injection"; }
    @Override public String getDescription() {
        return "Conservatively tests MongoDB-style operator injection in query, form, and nested JSON values using repeatable paired controls.";
    }
    @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
    @Override public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
    }

    @Override public void destroy() {}

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        return run(requestResponse, null);
    }

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        return run(requestResponse, targetParameterName);
    }

    private List<Finding> run(HttpRequestResponse original, String requestedParameter) {
        if (original == null || original.request() == null || original.response() == null) {
            return Collections.emptyList();
        }
        if (!ResponseGuard.isUsableResponse(original)) return Collections.emptyList();

        List<InjectionPoint> points = extractInjectionPoints(original.request());
        if (requestedParameter != null) {
            points.removeIf(point -> !point.matches(requestedParameter));
        }
        if (!isSafeToReplay(original.request())) {
            api.logging().logToOutput("[NoSQLi] Skipping potentially state-changing request: "
                    + PrivacyManager.maskForDisplay(original.request().url()));
            return Collections.emptyList();
        }

        points.sort(Comparator.comparingInt(NoSqlInjectionScanner::priority));
        int maxParameters = Math.max(1, Math.min(50,
                config.getInt("nosqli.maxParameters", 12)));
        if (points.size() > maxParameters) points = new ArrayList<>(points.subList(0, maxParameters));

        String endpoint = ScanTargetIdentity.endpoint(original.request().url());
        for (InjectionPoint point : points) {
            if (cancelled()) break;
            if (dedup != null && !dedup.markIfNew(MODULE_ID, original.request().method(),
                    endpoint, point.identity())) continue;
            try {
                testPoint(original, point);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            } catch (RuntimeException error) {
                api.logging().logToError("[NoSQLi] Test failed for " + point.displayName()
                        + ": " + error.getMessage());
            }
        }
        return Collections.emptyList();
    }

    private void testPoint(HttpRequestResponse original, InjectionPoint point)
            throws InterruptedException {
        String canary = "omni" + UUID.randomUUID().toString().replace("-", "");

        HttpRequestResponse baselineReplay = send(original.request());
        if (!usable(baselineReplay)) return;
        perHostDelay();
        ResponseProfile baseline = profile(original);
        ResponseProfile replay = profile(baselineReplay);
        if (!sameOutcome(baseline, replay)) return;

        Probe falseProbe = probe(original, point, "$eq", canary);
        Probe trueProbe = probe(original, point, "$ne", canary);
        if (falseProbe == null || trueProbe == null
                || reflected(falseProbe, canary) || reflected(trueProbe, canary)) return;

        Signal initialSignal = confirmationSignal(
                baseline, replay, trueProbe.profile(), falseProbe.profile());
        if (initialSignal == Signal.NONE) return;

        Probe falseRepeat = probe(original, point, "$eq", canary);
        Probe trueRepeat = probe(original, point, "$ne", canary);
        if (falseRepeat == null || trueRepeat == null
                || reflected(falseRepeat, canary) || reflected(trueRepeat, canary)) return;
        if (!sameOutcome(falseProbe.profile(), falseRepeat.profile())
                || !sameOutcome(trueProbe.profile(), trueRepeat.profile())) return;
        if (confirmationSignal(baseline, replay,
                trueRepeat.profile(), falseRepeat.profile()) != initialSignal) return;

        String regexFalse = "^" + canary + "$";
        Probe regexFalseProbe = probe(original, point, "$regex", regexFalse);
        Probe regexTrueProbe = probe(original, point, "$regex", ".*");
        if (regexFalseProbe == null || regexTrueProbe == null
                || reflected(regexFalseProbe, canary) || reflected(regexTrueProbe, canary)) return;
        if (!confirmsSignal(initialSignal, baseline,
                regexTrueProbe.profile(), regexFalseProbe.profile())) return;

        String title = initialSignal == Signal.AUTHENTICATION
                || initialSignal == Signal.REDIRECT
                ? "NoSQL Operator Injection — Authentication/Access Bypass"
                : "NoSQL Operator Injection — Query Filter Bypass";

        findingsStore.addFinding(Finding.builder(MODULE_ID, title,
                        Severity.HIGH, Confidence.FIRM)
                .url(original.request().url())
                .parameter(point.displayName())
                .evidence(buildEvidence(initialSignal, baseline,
                        trueProbe.profile(), falseProbe.profile(),
                        regexTrueProbe.profile(), regexFalseProbe.profile()))
                .description("The parameter accepted MongoDB-style query operators. Repeated $ne/$eq "
                        + "controls produced stable, meaningfully different outcomes, and an independent "
                        + "$regex broad/impossible pair confirmed the same behavior.")
                .remediation("Accept scalar values only. Reject keys beginning with '$' and unexpected nested "
                        + "objects, use strict request schemas, and build database queries from allow-listed fields.")
                .payload(trueProbe.payload())
                .requestResponse(trueProbe.exchange())
                .build());
    }

    private Probe probe(HttpRequestResponse original, InjectionPoint point,
                        String operator, String value) throws InterruptedException {
        if (cancelled()) return null;
        Mutation mutation = mutate(original.request(), point, operator, value);
        if (mutation == null) return null;
        HttpRequestResponse exchange = send(mutation.request());
        if (!usable(exchange)) return null;
        perHostDelay();
        return new Probe(exchange, profile(exchange), mutation.payload());
    }

    private HttpRequestResponse send(HttpRequest request) {
        if (cancelled()) return null;
        try {
            return StepperHttp.sendRequest(request);
        } catch (RuntimeException error) {
            if (Thread.interrupted()) Thread.currentThread().interrupt();
            return null;
        }
    }

    private Mutation mutate(HttpRequest request, InjectionPoint point,
                            String operator, String value) {
        if (point.kind() == PointKind.JSON) {
            String changed = buildJsonOperatorPayload(
                    request.bodyToString(), point.jsonPath(), operator, value);
            if (changed.equals(request.bodyToString())) return null;
            JsonObject operatorObject = new JsonObject();
            operatorObject.addProperty(operator, value);
            return new Mutation(request.withBody(changed), operatorObject.toString());
        }

        HttpRequest changed = buildParameterOperatorRequest(request, point.name(),
                point.originalValue(), point.parameterType(), operator, value);
        if (changed == request) return null;
        HttpParameter injectedParameter = HttpParameter.parameter(
                point.name() + "[" + operator + "]", value, point.parameterType());
        return new Mutation(changed, injectedParameter.name() + "=" + value);
    }

    private static HttpRequest buildParameterOperatorRequest(
            HttpRequest request, String name, String originalValue,
            HttpParameterType type, String operator, String value) {
        if (request == null || name == null || originalValue == null || value == null
                || (type != HttpParameterType.URL && type != HttpParameterType.BODY)
                || !Set.of("$ne", "$eq", "$regex").contains(operator)) return request;
        HttpParameter originalParameter = HttpParameter.parameter(name, originalValue, type);
        HttpParameter injectedParameter = HttpParameter.parameter(
                name + "[" + operator + "]", value, type);
        return request.withRemovedParameters(originalParameter)
                .withAddedParameters(injectedParameter);
    }

    private List<InjectionPoint> extractInjectionPoints(HttpRequest request) {
        List<InjectionPoint> points = new ArrayList<>();
        for (var parameter : request.parameters()) {
            if (parameter.type() != HttpParameterType.URL
                    && parameter.type() != HttpParameterType.BODY) continue;
            if (!isEligibleName(parameter.name()) || !isEligibleValue(parameter.value())) continue;
            points.add(new InjectionPoint(parameter.name(), parameter.value(),
                    parameter.type(), PointKind.PARAMETER, List.of(), parameter.name()));
        }

        if (isJsonRequest(request)) {
            try {
                for (JsonScanSupport.Target target : JsonScanSupport.extractTargets(request.bodyToString())) {
                    String leaf = target.path().isEmpty() ? "" : String.valueOf(
                            target.path().get(target.path().size() - 1));
                    if (!isEligibleName(leaf) || !isEligibleValue(target.value())) continue;
                    points.add(new InjectionPoint(target.displayName(), target.value(),
                            HttpParameterType.JSON, PointKind.JSON,
                            target.path(), target.identityName()));
                }
            } catch (RuntimeException ignored) {
                // Invalid or pathologically nested JSON is not a safe injection target.
            }
        }
        return deduplicate(points);
    }

    private static List<InjectionPoint> deduplicate(List<InjectionPoint> points) {
        List<InjectionPoint> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        for (InjectionPoint point : points) {
            if (identities.add(point.kind() + ":" + point.identity())) result.add(point);
        }
        return result;
    }

    private static boolean isEligibleName(String name) {
        if (name == null || name.isBlank() || name.length() > 256) return false;
        if (name.contains("[") || name.contains("]") || name.contains("$")) return false;
        String normalized = normalizeKey(name);
        return !SKIPPED_PARAMETER_NAMES.contains(normalized)
                && !normalized.endsWith("csrf") && !normalized.endsWith("captcha");
    }

    private static boolean isEligibleValue(String value) {
        return value != null && value.length() <= 4096;
    }

    private static int priority(InjectionPoint point) {
        String leaf = point.displayName();
        int dot = Math.max(leaf.lastIndexOf('.'), leaf.lastIndexOf(']'));
        if (dot >= 0 && dot + 1 < leaf.length()) leaf = leaf.substring(dot + 1);
        return HIGH_PRIORITY_NAMES.contains(normalizeKey(leaf)) ? 0 : 1;
    }

    private boolean isSafeToReplay(HttpRequest request) {
        for (var parameter : request.parameters()) {
            if (isMutatingActionParameter(parameter.name(), parameter.value())) return false;
        }
        return isSafeReplayCandidate(request.method(), request.url(),
                config.getBool("nosqli.postUnknown.enabled", false));
    }

    static boolean isMutatingActionParameter(String name, String value) {
        String normalizedName = normalizeKey(name);
        if (!MUTATING_ACTION_KEYS.contains(normalizedName)) return false;
        String normalizedValue = normalizeKey(value);
        return MUTATING_ACTION_VALUES.stream().anyMatch(action ->
                normalizedValue.equals(action)
                        || normalizedValue.startsWith(action)
                        || normalizedValue.endsWith(action));
    }

    static boolean isSafeReplayCandidate(String method, String url,
                                         boolean allowUnknownPost) {
        if (method == null) return false;
        String path;
        try { path = URI.create(url).getPath(); }
        catch (RuntimeException ignored) { path = url == null ? "" : url; }
        if (path == null) path = "";
        try { path = URLDecoder.decode(path, StandardCharsets.UTF_8); }
        catch (IllegalArgumentException ignored) { /* retain the raw path */ }
        if (MUTATING_PATH.matcher(path).find()) return false;
        if (method.equalsIgnoreCase("GET")) return true;
        if (!method.equalsIgnoreCase("POST")) return false;
        if (READ_ONLY_POST_PATH.matcher(path).find()) return true;
        return allowUnknownPost;
    }

    private static boolean isJsonRequest(HttpRequest request) {
        for (var header : request.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                String value = header.value().toLowerCase(Locale.ROOT);
                return value.contains("application/json") || value.contains("+json");
            }
        }
        return false;
    }

    private static String normalizeKey(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]", "");
    }

    static String buildJsonOperatorPayload(String body, List<Object> path,
                                           String operator, String value) {
        if (operator == null || !Set.of("$ne", "$eq", "$regex").contains(operator)) return body;
        JsonObject operatorObject = new JsonObject();
        operatorObject.addProperty(operator, value);
        return JsonScanSupport.replaceElement(body, path, operatorObject);
    }

    private static boolean usable(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null
                && ResponseGuard.isUsableResponse(exchange);
    }

    private static boolean cancelled() {
        return Thread.currentThread().isInterrupted() || ScanState.isCancelled();
    }

    private void perHostDelay() throws InterruptedException {
        int delay = Math.min(10_000, Math.max(0,
                config.getInt("nosqli.perHostDelay", 350)));
        if (delay > 0) Thread.sleep(delay);
    }

    private static boolean reflected(Probe probe, String canary) {
        if (probe == null || canary == null) return true;
        String body = probe.exchange().response().bodyToString();
        if (body != null && body.contains(canary)) return true;
        String location = responseHeader(probe.exchange(), "Location");
        return location != null && location.contains(canary);
    }

    private static String buildEvidence(Signal signal, ResponseProfile baseline,
                                        ResponseProfile broad, ResponseProfile impossible,
                                        ResponseProfile regexBroad, ResponseProfile regexImpossible) {
        return "Confirmation signal: " + signal + ". Baseline status/cardinality="
                + baseline.status() + "/" + baseline.cardinality()
                + "; repeated $ne broad status/cardinality=" + broad.status() + "/" + broad.cardinality()
                + "; repeated $eq impossible status/cardinality=" + impossible.status() + "/" + impossible.cardinality()
                + "; independent $regex broad status/cardinality=" + regexBroad.status() + "/" + regexBroad.cardinality()
                + "; $regex impossible status/cardinality=" + regexImpossible.status() + "/" + regexImpossible.cardinality()
                + ". Response structures and outcomes were stable across repeated controls.";
    }

    private static ResponseProfile profile(HttpRequestResponse exchange) {
        String body = exchange.response().bodyToString();
        if (body == null) body = "";
        return profile(exchange.response().statusCode(), body,
                responseHeader(exchange, "Location"));
    }

    static ResponseProfile profile(int status, String body, String location) {
        if (body == null) body = "";
        String redirect = normalizeRedirect(location);
        if (body.length() <= MAX_PROFILE_BODY && hasSafeNesting(body)) {
            try {
                JsonElement json = JsonParser.parseString(body);
                return new ResponseProfile(status, structure(json),
                        resultCardinality(json), hasAuthenticationSuccess(json), redirect);
            } catch (RuntimeException ignored) {
                // Not JSON; use a value-insensitive text structure.
            }
        }
        return new ResponseProfile(status, textStructure(body),
                -1, false, redirect);
    }

    static Signal confirmationSignal(ResponseProfile baseline, ResponseProfile replay,
                                     ResponseProfile broad, ResponseProfile impossible) {
        if (!sameOutcome(baseline, replay)) return Signal.NONE;
        return signalForPair(baseline, broad, impossible);
    }

    static boolean confirmsSignal(Signal expected, ResponseProfile baseline,
                                  ResponseProfile broad, ResponseProfile impossible) {
        return expected != Signal.NONE && signalForPair(baseline, broad, impossible) == expected;
    }

    private static Signal signalForPair(ResponseProfile baseline,
                                        ResponseProfile broad, ResponseProfile impossible) {
        if (broad == null || impossible == null || !applicationSuccess(broad.status())) {
            return Signal.NONE;
        }
        if (broad.authenticationSuccess() && !impossible.authenticationSuccess()) {
            return Signal.AUTHENTICATION;
        }
        if (broad.cardinality() > 0 && impossible.cardinality() >= 0
                && broad.cardinality() > impossible.cardinality()
                && (baseline.cardinality() < 0 || broad.cardinality() >= baseline.cardinality())) {
            return Signal.CARDINALITY;
        }
        if (broad.status() >= 200 && broad.status() < 300
                && impossible.status() >= 400 && impossible.status() < 500) {
            return Signal.STATUS;
        }
        if (broad.status() >= 300 && broad.status() < 400
                && impossible.status() >= 300 && impossible.status() < 400
                && !broad.redirectPath().isEmpty()
                && !broad.redirectPath().equals(impossible.redirectPath())) {
            return Signal.REDIRECT;
        }
        return Signal.NONE;
    }

    static boolean sameOutcome(ResponseProfile first, ResponseProfile second) {
        return first != null && second != null
                && first.status() == second.status()
                && first.cardinality() == second.cardinality()
                && first.authenticationSuccess() == second.authenticationSuccess()
                && first.structure().equals(second.structure())
                && first.redirectPath().equals(second.redirectPath());
    }

    private static boolean applicationSuccess(int status) {
        return status >= 200 && status < 400;
    }

    private static int resultCardinality(JsonElement element) {
        if (element == null || element.isJsonNull()) return -1;
        if (element.isJsonArray()) return element.getAsJsonArray().size();
        return largestNamedArray(element);
    }

    private static int largestNamedArray(JsonElement element) {
        if (element == null || element.isJsonNull()) return -1;
        int largest = -1;
        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                JsonElement value = entry.getValue();
                if (RESULT_ARRAY_KEYS.contains(entry.getKey().toLowerCase(Locale.ROOT))
                        && value.isJsonArray()) {
                    largest = Math.max(largest, value.getAsJsonArray().size());
                }
                largest = Math.max(largest, largestNamedArray(value));
            }
        } else if (element.isJsonArray()) {
            for (JsonElement value : element.getAsJsonArray()) {
                largest = Math.max(largest, largestNamedArray(value));
            }
        }
        return largest;
    }

    private static boolean hasAuthenticationSuccess(JsonElement element) {
        if (element == null || element.isJsonNull()) return false;
        if (element.isJsonArray()) {
            for (JsonElement child : element.getAsJsonArray()) {
                if (hasAuthenticationSuccess(child)) return true;
            }
            return false;
        }
        if (!element.isJsonObject()) return false;
        JsonObject object = element.getAsJsonObject();
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            String key = normalizeKey(entry.getKey());
            JsonElement value = entry.getValue();
            if ((key.equals("success") || key.equals("authenticated") || key.equals("isauthenticated"))
                    && value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean()
                    && value.getAsBoolean()) return true;
            if (AUTH_VALUE_KEYS.contains(key) && nonTrivial(value)) return true;
            if (AUTH_OBJECT_KEYS.contains(key) && value.isJsonObject()
                    && !value.getAsJsonObject().entrySet().isEmpty()) return true;
            if (hasAuthenticationSuccess(value)) return true;
        }
        return false;
    }

    private static boolean nonTrivial(JsonElement value) {
        if (value == null || value.isJsonNull()) return false;
        if (value.isJsonPrimitive()) {
            JsonPrimitive primitive = value.getAsJsonPrimitive();
            if (primitive.isString()) return !primitive.getAsString().isBlank();
            if (primitive.isBoolean()) return primitive.getAsBoolean();
            return true;
        }
        if (value.isJsonArray()) return !value.getAsJsonArray().isEmpty();
        return value.isJsonObject() && !value.getAsJsonObject().entrySet().isEmpty();
    }

    private static String structure(JsonElement root) {
        StringBuilder output = new StringBuilder();
        appendStructure(root, output, new int[]{0});
        return output.toString();
    }

    private static void appendStructure(JsonElement element, StringBuilder output, int[] nodes) {
        if (++nodes[0] > MAX_STRUCTURE_NODES || output.length() > 32_000) {
            output.append("#TRUNCATED");
            return;
        }
        if (element == null || element.isJsonNull()) { output.append('0'); return; }
        if (element.isJsonPrimitive()) {
            JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isBoolean()) output.append("B:").append(primitive.getAsBoolean());
            else if (primitive.isNumber()) output.append('N');
            else output.append('S');
            return;
        }
        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            output.append('[').append(array.size()).append(':');
            int limit = Math.min(array.size(), 5);
            for (int i = 0; i < limit; i++) appendStructure(array.get(i), output, nodes);
            output.append(']');
            return;
        }
        output.append('{');
        TreeSet<String> keys = new TreeSet<>(element.getAsJsonObject().keySet());
        for (String key : keys) {
            output.append(key).append(':');
            appendStructure(element.getAsJsonObject().get(key), output, nodes);
            output.append(';');
        }
        output.append('}');
    }

    private static String textStructure(String body) {
        Matcher tags = HTML_TAG.matcher(body);
        StringBuilder signature = new StringBuilder("HTML:");
        int count = 0;
        while (tags.find() && count++ < 500) signature.append(tags.group(1).toLowerCase(Locale.ROOT)).append(',');
        if (count > 0) return signature.append("#").append(body.length() / 256).toString();
        String normalized = LONG_DYNAMIC_TOKEN.matcher(body.toLowerCase(Locale.ROOT)).replaceAll("#token");
        normalized = NUMBER.matcher(normalized).replaceAll("#n").replaceAll("\\s+", " ").trim();
        return normalized.length() > 8_000 ? normalized.substring(0, 8_000) : normalized;
    }

    private static boolean hasSafeNesting(String value) {
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quoted) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') quoted = false;
            } else if (c == '"') {
                quoted = true;
            } else if (c == '{' || c == '[') {
                if (++depth > MAX_JSON_DEPTH) return false;
            } else if (c == '}' || c == ']') {
                if (--depth < 0) return false;
            }
        }
        return depth == 0 && !quoted;
    }

    private static String responseHeader(HttpRequestResponse exchange, String name) {
        for (var header : exchange.response().headers()) {
            if (header.name().equalsIgnoreCase(name)) return header.value();
        }
        return "";
    }

    private static String normalizeRedirect(String location) {
        if (location == null || location.isBlank()) return "";
        try {
            URI uri = URI.create(location);
            String path = uri.getPath();
            return (uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT))
                    + (path == null || path.isBlank() ? "/" : path);
        } catch (RuntimeException ignored) {
            int query = location.indexOf('?');
            return query >= 0 ? location.substring(0, query) : location;
        }
    }

    enum Signal { NONE, CARDINALITY, AUTHENTICATION, STATUS, REDIRECT }
    enum PointKind { PARAMETER, JSON }

    record ResponseProfile(int status, String structure, int cardinality,
                           boolean authenticationSuccess, String redirectPath) {}
    private record Mutation(HttpRequest request, String payload) {}
    private record Probe(HttpRequestResponse exchange, ResponseProfile profile, String payload) {}
    private record InjectionPoint(String name, String originalValue,
                                  HttpParameterType parameterType, PointKind kind,
                                  List<Object> jsonPath, String identity) {
        String displayName() { return name; }
        boolean matches(String requested) {
            if (requested == null) return false;
            if (name.equalsIgnoreCase(requested) || identity.equals(requested)) return true;
            if (!jsonPath.isEmpty()) {
                Object leaf = jsonPath.get(jsonPath.size() - 1);
                return leaf instanceof String key && key.equalsIgnoreCase(requested);
            }
            return false;
        }
    }
}

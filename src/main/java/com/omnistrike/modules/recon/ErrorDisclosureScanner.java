package com.omnistrike.modules.recon;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.model.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ErrorDisclosureScanner — passive detector for verbose server error pages,
 * stack traces, and framework debug output leaked in HTTP responses.
 *
 * Covers Java (core + Jackson + Spring), Python (CPython + Django + Werkzeug/Flask),
 * PHP (core + Laravel Whoops/Ignition), .NET (ASP.NET yellow page + stack frames),
 * Ruby/Rails, Node.js, Go panics, and database driver exceptions.
 *
 * Rules:
 *   - 4xx responses are NEVER flagged (user-error bodies are out of scope).
 *     Only 5xx, and 2xx/3xx that contain a trace body, fire findings.
 *   - Strong anchors only: stack frames with file+line, distinctive debug markup,
 *     or fully-qualified exception class names. Generic words like "Exception"
 *     alone never trigger — too common in docs and JSON payloads.
 *   - One finding per host + path + error category — no per-request spam.
 *   - Severity INFO, Confidence TENTATIVE.
 */
public class ErrorDisclosureScanner implements ScanModule {

    private static final String MODULE_ID = "error-disclosure";
    private static final int MAX_BODY_SIZE = 512_000;
    private static final int MIN_BODY_SIZE = 30;

    private MontoyaApi api;
    private ModuleConfig config;

    // Dedup: "host|path|category" → true
    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    private static final Set<String> SCANNABLE_TYPES = Set.of(
            "text/html", "text/plain", "text/xml",
            "application/json", "application/xml", "application/xhtml+xml",
            "application/problem+json", "application/problem+xml"
    );

    // ── Error categories ──
    private enum Category {
        JAVA("Java stack trace"),
        JACKSON("Jackson deserialization error"),
        SPRING("Spring framework error"),
        PYTHON("Python traceback"),
        DJANGO("Django debug page"),
        WERKZEUG("Werkzeug/Flask debugger"),
        PHP("PHP error with stack trace"),
        LARAVEL("Laravel Whoops/Ignition debug page"),
        DOTNET(".NET/ASP.NET error page"),
        RUBY("Ruby/Rails stack trace"),
        NODEJS("Node.js stack trace"),
        GO("Go panic / runtime error"),
        DATABASE("Database driver error");

        final String displayName;
        Category(String displayName) { this.displayName = displayName; }
    }

    // ── Patterns ──

    // Java: "at com.example.Foo.bar(Foo.java:42)" — extremely distinctive
    private static final Pattern JAVA_STACK_FRAME = Pattern.compile(
            "(?m)^\\s*at\\s+[\\w$.]+\\.[\\w$<>]+\\([\\w$]+\\.java:\\d+\\)");

    // Java: "Caused by: some.package.SomeException"
    private static final Pattern JAVA_CAUSED_BY = Pattern.compile(
            "Caused by:\\s+(?:[a-z][\\w]*\\.){2,}[A-Z]\\w*(?:Exception|Error)\\b");

    // Jackson: specific class names in com.fasterxml.jackson.*
    private static final Pattern JACKSON_CLASS = Pattern.compile(
            "com\\.fasterxml\\.jackson\\.[\\w.]+"
                    + "|(?:JsonMappingException|JsonParseException|UnrecognizedPropertyException"
                    + "|InvalidDefinitionException|MismatchedInputException|InvalidFormatException"
                    + "|InvalidTypeIdException|ValueInstantiationException|IgnoredPropertyException"
                    + "|DatabindException|JsonProcessingException|JsonGenerationException)\\b");

    // Jackson: characteristic error messages (only trusted when co-occurring with a stack frame)
    private static final Pattern JACKSON_MSG = Pattern.compile(
            "Cannot deserialize (?:value|instance) of type"
                    + "|Could not read JSON"
                    + "|Unrecognized field \"[^\"]+\""
                    + "|Cannot construct instance of"
                    + "|No suitable constructor found for type"
                    + "|Instantiation of \\[simple type"           // InvalidDefinitionException verbose form
                    + "|No content to map due to end-of-input"     // MismatchedInputException — empty body
                    + "|Cannot deserialize Map key of type"        // InvalidFormatException — Map key mismatch
                    + "|N/A \\(no Creators, like default constructor"  // InvalidDefinitionException — no-arg ctor
                    + "|Type id handling not implemented"           // abstract type with no @JsonSubTypes
                    + "|Problem deserializing"                      // broad Jackson error prefix
                    + "|Trailing token \\(of type");               // extra content after root JSON value

    // Jackson polymorphic type errors — standalone signal, no stack frame required.
    // These messages come exclusively from Jackson's InvalidTypeIdException / @JsonTypeInfo handling.
    // Their presence confirms the app uses polymorphic deserialization (DefaultTyping or
    // @JsonTypeInfo), which is the exact attack surface for Jackson gadget-chain exploits
    // (CVE-2017-7525, CVE-2019-14379, CVE-2020-24616, etc.).
    // Anchors: "type id '" and "[simple type, class " are Jackson-internal terminology
    // that cannot occur in normal application content.
    private static final Pattern JACKSON_POLY = Pattern.compile(
            "Could not resolve type id '[^']{1,200}'"          // InvalidTypeIdException — unknown subtype
                    + "|missing type id property '[^']{1,50}'" // @JsonTypeInfo property absent in JSON
                    + "|Subtype of \\[simple type, class ");    // subtype resolution failure prefix

    // Java reflection errors — FP-safe: fully-qualified java.lang.* prefix + colon/class suffix
    private static final Pattern JAVA_REFLECT = Pattern.compile(
            "java\\.lang\\.ClassNotFoundException:\\s+[\\w$.]{3,}"   // missing class at runtime
                    + "|java\\.lang\\.NoSuchMethodException:\\s+[\\w$.]{3,}"  // missing method
                    + "|java\\.lang\\.NoSuchFieldException:\\s+[\\w$.]{3,}"   // missing field
                    + "|java\\.lang\\.reflect\\.InvocationTargetException");  // reflective call failure

    // Java native serialization errors — FP-safe: java.io.* fully-qualified prefix
    private static final Pattern JAVA_SERIAL = Pattern.compile(
            "java\\.io\\.InvalidClassException:"         // serial UID mismatch / class evolution
                    + "|java\\.io\\.NotSerializableException:\\s+[\\w$.]{3,}"  // non-serializable class
                    + "|java\\.io\\.StreamCorruptedException"  // invalid/truncated serialization stream
                    + "|java\\.io\\.InvalidObjectException:"); // validateObject() rejection

    // JAXB (Java XML Binding) errors — FP-safe: javax/jakarta.xml.bind.* prefix
    private static final Pattern JAVA_JAXB = Pattern.compile(
            "(?:javax|jakarta)\\.xml\\.bind\\.(?:JAXBException|MarshalException|UnmarshalException)");

    // Spring: fully-qualified Spring exception class
    private static final Pattern SPRING_EXCEPTION = Pattern.compile(
            "org\\.springframework\\.[\\w.]+\\.[A-Z]\\w*(?:Exception|Error)\\b");

    // Spring Boot Whitelabel Error Page (dev mode leaked to prod)
    private static final Pattern SPRING_WHITELABEL = Pattern.compile(
            "(?i)<title>[^<]*Whitelabel Error Page</title>"
                    + "|This application has no explicit mapping for /error");

    // Python: "Traceback (most recent call last):" + at least one File line
    private static final Pattern PYTHON_TRACEBACK = Pattern.compile(
            "Traceback \\(most recent call last\\):[\\s\\S]{0,2000}?"
                    + "File \"[^\"]+\\.py\", line \\d+");

    // Django DEBUG=True page — highly distinctive markup
    private static final Pattern DJANGO_DEBUG = Pattern.compile(
            "(?i)You(?:'|&#39;)re seeing this error because you have <code>DEBUG = True</code>"
                    + "|<title>\\w+Error at /"
                    + "|Django Version:</th>"
                    + "|Exception Type:</th>\\s*<td>");

    // Werkzeug / Flask interactive debugger
    private static final Pattern WERKZEUG_DEBUG = Pattern.compile(
            "(?i)<title>[^<]*Werkzeug Debugger</title>"
                    + "|The Werkzeug Debugger"
                    + "|class=\"debugger\"|werkzeug\\.debug|data-traceback-id");

    // PHP: error with filename+line, or Uncaught ... Stack trace: #0
    private static final Pattern PHP_ERROR = Pattern.compile(
            "(?i)<b>(?:Fatal error|Parse error|Warning|Notice)</b>:.*?on line <b>\\d+</b>"
                    + "|PHP (?:Fatal error|Parse error|Warning|Notice):.*?on line \\d+"
                    + "|Uncaught (?:[A-Z]\\w+\\\\)*[A-Z]\\w+(?:Exception|Error):[\\s\\S]{0,500}Stack trace:"
                    + "|(?m)^#\\d+\\s+.+?\\.php\\(\\d+\\):\\s+\\w+");

    // Laravel Whoops / Ignition debug page — distinctive HTML class names and namespace fragments
    private static final Pattern LARAVEL_DEBUG = Pattern.compile(
            "(?i)<title>[^<]*Whoops!"
                    + "|class=\"exception-message"
                    + "|id=\"exception-header"
                    + "|\\bIlluminate\\\\[A-Z]\\w+\\\\[A-Z]"
                    + "|class=\"frame-code|<div class=\"Whoops");

    // ASP.NET yellow screen
    private static final Pattern DOTNET_YELLOW = Pattern.compile(
            "(?i)Server Error in (?:&#39;|')[^'&]*(?:&#39;|') Application\\."
                    + "|<title>\\s*Runtime Error\\s*</title>"
                    + "|<b>Description:\\s*</b>\\s*An unhandled exception");

    // .NET stack frame with "in <file>:line N" (distinct: Java uses "(File.java:N)")
    private static final Pattern DOTNET_FRAME = Pattern.compile(
            "(?m)^\\s*at\\s+[\\w.<>]+\\([^)]*\\)\\s+in\\s+[^:\\n]+:line\\s+\\d+");

    // Fully-qualified System.* or Microsoft.* exception class
    private static final Pattern DOTNET_EXCEPTION = Pattern.compile(
            "(?:System|Microsoft)(?:\\.[A-Z][\\w]+)+\\.[A-Z]\\w*Exception\\b");

    // Ruby: "/path/to/file.rb:42:in `method'"
    private static final Pattern RUBY_FRAME = Pattern.compile(
            "(?m)^(?:\\s|from\\s)?.+?\\.rb:\\d+:in\\s+[`'][^'\\n]+'");

    // Rails-specific error class names
    private static final Pattern RAILS_ERROR = Pattern.compile(
            "(?:ActionController|ActiveRecord|ActionView|ActiveModel)::[A-Z]\\w+(?:Error|Exception)\\b");

    // Node.js: "    at funcName (/path/file.js:42:10)"
    private static final Pattern NODEJS_FRAME = Pattern.compile(
            "(?m)^\\s+at\\s+[\\w.<>\\[\\] ]+\\s\\([\\w./\\\\-]+\\.(?:js|ts|mjs|cjs):\\d+:\\d+\\)");

    // Go: goroutine header, panic prefix, or .go:line+offset
    private static final Pattern GO_PANIC = Pattern.compile(
            "(?m)^(?:panic: |goroutine \\d+ \\[\\w+\\]:|fatal error: |runtime error: )"
                    + "|(?m)^\\s+[\\w./-]+\\.go:\\d+\\s+\\+0x[0-9a-f]+");

    // Database driver / SQL errors that expose schema, query, or driver internals.
    // Anchored to distinctive vendor-specific strings to avoid FP on generic "error" words.
    private static final Pattern DB_ERROR = Pattern.compile(
            // Oracle
            "ORA-\\d{5}:"
            // PostgreSQL driver class
            + "|org\\.postgresql\\.util\\.PSQLException"
            // MySQL driver class
            + "|com\\.mysql\\.(?:cj\\.)?jdbc\\.exceptions"
            // MySQL "SQL syntax" error — exact wording emitted by MySQL
            + "|You have an error in your SQL syntax; check the manual"
            // MSSQL unclosed quote — exact wording
            + "|Unclosed quotation mark after the character string"
            // MSSQL generic: "Incorrect syntax near" — only flag when paired with "near '"
            + "|Incorrect syntax near '[^']{1,50}'"
            // PHP PDO
            + "|PDOException\\b[\\s\\S]{0,300}?(?:Stack trace|SQLSTATE)"
            // PHP SQLSTATE with code+message
            + "|SQLSTATE\\[\\w+\\]:[^\\n]{5,200}"
            // MSSQL: Microsoft SQL Server + Error + State in same error block
            + "|Microsoft SQL Server[\\s\\S]{0,100}Error:[\\s\\S]{0,100}State:"
            // MSSQL OLE DB provider string
            + "|\\[Microsoft]\\[ODBC\\s+[\\w ]+Driver]"
            // MongoDB driver
            + "|MongoError:\\s+[A-Z].{5,200}at\\s"
            // Python SQLAlchemy
            + "|SQLAlchemy[\\w.]*Error:"
            // Python psycopg2
            + "|psycopg2\\.errors\\.[A-Z]"
            // SQLite
            + "|sqlite3\\.OperationalError:"
            + "|near \"[^\"]{1,40}\": syntax error"
            // Hibernate (Java ORM) — fully qualified class avoids FP
            + "|org\\.hibernate\\.exception\\.[A-Z]\\w+Exception"
            + "|org\\.hibernate\\.HibernateException"
            // JPA/Jakarta Persistence
            + "|javax\\.persistence\\.[A-Z]\\w+Exception"
            + "|jakarta\\.persistence\\.[A-Z]\\w+Exception"
            // Sequelize (Node ORM) with stack trace
            + "|sequelize[\\w.]*Error:[\\s\\S]{0,200}at\\s"
            // DB2
            + "|DB2 SQL Error: SQLCODE=-?\\d+"
            // SQLCODE (IBM DB2 / generic)
            + "|SQLCODE\\s*=\\s*-?\\d{3,6}");

    // ── Module interface ──

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Error Disclosure Scanner"; }

    @Override
    public String getDescription() {
        return "Passively detects verbose server error pages and stack traces in HTTP responses. "
                + "Covers Java (incl. Jackson + Spring), Python (incl. Django + Flask/Werkzeug), "
                + "PHP (incl. Laravel), .NET/ASP.NET, Ruby/Rails, Node.js, Go, and database drivers. "
                + "Skips all 4xx responses. Flags INFO / Tentative — one finding per path per category.";
    }

    @Override public ModuleCategory getCategory() { return ModuleCategory.RECON; }
    @Override public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override public void destroy() { }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        int status;
        try { status = response.statusCode(); } catch (Exception e) { return findings; }

        // 4xx = user error — never flag per project policy.
        if (status >= 400 && status < 500) return findings;

        if (!isScannableType(response)) return findings;

        String host, path, url;
        try {
            host = requestResponse.request().httpService().host();
            path = requestResponse.request().pathWithoutQuery();
            url  = requestResponse.request().url();
        } catch (Exception e) { return findings; }

        String body;
        try { body = response.bodyToString(); } catch (Exception e) { return findings; }
        if (body == null || body.length() < MIN_BODY_SIZE) return findings;
        if (body.length() > MAX_BODY_SIZE) body = body.substring(0, MAX_BODY_SIZE);

        checkJava(body, host, path, url, requestResponse, findings);
        checkJackson(body, host, path, url, requestResponse, findings);
        checkSpring(body, host, path, url, requestResponse, findings);
        checkPython(body, host, path, url, requestResponse, findings);
        checkDjango(body, host, path, url, requestResponse, findings);
        checkWerkzeug(body, host, path, url, requestResponse, findings);
        checkPhp(body, host, path, url, requestResponse, findings);
        checkLaravel(body, host, path, url, requestResponse, findings);
        checkDotNet(body, host, path, url, requestResponse, findings);
        checkRuby(body, host, path, url, requestResponse, findings);
        checkNodeJs(body, host, path, url, requestResponse, findings);
        checkGo(body, host, path, url, requestResponse, findings);
        checkDatabase(body, host, path, url, requestResponse, findings);

        return findings;
    }

    // ── Detectors ──

    private void checkJava(String body, String host, String path, String url,
                            HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.JAVA)) return;

        // Tier 1: Stack frame — "at com.example.Foo.bar(Foo.java:42)"
        Matcher m = JAVA_STACK_FRAME.matcher(body);
        String ev = m.find() ? m.group() : null;

        // Tier 2: Caused by with FQ exception class
        if (ev == null) {
            Matcher c = JAVA_CAUSED_BY.matcher(body);
            if (c.find()) ev = c.group();
        }

        // Tier 3: Reflection errors — FQ java.lang.* prefix makes these standalone-safe
        if (ev == null) ev = firstMatch(JAVA_REFLECT, body);

        // Tier 4: Native Java serialization errors — FQ java.io.* prefix, standalone-safe
        if (ev == null) ev = firstMatch(JAVA_SERIAL, body);

        // Tier 5: JAXB XML binding errors — FQ javax/jakarta.xml.bind.* prefix, standalone-safe
        if (ev == null) ev = firstMatch(JAVA_JAXB, body);

        if (ev == null) { unmark(host, path, Category.JAVA); return; }
        out.add(finding(Category.JAVA, url, rr, ev,
                "Java exception or stack trace leaked in response body — exposes internal "
                        + "class names, file paths, line numbers, and runtime state. "
                        + "Includes stack frames, reflection errors (ClassNotFoundException, "
                        + "NoSuchMethodException), native serialization errors "
                        + "(InvalidClassException, StreamCorruptedException), and JAXB binding errors.",
                "Configure a global exception handler that logs the trace server-side and "
                        + "returns a generic error response. Never propagate stack traces, "
                        + "exception messages, or class names to clients."));
    }

    private void checkJackson(String body, String host, String path, String url,
                               HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.JACKSON)) return;

        // Tier 1: Fully-qualified Jackson class name — strongest, standalone safe
        Matcher cls = JACKSON_CLASS.matcher(body);
        boolean hasClass = cls.find();

        // Tier 2: Polymorphic type-id error — standalone safe (Jackson-internal terminology).
        // Higher priority than generic message matching because it implies gadget-chain surface.
        Matcher poly = JACKSON_POLY.matcher(body);
        boolean hasPoly = !hasClass && poly.find();

        // Tier 3: Characteristic Jackson message, but only trusted alongside a Java stack frame
        boolean hasMsg = !hasClass && !hasPoly
                && JACKSON_MSG.matcher(body).find()
                && JAVA_STACK_FRAME.matcher(body).find();

        if (!hasClass && !hasPoly && !hasMsg) { unmark(host, path, Category.JACKSON); return; }

        String ev;
        String description;
        String remediation;

        if (hasPoly) {
            ev = poly.group();
            description = "Jackson polymorphic type handling error disclosed. The application uses "
                    + "@JsonTypeInfo or DefaultTyping, which is the exact attack surface targeted "
                    + "by Jackson gadget-chain deserialization exploits (CVE-2017-7525, "
                    + "CVE-2019-14379, CVE-2020-24616 family). The type id value in the error "
                    + "message may reflect attacker-controlled input. Verify whether "
                    + "DefaultTyping.NON_FINAL, OBJECT_AND_NON_CONCRETE, or EVERYTHING is active.";
            remediation = "Avoid DefaultTyping entirely. Replace with explicit @JsonSubTypes "
                    + "on a known sealed class hierarchy. If polymorphism is required, use "
                    + "a PolymorphicTypeValidator that allowlists only expected subtypes. "
                    + "Upgrade jackson-databind to the latest patched version.";
        } else {
            ev = hasClass ? cls.group() : firstMatch(JACKSON_MSG, body);
            description = "Jackson deserialization error leaked — exposes internal type names, "
                    + "field names, and sometimes user input reflected in the error message. "
                    + "Jackson errors are also a strong signal of a deserialization attack surface.";
            remediation = "Add a global @ControllerAdvice (Spring) or ObjectMapper error handler "
                    + "that swallows Jackson exceptions and returns a generic 400/500 body. "
                    + "Enable DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES carefully.";
        }

        out.add(finding(Category.JACKSON, url, rr, ev, description, remediation));
    }

    private void checkSpring(String body, String host, String path, String url,
                              HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.SPRING)) return;
        String ev = firstMatch(SPRING_WHITELABEL, body);
        if (ev == null) ev = firstMatch(SPRING_EXCEPTION, body);
        if (ev == null) { unmark(host, path, Category.SPRING); return; }
        out.add(finding(Category.SPRING, url, rr, ev,
                "Spring framework error or Whitelabel Error Page disclosed — "
                        + "indicates missing custom error handling in a Spring Boot application.",
                "Add a @ControllerAdvice with @ExceptionHandler for broad exception types. "
                        + "Set server.error.include-stacktrace=never and "
                        + "server.error.include-message=never in application.properties."));
    }

    private void checkPython(String body, String host, String path, String url,
                              HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.PYTHON)) return;
        Matcher m = PYTHON_TRACEBACK.matcher(body);
        if (!m.find()) { unmark(host, path, Category.PYTHON); return; }
        out.add(finding(Category.PYTHON, url, rr, m.group(),
                "Python traceback leaked — exposes source file paths, line numbers, "
                        + "and the full exception chain.",
                "Disable debug mode in production and catch exceptions at the WSGI/ASGI "
                        + "boundary to return a generic response."));
    }

    private void checkDjango(String body, String host, String path, String url,
                              HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.DJANGO)) return;
        Matcher m = DJANGO_DEBUG.matcher(body);
        if (!m.find()) { unmark(host, path, Category.DJANGO); return; }
        out.add(finding(Category.DJANGO, url, rr, m.group(),
                "Django debug page disclosed (DEBUG=True). These pages expose settings, "
                        + "installed apps, SQL queries, full tracebacks, and request data.",
                "Set DEBUG = False and configure ALLOWED_HOSTS in settings.py for production. "
                        + "Django's debug page must never be reachable externally."));
    }

    private void checkWerkzeug(String body, String host, String path, String url,
                                HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.WERKZEUG)) return;
        Matcher m = WERKZEUG_DEBUG.matcher(body);
        if (!m.find()) { unmark(host, path, Category.WERKZEUG); return; }
        out.add(finding(Category.WERKZEUG, url, rr, m.group(),
                "Werkzeug/Flask interactive debugger exposed. If the full debugger console "
                        + "is reachable, an attacker can execute arbitrary Python via the debugger PIN.",
                "Never use debug=True or the Werkzeug debugger in production. Deploy behind "
                        + "Gunicorn or uWSGI with debug disabled."));
    }

    private void checkPhp(String body, String host, String path, String url,
                           HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.PHP)) return;
        Matcher m = PHP_ERROR.matcher(body);
        if (!m.find()) { unmark(host, path, Category.PHP); return; }
        out.add(finding(Category.PHP, url, rr, m.group(),
                "PHP error or stack trace leaked — exposes file system paths, line numbers, "
                        + "and sometimes function arguments.",
                "Set display_errors=Off and log_errors=On in php.ini for production. "
                        + "Route errors to a log file; never render them to users."));
    }

    private void checkLaravel(String body, String host, String path, String url,
                               HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.LARAVEL)) return;
        Matcher m = LARAVEL_DEBUG.matcher(body);
        if (!m.find()) { unmark(host, path, Category.LARAVEL); return; }
        out.add(finding(Category.LARAVEL, url, rr, m.group(),
                "Laravel Whoops/Ignition debug page exposed — discloses environment variables, "
                        + "source code excerpts, and request data. Historical CVE-2021-3129 in "
                        + "facade/ignition allowed unauthenticated RCE via this debug surface.",
                "Set APP_DEBUG=false in .env for production. Ensure facade/ignition >= 2.5.2. "
                        + "Implement a custom exception renderer."));
    }

    private void checkDotNet(String body, String host, String path, String url,
                              HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.DOTNET)) return;
        String ev = firstMatch(DOTNET_YELLOW, body);
        if (ev == null) ev = firstMatch(DOTNET_FRAME, body);
        if (ev == null) {
            // Exception class name is a weak signal alone; require a StackTrace keyword nearby.
            Matcher ex = DOTNET_EXCEPTION.matcher(body);
            if (ex.find() && (body.contains("Stack Trace:") || body.contains("StackTrace"))) {
                ev = ex.group();
            }
        }
        if (ev == null) { unmark(host, path, Category.DOTNET); return; }
        out.add(finding(Category.DOTNET, url, rr, ev,
                ".NET/ASP.NET error page or stack trace leaked in response body.",
                "Set <customErrors mode=\"On\"/> in web.config. For ASP.NET Core, remove "
                        + "UseDeveloperExceptionPage() from the production pipeline and set "
                        + "<compilation debug=\"false\"/>."));
    }

    private void checkRuby(String body, String host, String path, String url,
                            HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.RUBY)) return;
        String ev = firstMatch(RUBY_FRAME, body);
        if (ev == null) {
            // Rails error class alone is weak; require a Ruby frame or Rails.root context.
            Matcher r = RAILS_ERROR.matcher(body);
            if (r.find() && (RUBY_FRAME.matcher(body).find() || body.contains("Rails.root:"))) {
                ev = r.group();
            }
        }
        if (ev == null) { unmark(host, path, Category.RUBY); return; }
        out.add(finding(Category.RUBY, url, rr, ev,
                "Ruby/Rails stack trace leaked in response body.",
                "Set config.consider_all_requests_local = false in production.rb and ensure "
                        + "RAILS_ENV is production. Handle exceptions with a custom rescue_from."));
    }

    private void checkNodeJs(String body, String host, String path, String url,
                              HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.NODEJS)) return;
        String ev = firstMatch(NODEJS_FRAME, body);
        // If no direct frame yet, check for specific error messages — but require a frame to confirm.
        if (ev == null && NODEJS_FRAME.matcher(body).find()) {
            ev = firstMatch(Pattern.compile(
                    "Error: Cannot find module '[^']+'"
                            + "|UnhandledPromiseRejectionWarning:"), body);
        }
        if (ev == null) { unmark(host, path, Category.NODEJS); return; }
        out.add(finding(Category.NODEJS, url, rr, ev,
                "Node.js stack trace leaked — exposes absolute file paths on the server filesystem.",
                "Add a global Express error handler that returns a generic response. "
                        + "Never send err.stack or err.message to clients in production."));
    }

    private void checkGo(String body, String host, String path, String url,
                          HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.GO)) return;
        Matcher m = GO_PANIC.matcher(body);
        if (!m.find()) { unmark(host, path, Category.GO); return; }
        out.add(finding(Category.GO, url, rr, m.group(),
                "Go panic or runtime error leaked in response body.",
                "Add a recover() middleware wrapping each HTTP handler. Log the panic "
                        + "server-side and return a generic 500 response to clients."));
    }

    private void checkDatabase(String body, String host, String path, String url,
                                HttpRequestResponse rr, List<Finding> out) {
        if (!mark(host, path, Category.DATABASE)) return;
        Matcher m = DB_ERROR.matcher(body);
        if (!m.find()) { unmark(host, path, Category.DATABASE); return; }
        out.add(finding(Category.DATABASE, url, rr, m.group(),
                "Database / SQL error leaked in response body — exposes schema names, table/column "
                        + "names, query fragments, SQLSTATE codes, or vendor-specific error text "
                        + "(MySQL syntax errors, ORA-, PSQLException, MSSQL, SQLite, Hibernate, etc.). "
                        + "Strong indicator of a SQL injection attack surface.",
                "Catch all database exceptions in the data-access layer and return a generic error. "
                        + "Never propagate raw driver messages (ORA-, SQLSTATE, MySQL syntax errors, "
                        + "etc.) to clients. Enable WAF rules for common SQL error strings."));
    }

    // ── Helpers ──

    private boolean isScannableType(HttpResponse response) {
        for (var h : response.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                String ct = h.value().toLowerCase();
                for (String t : SCANNABLE_TYPES) { if (ct.contains(t)) return true; }
                return false;
            }
        }
        return true; // no Content-Type → scan anyway (many error pages omit it)
    }

    private boolean mark(String host, String path, Category cat) {
        return seen.putIfAbsent(host + "|" + path + "|" + cat.name(), Boolean.TRUE) == null;
    }

    private void unmark(String host, String path, Category cat) {
        seen.remove(host + "|" + path + "|" + cat.name());
    }

    private static String firstMatch(Pattern p, String body) {
        Matcher m = p.matcher(body);
        return m.find() ? m.group() : null;
    }

    private static Finding finding(Category cat, String url, HttpRequestResponse rr,
                                    String rawEvidence, String description, String remediation) {
        String ev = rawEvidence == null ? "" : rawEvidence.replaceAll("\\s+", " ").trim();
        if (ev.length() > 300) ev = ev.substring(0, 300) + "...";
        return Finding.builder(MODULE_ID, cat.displayName + " disclosed",
                        Severity.INFO, Confidence.TENTATIVE)
                .url(url)
                .description(description)
                .evidence(ev)
                .responseEvidence(ev)
                .remediation(remediation)
                .requestResponse(rr)
                .build();
    }
}

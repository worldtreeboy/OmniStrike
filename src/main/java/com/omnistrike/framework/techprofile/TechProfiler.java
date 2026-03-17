package com.omnistrike.framework.techprofile;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.ActiveScanExecutor;
import com.omnistrike.framework.techprofile.TechContext.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * High-Fidelity Technology Interrogation Engine.
 *
 * Three-phase pipeline:
 *   1. interrogate() — Passive. Extracts every evidence signal from headers, cookies,
 *      error pages, and body patterns. Feeds weighted scores to TechRegistry.
 *   2. correlate()   — Detects contradictions (liar proxies), resolves ambiguities,
 *      and triggers tie-breaker probes when evidence is split between two techs.
 *   3. tieBreak()    — Active. Sends differential syntax probes to resolve
 *      category-specific ambiguities (Java vs .NET, PHP vs Python, Linux vs Windows).
 *
 * Zero-FP rule: a tech is CONFIRMED only when it passes a Positive Probe AND
 * fails a Negative Probe (competing tech behaviour is absent). Single-signal
 * matches stay TENTATIVE until corroborated by a second independent signal.
 *
 * Thread model: interrogate() and correlate() run on the passive executor
 * (non-blocking). tieBreak() runs on ActiveScanExecutor (rate-limited).
 */
public final class TechProfiler implements TechRegistry.TechUpdateListener {

    private final TechRegistry registry;
    private final MontoyaApi api;
    private volatile ActiveScanExecutor executor;

    private final Set<String> tieBreakQueued = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean enabled = new AtomicBoolean(true);

    // ── Proxy/WAF/CDN signatures that mask origin tech ────────────────────
    private static final Set<String> PROXY_SIGNATURES = Set.of(
            "cloudflare", "akamai", "fastly", "varnish", "incapsula",
            "sucuri", "stackpath", "edgecast", "keycdn", "cloudfront",
            "azurewebsites.net", "herokuapp.com", "netlify"
    );

    public TechProfiler(TechRegistry registry, MontoyaApi api) {
        this.registry = Objects.requireNonNull(registry);
        this.api = Objects.requireNonNull(api);
        // Subscribe to cross-module feedback — triggers tie-breakers when new evidence arrives
        registry.addListener(this);
    }

    public void setExecutor(ActiveScanExecutor executor) { this.executor = executor; }
    public void setEnabled(boolean enabled) { this.enabled.set(enabled); }
    public boolean isEnabled() { return enabled.get(); }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 1: interrogate() — Passive evidence extraction
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Passively extract every technology signal from a request/response pair.
     * Called for every in-scope proxied response. Must be fast.
     */
    public void interrogate(HttpRequestResponse reqResp) {
        if (!enabled.get() || reqResp == null) return;
        HttpRequest request = reqResp.request();
        HttpResponse response = reqResp.response();
        if (request == null || response == null) return;

        String host;
        try { host = request.httpService().host(); } catch (Exception e) { return; }

        // ── Response headers ──────────────────────────────────────────────
        String serverHeader = null;
        for (var header : response.headers()) {
            String name = header.name().toLowerCase(Locale.ROOT);
            String value = header.value();
            if (value == null || value.isEmpty()) continue;

            switch (name) {
                case "server" -> {
                    serverHeader = value;
                    interrogateServerHeader(host, value);
                }
                case "x-powered-by" -> interrogatePoweredBy(host, value);
                case "x-aspnet-version", "x-aspnetmvc-version" ->
                        registry.addEvidence(host, TechStack.DOTNET, TechContext.W_VERSION_HEADER,
                                "hdr:" + name + ":" + value);
                case "x-drupal-cache", "x-drupal-dynamic-cache" ->
                        registry.addEvidence(host, TechStack.DRUPAL, TechContext.W_VERSION_HEADER,
                                "hdr:" + name);
                case "x-generator" -> interrogateGenerator(host, value);
                case "x-runtime" -> {
                    if (value.matches("\\d+\\.\\d+"))
                        registry.addEvidence(host, TechStack.RUBY, TechContext.W_URI_PATTERN, "hdr:x-runtime");
                }
                case "set-cookie" -> interrogateCookie(host, value);
                default -> { /* skip */ }
            }
        }

        // ── Request cookies (browser-sent) ────────────────────────────────
        for (var param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) {
                interrogateCookie(host, param.name() + "=");
            }
        }

        // ── Response body (first 8KB — error pages, stack traces) ─────────
        try {
            String body = response.bodyToString();
            if (body != null && body.length() > 10) {
                String sample = body.length() > 8192 ? body.substring(0, 8192) : body;
                interrogateBody(host, sample, response.statusCode());
            }
        } catch (Exception ignored) {}

        // ── Phase 2: correlate — detect proxies, resolve contradictions ───
        correlate(host, serverHeader, response);
    }

    private void interrogateServerHeader(String host, String value) {
        String lv = value.toLowerCase(Locale.ROOT);
        for (var rule : SERVER_RULES) {
            if (lv.contains(rule.pattern)) {
                // Server header gets LOW weight — easily spoofed by reverse proxies
                registry.addEvidence(host, rule.tech, TechContext.W_SERVER_HEADER,
                        "hdr:server:" + rule.pattern);
            }
        }
    }

    private void interrogatePoweredBy(String host, String value) {
        String lv = value.toLowerCase(Locale.ROOT);
        for (var rule : POWERED_BY_RULES) {
            if (lv.contains(rule.pattern)) {
                registry.addEvidence(host, rule.tech, rule.weight,
                        "hdr:x-powered-by:" + rule.pattern);
            }
        }
    }

    private void interrogateGenerator(String host, String value) {
        String lv = value.toLowerCase(Locale.ROOT);
        if (lv.contains("wordpress"))
            registry.addEvidence(host, TechStack.WORDPRESS, TechContext.W_VERSION_HEADER, "hdr:generator:wp");
        else if (lv.contains("drupal"))
            registry.addEvidence(host, TechStack.DRUPAL, TechContext.W_VERSION_HEADER, "hdr:generator:drupal");
    }

    private void interrogateCookie(String host, String cookieStr) {
        String lv = cookieStr.toLowerCase(Locale.ROOT);
        for (var rule : COOKIE_RULES) {
            if (lv.startsWith(rule.prefix)) {
                registry.addEvidence(host, rule.tech, rule.weight, "cookie:" + rule.prefix);
            }
        }
    }

    private void interrogateBody(String host, String body, int statusCode) {
        boolean isError = statusCode >= 400;

        for (var rule : BODY_RULES) {
            if (rule.errorOnly && !isError) continue;
            if (rule.compiled.matcher(body).find()) {
                registry.addEvidence(host, rule.tech, rule.weight,
                        "body:" + rule.tech + ":" + rule.evidenceKey);
            }
        }

        // DBMS errors — highly specific, CONFIRMED-weight
        if (isError) {
            String bodyLower = body.toLowerCase(Locale.ROOT);
            for (var rule : DBMS_ERROR_RULES) {
                if (bodyLower.contains(rule.pattern)) {
                    registry.addEvidence(host, rule.tech, TechContext.W_DBMS_ERROR,
                            "dbms:" + rule.pattern);
                    break; // One DBMS per response
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 2: correlate() — contradiction detection & proxy handling
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Detect when a proxy/WAF/CDN is masking the origin. If the Server header
     * contradicts stronger evidence (X-Powered-By, stack traces, version headers),
     * mark the host as proxy-masked and trust the stronger signal.
     */
    private void correlate(String host, String serverHeader, HttpResponse response) {
        if (serverHeader == null) return;
        String serverLower = serverHeader.toLowerCase(Locale.ROOT);

        // Check for known proxy/CDN/WAF signatures in Server header
        for (String sig : PROXY_SIGNATURES) {
            if (serverLower.contains(sig)) {
                registry.markProxyDetected(host);
                return; // Known proxy — Server header is unreliable, skip contradiction check
            }
        }

        // Check for via/x-cache headers indicating reverse proxy
        for (var header : response.headers()) {
            String name = header.name().toLowerCase(Locale.ROOT);
            if (name.equals("via") || name.equals("x-cache") || name.equals("x-cache-hits")
                    || name.equals("cf-ray") || name.equals("x-akamai-transformed")
                    || name.equals("x-served-by") || name.equals("x-varnish")) {
                registry.markProxyDetected(host);
                break;
            }
        }

        // Contradiction check: Server says X, but version header says Y
        TechContext ctx = registry.getOrCreate(host);

        // Example: Server: nginx, but X-AspNet-Version present → .NET behind Nginx reverse proxy
        if (serverLower.contains("nginx") || serverLower.contains("apache")) {
            if (ctx.getScore(TechStack.DOTNET) >= TechContext.W_VERSION_HEADER) {
                registry.resolveContradiction(host, TechStack.NGINX, TechStack.DOTNET,
                        0, "contradiction:server-vs-aspnet"); // Weight 0 — DOTNET already scored
            }
            if (ctx.getScore(TechStack.JAVA) >= TechContext.W_COOKIE_NAME) {
                registry.resolveContradiction(host, TechStack.NGINX, TechStack.JAVA,
                        0, "contradiction:server-vs-jsessionid");
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 3: tieBreak() — Active differential probes
    // ════════════════════════════════════════════════════════════════════════

    /**
     * TechUpdateListener callback. When new evidence arrives but a category
     * is still ambiguous (multiple candidates, none CONFIRMED), queue a
     * tie-breaker probe to force a definitive answer.
     */
    @Override
    public void onTechUpdated(String host, TechStack tech, int newScore, ConfidenceLevel level) {
        if (!enabled.get() || executor == null) return;
        if (level == ConfidenceLevel.CONFIRMED) return; // Already resolved — no tie-breaker needed

        TechCategory category = tech.category();
        TechContext ctx = registry.get(host);
        if (ctx == null || !ctx.needsTieBreaker(category)) return;

        String key = host + "|" + category;
        if (!tieBreakQueued.add(key)) return; // Already queued

        // Queue tie-breaker on scan executor (respects rate limits)
        executor.submit(() -> {
            try {
                executeTieBreaker(host, category, ctx);
            } catch (Exception e) {
                log("[TieBreaker] Error for " + host + "/" + category + ": " + e.getMessage());
            }
        });
    }

    /**
     * Execute differential probes to resolve ambiguity in a category.
     * Each tie-breaker tests BOTH a positive assertion AND a negative assertion
     * against the competing tech.
     */
    private void executeTieBreaker(String host, TechCategory category, TechContext ctx) {
        // ── OS pre-probe: ICMP TTL fingerprint ────────────────────────────
        // Classic network-layer OS detection: Linux default TTL=64, Windows=128.
        // Runs before HTTP-based tie-breakers because it's faster (single ICMP echo)
        // and doesn't require an injectable parameter.
        // Weight is LOW (W_URI_PATTERN = 15) — TTL is trivially modified via sysctl/registry
        // and decremented by each hop, so this is TENTATIVE evidence at best.
        if (category == TechCategory.OS && ctx.isUnknown(TechCategory.OS)) {
            probeTtl(host);
        }

        TieBreaker[] breakers = TIE_BREAKERS.get(category);
        if (breakers == null) return;

        TechStack[] contenders = ctx.getTopTwo(category);
        if (contenders.length < 2) return; // Only one candidate — no tie to break

        log("[TieBreaker] " + host + " " + category + ": "
                + contenders[0] + "(" + ctx.getScore(contenders[0]) + ") vs "
                + contenders[1] + "(" + ctx.getScore(contenders[1]) + ")");

        for (TieBreaker tb : breakers) {
            // Only run if both contenders are in the tie-breaker's scope
            if (!tb.techA.equals(contenders[0]) && !tb.techA.equals(contenders[1])) continue;
            if (!tb.techB.equals(contenders[0]) && !tb.techB.equals(contenders[1])) continue;

            // Already resolved by earlier probe or cross-module feedback?
            if (ctx.isConfirmed(tb.techA) || ctx.isConfirmed(tb.techB)) return;

            executeSingleTieBreaker(host, ctx, tb);
        }
    }

    private void executeSingleTieBreaker(String host, TechContext ctx, TieBreaker tb) {
        // Send probe payload and analyze response
        HttpRequestResponse resp = sendProbe(host, ctx, tb.probePayload);
        if (resp == null || resp.response() == null) return;

        String body = safeBody(resp.response());

        // Positive assertion: does the response match techA's expected behaviour?
        boolean positiveMatch = tb.positivePattern.matcher(body).find();
        // Negative assertion: does the response match techB's expected behaviour?
        boolean negativeMatch = tb.negativePattern.matcher(body).find();

        if (positiveMatch && !negativeMatch) {
            // TechA confirmed: positive probe matched AND competing tech's pattern absent
            registry.addEvidence(host, tb.techA, TechContext.W_PROBE_POSITIVE,
                    "tiebreak:" + tb.name + ":positive");
            registry.addEvidence(host, tb.techA, TechContext.W_PROBE_NEGATIVE,
                    "tiebreak:" + tb.name + ":negative-absent");
            log("[TieBreaker] RESOLVED " + host + " → " + tb.techA + " (positive match, negative absent)");
        } else if (negativeMatch && !positiveMatch) {
            // TechB confirmed (reversed)
            registry.addEvidence(host, tb.techB, TechContext.W_PROBE_POSITIVE,
                    "tiebreak:" + tb.name + ":reverse-positive");
            registry.addEvidence(host, tb.techB, TechContext.W_PROBE_NEGATIVE,
                    "tiebreak:" + tb.name + ":reverse-negative-absent");
            log("[TieBreaker] RESOLVED " + host + " → " + tb.techB + " (reverse match)");
        }
        // Both match or neither → inconclusive, don't update. Zero-FP: no guessing.
    }

    /**
     * Double-blind verification: send probe payload with a unique random salt.
     * If the response contains the salt, the server is reflecting input (WAF echo),
     * not actually processing it. Used by tie-breaker probes to verify dynamic behaviour.
     */
    private boolean isReflection(HttpRequestResponse resp, String salt) {
        if (resp == null || resp.response() == null) return false;
        String body = safeBody(resp.response());
        return body.contains(salt);
    }

    // ── ICMP TTL OS Fingerprinting ────────────────────────────────────────

    /** Weight for TTL-based OS inference. Low — TTL is modifiable and hop-dependent. */
    private static final int W_TTL = 15;

    /**
     * Ping the host and infer OS from the response TTL.
     *
     * Default TTLs:
     *   Linux/macOS/FreeBSD → 64    (observed as ~40-64 after hops)
     *   Windows             → 128   (observed as ~100-128 after hops)
     *   Solaris/Cisco       → 255   (rare in web targets)
     *
     * The ranges don't overlap even after 30+ hops, making this a reliable
     * (if low-confidence) OS indicator. Weight is W_TTL (15) — needs
     * corroboration from error pages or path leaks to reach PROBABLE.
     *
     * Runs ping with 1-second timeout. If ICMP is blocked (common behind
     * corporate firewalls), this silently returns with no update.
     */
    private void probeTtl(String host) {
        try {
            // Determine ping syntax based on OmniStrike's OWN OS (not the target's)
            boolean isWindows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
            String[] cmd = isWindows
                    ? new String[]{"ping", "-n", "1", "-w", "1000", host}
                    : new String[]{"ping", "-c", "1", "-W", "1", host};

            Process process = new ProcessBuilder(cmd)
                    .redirectErrorStream(true)
                    .start();

            // Read output with timeout — don't block scanner threads forever
            String output;
            try (var reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                output = sb.toString();
            }

            boolean exited = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            if (!exited) {
                process.destroyForcibly();
                return;
            }
            if (process.exitValue() != 0) return; // Host unreachable or ICMP blocked

            // Extract TTL from ping output
            // Linux format:  "64 bytes from x.x.x.x: icmp_seq=1 ttl=64 time=1.23 ms"
            // Windows format: "Reply from x.x.x.x: bytes=32 time=1ms TTL=128"
            java.util.regex.Matcher m = Pattern.compile("(?i)ttl[=:]\\s*(\\d+)").matcher(output);
            if (!m.find()) return;

            int ttl = Integer.parseInt(m.group(1));

            // Infer default TTL (undo hop decrements by rounding up to nearest standard)
            // Standard defaults: 64 (Linux), 128 (Windows), 255 (Solaris/network)
            TechStack inferredOs;
            if (ttl <= 64) {
                inferredOs = TechStack.LINUX; // Linux/macOS/FreeBSD family
            } else if (ttl <= 128) {
                inferredOs = TechStack.WINDOWS;
            } else {
                return; // TTL > 128 → Solaris/network device, not useful for web scanning
            }

            registry.addEvidence(host, inferredOs, W_TTL, "icmp:ttl:" + ttl);
            log("[TechProfiler] ICMP TTL=" + ttl + " → " + inferredOs + " (weight " + W_TTL + ")");

        } catch (Exception e) {
            // ICMP blocked, ping not available, or timeout. Silent — not an error.
        }
    }

    private HttpRequestResponse sendProbe(String host, TechContext ctx, String payloadValue) {
        try {
            String encoded = java.net.URLEncoder.encode(payloadValue, java.nio.charset.StandardCharsets.UTF_8);
            String path = "/?omnistrike_probe=" + encoded;
            burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, 443, true);
            HttpRequest req = HttpRequest.httpRequest(service,
                    "GET " + path + " HTTP/1.1\r\n"
                            + "Host: " + host + "\r\n"
                            + "User-Agent: Mozilla/5.0\r\n"
                            + "Accept: */*\r\n"
                            + "Connection: close\r\n\r\n");
            return api.http().sendRequest(req);
        } catch (Exception e) {
            return null;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Adaptive Routing — payload prioritization
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Sort payloads by relevance to the host's TechContext. Stable sort.
     * CONFIRMED match → 100, PROBABLE → 50, Generic → 25, Non-match → 0.
     */
    public static <T> List<T> route(List<T> payloads, TechContext ctx,
                                     Function<T, Set<TechStack>> techMapper) {
        if (ctx == null || payloads.size() <= 1) return new ArrayList<>(payloads);

        record Scored<T>(T payload, int score) {}
        List<Scored<T>> scored = new ArrayList<>(payloads.size());
        for (T p : payloads) {
            Set<TechStack> techs = techMapper.apply(p);
            int s = (techs == null || techs.isEmpty()) ? 25 : 0;
            if (techs != null) {
                for (TechStack t : techs) s = Math.max(s, ctx.relevanceScore(t));
            }
            scored.add(new Scored<>(p, s));
        }
        scored.sort((a, b) -> Integer.compare(b.score(), a.score()));

        List<T> result = new ArrayList<>(scored.size());
        for (var sp : scored) result.add(sp.payload());
        return result;
    }

    /**
     * Three-wave payload sequence: polyglots → tech-matched → rest.
     */
    public static <T> List<T> getPayloadSequence(List<T> allPayloads, TechContext ctx,
                                                   Function<T, Set<TechStack>> techMapper,
                                                   java.util.function.Predicate<T> isPolyglot) {
        if (ctx == null) return new ArrayList<>(allPayloads);

        List<T> wave1 = new ArrayList<>(), wave2 = new ArrayList<>(), wave3 = new ArrayList<>();
        for (T p : allPayloads) {
            if (isPolyglot.test(p)) wave1.add(p);
            else if (ctx.isRelevant(techMapper.apply(p))) wave2.add(p);
            else wave3.add(p);
        }
        wave2 = route(wave2, ctx, techMapper);

        List<T> result = new ArrayList<>(allPayloads.size());
        result.addAll(wave1);
        result.addAll(wave2);
        result.addAll(wave3);
        return result;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Cleanup
    // ════════════════════════════════════════════════════════════════════════

    public void clear() { tieBreakQueued.clear(); }
    public void destroy() {
        registry.removeListener(this);
        tieBreakQueued.clear();
    }

    private void log(String msg) {
        try { api.logging().logToOutput(msg); } catch (Exception ignored) {}
    }

    private static String safeBody(HttpResponse resp) {
        try { String b = resp.bodyToString(); return b != null ? b : ""; }
        catch (Exception e) { return ""; }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Rule tables — weighted evidence sources
    // ════════════════════════════════════════════════════════════════════════

    private record ServerRule(String pattern, TechStack tech) {}
    private static final ServerRule[] SERVER_RULES = {
            new ServerRule("apache", TechStack.APACHE),
            new ServerRule("nginx", TechStack.NGINX),
            new ServerRule("microsoft-iis", TechStack.IIS),
            new ServerRule("tomcat", TechStack.TOMCAT),
            new ServerRule("jetty", TechStack.JETTY),
            new ServerRule("undertow", TechStack.UNDERTOW),
            new ServerRule("lighttpd", TechStack.LIGHTTPD),
            new ServerRule("caddy", TechStack.CADDY),
            new ServerRule("openresty", TechStack.NGINX),
    };

    private record PoweredByRule(String pattern, TechStack tech, int weight) {}
    private static final PoweredByRule[] POWERED_BY_RULES = {
            new PoweredByRule("php",          TechStack.PHP,         TechContext.W_POWERED_BY),
            new PoweredByRule("asp.net",      TechStack.DOTNET,      TechContext.W_POWERED_BY),
            new PoweredByRule("express",      TechStack.EXPRESS,     TechContext.W_POWERED_BY),
            new PoweredByRule("servlet",      TechStack.JAVA,        TechContext.W_POWERED_BY),
            new PoweredByRule("spring",       TechStack.SPRING,      TechContext.W_POWERED_BY),
            new PoweredByRule("spring boot",  TechStack.SPRING_BOOT, TechContext.W_POWERED_BY),
            new PoweredByRule("django",       TechStack.DJANGO,      TechContext.W_POWERED_BY),
            new PoweredByRule("flask",        TechStack.FLASK,       TechContext.W_POWERED_BY),
            new PoweredByRule("rails",        TechStack.RAILS,       TechContext.W_POWERED_BY),
            new PoweredByRule("koa",          TechStack.NODEJS,      TechContext.W_POWERED_BY),
            new PoweredByRule("next.js",      TechStack.NODEJS,      TechContext.W_URI_PATTERN),
            new PoweredByRule("phusion passenger", TechStack.RUBY,   TechContext.W_POWERED_BY),
    };

    private record CookieRule(String prefix, TechStack tech, int weight) {}
    private static final CookieRule[] COOKIE_RULES = {
            new CookieRule("jsessionid=",       TechStack.JAVA,        TechContext.W_COOKIE_NAME),
            new CookieRule("phpsessid=",        TechStack.PHP,         TechContext.W_COOKIE_NAME),
            new CookieRule("asp.net_sessionid=", TechStack.DOTNET,     TechContext.W_COOKIE_NAME),
            new CookieRule(".aspnetcore.",       TechStack.ASPNET_CORE, TechContext.W_COOKIE_NAME),
            new CookieRule("_rails_session=",   TechStack.RAILS,       TechContext.W_COOKIE_NAME),
            new CookieRule("rack.session=",     TechStack.RUBY,        TechContext.W_COOKIE_NAME),
            new CookieRule("laravel_session=",  TechStack.LARAVEL,     TechContext.W_COOKIE_NAME),
            new CookieRule("symfony=",          TechStack.SYMFONY,     TechContext.W_COOKIE_NAME),
            new CookieRule("csrftoken=",        TechStack.DJANGO,      TechContext.W_URI_PATTERN),
            new CookieRule("connect.sid=",      TechStack.NODEJS,      TechContext.W_URI_PATTERN),
            new CookieRule("wp-settings-",      TechStack.WORDPRESS,   TechContext.W_COOKIE_NAME),
            new CookieRule("wordpress_",        TechStack.WORDPRESS,   TechContext.W_COOKIE_NAME),
    };

    private static final class BodyRule {
        final Pattern compiled;
        final TechStack tech;
        final int weight;
        final boolean errorOnly;
        final String evidenceKey;

        BodyRule(String regex, TechStack tech, int weight, boolean errorOnly, String evidenceKey) {
            this.compiled = Pattern.compile(regex);
            this.tech = tech;
            this.weight = weight;
            this.errorOnly = errorOnly;
            this.evidenceKey = evidenceKey;
        }
    }

    private static final BodyRule[] BODY_RULES = {
            // Stack traces — W_STACK_TRACE (100 points). Structural proof, zero ambiguity.
            new BodyRule("at\\s+[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+\\(\\w+\\.java:\\d+\\)",
                    TechStack.JAVA, TechContext.W_STACK_TRACE, true, "java-stacktrace"),
            new BodyRule("Traceback \\(most recent call last\\)",
                    TechStack.PYTHON, TechContext.W_STACK_TRACE, true, "python-traceback"),
            new BodyRule("File \"[^\"]+\\.py\", line \\d+",
                    TechStack.PYTHON, TechContext.W_STACK_TRACE, true, "python-file-line"),
            new BodyRule("at Object\\.<anonymous>\\s+\\([^)]+\\.js:\\d+:\\d+\\)",
                    TechStack.NODEJS, TechContext.W_STACK_TRACE, true, "node-stacktrace"),
            new BodyRule("(?i)Fatal error.*on line \\d+",
                    TechStack.PHP, TechContext.W_STACK_TRACE, true, "php-fatal"),
            new BodyRule("(?i)Stack Trace:.*at System\\.",
                    TechStack.DOTNET, TechContext.W_STACK_TRACE, true, "dotnet-stacktrace"),
            new BodyRule("(?i)Server Error in '/' Application",
                    TechStack.DOTNET, TechContext.W_STACK_TRACE, true, "dotnet-server-error"),
            new BodyRule("ActionController::RoutingError",
                    TechStack.RAILS, TechContext.W_STACK_TRACE, true, "rails-routing-error"),

            // Default error pages — W_DEFAULT_ERROR_PAGE (80 points)
            new BodyRule("(?i)apache/[0-9.]+.*server at",
                    TechStack.APACHE, TechContext.W_DEFAULT_ERROR_PAGE, true, "apache-error-page"),
            new BodyRule("(?i)apache tomcat/[0-9.]+",
                    TechStack.TOMCAT, TechContext.W_DEFAULT_ERROR_PAGE, true, "tomcat-error-page"),
            new BodyRule("(?i)whitelabel error page",
                    TechStack.SPRING_BOOT, TechContext.W_DEFAULT_ERROR_PAGE, true, "spring-whitelabel"),
            new BodyRule("(?i)<title>IIS.*Detailed Error",
                    TechStack.IIS, TechContext.W_DEFAULT_ERROR_PAGE, true, "iis-detailed-error"),
            new BodyRule("(?i)django debug",
                    TechStack.DJANGO, TechContext.W_DEFAULT_ERROR_PAGE, true, "django-debug"),
            new BodyRule("(?i)laravel.*whoops",
                    TechStack.LARAVEL, TechContext.W_DEFAULT_ERROR_PAGE, true, "laravel-whoops"),

            // OS filesystem path leaks — W_PATH_LEAK (90 points)
            new BodyRule("(?i)\\b/var/www/|/home/\\w+/|/usr/share/|/etc/\\w+\\.conf",
                    TechStack.LINUX, TechContext.W_PATH_LEAK, true, "linux-path"),
            new BodyRule("(?i)[A-Z]:\\\\(?:inetpub|windows|program files|users)\\\\",
                    TechStack.WINDOWS, TechContext.W_PATH_LEAK, true, "windows-path"),
    };

    private record DbmsErrorRule(String pattern, TechStack tech) {}
    private static final DbmsErrorRule[] DBMS_ERROR_RULES = {
            new DbmsErrorRule("you have an error in your sql syntax", TechStack.MYSQL),
            new DbmsErrorRule("mysql_fetch", TechStack.MYSQL),
            new DbmsErrorRule("mysqlexception", TechStack.MYSQL),
            new DbmsErrorRule("com.mysql.jdbc", TechStack.MYSQL),
            new DbmsErrorRule("mariadb", TechStack.MYSQL),
            new DbmsErrorRule("pg_query", TechStack.POSTGRESQL),
            new DbmsErrorRule("psqlexception", TechStack.POSTGRESQL),
            new DbmsErrorRule("org.postgresql", TechStack.POSTGRESQL),
            new DbmsErrorRule("unterminated quoted string at or near", TechStack.POSTGRESQL),
            new DbmsErrorRule("unclosed quotation mark after the character string", TechStack.MSSQL),
            new DbmsErrorRule("sqlserverexception", TechStack.MSSQL),
            new DbmsErrorRule("com.microsoft.sqlserver.jdbc", TechStack.MSSQL),
            new DbmsErrorRule("ora-", TechStack.ORACLE),
            new DbmsErrorRule("oracle.jdbc", TechStack.ORACLE),
            new DbmsErrorRule("sqlite3::", TechStack.SQLITE),
            new DbmsErrorRule("sqlite_error", TechStack.SQLITE),
            new DbmsErrorRule("mongoerror", TechStack.MONGODB),
    };

    // ════════════════════════════════════════════════════════════════════════
    //  Tie-Breaker Differential Probes
    //
    //  Each tie-breaker tests two competing techs. It sends a probe payload
    //  and checks for:
    //    - positivePattern: matches techA's behaviour (techA CONFIRMED)
    //    - negativePattern: matches techB's behaviour (techB CONFIRMED instead)
    //  If both match or neither → inconclusive, no update.
    // ════════════════════════════════════════════════════════════════════════

    private record TieBreaker(String name, TechStack techA, TechStack techB,
                               String probePayload, Pattern positivePattern, Pattern negativePattern) {}

    private static final Map<TechCategory, TieBreaker[]> TIE_BREAKERS = createTieBreakers();

    private static Map<TechCategory, TieBreaker[]> createTieBreakers() {
        Map<TechCategory, TieBreaker[]> map = new EnumMap<>(TechCategory.class);

        // ── LANGUAGE: Java vs .NET ("Enterprise" tie-breaker) ─────────────
        // Probe: send single quote. Java errors contain "java.", .NET errors contain "System."
        // Both are structurally unique — no other language uses these package prefixes in stack traces.
        map.put(TechCategory.LANGUAGE, new TieBreaker[]{
                // Java vs .NET: error class hierarchy is structurally distinct
                new TieBreaker("java-vs-dotnet", TechStack.JAVA, TechStack.DOTNET,
                        "omnistrike'\"--",
                        Pattern.compile("(?i)java\\.|javax\\.|org\\.apache\\.|at [a-z]+\\.[a-z]+.*\\(.*\\.java:\\d+\\)"),
                        Pattern.compile("(?i)System\\.|Microsoft\\.|at [A-Z][a-zA-Z]+\\..*\\(.*\\.cs:\\d+\\)")),

                // PHP vs Python: error message format is structurally distinct
                new TieBreaker("php-vs-python", TechStack.PHP, TechStack.PYTHON,
                        "omnistrike'\"<>",
                        Pattern.compile("(?i)(?:Fatal error|Warning|Notice):.*on line \\d+|\\bPHP\\b.*\\bStack trace"),
                        Pattern.compile("(?i)Traceback \\(most recent call last\\)|File \".*\\.py\", line \\d+")),

                // PHP vs Ruby: error format divergence
                new TieBreaker("php-vs-ruby", TechStack.PHP, TechStack.RUBY,
                        "omnistrike'\"<>",
                        Pattern.compile("(?i)(?:Fatal error|Warning|Notice):.*on line \\d+"),
                        Pattern.compile("(?i)ActionController|NoMethodError|NameError|Ruby")),

                // Python vs Node.js
                new TieBreaker("python-vs-node", TechStack.PYTHON, TechStack.NODEJS,
                        "omnistrike'\"<>",
                        Pattern.compile("(?i)Traceback|File \".*\\.py\""),
                        Pattern.compile("(?i)at Object\\..*\\.js:\\d+|SyntaxError.*Unexpected")),
        });

        // ── OS: Linux vs Windows ──────────────────────────────────────────
        // Probe: path traversal payload. Linux leaks /var/www style paths, Windows leaks C:\
        map.put(TechCategory.OS, new TieBreaker[]{
                new TieBreaker("linux-vs-windows", TechStack.LINUX, TechStack.WINDOWS,
                        "../../../../etc/passwd",
                        Pattern.compile("root:.*:0:0:|(?i)/var/www/|/home/\\w+/|/usr/"),
                        Pattern.compile("(?i)[A-Z]:\\\\|\\\\inetpub\\\\|\\\\windows\\\\")),
        });

        // ── DATABASE: MySQL vs PostgreSQL vs MSSQL ────────────────────────
        // Probe: single quote → DBMS-specific SQL syntax errors
        map.put(TechCategory.DATABASE, new TieBreaker[]{
                new TieBreaker("mysql-vs-postgres", TechStack.MYSQL, TechStack.POSTGRESQL,
                        "1'",
                        Pattern.compile("(?i)you have an error in your sql syntax|mysql"),
                        Pattern.compile("(?i)unterminated quoted string|pg_query|org\\.postgresql")),

                new TieBreaker("mysql-vs-mssql", TechStack.MYSQL, TechStack.MSSQL,
                        "1'",
                        Pattern.compile("(?i)you have an error in your sql syntax|mysql"),
                        Pattern.compile("(?i)unclosed quotation mark|sqlserverexception|microsoft.*sql")),

                new TieBreaker("postgres-vs-mssql", TechStack.POSTGRESQL, TechStack.MSSQL,
                        "1'",
                        Pattern.compile("(?i)unterminated quoted string|pg_query"),
                        Pattern.compile("(?i)unclosed quotation mark|sqlserverexception")),
        });

        return map;
    }
}

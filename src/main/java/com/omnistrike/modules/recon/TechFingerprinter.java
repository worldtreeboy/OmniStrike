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
 * TechFingerprinter — passive technology detection module.
 *
 * Identifies web servers, languages, frameworks, CMS, JS libraries, WAF/CDN,
 * caches, cloud platforms, and databases from HTTP headers, cookies, body
 * patterns, and error pages. One finding per technology per host.
 */
public class TechFingerprinter implements ScanModule {

    private static final String MODULE_ID = "tech-fingerprinter";
    private static final int MAX_BODY_SIZE = 512_000;

    private MontoyaApi api;
    private ModuleConfig config;

    // Dedup: "host|techName" → true
    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    // ── Tech categories ──
    private enum TechCategory {
        WEB_SERVER, LANGUAGE, FRAMEWORK, CMS, JS_LIBRARY, WAF_CDN, CACHE, CLOUD, DATABASE
    }

    private static final class TechMatch {
        final String name;
        final TechCategory category;
        final String version; // nullable

        TechMatch(String name, TechCategory category, String version) {
            this.name = name;
            this.category = category;
            this.version = version;
        }
    }

    // ── Header → technology mappings ──
    private static final Map<String, List<HeaderRule>> HEADER_RULES = new LinkedHashMap<>();

    private static final class HeaderRule {
        final Pattern pattern; // null = any value
        final String techName;
        final TechCategory category;
        final int versionGroup; // regex group for version, -1 if none

        HeaderRule(Pattern pattern, String techName, TechCategory category, int versionGroup) {
            this.pattern = pattern;
            this.techName = techName;
            this.category = category;
            this.versionGroup = versionGroup;
        }
    }

    static {
        // Server header
        addHeaderRule("server", "(?i)apache(?:[/ ]([\\d.]+))?", "Apache", TechCategory.WEB_SERVER, 1);
        addHeaderRule("server", "(?i)nginx(?:/([\\d.]+))?", "Nginx", TechCategory.WEB_SERVER, 1);
        addHeaderRule("server", "(?i)microsoft-iis(?:/([\\d.]+))?", "Microsoft IIS", TechCategory.WEB_SERVER, 1);
        addHeaderRule("server", "(?i)litespeed", "LiteSpeed", TechCategory.WEB_SERVER, -1);
        addHeaderRule("server", "(?i)caddy", "Caddy", TechCategory.WEB_SERVER, -1);
        addHeaderRule("server", "(?i)openresty(?:/([\\d.]+))?", "OpenResty", TechCategory.WEB_SERVER, 1);
        addHeaderRule("server", "(?i)gunicorn(?:/([\\d.]+))?", "Gunicorn", TechCategory.WEB_SERVER, 1);
        addHeaderRule("server", "(?i)cowboy", "Cowboy (Erlang)", TechCategory.WEB_SERVER, -1);
        addHeaderRule("server", "(?i)cloudflare", "Cloudflare", TechCategory.WAF_CDN, -1);
        addHeaderRule("server", "(?i)AmazonS3", "Amazon S3", TechCategory.CLOUD, -1);

        // X-Powered-By
        addHeaderRule("x-powered-by", "(?i)php(?:/([\\d.]+))?", "PHP", TechCategory.LANGUAGE, 1);
        addHeaderRule("x-powered-by", "(?i)asp\\.?net", "ASP.NET", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)express", "Express.js", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)servlet(?:/([\\d.]+))?", "Java Servlet", TechCategory.FRAMEWORK, 1);
        addHeaderRule("x-powered-by", "(?i)next\\.?js", "Next.js", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)nuxt", "Nuxt.js", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)flask", "Flask", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)django", "Django", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-powered-by", "(?i)ruby", "Ruby", TechCategory.LANGUAGE, -1);
        addHeaderRule("x-powered-by", "(?i)perl", "Perl", TechCategory.LANGUAGE, -1);

        // Version-specific headers
        addHeaderRule("x-aspnet-version", "([\\d.]+)", "ASP.NET", TechCategory.FRAMEWORK, 1);
        addHeaderRule("x-aspnetmvc-version", "([\\d.]+)", "ASP.NET MVC", TechCategory.FRAMEWORK, 1);

        // Generator / CMS headers
        addHeaderRule("x-generator", "(?i)drupal", "Drupal", TechCategory.CMS, -1);
        addHeaderRule("x-generator", "(?i)wordpress", "WordPress", TechCategory.CMS, -1);
        addHeaderRule("x-generator", "(?i)joomla", "Joomla", TechCategory.CMS, -1);

        // WAF / CDN headers
        addHeaderRule("cf-ray", null, "Cloudflare CDN", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-cdn", null, "CDN Detected", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-sucuri-id", null, "Sucuri WAF", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-akamai-transformed", null, "Akamai CDN", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-amz-cf-id", null, "Amazon CloudFront", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-amz-cf-pop", null, "Amazon CloudFront", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-cache", "(?i).*cloudfront.*", "Amazon CloudFront", TechCategory.WAF_CDN, -1);
        addHeaderRule("x-azure-ref", null, "Azure CDN", TechCategory.CLOUD, -1);
        addHeaderRule("x-ms-request-id", null, "Microsoft Azure", TechCategory.CLOUD, -1);

        // Cache headers
        addHeaderRule("x-varnish", null, "Varnish Cache", TechCategory.CACHE, -1);
        addHeaderRule("via", "(?i).*varnish.*", "Varnish Cache", TechCategory.CACHE, -1);
        addHeaderRule("x-drupal-cache", null, "Drupal", TechCategory.CMS, -1);

        // Misc
        addHeaderRule("x-runtime", null, "Ruby on Rails", TechCategory.FRAMEWORK, -1);
        addHeaderRule("x-request-id", null, null, null, -1); // skip, too generic
        addHeaderRule("x-turbo-charged-by", "(?i)litespeed", "LiteSpeed Cache", TechCategory.CACHE, -1);
    }

    private static void addHeaderRule(String header, String regex, String tech, TechCategory cat, int vGroup) {
        if (tech == null) return;
        Pattern p = regex != null ? Pattern.compile(regex) : null;
        HEADER_RULES.computeIfAbsent(header.toLowerCase(), k -> new ArrayList<>())
                .add(new HeaderRule(p, tech, cat, vGroup));
    }

    // ── Cookie → technology mappings ──
    private static final Map<String, CookieRule> COOKIE_RULES = new LinkedHashMap<>();

    private static final class CookieRule {
        final String techName;
        final TechCategory category;

        CookieRule(String techName, TechCategory category) {
            this.techName = techName;
            this.category = category;
        }
    }

    static {
        COOKIE_RULES.put("jsessionid", new CookieRule("Java", TechCategory.LANGUAGE));
        COOKIE_RULES.put("phpsessid", new CookieRule("PHP", TechCategory.LANGUAGE));
        COOKIE_RULES.put("asp.net_sessionid", new CookieRule("ASP.NET", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("laravel_session", new CookieRule("Laravel", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("connect.sid", new CookieRule("Express.js", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("ci_session", new CookieRule("CodeIgniter", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("symfony", new CookieRule("Symfony", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("cakephp", new CookieRule("CakePHP", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("rack.session", new CookieRule("Ruby Rack", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("_rails", new CookieRule("Ruby on Rails", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("_session_id", new CookieRule("Ruby on Rails", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("csrftoken", new CookieRule("Django", TechCategory.FRAMEWORK));
        COOKIE_RULES.put("django", new CookieRule("Django", TechCategory.FRAMEWORK));
    }

    // WordPress cookie prefixes
    private static final List<String> WP_COOKIE_PREFIXES = List.of(
            "wp-settings-", "wordpress_", "wp_"
    );

    // ── Body patterns ──
    private static final List<BodyRule> BODY_RULES = new ArrayList<>();

    private static final class BodyRule {
        final Pattern pattern;
        final String techName;
        final TechCategory category;
        final int versionGroup;
        final boolean errorPageOnly; // only match on 4xx/5xx responses

        BodyRule(Pattern pattern, String techName, TechCategory category, int versionGroup, boolean errorPageOnly) {
            this.pattern = pattern;
            this.techName = techName;
            this.category = category;
            this.versionGroup = versionGroup;
            this.errorPageOnly = errorPageOnly;
        }
    }

    static {
        // Meta generator tags
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\\s*([\\d.]*)", "WordPress", TechCategory.CMS, 1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Drupal\\s*([\\d.]*)", "Drupal", TechCategory.CMS, 1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla", "Joomla", TechCategory.CMS, -1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']TYPO3", "TYPO3", TechCategory.CMS, -1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Shopify", "Shopify", TechCategory.CMS, -1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Wix", "Wix", TechCategory.CMS, -1, false);
        addBodyRule("(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Squarespace", "Squarespace", TechCategory.CMS, -1, false);

        // WordPress-specific paths
        addBodyRule("(?i)/wp-content/", "WordPress", TechCategory.CMS, -1, false);
        addBodyRule("(?i)/wp-includes/", "WordPress", TechCategory.CMS, -1, false);

        // JS frameworks & libraries in script tags
        addBodyRule("(?i)jquery(?:[/.-]([\\d.]+))?(?:\\.min)?\\.js", "jQuery", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)react(?:[/.-]([\\d.]+))?(?:\\.production\\.min)?\\.js", "React", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)angular(?:[/.-]([\\d.]+))?(?:\\.min)?\\.js", "Angular", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)vue(?:[/.-]([\\d.]+))?(?:\\.min|\\.global)?\\.js", "Vue.js", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)bootstrap(?:[/.-]([\\d.]+))?(?:\\.min)?\\.(js|css)", "Bootstrap", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)lodash(?:[/.-]([\\d.]+))?(?:\\.min)?\\.js", "Lodash", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)moment(?:[/.-]([\\d.]+))?(?:\\.min)?\\.js", "Moment.js", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)axios(?:[/.-]([\\d.]+))?(?:\\.min)?\\.js", "Axios", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)ember(?:[/.-]([\\d.]+))?(?:\\.min|\\.prod)?\\.js", "Ember.js", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)backbone(?:[/.-]([\\d.]+))?(?:-min)?\\.js", "Backbone.js", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("(?i)svelte", "Svelte", TechCategory.JS_LIBRARY, -1, false);
        addBodyRule("(?i)tailwindcss|tailwind\\.min\\.css", "Tailwind CSS", TechCategory.JS_LIBRARY, -1, false);

        // Next.js / Nuxt.js data markers
        addBodyRule("__NEXT_DATA__", "Next.js", TechCategory.FRAMEWORK, -1, false);
        addBodyRule("__NUXT__", "Nuxt.js", TechCategory.FRAMEWORK, -1, false);
        addBodyRule("window\\.__remixContext", "Remix", TechCategory.FRAMEWORK, -1, false);
        addBodyRule("ng-version=[\"']([\\d.]+)", "Angular", TechCategory.JS_LIBRARY, 1, false);
        addBodyRule("data-reactroot", "React", TechCategory.JS_LIBRARY, -1, false);

        // Error pages (4xx/5xx only)
        addBodyRule("(?i)apache tomcat(?:/([\\d.]+))?", "Apache Tomcat", TechCategory.WEB_SERVER, 1, true);
        addBodyRule("(?i)java\\.lang\\.[A-Z]\\w+Exception", "Java", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)at\\s+[\\w$.]+\\([\\w]+\\.java:\\d+\\)", "Java", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)Traceback \\(most recent call last\\)", "Python", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)File \"[^\"]+\\.py\", line \\d+", "Python", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)ActionController::RoutingError", "Ruby on Rails", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)Rails\\.root:", "Ruby on Rails", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)<b>Fatal error</b>:.*on line <b>\\d+</b>", "PHP", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)Parse error:.*\\.php", "PHP", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)ASP\\.NET.*Unhandled Exception", "ASP.NET", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)Server Error in '/' Application", "ASP.NET", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)Microsoft OLE DB Provider", "ASP Classic", TechCategory.LANGUAGE, -1, true);
        addBodyRule("(?i)CDbException|Yii Framework", "Yii", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)Laravel.*Whoops!", "Laravel", TechCategory.FRAMEWORK, -1, true);
        addBodyRule("(?i)Symfony\\\\Component\\\\", "Symfony", TechCategory.FRAMEWORK, -1, true);
    }

    private static void addBodyRule(String regex, String tech, TechCategory cat, int vGroup, boolean errorOnly) {
        BODY_RULES.add(new BodyRule(Pattern.compile(regex), tech, cat, vGroup, errorOnly));
    }

    // ─── ScanModule interface ───

    @Override
    public String getId() { return MODULE_ID; }

    @Override
    public String getName() { return "Technology Fingerprinter"; }

    @Override
    public String getDescription() {
        return "Detects web servers, languages, frameworks, CMS, JS libraries, WAF/CDN, caches, and cloud platforms from HTTP traffic.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.RECON; }

    @Override
    public boolean isPassive() { return true; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public void destroy() { }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        if (response == null) return findings;

        String host;
        try {
            host = requestResponse.request().httpService().host();
        } catch (Exception e) {
            return findings;
        }
        String url = requestResponse.request().url();
        int statusCode = response.statusCode();
        boolean isErrorPage = statusCode >= 400;

        // Collect all detected technologies from this flow
        List<TechMatch> detectedTechs = new ArrayList<>();

        // 1. Headers
        detectFromHeaders(response, detectedTechs);

        // 2. Cookies (from Set-Cookie headers)
        detectFromCookies(response, detectedTechs);

        // 3. Body patterns
        detectFromBody(response, isErrorPage, detectedTechs);

        // 4. Emit findings (one per unique host+tech)
        for (TechMatch tech : detectedTechs) {
            String dedupKey = host + "|" + tech.name;
            if (seen.putIfAbsent(dedupKey, Boolean.TRUE) != null) continue;

            boolean hasVersion = tech.version != null && !tech.version.isEmpty();
            Severity severity = hasVersion ? Severity.LOW : Severity.INFO;
            String title = tech.name + (hasVersion ? " " + tech.version : "") + " detected on " + host;
            String categoryLabel = formatCategory(tech.category);

            StringBuilder desc = new StringBuilder();
            desc.append("Technology: ").append(tech.name);
            if (hasVersion) desc.append(" ").append(tech.version);
            desc.append("\nCategory: ").append(categoryLabel);
            desc.append("\nHost: ").append(host);

            String evidence = categoryLabel + ": " + tech.name + (hasVersion ? " " + tech.version : "");

            Finding.Builder builder = Finding.builder(MODULE_ID, title, severity, Confidence.FIRM)
                    .url(url)
                    .evidence(evidence)
                    .description(desc.toString())
                    .requestResponse(requestResponse);

            if (hasVersion) {
                builder.remediation("Remove version information from HTTP headers and responses to reduce information disclosure. "
                        + "Configure the web server to suppress version banners.");
            }

            findings.add(builder.build());
        }

        return findings;
    }

    // ─── Detection methods ───

    private void detectFromHeaders(HttpResponse response, List<TechMatch> results) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (var h : response.headers()) {
            headers.merge(h.name().toLowerCase(), h.value(), (a, b) -> a + ", " + b);
        }

        for (Map.Entry<String, List<HeaderRule>> entry : HEADER_RULES.entrySet()) {
            String headerValue = headers.get(entry.getKey());
            if (headerValue == null) continue;

            for (HeaderRule rule : entry.getValue()) {
                if (rule.pattern == null) {
                    // Any value triggers detection
                    results.add(new TechMatch(rule.techName, rule.category, null));
                } else {
                    Matcher m = rule.pattern.matcher(headerValue);
                    if (m.find()) {
                        String version = (rule.versionGroup > 0 && rule.versionGroup <= m.groupCount())
                                ? m.group(rule.versionGroup) : null;
                        results.add(new TechMatch(rule.techName, rule.category, version));
                    }
                }
            }
        }
    }

    private void detectFromCookies(HttpResponse response, List<TechMatch> results) {
        for (var header : response.headers()) {
            if (!header.name().equalsIgnoreCase("Set-Cookie")) continue;
            String value = header.value().toLowerCase();

            // Extract cookie name (before '=')
            int eqIdx = value.indexOf('=');
            String cookieName = eqIdx > 0 ? value.substring(0, eqIdx).trim() : value.trim();

            // Exact match
            CookieRule rule = COOKIE_RULES.get(cookieName);
            if (rule != null) {
                results.add(new TechMatch(rule.techName, rule.category, null));
                continue;
            }

            // Prefix match (WordPress cookies, Django, Rails)
            for (String prefix : WP_COOKIE_PREFIXES) {
                if (cookieName.startsWith(prefix)) {
                    results.add(new TechMatch("WordPress", TechCategory.CMS, null));
                    break;
                }
            }

            // Partial matches for other frameworks
            if (cookieName.contains("django")) {
                results.add(new TechMatch("Django", TechCategory.FRAMEWORK, null));
            } else if (cookieName.startsWith("_rails") || cookieName.equals("_session_id")) {
                results.add(new TechMatch("Ruby on Rails", TechCategory.FRAMEWORK, null));
            }
        }
    }

    private void detectFromBody(HttpResponse response, boolean isErrorPage, List<TechMatch> results) {
        String body;
        try {
            body = response.bodyToString();
        } catch (Exception e) {
            return;
        }
        if (body == null || body.isEmpty()) return;
        if (body.length() > MAX_BODY_SIZE) {
            body = body.substring(0, MAX_BODY_SIZE);
        }

        for (BodyRule rule : BODY_RULES) {
            if (rule.errorPageOnly && !isErrorPage) continue;

            Matcher m = rule.pattern.matcher(body);
            if (m.find()) {
                String version = (rule.versionGroup > 0 && rule.versionGroup <= m.groupCount())
                        ? m.group(rule.versionGroup) : null;
                results.add(new TechMatch(rule.techName, rule.category, version));
            }
        }
    }

    // ─── Helpers ───

    private static String formatCategory(TechCategory cat) {
        return switch (cat) {
            case WEB_SERVER -> "Web Server";
            case LANGUAGE -> "Language";
            case FRAMEWORK -> "Framework";
            case CMS -> "CMS";
            case JS_LIBRARY -> "JS Library";
            case WAF_CDN -> "WAF/CDN";
            case CACHE -> "Cache";
            case CLOUD -> "Cloud";
            case DATABASE -> "Database";
        };
    }
}

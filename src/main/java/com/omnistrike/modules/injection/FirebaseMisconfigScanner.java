package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.*;
import com.omnistrike.model.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE: Firebase / Firestore Misconfiguration Scanner
 *
 * This module CANNOT be manually triggered by the user. It is an active module
 * that passively gates on Firebase/Firestore indicators in responses. Only when
 * Firebase is confirmed does it fire misconfiguration probes.
 *
 * Flow:
 *   1. Receives request/response via processHttpFlow() during active scanning
 *   2. Checks the RESPONSE body and URL for Firebase/Firestore indicators
 *   3. If NO Firebase indicators -> returns empty (zero probes sent)
 *   4. If Firebase detected -> reports INFO finding, then probes for misconfigurations
 *   5. Tests: unauthenticated read, unauthenticated write, Firestore enum, auth enum
 *
 * Stop-scan: Respects ScanState.isCancelled() and Thread.isInterrupted().
 */
public class FirebaseMisconfigScanner implements ScanModule {

    private static final String MODULE_ID = "firebase-misconfig-scanner";

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;

    // -- Firebase detection patterns (passive gate) ----------------------------

    // Error messages that confirm Firebase / Firestore
    private static final Pattern FIREBASE_ERROR_PATTERN = Pattern.compile(
            "FirebaseError|firebase\\..*exception|firebase.*auth.*error"
                    + "|firestore\\.googleapis|Firestore.*error"
                    + "|Permission denied.*firestore"
                    + "|Missing or insufficient permissions"
                    + "|firebase-auth",
            Pattern.CASE_INSENSITIVE);

    // URL patterns that strongly indicate Firebase / Firestore endpoints
    private static final Pattern FIREBASE_URL_PATTERN = Pattern.compile(
            "\\.firebaseio\\.com"
                    + "|firestore\\.googleapis\\.com"
                    + "|\\.firebaseapp\\.com"
                    + "|identitytoolkit\\.googleapis\\.com"
                    + "|securetoken\\.googleapis\\.com",
            Pattern.CASE_INSENSITIVE);

    // Firebase config detection is done via co-occurrence check in detectFirebase()
    // (requires all three of "projectId", "storageBucket", "apiKey" to be present)

    // -- Realtime DB common paths to probe ------------------------------------

    private static final String[] RTDB_READ_PATHS = {
            "/.json",
            "/users.json",
            "/admin.json",
            "/config.json",
            "/messages.json"
    };

    // -- Firestore common collections to probe --------------------------------

    private static final String[] FIRESTORE_COLLECTIONS = {
            "users", "admin", "config", "messages", "orders", "payments"
    };

    // -- Project extraction patterns ------------------------------------------

    // Extract project ID from firebaseio.com URL: https://PROJECT.firebaseio.com/...
    private static final Pattern RTDB_PROJECT_PATTERN = Pattern.compile(
            "https?://([a-zA-Z0-9_-]+)\\.firebaseio\\.com", Pattern.CASE_INSENSITIVE);

    // Extract project ID from Firestore URL: firestore.googleapis.com/v1/projects/PROJECT/...
    private static final Pattern FIRESTORE_PROJECT_PATTERN = Pattern.compile(
            "firestore\\.googleapis\\.com/v[0-9]+/projects/([a-zA-Z0-9_-]+)",
            Pattern.CASE_INSENSITIVE);

    // Extract project ID from identitytoolkit URL: identitytoolkit.googleapis.com/v1/...?key=API_KEY
    private static final Pattern AUTH_API_KEY_PATTERN = Pattern.compile(
            "identitytoolkit\\.googleapis\\.com.*[?&]key=([a-zA-Z0-9_-]+)",
            Pattern.CASE_INSENSITIVE);

    // -- ScanModule interface -------------------------------------------------

    @Override public String getId() { return MODULE_ID; }
    @Override public String getName() { return "Firebase / Firestore Misconfiguration"; }
    @Override public String getDescription() {
        return "Detects Firebase/Firestore usage and tests for misconfigured security rules. "
                + "Only activates when Firebase indicators are detected in traffic.";
    }
    @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
    @Override public boolean isPassive() { return false; } // Active module with passive gate

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        // collaboratorManager not used -- no OOB needed for Firebase misconfig
    }

    @Override public void destroy() {}

    // -- Main entry point -----------------------------------------------------

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        if (requestResponse.response() == null) return Collections.emptyList();

        String url = requestResponse.request().url();
        String urlPath = extractPath(url);

        // PASSIVE GATE: Check for Firebase indicators
        FirebaseDetection detection = detectFirebase(requestResponse);
        if (detection == null) return Collections.emptyList();

        // Firebase confirmed -- report INFO finding
        if (dedup.markIfNew(MODULE_ID, urlPath, "firebase-detected")) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Firebase / Firestore Detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence(detection.evidence)
                    .description("The target application uses Firebase / Firestore. "
                            + "Misconfiguration testing will be performed automatically.")
                    .requestResponse(requestResponse)
                    .build());
            api.logging().logToOutput("[Firebase] Firebase detected: " + url + " | " + detection.evidence);
        }

        // ACTIVE ATTACK: Probe for misconfigurations
        try {
            testFirebaseMisconfigurations(requestResponse, detection, url, urlPath);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return Collections.emptyList();
    }

    // -- Firebase Detection (passive gate) ------------------------------------

    private FirebaseDetection detectFirebase(HttpRequestResponse reqResp) {
        String body = reqResp.response().bodyToString();
        if (body == null) body = "";
        String url = reqResp.request().url();

        // Check 1: URL pattern alone (Firebase domains are very specific)
        if (FIREBASE_URL_PATTERN.matcher(url).find()) {
            String apiKey = null;
            Matcher keyMatcher = AUTH_API_KEY_PATTERN.matcher(url);
            if (keyMatcher.find()) apiKey = keyMatcher.group(1);
            if (apiKey == null) apiKey = extractApiKeyFromBody(body);
            return new FirebaseDetection(
                    "Firebase URL pattern: " + url,
                    extractProjectFromUrl(url),
                    detectServiceType(url),
                    apiKey);
        }

        // Check 2: Error pattern in response body
        if (FIREBASE_ERROR_PATTERN.matcher(body).find()) {
            return new FirebaseDetection(
                    "Firebase error pattern in response body",
                    extractProjectFromBody(body),
                    detectServiceTypeFromBody(body, url),
                    extractApiKeyFromBody(body));
        }

        // Check 3: Firebase config co-occurrence in response body (all three must be present)
        if (body.contains("\"projectId\"") && body.contains("\"storageBucket\"") && body.contains("\"apiKey\"")) {
            return new FirebaseDetection(
                    "Firebase configuration pattern in response body",
                    extractProjectFromBody(body),
                    ServiceType.UNKNOWN,
                    extractApiKeyFromBody(body));
        }

        return null; // No Firebase detected -- module stays dormant
    }

    // -- Active Misconfiguration Testing --------------------------------------

    private void testFirebaseMisconfigurations(HttpRequestResponse original,
                                                FirebaseDetection detection,
                                                String url, String urlPath)
            throws InterruptedException {

        String project = detection.projectId;
        if (project == null || project.isEmpty()) {
            api.logging().logToOutput("[Firebase] Could not extract project ID from: " + url);
            return;
        }

        // Phase 1: Unauthenticated Read (Realtime DB)
        if (detection.serviceType == ServiceType.REALTIME_DB
                || detection.serviceType == ServiceType.UNKNOWN) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (dedup.markIfNew(MODULE_ID, urlPath, "rtdb-read:" + project)) {
                testRealtimeDbRead(original, project, url);
            }
        }

        // Phase 2: Unauthenticated Write Test (Realtime DB)
        if (detection.serviceType == ServiceType.REALTIME_DB
                || detection.serviceType == ServiceType.UNKNOWN) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (dedup.markIfNew(MODULE_ID, urlPath, "rtdb-write:" + project)) {
                testRealtimeDbWrite(original, project, url);
            }
        }

        // Phase 3: Firestore Collection Enumeration
        if (detection.serviceType == ServiceType.FIRESTORE
                || detection.serviceType == ServiceType.UNKNOWN) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            if (dedup.markIfNew(MODULE_ID, urlPath, "firestore-enum:" + project)) {
                testFirestoreEnumeration(original, project, url);
            }
        }

        // Phase 4: Firebase Auth Enumeration
        if (detection.serviceType == ServiceType.AUTH
                || detection.serviceType == ServiceType.UNKNOWN) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
            String apiKey = detection.apiKey;
            if (apiKey == null || apiKey.isEmpty()) {
                apiKey = extractApiKeyFromBody(original.response().bodyToString());
            }
            if (apiKey != null && !apiKey.isEmpty()) {
                if (dedup.markIfNew(MODULE_ID, urlPath, "auth-enum:" + project)) {
                    testFirebaseAuthEnumeration(original, apiKey, url);
                }
            }
        }
    }

    // -- Phase 1: Unauthenticated Read (Realtime DB) --------------------------

    private void testRealtimeDbRead(HttpRequestResponse original, String project, String url)
            throws InterruptedException {
        String rtdbBase = "https://" + project + ".firebaseio.com";

        for (String path : RTDB_READ_PATHS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String probeUrl = rtdbBase + path;
            HttpRequestResponse result = sendGet(probeUrl);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            String body = result.response().bodyToString();
            if (body == null) body = "";

            // FP Prevention: require 200, valid JSON with actual data (not error/denied)
            if (status == 200
                    && body.length() > 4 // more than just "null"
                    && !body.equals("null")
                    && !body.toLowerCase().contains("\"error\"")
                    && !body.toLowerCase().contains("permission denied")
                    && !body.toLowerCase().contains("permission_denied")
                    && looksLikeJson(body)) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Firebase Realtime DB Unauthenticated Read — " + path,
                                Severity.HIGH, Confidence.FIRM)
                        .url(probeUrl)
                        .evidence("Unauthenticated GET to " + probeUrl + " returned "
                                + body.length() + " bytes of JSON data. "
                                + "Firebase security rules allow public read access.")
                        .description("The Firebase Realtime Database at " + rtdbBase
                                + " allows unauthenticated read access. An attacker can "
                                + "exfiltrate all data stored in the database without credentials.")
                        .remediation("Configure Firebase Realtime Database security rules to "
                                + "require authentication: "
                                + "{ \"rules\": { \".read\": \"auth != null\" } }")
                        .payload(probeUrl)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 2: Unauthenticated Write Test (Realtime DB) --------------------

    private void testRealtimeDbWrite(HttpRequestResponse original, String project, String url)
            throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String rtdbBase = "https://" + project + ".firebaseio.com";
        String testPath = rtdbBase + "/omnistrike_test.json";
        String testPayload = "{\"test\":true}";

        // Send PUT to write test data
        HttpRequestResponse writeResult = sendPut(testPath, testPayload);
        if (writeResult == null || writeResult.response() == null) return;
        if (!ResponseGuard.isUsableResponse(writeResult)) return;

        int writeStatus = writeResult.response().statusCode();
        if (writeStatus != 200) { perHostDelay(); return; }

        // FP Prevention: verify written data can be read back
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        HttpRequestResponse readBack = sendGet(testPath);
        boolean confirmed = false;
        if (readBack != null && readBack.response() != null) {
            String readBody = readBack.response().bodyToString();
            if (readBody != null && readBody.contains("\"test\"") && readBody.contains("true")) {
                confirmed = true;
            }
        }

        // Immediately DELETE the test node to clean up (always execute -- even during cancellation)
        perHostDelay();
        sendDelete(testPath);

        if (confirmed) {
            findingsStore.addFinding(Finding.builder(MODULE_ID,
                            "Firebase Realtime DB Unauthenticated Write",
                            Severity.CRITICAL, Confidence.CERTAIN)
                    .url(testPath)
                    .evidence("Unauthenticated PUT to " + testPath + " succeeded (HTTP 200). "
                            + "Written data was verified by reading it back. "
                            + "Test node was cleaned up via DELETE.")
                    .description("The Firebase Realtime Database at " + rtdbBase
                            + " allows unauthenticated write access. An attacker can "
                            + "modify, insert, or delete any data in the database without credentials.")
                    .remediation("Configure Firebase Realtime Database security rules to "
                            + "require authentication: "
                            + "{ \"rules\": { \".write\": \"auth != null\" } }")
                    .payload(testPayload)
                    .requestResponse(writeResult)
                    .build());
        }
    }

    // -- Phase 3: Firestore Collection Enumeration ----------------------------

    private void testFirestoreEnumeration(HttpRequestResponse original, String project, String url)
            throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String firestoreBase = "https://firestore.googleapis.com/v1/projects/"
                + project + "/databases/(default)/documents/";

        // Differential probe: two collections must produce different responses
        String probeUrlA = firestoreBase + "users";
        String probeUrlB = firestoreBase + "omnistrike_nonexistent_" + System.currentTimeMillis();

        HttpRequestResponse resultA = sendGet(probeUrlA);
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        HttpRequestResponse resultB = sendGet(probeUrlB);
        perHostDelay();

        if (resultA == null || resultA.response() == null
                || resultB == null || resultB.response() == null) return;

        String bodyA = resultA.response().bodyToString();
        String bodyB = resultB.response().bodyToString();
        if (bodyA == null) bodyA = "";
        if (bodyB == null) bodyB = "";

        // If both probes produce identical responses, can't distinguish real from nonexistent
        if (bodyA.equals(bodyB)) {
            api.logging().logToOutput("[Firebase] Firestore differential probe failed — "
                    + "responses are identical. Skipping enumeration.");
            return;
        }

        for (String collection : FIRESTORE_COLLECTIONS) {
            if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

            String probeUrl = firestoreBase + collection;
            HttpRequestResponse result = sendGet(probeUrl);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            int status = result.response().statusCode();
            String body = result.response().bodyToString();
            if (body == null) body = "";

            // FP Prevention: require "documents" array in response
            if (status == 200
                    && body.contains("\"documents\"")
                    && !body.toLowerCase().contains("permission_denied")
                    && !body.toLowerCase().contains("missing or insufficient permissions")) {

                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Firestore Unauthenticated Collection Access — " + collection,
                                Severity.HIGH, Confidence.FIRM)
                        .url(probeUrl)
                        .evidence("Unauthenticated GET to Firestore collection '" + collection
                                + "' returned documents. Response contains \"documents\" array. "
                                + "Differential probe confirmed real data (nonexistent collection "
                                + "produced different response). Response length: " + body.length() + " bytes.")
                        .description("The Firestore collection '" + collection + "' in project '"
                                + project + "' is readable without authentication. "
                                + "An attacker can enumerate and exfiltrate all documents in this collection.")
                        .remediation("Configure Firestore security rules to require authentication: "
                                + "match /" + collection + "/{document} { allow read: if request.auth != null; }")
                        .payload(probeUrl)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    // -- Phase 4: Firebase Auth Enumeration -----------------------------------

    private void testFirebaseAuthEnumeration(HttpRequestResponse original, String apiKey, String url)
            throws InterruptedException {
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String authBase = "https://identitytoolkit.googleapis.com/v1";

        // Test 1: signInWithPassword with known-bad creds to check error differentiation
        String signInUrl = authBase + "/accounts:signInWithPassword?key=" + apiKey;
        String nonexistentPayload = "{\"email\":\"omnistrike_nonexistent_probe@test.invalid\","
                + "\"password\":\"OmniStrikeProbe!123\",\"returnSecureToken\":true}";
        String badPasswordPayload = "{\"email\":\"admin@test.invalid\","
                + "\"password\":\"OmniStrikeProbe!123\",\"returnSecureToken\":true}";

        HttpRequestResponse resultNonexistent = sendPost(signInUrl, nonexistentPayload);
        perHostDelay();
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;
        HttpRequestResponse resultBadPassword = sendPost(signInUrl, badPasswordPayload);
        perHostDelay();

        if (resultNonexistent != null && resultNonexistent.response() != null
                && resultBadPassword != null && resultBadPassword.response() != null) {

            String bodyNonexistent = resultNonexistent.response().bodyToString();
            String bodyBadPassword = resultBadPassword.response().bodyToString();
            if (bodyNonexistent == null) bodyNonexistent = "";
            if (bodyBadPassword == null) bodyBadPassword = "";

            // FP Prevention: require specific Firebase error code differentiation
            // EMAIL_NOT_FOUND vs INVALID_PASSWORD or INVALID_LOGIN_CREDENTIALS
            boolean hasEmailNotFound = bodyNonexistent.contains("EMAIL_NOT_FOUND");
            boolean hasInvalidPassword = bodyBadPassword.contains("INVALID_PASSWORD");
            boolean hasDifferentCodes = !bodyNonexistent.equals(bodyBadPassword)
                    && extractFirebaseErrorCode(bodyNonexistent) != null
                    && extractFirebaseErrorCode(bodyBadPassword) != null
                    && !extractFirebaseErrorCode(bodyNonexistent)
                    .equals(extractFirebaseErrorCode(bodyBadPassword));

            if (hasEmailNotFound || hasDifferentCodes) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Firebase Auth User Enumeration via signInWithPassword",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(signInUrl)
                        .evidence("signInWithPassword endpoint returns different error codes "
                                + "for nonexistent vs existing users. "
                                + "Nonexistent user error: " + extractFirebaseErrorCode(bodyNonexistent) + ". "
                                + "Bad password error: " + extractFirebaseErrorCode(bodyBadPassword) + ". "
                                + "This allows user enumeration.")
                        .description("The Firebase Authentication endpoint exposes user enumeration "
                                + "via different error messages for nonexistent accounts vs wrong passwords. "
                                + "An attacker can determine which email addresses have registered accounts.")
                        .remediation("Enable email enumeration protection in Firebase Console: "
                                + "Authentication > Settings > User Actions > Email Enumeration Protection.")
                        .payload(nonexistentPayload)
                        .requestResponse(resultNonexistent)
                        .build());
            }
        }

        // Test 2: createAuthUri for email enumeration
        if (Thread.currentThread().isInterrupted() || ScanState.isCancelled()) return;

        String createAuthUriUrl = authBase + "/accounts:createAuthUri?key=" + apiKey;
        String emailProbePayload = "{\"identifier\":\"omnistrike_probe@test.invalid\","
                + "\"continueUri\":\"https://localhost\"}";

        HttpRequestResponse emailResult = sendPost(createAuthUriUrl, emailProbePayload);
        if (emailResult != null && emailResult.response() != null) {
            int status = emailResult.response().statusCode();
            String body = emailResult.response().bodyToString();
            if (body == null) body = "";

            // If the endpoint responds with "registered" field, it reveals user existence
            if (status == 200 && body.contains("\"registered\"")) {
                findingsStore.addFinding(Finding.builder(MODULE_ID,
                                "Firebase Auth Email Enumeration via createAuthUri",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(createAuthUriUrl)
                        .evidence("createAuthUri endpoint returns a 'registered' field "
                                + "indicating whether the email exists. "
                                + "Response: " + truncate(body, 300))
                        .description("The Firebase createAuthUri endpoint reveals whether "
                                + "email addresses are registered. An attacker can enumerate "
                                + "valid user emails without authentication.")
                        .remediation("Enable email enumeration protection in Firebase Console: "
                                + "Authentication > Settings > User Actions > Email Enumeration Protection.")
                        .payload(emailProbePayload)
                        .requestResponse(emailResult)
                        .build());
            }
        }
    }

    // -- HTTP Request Sending -------------------------------------------------

    private HttpRequestResponse sendGet(String targetUrl) {
        if (ScanState.isCancelled()) return null;
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl);
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequestResponse sendPut(String targetUrl, String jsonBody) {
        if (ScanState.isCancelled()) return null;
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                    .withMethod("PUT")
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(jsonBody);
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequestResponse sendPost(String targetUrl, String jsonBody) {
        if (ScanState.isCancelled()) return null;
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                    .withMethod("POST")
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(jsonBody);
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result != null && !ResponseGuard.isUsableResponse(result)) return null;
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequestResponse sendDelete(String targetUrl) {
        // No cancellation check -- cleanup DELETE must always execute
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                    .withMethod("DELETE");
            HttpRequestResponse result = api.http().sendRequest(request);
            // Don't care about response for cleanup
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // -- Project ID Extraction ------------------------------------------------

    private String extractProjectFromUrl(String url) {
        // Try Realtime DB: https://PROJECT.firebaseio.com
        Matcher rtdbMatcher = RTDB_PROJECT_PATTERN.matcher(url);
        if (rtdbMatcher.find()) return rtdbMatcher.group(1);

        // Try Firestore: firestore.googleapis.com/v1/projects/PROJECT/...
        Matcher firestoreMatcher = FIRESTORE_PROJECT_PATTERN.matcher(url);
        if (firestoreMatcher.find()) return firestoreMatcher.group(1);

        // Try firebaseapp.com: https://PROJECT.firebaseapp.com
        Pattern appPattern = Pattern.compile(
                "https?://([a-zA-Z0-9_-]+)\\.firebaseapp\\.com", Pattern.CASE_INSENSITIVE);
        Matcher appMatcher = appPattern.matcher(url);
        if (appMatcher.find()) return appMatcher.group(1);

        return null;
    }

    private String extractProjectFromBody(String body) {
        if (body == null) return null;

        // Try "projectId": "..."
        Pattern projectIdPattern = Pattern.compile("\"projectId\"\\s*:\\s*\"([a-zA-Z0-9_-]+)\"");
        Matcher m = projectIdPattern.matcher(body);
        if (m.find()) return m.group(1);

        // Try storageBucket: "PROJECT.appspot.com"
        Pattern bucketPattern = Pattern.compile(
                "\"storageBucket\"\\s*:\\s*\"([a-zA-Z0-9_-]+)\\.appspot\\.com\"");
        m = bucketPattern.matcher(body);
        if (m.find()) return m.group(1);

        // Try authDomain: "PROJECT.firebaseapp.com"
        Pattern authDomainPattern = Pattern.compile(
                "\"authDomain\"\\s*:\\s*\"([a-zA-Z0-9_-]+)\\.firebaseapp\\.com\"");
        m = authDomainPattern.matcher(body);
        if (m.find()) return m.group(1);

        // Try databaseURL: "https://PROJECT.firebaseio.com"
        Pattern dbUrlPattern = Pattern.compile(
                "\"databaseURL\"\\s*:\\s*\"https?://([a-zA-Z0-9_-]+)\\.firebaseio\\.com\"");
        m = dbUrlPattern.matcher(body);
        if (m.find()) return m.group(1);

        return null;
    }

    private String extractApiKeyFromBody(String body) {
        if (body == null) return null;

        // From identitytoolkit URL
        Matcher m = AUTH_API_KEY_PATTERN.matcher(body);
        if (m.find()) return m.group(1);

        // From Firebase config: "apiKey": "..."
        Pattern apiKeyPattern = Pattern.compile("\"apiKey\"\\s*:\\s*\"([a-zA-Z0-9_-]+)\"");
        m = apiKeyPattern.matcher(body);
        if (m.find()) return m.group(1);

        return null;
    }

    private String extractFirebaseErrorCode(String body) {
        if (body == null) return null;
        // Firebase error format: "message": "EMAIL_NOT_FOUND" or "message": "INVALID_PASSWORD"
        Pattern errorPattern = Pattern.compile("\"message\"\\s*:\\s*\"([A-Z_]+)\"");
        Matcher m = errorPattern.matcher(body);
        if (m.find()) return m.group(1);
        return null;
    }

    // -- Service Type Detection -----------------------------------------------

    private enum ServiceType {
        REALTIME_DB, FIRESTORE, AUTH, UNKNOWN
    }

    private ServiceType detectServiceType(String url) {
        if (url == null) return ServiceType.UNKNOWN;
        String lower = url.toLowerCase();
        if (lower.contains(".firebaseio.com")) return ServiceType.REALTIME_DB;
        if (lower.contains("firestore.googleapis.com")) return ServiceType.FIRESTORE;
        if (lower.contains("identitytoolkit.googleapis.com")
                || lower.contains("securetoken.googleapis.com")) return ServiceType.AUTH;
        return ServiceType.UNKNOWN;
    }

    private ServiceType detectServiceTypeFromBody(String body, String url) {
        ServiceType fromUrl = detectServiceType(url);
        if (fromUrl != ServiceType.UNKNOWN) return fromUrl;
        if (body == null) return ServiceType.UNKNOWN;
        String lower = body.toLowerCase();
        if (lower.contains("firebaseio.com")) return ServiceType.REALTIME_DB;
        if (lower.contains("firestore")) return ServiceType.FIRESTORE;
        if (lower.contains("firebase-auth") || lower.contains("identitytoolkit")) return ServiceType.AUTH;
        return ServiceType.UNKNOWN;
    }

    // -- Utility Methods ------------------------------------------------------

    private boolean looksLikeJson(String text) {
        if (text == null || text.isEmpty()) return false;
        String trimmed = text.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private String truncate(String text, int maxLen) {
        if (text == null) return "";
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + "...";
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("firebase.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private String extractPath(String url) {
        try {
            int s = url.indexOf("://");
            if (s >= 0) {
                int q = url.indexOf('?', s + 3);
                return q >= 0 ? url.substring(s, q) : url.substring(s);
            }
        } catch (Exception ignored) {}
        return url;
    }

    // -- Inner classes --------------------------------------------------------

    private static class FirebaseDetection {
        final String evidence;
        final String projectId;
        final ServiceType serviceType;
        final String apiKey; // nullable, extracted from identitytoolkit URLs

        FirebaseDetection(String evidence, String projectId, ServiceType serviceType) {
            this(evidence, projectId, serviceType, null);
        }

        FirebaseDetection(String evidence, String projectId, ServiceType serviceType, String apiKey) {
            this.evidence = evidence;
            this.projectId = projectId;
            this.serviceType = serviceType;
            this.apiKey = apiKey;
        }
    }
}

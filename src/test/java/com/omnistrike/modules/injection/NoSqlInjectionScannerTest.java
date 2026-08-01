package com.omnistrike.modules.injection;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NoSqlInjectionScannerTest {

    @Test
    void replacesNestedJsonScalarWithAnOperatorObject() {
        String changed = NoSqlInjectionScanner.buildJsonOperatorPayload(
                "{\"account\":{\"username\":\"alice\",\"role\":\"user\"}}",
                List.of("account", "username"), "$ne", "omni-canary");

        JsonObject root = JsonParser.parseString(changed).getAsJsonObject();
        assertEquals("omni-canary", root.getAsJsonObject("account")
                .getAsJsonObject("username").get("$ne").getAsString());
        assertEquals("user", root.getAsJsonObject("account").get("role").getAsString());
    }

    @Test
    void rejectsUnsafeJsonOperatorsInTheStructuralHelper() {
        String original = "{\"username\":\"alice\"}";
        assertEquals(original, NoSqlInjectionScanner.buildJsonOperatorPayload(
                original, List.of("username"), "$where", "sleep(5000)"));
    }

    @Test
    void confirmsOnlyARepeatableCardinalityDifferential() {
        var baseline = NoSqlInjectionScanner.profile(200,
                "{\"results\":[{\"id\":1}]}", "");
        var replay = NoSqlInjectionScanner.profile(200,
                "{\"results\":[{\"id\":99}]}", "");
        var broad = NoSqlInjectionScanner.profile(200,
                "{\"results\":[{\"id\":1},{\"id\":2},{\"id\":3}]}", "");
        var impossible = NoSqlInjectionScanner.profile(200,
                "{\"results\":[]}", "");

        assertEquals(NoSqlInjectionScanner.Signal.CARDINALITY,
                NoSqlInjectionScanner.confirmationSignal(baseline, replay, broad, impossible));
        assertTrue(NoSqlInjectionScanner.confirmsSignal(
                NoSqlInjectionScanner.Signal.CARDINALITY, baseline, broad, impossible));
    }

    @Test
    void ordinaryBodyTextChangesNeverConfirmInjection() {
        var baseline = NoSqlInjectionScanner.profile(200, "{\"message\":\"normal\"}", "");
        var replay = NoSqlInjectionScanner.profile(200, "{\"message\":\"changed nonce\"}", "");
        var broad = NoSqlInjectionScanner.profile(200, "{\"message\":\"welcome\"}", "");
        var impossible = NoSqlInjectionScanner.profile(200, "{\"message\":\"invalid\"}", "");

        assertEquals(NoSqlInjectionScanner.Signal.NONE,
                NoSqlInjectionScanner.confirmationSignal(baseline, replay, broad, impossible));
    }

    @Test
    void detectsAuthenticationAndRedirectSignalsWithoutUsingResponseLength() {
        var baseline = NoSqlInjectionScanner.profile(401, "{\"error\":\"denied\"}", "");
        var replay = NoSqlInjectionScanner.profile(401, "{\"error\":\"denied again\"}", "");
        var authenticated = NoSqlInjectionScanner.profile(200,
                "{\"success\":true,\"token\":\"abc\",\"user\":{\"id\":1}}", "");
        var denied = NoSqlInjectionScanner.profile(401, "{\"error\":\"denied\"}", "");
        assertEquals(NoSqlInjectionScanner.Signal.AUTHENTICATION,
                NoSqlInjectionScanner.confirmationSignal(baseline, replay, authenticated, denied));

        var redirectTrue = NoSqlInjectionScanner.profile(302, "", "/dashboard?nonce=1");
        var redirectFalse = NoSqlInjectionScanner.profile(302, "", "/login?error=1");
        assertTrue(NoSqlInjectionScanner.confirmsSignal(
                NoSqlInjectionScanner.Signal.REDIRECT, baseline, redirectTrue, redirectFalse));
    }

    @Test
    void unstableBaselineSuppressesOtherwisePlausibleSignal() {
        var baseline = NoSqlInjectionScanner.profile(200, "{\"results\":[{}]}", "");
        var unstableReplay = NoSqlInjectionScanner.profile(200, "{\"results\":[{},{}]}", "");
        var broad = NoSqlInjectionScanner.profile(200, "{\"results\":[{},{},{}]}", "");
        var impossible = NoSqlInjectionScanner.profile(200, "{\"results\":[]}", "");

        assertEquals(NoSqlInjectionScanner.Signal.NONE,
                NoSqlInjectionScanner.confirmationSignal(
                        baseline, unstableReplay, broad, impossible));
    }

    @Test
    void replaysOnlyGetAndReadLikePostRequestsByDefault() {
        assertTrue(NoSqlInjectionScanner.isSafeReplayCandidate(
                "GET", "https://example.test/api/users", false));
        assertTrue(NoSqlInjectionScanner.isSafeReplayCandidate(
                "POST", "https://example.test/api/login.php", false));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "POST", "https://example.test/api/data", false));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "GET", "https://example.test/api/delete?id=12", true));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "GET", "https://example.test/api/del%65te?id=12", true));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "GET", "https://example.test/api/delete-user?id=12", true));

        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "POST", "https://example.test/feedback/submit", true));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "PATCH", "https://example.test/api/search", true));
        assertFalse(NoSqlInjectionScanner.isSafeReplayCandidate(
                "POST", "https://example.test/api/data", false));
    }

    @Test
    void recognizesDestructiveActionAndMethodOverrideParameters() {
        assertTrue(NoSqlInjectionScanner.isMutatingActionParameter("action", "deleteUser"));
        assertTrue(NoSqlInjectionScanner.isMutatingActionParameter("_method", "DELETE"));
        assertTrue(NoSqlInjectionScanner.isMutatingActionParameter("operation", "account-reset"));
        assertFalse(NoSqlInjectionScanner.isMutatingActionParameter("action", "search"));
        assertFalse(NoSqlInjectionScanner.isMutatingActionParameter("query", "delete"));
    }
}

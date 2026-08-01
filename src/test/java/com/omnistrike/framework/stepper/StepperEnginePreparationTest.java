package com.omnistrike.framework.stepper;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.ScopeManager;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StepperEnginePreparationTest {

    @Test
    void cacheRequiresTheExactPrerequisiteFingerprint() {
        long now = 50_000L;

        assertTrue(StepperEngine.isCacheValid(
                now, 45_000L, 10, 2, 2, "chain-a", "chain-a"));
        assertFalse(StepperEngine.isCacheValid(
                now, 45_000L, 10, 2, 2, "chain-a", "chain-b"));
        assertFalse(StepperEngine.isCacheValid(
                now, 39_999L, 10, 2, 2, "chain-a", "chain-a"));
        assertFalse(StepperEngine.isCacheValid(
                now, 45_000L, 0, 2, 2, "chain-a", "chain-a"));
        assertFalse(StepperEngine.isCacheValid(
                now, 55_000L, 10, 2, 2, "chain-a", "chain-a"));
    }

    @Test
    void recognizesOneDynamicPathSegmentWithoutWildcardingStaticRoutes() {
        assertTrue(StepperEngine.pathMutationMatches(
                "/api/users/123", "/api/users/%27%20OR%201=1"));
        assertTrue(StepperEngine.pathMutationMatches(
                "/api/users/{{userId}}", "/api/users/9f03d1"));
        assertTrue(StepperEngine.pathMutationMatches(
                "/orders/550e8400-e29b-41d4-a716-446655440000", "/orders/payload"));

        assertFalse(StepperEngine.pathMutationMatches(
                "/api/users/list", "/api/users/delete"));
        assertFalse(StepperEngine.pathMutationMatches(
                "/api/users/123", "/api/admin/payload"));
        assertFalse(StepperEngine.pathMutationMatches("/123", "/payload"));
        assertFalse(StepperEngine.pathMutationMatches(
                "/api/users/123", "/api/users/123"));
    }

    @Test
    void distinguishesStepperVariablesFromSstiExpressions() {
        assertEquals(java.util.Set.of("token", "user.id"),
                StepperEngine.requiredPlaceholderNames(
                        "Bearer {{ token }} /users/{{user.id}} {{7*7}} {{foo bar}}"));
    }

    @Test
    void cachedContextSnapshotsAreIsolatedFromRefreshMutation() {
        ChainContext original = new ChainContext();
        original.variableStore.set("token", "first");
        original.cookieJar.put("sid", "one");
        original.lastChainRunTime = 123L;
        original.lastChainPrereqCount = 2;
        original.lastChainFingerprint = "chain-a";

        ChainContext snapshot = original.snapshot();
        original.variableStore.set("token", "second");
        original.cookieJar.put("sid", "two");
        original.lastChainFingerprint = "chain-b";

        assertEquals("first", snapshot.variableStore.get("token"));
        assertEquals("one", snapshot.cookieJar.get("sid"));
        assertEquals("chain-a", snapshot.lastChainFingerprint);
    }

    @Test
    void prerequisiteTimeoutIsBounded() {
        StepperEngine engine = new StepperEngine(null, null);
        engine.setPrerequisiteTimeoutMs(1);
        assertEquals(1_000L, engine.getPrerequisiteTimeoutMs());
        engine.setPrerequisiteTimeoutMs(Long.MAX_VALUE);
        assertEquals(120_000L, engine.getPrerequisiteTimeoutMs());
    }

    @Test
    void pausedMatchedRequestFailsInsteadOfSilentlyBypassingStepper() {
        HttpRequest target = request("POST", "/api/final", "value=1");
        StepperEngine engine = new StepperEngine(null, new ScopeManager());
        engine.addStep(new StepperStep("C", target));
        engine.setEnabled(true);
        engine.setPaused(true);

        StepperEngine.PreparationResult result = engine.prepareOutgoingRequest(target);

        assertTrue(result.matched());
        assertFalse(result.successful());
        assertTrue(result.message().contains("paused"));
    }

    @Test
    void targetWithoutPrerequisitesCannotReuseStaleExtractedVariables() throws Exception {
        HttpRequest target = request("POST", "/api/final", "token={{stale}}");
        StepperEngine engine = new StepperEngine(null, new ScopeManager());
        engine.addStep(new StepperStep("C", target));
        engine.setEnabled(true);
        displayContext(engine).variableStore.set("stale", "old-run-value");

        StepperEngine.PreparationResult result = engine.prepareOutgoingRequest(target);

        assertTrue(result.matched());
        assertFalse(result.successful());
        assertTrue(result.message().contains("stale"));
    }

    @Test
    void changingCacheTtlCannotResurrectAnOldSnapshot() throws Exception {
        StepperEngine engine = new StepperEngine(null, new ScopeManager());
        ChainContext context = displayContext(engine);
        context.lastChainRunTime = 1234L;
        context.lastChainPrereqCount = 2;
        context.lastChainFingerprint = "old";

        engine.setCacheTtlSeconds(60);

        assertEquals(0L, engine.getLastChainRunTime());
        assertEquals(-1, context.lastChainPrereqCount);
        assertEquals("", context.lastChainFingerprint);
    }

    private static ChainContext displayContext(StepperEngine engine) throws Exception {
        Field field = StepperEngine.class.getDeclaredField("displayContext");
        field.setAccessible(true);
        return (ChainContext) field.get(engine);
    }

    private static HttpRequest request(String method, String path, String body) {
        HttpService service = (HttpService) Proxy.newProxyInstance(
                HttpService.class.getClassLoader(), new Class<?>[]{HttpService.class},
                (proxy, invoked, args) -> switch (invoked.getName()) {
                    case "host" -> "example.test";
                    case "port" -> 443;
                    case "secure" -> true;
                    default -> defaultValue(invoked.getReturnType());
                });
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(), new Class<?>[]{HttpRequest.class},
                (proxy, invoked, args) -> switch (invoked.getName()) {
                    case "method" -> method;
                    case "path", "pathWithoutQuery" -> path;
                    case "bodyToString" -> body;
                    case "httpService" -> service;
                    case "headers" -> List.of();
                    default -> defaultValue(invoked.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == short.class) return (short) 0;
        if (type == byte.class) return (byte) 0;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }
}

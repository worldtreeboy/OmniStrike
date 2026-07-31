package com.omnistrike.framework.stepper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import com.omnistrike.framework.PersistenceManager;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertFalse;

class StepperEngineMemoryOnlyTest {

    @Test
    void startupAndMutationsPurgeLegacyCredentialBearingState() {
        Map<String, String> strings = new ConcurrentHashMap<>();
        strings.put("omnistrike.stepper.state", "BASE64_LOGIN_REQUEST_WITH_SECRET");

        Preferences preferences = (Preferences) Proxy.newProxyInstance(
                Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getString" -> strings.get((String) args[0]);
                    case "setString" -> { strings.put((String) args[0], (String) args[1]); yield null; }
                    case "deleteString" -> { strings.remove((String) args[0]); yield null; }
                    case "stringKeys" -> strings.keySet();
                    default -> null;
                });
        Persistence persistence = (Persistence) Proxy.newProxyInstance(
                Persistence.class.getClassLoader(), new Class<?>[]{Persistence.class},
                (proxy, method, args) -> method.getName().equals("preferences") ? preferences : null);
        MontoyaApi api = (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> method.getName().equals("persistence") ? persistence : null);

        StepperEngine engine = new StepperEngine(null, null);
        engine.setPersistence(new PersistenceManager(api));
        engine.loadPersistedState();
        assertFalse(strings.containsKey("omnistrike.stepper.state"));

        strings.put("omnistrike.stepper.state", "ANOTHER_SECRET");
        engine.saveState();
        assertFalse(strings.containsKey("omnistrike.stepper.state"));
    }
}

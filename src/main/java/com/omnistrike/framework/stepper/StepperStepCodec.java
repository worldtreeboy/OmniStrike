package com.omnistrike.framework.stepper;

import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Legacy Stepper serialization codec retained only for migration tests.
 *
 * <p>Older releases stored HTTP requests as their host/port/secure tuple plus
 * raw Base64 bytes. Current releases purge that state because it can contain
 * credentials. The actual
 * {@link burp.api.montoya.http.message.requests.HttpRequest} conversion lives in
 * {@link StepperEngine}; this class only deals with plain data, which keeps it
 * unit-testable without a running Burp.
 */
public final class StepperStepCodec {

    private StepperStepCodec() {}

    private static final Gson GSON = new Gson();

    /** Serialized form of one {@link ExtractionRule}. */
    public static final class RuleData {
        public String name;
        public String type;     // ExtractionType enum name
        public String pattern;
    }

    /** Serialized form of one {@link StepperStep}. */
    public static final class StepData {
        public String name;
        public boolean enabled = true;
        public String host;
        public int port;
        public boolean secure;
        public String requestB64;          // Base64 of the raw request bytes
        public List<RuleData> rules = new ArrayList<>();
    }

    /** Full persisted Stepper state. */
    public static final class StepperState {
        public boolean enabled;
        public boolean cookieJarEnabled = true;
        public boolean stopOnFailure;
        public boolean perRequestMode;
        public int cacheTtlSeconds = 10;
        public List<StepData> steps = new ArrayList<>();
        public Map<String, String> pinnedVariables = new LinkedHashMap<>();
        public Map<String, String> pinnedCookies = new LinkedHashMap<>();
    }

    public static String toJson(StepperState state) {
        try {
            return GSON.toJson(state != null ? state : new StepperState());
        } catch (Exception e) {
            return "";
        }
    }

    /** Parses persisted state. Never throws — returns a fresh empty state on any problem. */
    public static StepperState fromJson(String json) {
        if (json == null || json.isBlank()) return new StepperState();
        try {
            StepperState s = GSON.fromJson(json, StepperState.class);
            if (s == null) return new StepperState();
            // Defensive: Gson leaves null for absent collections.
            if (s.steps == null) s.steps = new ArrayList<>();
            if (s.pinnedVariables == null) s.pinnedVariables = new LinkedHashMap<>();
            if (s.pinnedCookies == null) s.pinnedCookies = new LinkedHashMap<>();
            for (StepData sd : s.steps) {
                if (sd != null && sd.rules == null) sd.rules = new ArrayList<>();
            }
            return s;
        } catch (Exception e) {
            return new StepperState();
        }
    }
}

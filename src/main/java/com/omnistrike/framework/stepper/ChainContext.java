package com.omnistrike.framework.stepper;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-execution state for a Stepper chain run.
 *
 * In cached mode, a single shared instance (the engine's displayContext) is reused
 * across requests and gated by chainLock.
 *
 * In per-request mode, a fresh ChainContext is allocated for every outgoing request
 * so multiple Burp scanner threads can run A->B->C->D pipelines concurrently without
 * clobbering each other's variables or cookies. A snapshot is copied into the engine's
 * displayContext after each run for UI display.
 */
public class ChainContext {

    public final StepperVariableStore variableStore = new StepperVariableStore();

    public final ConcurrentHashMap<String, String> cookieJar = new ConcurrentHashMap<>();

    /** RFC 6265 identity for a chain-collected cookie. */
    public record CookieKey(String name, String domain, String path) {}

    /**
     * Actual scoped cookies used for injection. This is separate from cookieJar,
     * which remains a simple name/value projection for the UI and pinned-cookie
     * controls.
     */
    public final ConcurrentHashMap<CookieKey, ScopedCookie> scopedCookies = new ConcurrentHashMap<>();

    /** Where a chain-collected cookie came from and how it is scoped (RFC 6265). */
    public static final class CookieOrigin {
        /** Lowercased host of the response that set the cookie. */
        public final String host;
        /** Domain attribute value (lowercased, leading dot stripped); null = host-only cookie. */
        public final String domain;
        /** True if the Set-Cookie carried the Secure attribute. */
        public final boolean secure;
        /** Path attribute value, or the default-path of the setting request. */
        public final String path;

        public CookieOrigin(String host, String domain, boolean secure, String path) {
            this.host = host;
            this.domain = domain;
            this.secure = secure;
            this.path = path;
        }
    }

    /** Cookie value plus its validated scope and creation order. */
    public static final class ScopedCookie {
        public final String name;
        public final String value;
        public final CookieOrigin origin;
        public final long creationOrder;

        public ScopedCookie(String name, String value, CookieOrigin origin, long creationOrder) {
            this.name = name;
            this.value = value;
            this.origin = origin;
            this.creationOrder = creationOrder;
        }
    }

    public final List<HttpResponse> stepResponses = Collections.synchronizedList(new ArrayList<>());

    /** Epoch ms of the most recent successful chain run. 0 if never run. */
    public volatile long lastChainRunTime = 0;

    /** Number of prereq steps that ran last time. Used for cache invalidation. -1 if never run. */
    public volatile int lastChainPrereqCount = -1;

    /** Fingerprint of the exact prerequisite requests/rules that populated this context. */
    public volatile String lastChainFingerprint = "";

    /** Reset all per-run state. Pinned cookies are restored by the engine after this. */
    public void reset() {
        variableStore.clear();
        cookieJar.clear();
        scopedCookies.clear();
        stepResponses.clear();
    }

    /** Isolated copy used while a cached chain is refreshed by another scanner thread. */
    public ChainContext snapshot() {
        ChainContext copy = new ChainContext();
        for (var entry : variableStore.getAll().entrySet()) {
            copy.variableStore.set(entry.getKey(), entry.getValue());
        }
        copy.cookieJar.putAll(cookieJar);
        copy.scopedCookies.putAll(scopedCookies);
        synchronized (stepResponses) {
            copy.stepResponses.addAll(stepResponses);
        }
        copy.lastChainRunTime = lastChainRunTime;
        copy.lastChainPrereqCount = lastChainPrereqCount;
        copy.lastChainFingerprint = lastChainFingerprint;
        return copy;
    }
}

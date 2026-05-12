package com.omnistrike.framework.stepper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Drop-in replacement for {@code api.http().sendRequest(request)} that routes
 * the outgoing request through Stepper first.
 *
 * Why this exists: Montoya's {@code api.http().sendRequest()} deliberately does
 * NOT invoke registered {@link burp.api.montoya.http.handler.HttpHandler}s.
 * That means Stepper (which hooks the HttpHandler) never sees requests sent
 * from inside this extension. Burp's built-in tools (Proxy, Repeater, Intruder,
 * Scanner) fire the handler natively, so Stepper works there; but OmniStrike's
 * own scan modules use {@code api.http().sendRequest()} directly, bypassing it.
 *
 * Every scan module should call {@code StepperHttp.sendRequest(req)} instead of
 * {@code api.http().sendRequest(req)} so Stepper preprocessing runs.
 *
 * Recursion: {@link StepperEngine#processOutgoingRequest} sets a ThreadLocal
 * flag while executing the chain, so prereq sends from inside the chain
 * (which themselves call {@code api.http().sendRequest} directly, not this
 * wrapper) won't recurse — and even if a chain-internal call accidentally
 * went through this wrapper, the flag would cause an immediate pass-through.
 */
public final class StepperHttp {

    private static volatile MontoyaApi api;
    private static volatile StepperEngine stepper;

    private StepperHttp() {}

    /** Called once during extension load with the Montoya API and the configured engine. */
    public static void init(MontoyaApi montoyaApi, StepperEngine stepperEngine) {
        api = montoyaApi;
        stepper = stepperEngine;
    }

    /**
     * Sends the request, applying Stepper preprocessing (prereq chain + variable
     * substitution + cookie injection) first if Stepper is enabled.
     *
     * Falls back to a raw send if {@link #init} was never called (e.g. during
     * an unusual load order) so modules don't NPE.
     */
    public static HttpRequestResponse sendRequest(HttpRequest request) {
        MontoyaApi a = api;
        if (a == null) {
            // init() wasn't called — extension still loading or torn down.
            // Best-effort: caller must have an api reference, but we don't.
            // Returning null is worse than throwing here; the alternative is
            // that the calling module crashes on a NPE accessing a.http().
            throw new IllegalStateException("StepperHttp.init() was never called");
        }
        HttpRequest finalReq = preprocess(request);
        return a.http().sendRequest(finalReq);
    }

    private static HttpRequest preprocess(HttpRequest request) {
        StepperEngine s = stepper;
        if (s == null || !s.isEnabled()) return request;
        if (StepperEngine.isExecutingChain()) return request;
        try {
            return s.processOutgoingRequest(request);
        } catch (Exception e) {
            // Never break a scan-module send because Stepper threw — fall through
            return request;
        }
    }
}

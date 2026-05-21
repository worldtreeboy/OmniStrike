package com.omnistrike.framework.stepper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.SessionKeepAlive;

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
    private static volatile SessionKeepAlive sessionKeepAlive;

    private StepperHttp() {}

    /** Called once during extension load with the Montoya API and the configured engine. */
    public static void init(MontoyaApi montoyaApi, StepperEngine stepperEngine) {
        api = montoyaApi;
        stepper = stepperEngine;
    }

    /**
     * Wires the Session Keep-Alive so module sends also receive fresh session
     * cookies. Set after the extension constructs the {@link SessionKeepAlive}.
     */
    public static void setSessionKeepAlive(SessionKeepAlive keepAlive) {
        sessionKeepAlive = keepAlive;
    }

    /**
     * Sends the request, applying Stepper preprocessing (prereq chain + variable
     * substitution + cookie injection) first if Stepper is enabled, then overlaying
     * the latest Session Keep-Alive cookies for the request's domain.
     *
     * <p>Order matters: Stepper runs to completion first so its variable
     * substitution and chain logic are never disturbed; Session Keep-Alive then
     * has the final say on session cookies. This keeps keep-alive from interfering
     * with Stepper while still guaranteeing fresh cookies on every module send.
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
        // Overlay fresh session cookies AFTER Stepper, so keep-alive never
        // disturbs Stepper's processing. No-op when keep-alive is disabled or
        // the host doesn't match the saved login domain.
        SessionKeepAlive ka = sessionKeepAlive;
        if (ka != null) {
            finalReq = ka.applyFreshCookies(finalReq);
        }
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

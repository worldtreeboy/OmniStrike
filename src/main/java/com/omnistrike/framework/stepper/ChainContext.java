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

    public final List<HttpResponse> stepResponses = Collections.synchronizedList(new ArrayList<>());

    /** Epoch ms of the most recent successful chain run. 0 if never run. */
    public volatile long lastChainRunTime = 0;

    /** Number of prereq steps that ran last time. Used for cache invalidation. -1 if never run. */
    public volatile int lastChainPrereqCount = -1;

    /** Reset all per-run state. Pinned cookies are restored by the engine after this. */
    public void reset() {
        variableStore.clear();
        cookieJar.clear();
        stepResponses.clear();
    }
}

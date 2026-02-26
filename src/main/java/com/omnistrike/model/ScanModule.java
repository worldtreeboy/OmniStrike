package com.omnistrike.model;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

/**
 * Interface that all scan modules must implement.
 * The framework routes in-scope traffic to enabled modules via processHttpFlow().
 */
public interface ScanModule {

    /** Unique module ID (e.g. "param-miner", "sqli-detector") */
    String getId();

    /** Display name for the UI */
    String getName();

    /** Short description of what this module does */
    String getDescription();

    /** Module category: RECON or INJECTION */
    ModuleCategory getCategory();

    /** Whether this module is passive (observe only) or active (sends its own requests) */
    boolean isPassive();

    /**
     * Called for every in-scope request/response pair.
     * Passive modules: analyze and return findings immediately (must be fast).
     * Active modules: queue work to the thread pool and may return empty list initially,
     *                 then add findings to the FindingsStore asynchronously.
     */
    List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api);

    /**
     * Process only a specific parameter. Active scanners should override this
     * to filter their injection points to just the named parameter.
     * Default falls back to full scan (for passive modules and scanners where
     * per-parameter targeting doesn't apply).
     */
    default List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        return processHttpFlow(requestResponse, api);
    }

    /** Called once when the module is loaded. Perform any setup here. */
    void initialize(MontoyaApi api, ModuleConfig config);

    /** Called on extension unload. Clean up resources (threads, connections, etc.) */
    void destroy();
}

package com.omnistrike.framework;

import com.omnistrike.model.ModuleConfig;
import com.omnistrike.model.ScanModule;
import burp.api.montoya.MontoyaApi;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

/**
 * Registers and manages all scan modules.
 * Tracks which modules are enabled/disabled.
 */
public class ModuleRegistry {

    /** Well-known module ID for the AI Vulnerability Analyzer. */
    public static final String AI_MODULE_ID = "ai-vuln-analyzer";

    /**
     * Modules that are manual-trigger only (right-click context menu).
     * These are EXCLUDED from auto-scanning (TrafficInterceptor) but remain
     * available for manual scans via scanRequest() which looks up by ID directly.
     */
    private static final Set<String> MANUAL_ONLY_IDS = Set.of(
            "ws-scanner"           // WebSocket — user triggers fuzzing from panel
    );

    private static final Set<String> STATEFUL_MANUAL_ONLY_IDS = Set.of(
            "deser-scanner", "proto-pollution", "host-header");

    private static boolean isManualOnlyId(String moduleId) {
        return MANUAL_ONLY_IDS.contains(moduleId) || STATEFUL_MANUAL_ONLY_IDS.contains(moduleId);
    }

    /**
     * Modules that fire automatically based on technology fingerprinting and are
     * NOT user-triggerable (no right-click entry, no custom-scan checkbox).
     * They remain part of {@link #getEnabledActiveModules()} so the active-scan
     * pipeline still calls them; each module self-filters by inspecting the
     * request for its target fingerprint (e.g. D365 endpoints, Firebase URLs).
     * The UI surfaces them as always-on (checkbox shown but disabled).
     */
    private static final Set<String> AUTO_TRIGGERED_IDS = Set.of(
            "dynamics365-scanner",
            "sap-odata-scanner",
            "salesforce-soql-scanner",
            "firebase-misconfig-scanner",
            "sharepoint-caml-scanner",
            "servicenow-glide-scanner",
            "solr-query-scanner",
            "odoo-domain-scanner",
            "elasticsearch-query-scanner",
            "spring-actuator-scanner"
    );

    // ConcurrentLinkedHashMap preserves insertion order and is safe for concurrent reads.
    // Written at startup during registerModule(), read from proxy threads during scanning.
    // Using Collections.synchronizedMap wrapping LinkedHashMap ensures happens-before
    // between startup writes and later concurrent reads.
    private final Map<String, ScanModule> modules = Collections.synchronizedMap(new LinkedHashMap<>());
    private final ConcurrentHashMap<String, Boolean> enabledMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ModuleConfig> configMap = new ConcurrentHashMap<>();
    private volatile MontoyaApi api;

    public void registerModule(ScanModule module) {
        modules.put(module.getId(), module);
        enabledMap.put(module.getId(), Boolean.TRUE);
        configMap.put(module.getId(), new ModuleConfig());
    }

    /** Registers a module but defaults it to disabled. */
    public void registerModuleDisabled(ScanModule module) {
        modules.put(module.getId(), module);
        enabledMap.put(module.getId(), Boolean.FALSE);
        configMap.put(module.getId(), new ModuleConfig());
    }

    public void initializeAll(MontoyaApi api) {
        this.api = api;
        for (Map.Entry<String, ScanModule> entry : modules.entrySet()) {
            try {
                entry.getValue().initialize(api, configMap.get(entry.getKey()));
            } catch (Exception e) {
                api.logging().logToError("Failed to initialize module " + entry.getKey() + ": " + e.getMessage());
                enabledMap.put(entry.getKey(), Boolean.FALSE);
            }
        }
    }

    public void destroyAll() {
        for (ScanModule module : modules.values()) {
            try {
                module.destroy();
            } catch (Exception e) {
                if (api != null) {
                    api.logging().logToError("Error destroying module " + module.getId() + ": " + e.getMessage());
                }
            }
        }
    }

    public void setEnabled(String moduleId, boolean enabled) {
        enabledMap.put(moduleId, enabled);
    }

    public boolean isEnabled(String moduleId) {
        return enabledMap.getOrDefault(moduleId, false);
    }

    public ScanModule getModule(String moduleId) {
        return modules.get(moduleId);
    }

    public ModuleConfig getConfig(String moduleId) {
        return configMap.get(moduleId);
    }

    public List<ScanModule> getAllModules() {
        synchronized (modules) {
            return new ArrayList<>(modules.values());
        }
    }

    public List<ScanModule> getEnabledModules() {
        return filterModules(m -> true);
    }

    /**
     * Returns enabled passive modules, excluding manual-only modules.
     * Used by TrafficInterceptor for auto-scanning proxied traffic.
     */
    public List<ScanModule> getEnabledPassiveModules() {
        return filterModules(m -> m.isPassive() && !isManualOnlyId(m.getId()));
    }

    /**
     * Returns enabled active modules, excluding manual-only modules.
     * Used by TrafficInterceptor for auto-scanning proxied traffic.
     * Manual-only modules (BUP, CSRF, WS) are only reachable via
     * scanRequest() which looks up modules by explicit ID.
     */
    public List<ScanModule> getEnabledActiveModules() {
        return filterModules(m -> !m.isPassive() && !isManualOnlyId(m.getId()));
    }

    /** Returns all enabled modules except the AI module and manual-only modules. */
    public List<ScanModule> getEnabledNonAiModules() {
        return filterModules(m -> !AI_MODULE_ID.equals(m.getId())
                && !isManualOnlyId(m.getId()));
    }

    /**
     * Returns the modules eligible for an explicit user-triggered scan.
     * Unlike the automatic-routing views, this deliberately includes modules
     * marked manual-only; otherwise "All Modules" and the right-click picker
     * silently hide the very scanners that can only be run from those actions.
     */
    public List<ScanModule> getEnabledManualScanModules() {
        return filterModules(m -> !AI_MODULE_ID.equals(m.getId()));
    }

    /** Returns true if the given module ID is manual-trigger-only (excluded from auto-scan). */
    public boolean isManualOnly(String moduleId) {
        return isManualOnlyId(moduleId);
    }

    /**
     * Returns true if the module is auto-triggered by technology fingerprint
     * and should not expose a user-toggleable enable/disable switch.
     */
    public boolean isAutoTriggered(String moduleId) {
        return AUTO_TRIGGERED_IDS.contains(moduleId);
    }

    private List<ScanModule> filterModules(Predicate<ScanModule> filter) {
        List<ScanModule> result = new ArrayList<>();
        synchronized (modules) {
            for (ScanModule module : modules.values()) {
                if (isEnabled(module.getId()) && filter.test(module)) {
                    result.add(module);
                }
            }
        }
        return result;
    }
}

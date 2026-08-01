package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ModuleCategory;
import com.omnistrike.model.ModuleConfig;
import com.omnistrike.model.ScanModule;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModuleRegistryTest {

    @Test
    void manualOnlyScannerIsExcludedFromAutomaticViewButIncludedInManualView() {
        ModuleRegistry registry = new ModuleRegistry();
        registry.registerModule(new StubModule("deser-scanner", false));
        registry.registerModule(new StubModule("ordinary-active", false));

        assertFalse(registry.getEnabledActiveModules().stream()
                .anyMatch(module -> module.getId().equals("deser-scanner")));
        assertTrue(registry.getEnabledManualScanModules().stream()
                .anyMatch(module -> module.getId().equals("deser-scanner")));
    }

    @Test
    void exposesAllTenResponseGatedScannersToAllModulesRouting() {
        Set<String> expected = Set.of(
                "dynamics365-scanner", "sap-odata-scanner", "salesforce-soql-scanner",
                "firebase-misconfig-scanner", "sharepoint-caml-scanner",
                "servicenow-glide-scanner", "solr-query-scanner", "odoo-domain-scanner",
                "elasticsearch-query-scanner", "spring-actuator-scanner");
        ModuleRegistry registry = new ModuleRegistry();
        expected.forEach(id -> registry.registerModule(new StubModule(id, false)));
        registry.registerModule(new StubModule("ordinary-active", false));

        assertEquals(expected, registry.getEnabledAutoTriggeredModules().stream()
                .map(ScanModule::getId).collect(Collectors.toSet()));
    }

    private record StubModule(String getId, boolean isPassive) implements ScanModule {
        @Override public String getId() { return getId; }
        @Override public String getName() { return getId; }
        @Override public String getDescription() { return "test"; }
        @Override public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }
        @Override public boolean isPassive() { return isPassive; }
        @Override public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
            return Collections.emptyList();
        }
        @Override public void initialize(MontoyaApi api, ModuleConfig config) {}
        @Override public void destroy() {}
    }
}

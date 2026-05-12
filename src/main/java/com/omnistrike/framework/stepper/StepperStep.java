package com.omnistrike.framework.stepper;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A single prerequisite step in the Stepper chain.
 * Holds the original request template and extraction rules for capturing
 * values from the response.
 */
public class StepperStep {

    private String name;
    private volatile HttpRequest originalRequest;
    private final CopyOnWriteArrayList<ExtractionRule> extractionRules = new CopyOnWriteArrayList<>();
    private boolean enabled = true;

    public StepperStep(String name, HttpRequest originalRequest) {
        this.name = name;
        this.originalRequest = originalRequest;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public HttpRequest getOriginalRequest() { return originalRequest; }

    /** Replace the captured request — used by the "Edit Request" dialog. */
    public void setOriginalRequest(HttpRequest request) {
        if (request != null) this.originalRequest = request;
    }

    public List<ExtractionRule> getExtractionRules() {
        return List.copyOf(extractionRules);
    }

    public void addExtractionRule(ExtractionRule rule) {
        extractionRules.add(rule);
    }

    public void removeExtractionRule(int index) {
        if (index >= 0 && index < extractionRules.size()) {
            extractionRules.remove(index);
        }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /** Returns a short summary like "POST /api/auth/login". */
    public String getUrlSummary() {
        try {
            String method = originalRequest.method();
            String path = originalRequest.path();
            return method + " " + path;
        } catch (Exception e) {
            return "(unknown)";
        }
    }
}

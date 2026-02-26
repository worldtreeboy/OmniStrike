package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.ScanModule;
import com.omnistrike.model.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Bridges OmniStrike modules into Burp's native scanner pipeline.
 *
 * IMPORTANT: This ScanCheck ONLY runs for URLs explicitly queued via
 * queueForScan(). It does NOT scan random proxy traffic — the user must
 * right-click "Send to OmniStrike" or have scanning started with scope.
 *
 * All modules (passive + active) run in passiveAudit() because OmniStrike
 * modules handle their own insertion points.
 */
public class OmniStrikeScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final ModuleRegistry registry;
    private final FindingsStore findingsStore;

    // Maps URL → module IDs to run. Empty list = all modules.
    private final ConcurrentHashMap<String, List<String>> pendingScans = new ConcurrentHashMap<>();

    // Deferred findings queue — async findings (Collaborator callbacks, etc.) land here and get drained
    // the next time Burp calls passiveAudit(), so they appear in Dashboard.
    private final ConcurrentLinkedQueue<Finding> deferredFindings = new ConcurrentLinkedQueue<>();

    public OmniStrikeScanCheck(MontoyaApi api, ModuleRegistry registry, FindingsStore findingsStore) {
        this.api = api;
        this.registry = registry;
        this.findingsStore = findingsStore;
    }

    /**
     * Queue a URL for scanning with ALL enabled modules.
     */
    public void queueForScan(String url) {
        if (url != null) {
            pendingScans.put(stripQueryParams(url), List.of());
            api.logging().logToOutput("[OmniStrikeScanCheck] Queued for scan (all modules): " + stripQueryParams(url));
        }
    }

    /**
     * Queue a URL for scanning with SPECIFIC modules only.
     */
    public void queueForScan(String url, List<String> moduleIds) {
        if (url != null && moduleIds != null && !moduleIds.isEmpty()) {
            pendingScans.put(stripQueryParams(url), new ArrayList<>(moduleIds));
            api.logging().logToOutput("[OmniStrikeScanCheck] Queued for scan (" + moduleIds + "): " + stripQueryParams(url));
        } else {
            queueForScan(url);
        }
    }

    /**
     * Add a finding to the deferred queue. Used to bridge async findings
     * into Burp's Dashboard via the ScanCheck pipeline.
     */
    public void addDeferredFinding(Finding finding) {
        if (finding != null) {
            deferredFindings.add(finding);
        }
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        String requestUrl = baseRequestResponse.request().url();
        String urlBase = stripQueryParams(requestUrl);

        // Only scan if explicitly queued via context menu
        List<String> requestedModules = pendingScans.remove(urlBase);

        // If not queued for normal scan, check if we have deferred findings to drain.
        // Deferred findings carry their own request/response — we use that, NOT the
        // unrelated baseRequestResponse that Burp happened to pass for this URL.
        if (requestedModules == null) {
            if (!deferredFindings.isEmpty()) {
                List<AuditIssue> deferredIssues = drainDeferredFindings();
                if (!deferredIssues.isEmpty()) {
                    api.logging().logToOutput("[OmniStrikeScanCheck] Drained " + deferredIssues.size()
                            + " deferred finding(s) into Dashboard");
                    return AuditResult.auditResult(deferredIssues);
                }
            }
            // Not queued — skip silently (don't scan random traffic)
            return AuditResult.auditResult();
        }

        api.logging().logToOutput("[OmniStrikeScanCheck] === SCANNING: " + requestUrl + " ===");

        List<AuditIssue> issues = new ArrayList<>();

        // Snapshot FindingsStore BEFORE running modules — take an immutable snapshot of
        // all findings so we can diff after modules run without stale-index races.
        Set<Finding> findingsBefore = new HashSet<>(findingsStore.getAllFindings());

        // Determine which modules to run
        List<ScanModule> modulesToRun;
        if (requestedModules.isEmpty()) {
            // Empty list = all enabled non-AI modules (AI is invoked separately)
            modulesToRun = registry.getEnabledNonAiModules();
            api.logging().logToOutput("[OmniStrikeScanCheck] Running ALL " + modulesToRun.size() + " enabled non-AI module(s)");
        } else {
            // Specific modules requested
            modulesToRun = new ArrayList<>();
            for (String id : requestedModules) {
                ScanModule m = registry.getModule(id);
                if (m != null) modulesToRun.add(m);
            }
            api.logging().logToOutput("[OmniStrikeScanCheck] Running " + modulesToRun.size()
                    + " specific module(s): " + requestedModules);
        }

        for (ScanModule module : modulesToRun) {
            try {
                api.logging().logToOutput("[OmniStrikeScanCheck] > " + module.getId());
                List<Finding> findings = module.processHttpFlow(baseRequestResponse, api);
                if (findings != null && !findings.isEmpty()) {
                    api.logging().logToOutput("[OmniStrikeScanCheck]   " + module.getId()
                            + " returned " + findings.size() + " finding(s)");
                    for (Finding f : findings) {
                        findingsStore.addFinding(f);
                        AuditIssue issue = toAuditIssue(f, baseRequestResponse);
                        if (issue != null) issues.add(issue);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[OmniStrikeScanCheck] Error in " + module.getId()
                        + ": " + e.getClass().getName() + ": " + e.getMessage());
            }
        }

        // Check if modules added findings directly to FindingsStore (not via return value).
        // Use set-diff instead of index arithmetic to avoid stale-index races from
        // concurrent scans or clearModule() calls shifting indices.
        if (issues.isEmpty()) {
            List<Finding> findingsAfter = findingsStore.getAllFindings();
            int newCount = 0;
            for (Finding f : findingsAfter) {
                if (!findingsBefore.contains(f)) {
                    AuditIssue issue = toAuditIssue(f, baseRequestResponse);
                    if (issue != null) issues.add(issue);
                    newCount++;
                }
            }
            if (newCount > 0) {
                api.logging().logToOutput("[OmniStrikeScanCheck] Modules added " + newCount
                        + " finding(s) directly to FindingsStore");
            }
        }

        // Also drain any deferred findings that arrived while scanning
        issues.addAll(drainDeferredFindings());

        api.logging().logToOutput("[OmniStrikeScanCheck] === DONE: " + issues.size() + " AuditIssue(s) ===");
        return AuditResult.auditResult(issues);
    }

    /**
     * Drains all deferred findings from the queue and converts them to AuditIssues.
     * Each deferred finding uses its OWN request/response evidence — we never substitute
     * an unrelated request/response, as that would attribute findings to the wrong URL.
     * Findings without their own request/response are skipped (they'll be visible in
     * the OmniStrike findings panel even if they can't appear in Burp's Dashboard).
     */
    private List<AuditIssue> drainDeferredFindings() {
        List<AuditIssue> issues = new ArrayList<>();
        Finding deferred;
        while ((deferred = deferredFindings.poll()) != null) {
            if (deferred.getRequestResponse() == null) {
                api.logging().logToOutput("[OmniStrikeScanCheck] Skipping deferred finding without "
                        + "request/response evidence: " + deferred.getTitle());
                continue;
            }
            AuditIssue issue = toAuditIssue(deferred, deferred.getRequestResponse());
            if (issue != null) {
                issues.add(issue);
            }
        }
        return issues;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint) {
        // Empty — OmniStrike handles its own injection points in passiveAudit()
        return AuditResult.auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equals(existingIssue.name())
                && newIssue.baseUrl().equals(existingIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    private String stripQueryParams(String url) {
        if (url == null) return "";
        int qIdx = url.indexOf('?');
        return qIdx >= 0 ? url.substring(0, qIdx) : url;
    }

    private AuditIssue toAuditIssue(Finding f, HttpRequestResponse fallbackReqResp) {
        try {
            HttpRequestResponse rr = f.getRequestResponse() != null
                    ? f.getRequestResponse() : fallbackReqResp;
            if (rr == null || rr.request() == null) return null;

            // Apply highlighting markers (payload in request, evidence in response)
            rr = MarkerUtil.addMarkers(rr, f.getPayload(), f.getResponseEvidence());

            String baseUrl = extractBaseUrl(rr.request().url());
            if (baseUrl.isEmpty()) baseUrl = extractBaseUrl(f.getUrl());
            if (baseUrl.isEmpty()) return null;

            return AuditIssue.auditIssue(
                    "[OmniStrike] " + f.getTitle(),
                    buildDetailHtml(f),
                    f.getRemediation() != null ? f.getRemediation() : "",
                    baseUrl,
                    mapSeverity(f.getSeverity()),
                    mapConfidence(f.getConfidence()),
                    null,
                    null,
                    mapSeverity(f.getSeverity()),
                    rr
            );
        } catch (Exception e) {
            api.logging().logToError("[OmniStrikeScanCheck] toAuditIssue FAILED: "
                    + e.getClass().getName() + ": " + e.getMessage());
            return null;
        }
    }

    private String extractBaseUrl(String fullUrl) {
        if (fullUrl == null || fullUrl.isEmpty()) return "";
        try {
            URI uri = URI.create(fullUrl);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            if (scheme == null || host == null) return "";
            if (port > 0 && !isDefaultPort(scheme, port)) {
                return scheme + "://" + host + ":" + port;
            }
            return scheme + "://" + host;
        } catch (Exception e) {
            int schemeEnd = fullUrl.indexOf("://");
            if (schemeEnd < 0) return "";
            int pathStart = fullUrl.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return fullUrl;
            return fullUrl.substring(0, pathStart);
        }
    }

    private boolean isDefaultPort(String scheme, int port) {
        return ("http".equals(scheme) && port == 80)
                || ("https".equals(scheme) && port == 443);
    }

    private AuditIssueSeverity mapSeverity(Severity sev) {
        if (sev == null) return AuditIssueSeverity.INFORMATION;
        return switch (sev) {
            case CRITICAL, HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            case INFO -> AuditIssueSeverity.INFORMATION;
        };
    }

    private AuditIssueConfidence mapConfidence(Confidence conf) {
        if (conf == null) return AuditIssueConfidence.TENTATIVE;
        return switch (conf) {
            case CERTAIN -> AuditIssueConfidence.CERTAIN;
            case FIRM -> AuditIssueConfidence.FIRM;
            case TENTATIVE -> AuditIssueConfidence.TENTATIVE;
        };
    }

    private String buildDetailHtml(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("<h3>").append(esc(f.getTitle())).append("</h3>");
        sb.append("<p><b>Module:</b> ").append(esc(f.getModuleId())).append("</p>");
        sb.append("<p><b>Severity:</b> ").append(f.getSeverity())
                .append(" | <b>Confidence:</b> ").append(f.getConfidence()).append("</p>");
        if (f.getUrl() != null && !f.getUrl().isEmpty())
            sb.append("<p><b>URL:</b> ").append(esc(f.getUrl())).append("</p>");
        if (f.getParameter() != null && !f.getParameter().isEmpty())
            sb.append("<p><b>Parameter:</b> ").append(esc(f.getParameter())).append("</p>");
        if (f.getDescription() != null && !f.getDescription().isEmpty())
            sb.append("<p><b>Description:</b><br>").append(esc(f.getDescription())).append("</p>");
        if (f.getEvidence() != null && !f.getEvidence().isEmpty())
            sb.append("<p><b>Evidence:</b></p><pre>").append(esc(f.getEvidence())).append("</pre>");
        if (f.getRemediation() != null && !f.getRemediation().isEmpty())
            sb.append("<p><b>Remediation:</b><br>").append(esc(f.getRemediation())).append("</p>");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}

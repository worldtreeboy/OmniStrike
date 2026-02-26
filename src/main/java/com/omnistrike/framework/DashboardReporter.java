package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import java.net.URI;

/**
 * Bridges OmniStrike findings to Burp's native Dashboard/Site Map.
 * Every finding added to FindingsStore gets reported as a Burp AuditIssue,
 * making it visible in Dashboard > Issue Activity with "[OmniStrike]" prefix.
 */
public class DashboardReporter implements FindingsStore.FindingsListener {

    private final MontoyaApi api;
    private volatile OmniStrikeScanCheck scanCheck;
    private volatile Audit persistentAudit;

    public DashboardReporter(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Wire the persistent audit and scan check created in OmniStrikeExtension.
     * Once set, every finding is fed into the deferred queue and the persistent
     * audit is poked so Burp calls passiveAudit() → drains queue → Dashboard.
     */
    public void setDashboardBridge(OmniStrikeScanCheck scanCheck, Audit persistentAudit) {
        this.scanCheck = scanCheck;
        this.persistentAudit = persistentAudit;
    }

    @Override
    public void onFindingAdded(Finding finding) {
        try {
            HttpRequestResponse reqResp = finding.getRequestResponse();

            // Must have a request/response — Burp's Dashboard needs it to display the issue
            if (reqResp == null || reqResp.request() == null) {
                api.logging().logToOutput("[DashboardReporter] Skipping (no request data): " + finding.getTitle());
                return;
            }

            // Extract base URL from the request's HTTP service
            String baseUrl = extractBaseUrl(reqResp.request().url());
            if (baseUrl.isEmpty()) {
                baseUrl = extractBaseUrl(finding.getUrl());
            }
            if (baseUrl.isEmpty()) {
                api.logging().logToOutput("[DashboardReporter] Skipping (no URL): " + finding.getTitle());
                return;
            }

            AuditIssueSeverity severity = mapSeverity(finding.getSeverity());
            AuditIssueConfidence confidence = mapConfidence(finding.getConfidence());
            String detail = buildDetailHtml(finding);
            String remediation = finding.getRemediation() != null ? finding.getRemediation() : "";

            // Apply highlighting markers (payload in request, evidence in response)
            reqResp = MarkerUtil.addMarkers(reqResp, finding.getPayload(), finding.getResponseEvidence());

            // Step 1: Ensure the request/response is in Burp's site map
            // (Burp may not display issues for URLs not in the site map)
            try {
                api.siteMap().add(reqResp);
            } catch (Exception ignored) {
                // May already exist — that's fine
            }

            // Step 2: Create and add the AuditIssue
            AuditIssue issue = AuditIssue.auditIssue(
                    "[OmniStrike] " + finding.getTitle(),
                    detail,
                    remediation,
                    baseUrl,
                    severity,
                    confidence,
                    null,
                    null,
                    severity,
                    reqResp
            );

            api.siteMap().add(issue);
            api.logging().logToOutput("[DashboardReporter] OK: " + finding.getTitle()
                    + " [" + severity + "/" + confidence + "] @ " + baseUrl);

            // Bridge finding into the persistent Dashboard task box.
            // addDeferredFinding() queues it; addRequestResponse() pokes the
            // persistent Audit so Burp calls passiveAudit() which drains the queue.
            OmniStrikeScanCheck sc = this.scanCheck;
            Audit audit = this.persistentAudit;
            if (sc != null && audit != null) {
                sc.addDeferredFinding(finding);
                try {
                    audit.addRequestResponse(reqResp);
                } catch (Exception e) {
                    api.logging().logToOutput("[DashboardReporter] Dashboard bridge: " + e.getMessage());
                }
            }

        } catch (Throwable t) {
            // Catch Throwable (not just Exception) to also catch NoSuchMethodError, etc.
            api.logging().logToError("[DashboardReporter] FAILED: " + finding.getTitle()
                    + " | " + t.getClass().getName() + ": " + t.getMessage());
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
        return ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
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
        sb.append("<p><b>Severity:</b> ").append(f.getSeverity()).append(" | <b>Confidence:</b> ").append(f.getConfidence()).append("</p>");
        if (f.getUrl() != null && !f.getUrl().isEmpty()) {
            sb.append("<p><b>URL:</b> ").append(esc(f.getUrl())).append("</p>");
        }
        if (f.getParameter() != null && !f.getParameter().isEmpty()) {
            sb.append("<p><b>Parameter:</b> ").append(esc(f.getParameter())).append("</p>");
        }
        if (f.getDescription() != null && !f.getDescription().isEmpty()) {
            sb.append("<p><b>Description:</b><br>").append(esc(f.getDescription())).append("</p>");
        }
        if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
            sb.append("<p><b>Evidence:</b></p><pre>").append(esc(f.getEvidence())).append("</pre>");
        }
        if (f.getRemediation() != null && !f.getRemediation().isEmpty()) {
            sb.append("<p><b>Remediation:</b><br>").append(esc(f.getRemediation())).append("</p>");
        }
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}

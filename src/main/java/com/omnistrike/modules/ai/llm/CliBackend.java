package com.omnistrike.modules.ai.llm;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Executes LLM prompts via local CLI tools (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI).
 * Each call spawns a fresh process — no shared state, inherently thread-safe.
 *
 * SECURITY: The prompt is ALWAYS piped via stdin, never passed as a command-line argument.
 * Attacker-controlled HTTP response data embedded in prompts could contain shell metacharacters
 * (& | ; etc.) that cmd.exe /c would interpret, enabling remote code execution on the
 * pentester's machine. Stdin piping is immune to this because the data never passes through
 * the shell's command-line parser.
 */
public class CliBackend {

    private static final long TIMEOUT_SECONDS = 600;
    private static final Pattern ANSI_STRIP = Pattern.compile("\u001B\\[[;\\d]*[A-Za-z]");
    private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    /**
     * Sends a prompt to the specified CLI provider and returns the response text.
     *
     * @param provider CLI provider (CLI_CLAUDE, CLI_GEMINI, CLI_CODEX, CLI_OPENCODE)
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

        List<String> command = buildCommand(provider, binary);

        // On Windows, wrap with cmd.exe /c so .cmd/.bat wrappers (npm globals) are found.
        // Safe because command arguments never contain attacker-controlled content —
        // the prompt is always piped via stdin.
        if (IS_WINDOWS && !binary.contains("\\") && !binary.contains("/") && !binary.endsWith(".exe")) {
            command.add(0, "cmd.exe");
            command.add(1, "/c");
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            // Don't inherit env that might cause interactive prompts
            pb.environment().put("NO_COLOR", "1");
            pb.environment().put("TERM", "dumb");

            Process process = pb.start();

            // Always pipe the prompt via stdin — never pass as a CLI argument.
            try (OutputStream os = process.getOutputStream()) {
                os.write(prompt.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read stdout in a separate thread to avoid blocking
            StringBuilder output = new StringBuilder();
            Thread reader = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                } catch (IOException ignored) {}
            }, "OmniStrike-CLI-Reader");
            reader.setDaemon(true);
            reader.start();

            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new LlmException(LlmException.ErrorType.TIMEOUT,
                        provider.getDisplayName() + " timed out after " + TIMEOUT_SECONDS + "s");
            }

            // Wait for the reader thread to finish
            reader.join(5000);

            int exitCode = process.exitValue();
            String result = stripAnsi(output.toString().trim());

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
                // claude -p  (reads prompt from stdin)
                cmd.add("-p");
            }
            case CLI_GEMINI -> {
                // gemini --output-format text -p .  (reads prompt from stdin, -p . means stdin)
                cmd.add("--output-format");
                cmd.add("text");
                cmd.add("-p");
                cmd.add(".");
            }
            case CLI_CODEX -> {
                // codex exec --color never --skip-git-repo-check -  (reads prompt from stdin)
                cmd.add("exec");
                cmd.add("--color");
                cmd.add("never");
                cmd.add("--skip-git-repo-check");
                cmd.add("-");
            }
            case CLI_OPENCODE -> {
                // opencode run -  (reads prompt from stdin via - flag)
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

    private String stripAnsi(String text) {
        if (text == null) return "";
        return ANSI_STRIP.matcher(text).replaceAll("");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}

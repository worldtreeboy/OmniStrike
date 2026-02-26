package com.omnistrike.modules.ai.llm;

/**
 * Supported LLM providers for AI vulnerability analysis.
 * Each provider has a display name, default binary name, and default model.
 * All providers are CLI-based — invoke a local CLI tool via ProcessBuilder.
 */
public enum LlmProvider {

    // CLI providers — invoke a local CLI tool via ProcessBuilder
    CLI_CLAUDE("Claude CLI", "claude", "claude-cli"),
    CLI_GEMINI("Gemini CLI", "gemini", "gemini-cli"),
    CLI_CODEX("Codex CLI", "codex", "codex-cli"),
    CLI_OPENCODE("OpenCode CLI", "opencode", "opencode-cli");

    private final String displayName;
    private final String defaultBinary; // CLI binary name
    private final String defaultModel;

    LlmProvider(String displayName, String defaultBinary, String defaultModel) {
        this.displayName = displayName;
        this.defaultBinary = defaultBinary;
        this.defaultModel = defaultModel;
    }

    public String getDisplayName() { return displayName; }
    public String getDefaultModel() { return defaultModel; }

    /** Returns the default CLI binary name. */
    public String getCliCommand() { return defaultBinary; }

    /** All CLI providers now read the prompt from stdin to prevent command injection. */
    public boolean usesStdinForPrompt() {
        return true;
    }

    @Override
    public String toString() { return displayName; }
}

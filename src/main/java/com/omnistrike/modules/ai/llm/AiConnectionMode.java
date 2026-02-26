package com.omnistrike.modules.ai.llm;

/**
 * How the AI module connects to an LLM provider.
 * Only one mode can be active at a time (mutual exclusivity).
 */
public enum AiConnectionMode {

    NONE("Off"),              // AI disabled — default
    CLI("CLI Tool"),          // CLI-spawned providers (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI)
    API_KEY("API Key");       // Direct HTTP API with API key (Anthropic, OpenAI, Google Gemini)

    private final String displayName;

    AiConnectionMode(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() { return displayName; }

    @Override
    public String toString() { return displayName; }
}

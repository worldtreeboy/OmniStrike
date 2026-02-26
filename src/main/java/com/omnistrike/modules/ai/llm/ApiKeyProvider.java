package com.omnistrike.modules.ai.llm;

/**
 * Supported API key providers for direct HTTP API access.
 * Each provider has a display name, base URL, and list of available models.
 */
public enum ApiKeyProvider {

    ANTHROPIC("Anthropic (Claude)",
            "https://api.anthropic.com/v1/messages",
            new String[]{"claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"}),

    OPENAI("OpenAI",
            "https://api.openai.com/v1/chat/completions",
            new String[]{"gpt-5.2", "gpt-4o", "o3-mini"}),

    GEMINI("Google Gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            new String[]{"gemini-3.1-pro", "gemini-3-flash-preview", "gemini-2.5-flash"});

    private final String displayName;
    private final String baseUrl;
    private final String[] models;

    ApiKeyProvider(String displayName, String baseUrl, String[] models) {
        this.displayName = displayName;
        this.baseUrl = baseUrl;
        this.models = models;
    }

    public String getDisplayName() { return displayName; }
    public String getBaseUrl() { return baseUrl; }
    public String[] getModels() { return models; }

    /** Returns the first (default/most capable) model for this provider. */
    public String getDefaultModel() { return models[0]; }

    @Override
    public String toString() { return displayName; }
}

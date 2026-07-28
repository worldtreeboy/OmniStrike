package com.omnistrike.modules.ai.llm;

/**
 * Supported API key providers for direct HTTP API access.
 * Each provider has a display name, base URL, wire style, and list of suggested models.
 *
 * The model list is a convenience for the dropdown — the UI combo is editable, so any
 * newer model ID can be typed in directly. Model IDs change fast; check the provider's
 * docs if a default stops working.
 */
public enum ApiKeyProvider {

    ANTHROPIC("Anthropic (Claude)",
            "https://api.anthropic.com/v1/messages",
            Style.ANTHROPIC,
            new String[]{"claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"}),

    OPENAI("OpenAI",
            "https://api.openai.com/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"gpt-5.4", "gpt-5.2", "gpt-4o", "o3-mini"}),

    GEMINI("Google Gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            Style.GEMINI,
            new String[]{"gemini-3.1-pro", "gemini-3-flash-preview", "gemini-2.5-flash"}),

    XAI("xAI (Grok)",
            "https://api.x.ai/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"grok-4.5", "grok-4.3", "grok-build-0.1"}),

    MOONSHOT("Moonshot AI (Kimi)",
            "https://api.moonshot.ai/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"kimi-k2.6", "kimi-k2-0905-preview", "moonshot-v1-128k"}),

    DEEPSEEK("DeepSeek",
            "https://api.deepseek.com/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"deepseek-chat", "deepseek-reasoner"}),

    MISTRAL("Mistral AI",
            "https://api.mistral.ai/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"}),

    GROQ("Groq",
            "https://api.groq.com/openai/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"llama-3.3-70b-versatile", "openai/gpt-oss-120b", "qwen/qwen3-32b"}),

    OPENROUTER("OpenRouter",
            "https://openrouter.ai/api/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"anthropic/claude-opus-4.6", "openai/gpt-5.2", "moonshotai/kimi-k2", "x-ai/grok-4.5"}),

    OLLAMA("Ollama (Local)",
            "http://localhost:11434/v1/chat/completions",
            Style.OPENAI_COMPATIBLE,
            new String[]{"llama3.3", "qwen3", "mistral", "deepseek-r1"});

    /** Wire protocol the provider speaks. */
    public enum Style { ANTHROPIC, OPENAI_COMPATIBLE, GEMINI }

    private final String displayName;
    private final String baseUrl;
    private final Style style;
    private final String[] models;

    ApiKeyProvider(String displayName, String baseUrl, Style style, String[] models) {
        this.displayName = displayName;
        this.baseUrl = baseUrl;
        this.style = style;
        this.models = models;
    }

    public String getDisplayName() { return displayName; }
    public String getBaseUrl() { return baseUrl; }
    public Style getStyle() { return style; }
    public String[] getModels() { return models; }

    /** Returns the first (default/most capable) model for this provider. */
    public String getDefaultModel() { return models[0]; }

    /** True for providers that work without an API key (local inference). */
    public boolean allowsEmptyApiKey() { return this == OLLAMA; }

    @Override
    public String toString() { return displayName; }
}

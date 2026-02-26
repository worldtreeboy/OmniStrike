package com.omnistrike.modules.ai.llm;

import com.google.gson.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Unified client for calling LLM providers.
 * Supports two mutually exclusive backends:
 *   - CLI providers (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI)
 *   - API Key providers (Anthropic, OpenAI, Google Gemini via HTTP)
 *
 * Only one mode can be active at a time. The active connection mode determines
 * which backend is used when call() is invoked.
 *
 * All config fields are volatile — written from the EDT, read from the LLM background thread.
 */
public class LlmClient {

    private static final Gson GSON = new Gson();

    private final CliBackend cliBackend = new CliBackend();
    private final ApiKeyBackend apiKeyBackend = new ApiKeyBackend();

    // Logger callback — set by the extension to route to Montoya api.logging().logToError()
    private volatile java.util.function.Consumer<String> errorLogger;

    // Connection mode — determines which backend is used
    private volatile AiConnectionMode connectionMode = AiConnectionMode.NONE;

    // CLI config — written from EDT, read from LLM thread
    private volatile LlmProvider provider = LlmProvider.CLI_CLAUDE;
    private volatile String model = LlmProvider.CLI_CLAUDE.getDefaultModel();
    private volatile boolean configured = false;
    private volatile String cliBinaryPath = "";

    // API Key config — written from EDT, read from LLM thread
    private volatile ApiKeyProvider apiKeyProvider = ApiKeyProvider.ANTHROPIC;
    private volatile String apiKey = "";
    private volatile String apiKeyModel = ApiKeyProvider.ANTHROPIC.getDefaultModel();
    private volatile boolean apiKeyConfigured = false;

    public LlmClient() {
    }

    /** Sets the error logger (should route to api.logging().logToError()). */
    public void setErrorLogger(java.util.function.Consumer<String> logger) {
        this.errorLogger = logger;
    }

    private void logError(String message) {
        java.util.function.Consumer<String> logger = errorLogger;
        if (logger != null) {
            logger.accept(message);
        }
    }

    // ==================== Connection mode ====================

    public void setConnectionMode(AiConnectionMode mode) {
        this.connectionMode = mode;
    }

    public AiConnectionMode getConnectionMode() {
        return connectionMode;
    }

    // ==================== CLI configuration ====================

    /**
     * Updates the client configuration for CLI providers.
     */
    public void configureCli(LlmProvider provider, String binaryPath) {
        this.provider = provider;
        this.cliBinaryPath = binaryPath != null ? binaryPath : "";
        this.model = provider.getDefaultModel();
        this.configured = true;
    }

    // ==================== API Key configuration ====================

    /**
     * Updates the client configuration for API key providers.
     */
    public void configureApiKey(ApiKeyProvider provider, String apiKey, String model) {
        this.apiKeyProvider = provider;
        this.apiKey = apiKey != null ? apiKey : "";
        this.apiKeyModel = (model != null && !model.isBlank()) ? model : provider.getDefaultModel();
        this.apiKeyConfigured = true;
    }

    // ==================== Unified call / test ====================

    /**
     * Sends a prompt to the active backend and returns the raw text response.
     * Routes to CLI or API Key backend based on the current connection mode.
     */
    public String call(String prompt) throws LlmException {
        if (connectionMode == AiConnectionMode.API_KEY) {
            if (!apiKeyConfigured) {
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        "API key not configured — select a provider and enter your API key");
            }
            return apiKeyBackend.call(apiKeyProvider, apiKey, apiKeyModel, prompt);
        } else if (connectionMode == AiConnectionMode.CLI) {
            if (!configured) {
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        "CLI tool not configured — select a provider and set the binary path");
            }
            return cliBackend.call(provider, cliBinaryPath, prompt);
        }
        throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                "AI not configured — select CLI Tool or API Key mode");
    }

    /**
     * Tests connectivity to the active backend. Returns a status message.
     */
    public String testConnection() throws LlmException {
        if (connectionMode == AiConnectionMode.API_KEY) {
            if (!apiKeyConfigured) {
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        "API key not configured");
            }
            return apiKeyBackend.testConnection(apiKeyProvider, apiKey, apiKeyModel);
        } else if (connectionMode == AiConnectionMode.CLI) {
            return cliBackend.testConnection(provider, cliBinaryPath);
        }
        throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                "No connection mode selected");
    }

    // ==================== Response parsing ====================

    /**
     * Parses the LLM text response into structured findings.
     * Expects JSON with structure: {"findings": [{"title", "severity", ...}]}
     */
    public LlmAnalysisResult parseResponse(String rawText) {
        List<LlmAnalysisResult.LlmFinding> findings = new ArrayList<>();

        // Extract JSON block from the response (LLMs often wrap in markdown code fences)
        String json = extractJson(rawText);
        if (json == null) {
            return new LlmAnalysisResult(findings, rawText);
        }

        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.getAsJsonArray("findings");
            if (arr == null) return new LlmAnalysisResult(findings, rawText);

            for (JsonElement el : arr) {
                JsonObject obj = el.getAsJsonObject();
                findings.add(new LlmAnalysisResult.LlmFinding(
                        getStr(obj, "title"),
                        getStr(obj, "severity"),
                        getStr(obj, "description"),
                        getStr(obj, "evidence"),
                        getStr(obj, "poc"),
                        getStr(obj, "remediation"),
                        getStr(obj, "cwe")
                ));
            }
        } catch (Exception e) {
            // Log parse failure via Montoya logger — never use System.err
            logError("[LlmClient] Failed to parse AI findings JSON: " + e.getMessage()
                    + " | json snippet: " + (json != null ? json.substring(0, Math.min(json.length(), 300)) : "null"));
        }

        return new LlmAnalysisResult(findings, rawText);
    }

    private String extractJson(String text) {
        if (text == null) return null;
        // Try to find JSON in markdown code fences first.
        // Use "\n```" for the closing fence so we don't match backticks
        // inside JSON string values (e.g., evidence fields containing code snippets).
        int start = text.indexOf("```json");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) return text.substring(start, end).trim();
        }
        // Try generic code fence
        start = text.indexOf("```");
        if (start >= 0) {
            start = text.indexOf('\n', start) + 1;
            int end = text.indexOf("\n```", start);
            if (end > start) {
                String block = text.substring(start, end).trim();
                if (block.startsWith("{")) return block;
            }
        }
        // Try to find raw JSON object using brace matching
        start = text.indexOf('{');
        if (start >= 0) {
            int depth = 0;
            boolean inString = false;
            boolean escaped = false;
            for (int i = start; i < text.length(); i++) {
                char c = text.charAt(i);
                if (escaped) { escaped = false; continue; }
                if (c == '\\' && inString) { escaped = true; continue; }
                if (c == '"') { inString = !inString; continue; }
                if (inString) continue;
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return text.substring(start, i + 1);
                    }
                }
            }
        }
        return null;
    }

    private String getStr(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsString() : "";
    }

    // ==================== Getters ====================

    public LlmProvider getProvider() { return provider; }
    public String getModel() { return model; }

    /** Returns true if the active backend has been configured. */
    public boolean isConfigured() {
        if (connectionMode == AiConnectionMode.API_KEY) return apiKeyConfigured;
        if (connectionMode == AiConnectionMode.CLI) return configured;
        return false;
    }

    public String getCliBinaryPath() { return cliBinaryPath; }

    public ApiKeyProvider getApiKeyProvider() { return apiKeyProvider; }
    public String getApiKeyModel() { return apiKeyModel; }
}

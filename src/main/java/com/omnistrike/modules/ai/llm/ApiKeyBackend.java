package com.omnistrike.modules.ai.llm;

import com.google.gson.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * HTTP backend that calls LLM provider REST APIs directly using API keys.
 * Uses Java 17's built-in java.net.http.HttpClient — no external dependencies.
 *
 * Supports: Anthropic (Claude), OpenAI, Google Gemini.
 * Thread-safe — single shared HttpClient instance, no mutable state.
 */
public class ApiKeyBackend {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);
    private static final Gson GSON = new Gson();

    private final HttpClient httpClient;

    public ApiKeyBackend() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /**
     * Sends a prompt to the specified provider's API and returns the response text.
     *
     * @param provider the API provider (ANTHROPIC, OPENAI, GEMINI)
     * @param apiKey   the API key / secret
     * @param model    the model ID to use
     * @param prompt   the prompt text to send
     * @return the model's text response
     */
    public String call(ApiKeyProvider provider, String apiKey, String model, String prompt) throws LlmException {
        if (apiKey == null || apiKey.isBlank()) {
            throw new LlmException(LlmException.ErrorType.AUTH_FAILURE, "API key is empty");
        }

        try {
            String url = buildUrl(provider, model);
            String body = buildRequestBody(provider, model, prompt);
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));

            addAuthHeaders(reqBuilder, provider, apiKey);

            HttpResponse<String> response = httpClient.send(reqBuilder.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            int status = response.statusCode();
            if (status == 401 || status == 403) {
                throw new LlmException(LlmException.ErrorType.AUTH_FAILURE,
                        provider.getDisplayName() + " authentication failed (HTTP " + status + "): "
                                + truncate(response.body(), 200));
            }
            if (status == 429) {
                throw new LlmException(LlmException.ErrorType.RATE_LIMITED,
                        provider.getDisplayName() + " rate limited (HTTP 429): "
                                + truncate(response.body(), 200));
            }
            if (status < 200 || status >= 300) {
                throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                        provider.getDisplayName() + " returned HTTP " + status + ": "
                                + truncate(response.body(), 300));
            }

            return extractResponseText(provider, response.body());

        } catch (LlmException e) {
            throw e;
        } catch (java.net.http.HttpTimeoutException e) {
            throw new LlmException(LlmException.ErrorType.TIMEOUT,
                    provider.getDisplayName() + " request timed out after " + REQUEST_TIMEOUT.toSeconds() + "s", e);
        } catch (java.io.IOException e) {
            throw new LlmException(LlmException.ErrorType.CONNECTION_ERROR,
                    provider.getDisplayName() + " connection failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException(LlmException.ErrorType.TIMEOUT,
                    provider.getDisplayName() + " request interrupted", e);
        } catch (Exception e) {
            throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                    provider.getDisplayName() + " unexpected error: " + e.getMessage(), e);
        }
    }

    /**
     * Tests connectivity by sending a short test prompt.
     */
    public String testConnection(ApiKeyProvider provider, String apiKey, String model) throws LlmException {
        String response = call(provider, apiKey, model, "Respond with exactly: CONNECTION_OK");
        if (response.contains("CONNECTION_OK")) {
            return "Connected to " + provider.getDisplayName() + " API (" + model + ")";
        }
        return "Connected but unexpected response: " + truncate(response, 100);
    }

    // ==================== Request building ====================

    private String buildUrl(ApiKeyProvider provider, String model) {
        return switch (provider) {
            case ANTHROPIC -> provider.getBaseUrl();
            case OPENAI -> provider.getBaseUrl();
            case GEMINI -> provider.getBaseUrl() + "/models/" + model + ":generateContent";
        };
    }

    private void addAuthHeaders(HttpRequest.Builder builder, ApiKeyProvider provider, String apiKey) {
        switch (provider) {
            case ANTHROPIC -> {
                builder.header("x-api-key", apiKey);
                builder.header("anthropic-version", "2023-06-01");
            }
            case OPENAI -> builder.header("Authorization", "Bearer " + apiKey);
            case GEMINI -> builder.header("x-goog-api-key", apiKey);
        }
    }

    private String buildRequestBody(ApiKeyProvider provider, String model, String prompt) {
        JsonObject body = new JsonObject();

        switch (provider) {
            case ANTHROPIC -> {
                body.addProperty("model", model);
                body.addProperty("max_tokens", 8192);
                JsonArray messages = new JsonArray();
                JsonObject msg = new JsonObject();
                msg.addProperty("role", "user");
                msg.addProperty("content", prompt);
                messages.add(msg);
                body.add("messages", messages);
            }
            case OPENAI -> {
                body.addProperty("model", model);
                JsonArray messages = new JsonArray();
                JsonObject msg = new JsonObject();
                msg.addProperty("role", "user");
                msg.addProperty("content", prompt);
                messages.add(msg);
                body.add("messages", messages);
            }
            case GEMINI -> {
                JsonArray contents = new JsonArray();
                JsonObject content = new JsonObject();
                JsonArray parts = new JsonArray();
                JsonObject part = new JsonObject();
                part.addProperty("text", prompt);
                parts.add(part);
                content.add("parts", parts);
                contents.add(content);
                body.add("contents", contents);
            }
        }

        return GSON.toJson(body);
    }

    // ==================== Response parsing ====================

    private String extractResponseText(ApiKeyProvider provider, String responseBody) throws LlmException {
        try {
            JsonObject root = JsonParser.parseString(responseBody).getAsJsonObject();

            return switch (provider) {
                case ANTHROPIC -> {
                    // {"content": [{"type": "text", "text": "..."}]}
                    JsonArray content = root.getAsJsonArray("content");
                    if (content == null || content.isEmpty()) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "Anthropic response has no content array");
                    }
                    StringBuilder sb = new StringBuilder();
                    for (JsonElement el : content) {
                        JsonObject block = el.getAsJsonObject();
                        if ("text".equals(getStr(block, "type"))) {
                            sb.append(getStr(block, "text"));
                        }
                    }
                    yield sb.toString();
                }
                case OPENAI -> {
                    // {"choices": [{"message": {"content": "..."}}]}
                    JsonArray choices = root.getAsJsonArray("choices");
                    if (choices == null || choices.isEmpty()) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "OpenAI response has no choices array");
                    }
                    JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
                    if (message == null) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "OpenAI response has no message object");
                    }
                    yield getStr(message, "content");
                }
                case GEMINI -> {
                    // {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
                    JsonArray candidates = root.getAsJsonArray("candidates");
                    if (candidates == null || candidates.isEmpty()) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "Gemini response has no candidates array");
                    }
                    JsonObject content = candidates.get(0).getAsJsonObject().getAsJsonObject("content");
                    if (content == null) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "Gemini response has no content object");
                    }
                    JsonArray parts = content.getAsJsonArray("parts");
                    if (parts == null || parts.isEmpty()) {
                        throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                                "Gemini response has no parts array");
                    }
                    StringBuilder sb = new StringBuilder();
                    for (JsonElement el : parts) {
                        sb.append(getStr(el.getAsJsonObject(), "text"));
                    }
                    yield sb.toString();
                }
            };
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException(LlmException.ErrorType.PARSE_ERROR,
                    "Failed to parse " + provider.getDisplayName() + " response: " + e.getMessage()
                            + " | body snippet: " + truncate(responseBody, 200), e);
        }
    }

    private String getStr(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el != null && !el.isJsonNull()) ? el.getAsString() : "";
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}

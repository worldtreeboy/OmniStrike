package com.omnistrike.framework;

import burp.api.montoya.collaborator.InteractionType;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Minimal Java client for ProjectDiscovery Interactsh's register/poll protocol.
 *
 * <p>The Interactsh server encrypts interaction records with AES-CTR and encrypts
 * that AES key with the RSA public key supplied during registration. This client
 * keeps the private key and session secret in memory only.</p>
 */
final class InteractshClient implements AutoCloseable {

    static final int CORRELATION_ID_LENGTH = 20;
    static final int NONCE_LENGTH = 13;
    private static final int MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
    private static final String NONCE_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

    private final HttpClient httpClient;
    private final URI serverUri;
    private final String payloadAuthority;
    private final String correlationId;
    private final String secretKey;
    private final KeyPair keyPair;
    private final SecureRandom random = new SecureRandom();
    private final BiConsumer<String, CustomOobInteraction> interactionHandler;
    private final Consumer<String> logger;

    private volatile String token;
    private volatile boolean connected;
    private volatile ScheduledExecutorService poller;

    InteractshClient(String server, String token,
                     BiConsumer<String, CustomOobInteraction> interactionHandler,
                     Consumer<String> logger) throws Exception {
        this(server, token, interactionHandler, logger,
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build());
    }

    InteractshClient(String server, String token,
                     BiConsumer<String, CustomOobInteraction> interactionHandler,
                     Consumer<String> logger, HttpClient httpClient) throws Exception {
        this.serverUri = normalizeServerUri(server);
        this.payloadAuthority = payloadAuthority(serverUri);
        this.token = token != null ? token.trim() : "";
        this.interactionHandler = interactionHandler;
        this.logger = logger != null ? logger : ignored -> { };
        this.httpClient = httpClient;
        this.correlationId = randomToken(CORRELATION_ID_LENGTH,
                "0123456789abcdefghijklmnopqrstuv");
        this.secretKey = UUID.randomUUID().toString();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        this.keyPair = generator.generateKeyPair();
    }

    void connect() throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("public-key", encodePublicKey());
        body.addProperty("secret-key", secretKey);
        body.addProperty("correlation-id", correlationId);

        HttpResponse<String> response = send("POST", "/register", body.toString());
        if (response.statusCode() != 200) {
            throw new IOException("Interactsh registration failed (HTTP " + response.statusCode()
                    + "): " + summarize(response.body()));
        }

        JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
        String message = json.has("message") ? json.get("message").getAsString() : "";
        if (!"registration successful".equalsIgnoreCase(message)) {
            throw new IOException("Interactsh registration failed: " + summarize(response.body()));
        }

        connected = true;
        try {
            // Verify that this is a compatible Interactsh poll endpoint before the UI
            // reports the backend as ready. An empty poll response is a valid success.
            pollNow();
            startPolling();
        } catch (Exception e) {
            connected = false;
            throw e;
        }
    }

    boolean isConnected() {
        return connected;
    }

    String getServerAddress() {
        return payloadAuthority;
    }

    String generatePayloadId() {
        if (!connected) return null;
        return correlationId + randomToken(NONCE_LENGTH, NONCE_ALPHABET);
    }

    String generatePayload() {
        String id = generatePayloadId();
        return id != null ? id + "." + payloadAuthority : null;
    }

    private void startPolling() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "OmniStrike-InteractshPoller");
            thread.setDaemon(true);
            return thread;
        });
        poller = executor;
        executor.scheduleWithFixedDelay(() -> {
            try {
                pollNow();
            } catch (Exception e) {
                logger.accept("Interactsh poll error: " + e.getMessage());
            }
        }, 5, 5, TimeUnit.SECONDS);
    }

    void pollNow() throws Exception {
        if (!connected) return;
        String query = "/poll?id=" + urlEncode(correlationId) + "&secret=" + urlEncode(secretKey);
        HttpResponse<String> response = send("GET", query, null);
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode() + ": " + summarize(response.body()));
        }

        JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
        JsonArray encrypted = array(json, "data");
        String encryptedAesKey = string(json, "aes_key");

        if (!encrypted.isEmpty()) {
            if (encryptedAesKey.isBlank()) {
                throw new IOException("Interactsh poll response omitted aes_key");
            }
            byte[] aesKey = decryptAesKey(encryptedAesKey);
            for (JsonElement item : encrypted) {
                try {
                    handleInteractionJson(decryptInteraction(aesKey, item.getAsString()));
                } catch (Exception e) {
                    logger.accept("Interactsh interaction decrypt/parse error: " + e.getMessage());
                }
            }
            Arrays.fill(aesKey, (byte) 0);
        }

        handlePlaintextInteractions(array(json, "extra"));
        handlePlaintextInteractions(array(json, "tlddata"));
    }

    private void handlePlaintextInteractions(JsonArray interactions) {
        for (JsonElement item : interactions) {
            try {
                handleInteractionJson(item.getAsString());
            } catch (Exception e) {
                logger.accept("Interactsh interaction parse error: " + e.getMessage());
            }
        }
    }

    private void handleInteractionJson(String rawJson) throws Exception {
        JsonObject interaction = JsonParser.parseString(rawJson.trim()).getAsJsonObject();
        String uniqueId = string(interaction, "unique-id").toLowerCase(Locale.ROOT);
        if (uniqueId.length() < CORRELATION_ID_LENGTH || !uniqueId.startsWith(correlationId)) {
            logger.accept("Ignored Interactsh interaction with an unexpected correlation ID");
            return;
        }

        String protocol = string(interaction, "protocol").toUpperCase(Locale.ROOT);
        InteractionType type = mapType(protocol);
        RemoteEndpoint remote = parseRemoteEndpoint(string(interaction, "remote-address"));
        ZonedDateTime timestamp = parseTimestamp(string(interaction, "timestamp"));
        String rawRequest = string(interaction, "raw-request");

        CustomOobInteraction wrapped = new CustomOobInteraction(
                uniqueId, remote.address, remote.port, rawRequest, type, protocol, timestamp);
        interactionHandler.accept(uniqueId, wrapped);
    }

    private byte[] decryptAesKey(String encryptedAesKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);
        return rsa.doFinal(Base64.getDecoder().decode(encryptedAesKey));
    }

    private static String decryptInteraction(byte[] aesKey, String encryptedMessage) throws Exception {
        byte[] ciphertext = Base64.getDecoder().decode(encryptedMessage);
        if (ciphertext.length < 16) throw new IOException("ciphertext is shorter than the AES IV");

        byte[] iv = Arrays.copyOfRange(ciphertext, 0, 16);
        byte[] data = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        String plaintext = new String(aes.doFinal(data), StandardCharsets.UTF_8);
        return plaintext.replaceFirst("[\\s]+$", "");
    }

    private String encodePublicKey() {
        String base64Der = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(keyPair.getPublic().getEncoded());
        String pem = "-----BEGIN RSA PUBLIC KEY-----\n" + base64Der
                + "\n-----END RSA PUBLIC KEY-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));
    }

    private HttpResponse<String> send(String method, String endpoint, String jsonBody) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpointUri(endpoint))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .header("User-Agent", "OmniStrike-Interactsh/1");
        if (!token.isBlank()) builder.header("Authorization", token);
        if (jsonBody != null) {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<InputStream> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        byte[] bytes;
        try (InputStream input = response.body()) {
            bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
        }
        if (bytes.length > MAX_RESPONSE_BYTES) {
            throw new IOException("Interactsh response exceeded " + MAX_RESPONSE_BYTES + " bytes");
        }
        String body = new String(bytes, StandardCharsets.UTF_8);
        return new StringHttpResponse(response, body);
    }

    private URI endpointUri(String endpoint) {
        String base = serverUri.toString();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return URI.create(base + endpoint);
    }

    @Override
    public void close() {
        connected = false;
        ScheduledExecutorService executor = poller;
        poller = null;
        if (executor != null) executor.shutdownNow();

        try {
            JsonObject body = new JsonObject();
            body.addProperty("correlation-id", correlationId);
            body.addProperty("secret-key", secretKey);
            send("POST", "/deregister", body.toString());
        } catch (Exception ignored) {
            // Best effort only: unload/mode switching must not fail because the OAST server is down.
        } finally {
            token = "";
        }
    }

    private static URI normalizeServerUri(String server) {
        if (server == null || server.isBlank()) {
            throw new IllegalArgumentException("Interactsh server is required");
        }
        String value = server.trim();
        if (value.matches("(?i)^[a-z][a-z0-9+.-]*://.*")
                && !value.matches("(?i)^https?://.*")) {
            throw new IllegalArgumentException("Interactsh server must be an HTTP(S) URL with a valid host");
        }
        if (!value.matches("(?i)^https?://.*")) value = "https://" + value;
        URI uri = URI.create(value);
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        if (!(scheme.equals("https") || scheme.equals("http")) || uri.getHost() == null) {
            throw new IllegalArgumentException("Interactsh server must be an HTTP(S) URL with a valid host");
        }
        if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Interactsh server URL cannot contain credentials, a query, or a fragment");
        }
        return uri;
    }

    private static String payloadAuthority(URI uri) {
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        boolean defaultPort = port < 0 || ("https".equalsIgnoreCase(uri.getScheme()) && port == 443)
                || ("http".equalsIgnoreCase(uri.getScheme()) && port == 80);
        return defaultPort ? host : host + ":" + port;
    }

    private String randomToken(int length, String alphabet) {
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return result.toString();
    }

    private static JsonArray array(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && value.isJsonArray() ? value.getAsJsonArray() : new JsonArray();
    }

    private static String string(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && !value.isJsonNull() ? value.getAsString() : "";
    }

    private static InteractionType mapType(String protocol) {
        if (protocol.startsWith("DNS")) return InteractionType.DNS;
        if (protocol.startsWith("SMTP")) return InteractionType.SMTP;
        return InteractionType.HTTP; // HTTP(S), LDAP and other protocols use the generic HTTP bucket.
    }

    private static ZonedDateTime parseTimestamp(String value) {
        try {
            return ZonedDateTime.parse(value);
        } catch (Exception ignored) {
            return ZonedDateTime.now();
        }
    }

    private static RemoteEndpoint parseRemoteEndpoint(String value) {
        String host = value != null ? value.trim() : "";
        int port = 0;
        if (host.startsWith("[") && host.contains("]")) {
            int end = host.indexOf(']');
            port = parsePort(host.substring(end + 1));
            host = host.substring(1, end);
        } else {
            int firstColon = host.indexOf(':');
            int lastColon = host.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                port = parsePort(host.substring(lastColon));
                host = host.substring(0, lastColon);
            }
        }

        try {
            // Interactsh emits an IP literal. Refuse hostnames so a malicious configured
            // server cannot make OmniStrike perform another DNS lookup while parsing data.
            if (!(host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}") || host.contains(":"))) {
                throw new IOException("remote address is not an IP literal");
            }
            return new RemoteEndpoint(InetAddress.getByName(host), port);
        } catch (Exception ignored) {
            return new RemoteEndpoint(InetAddress.getLoopbackAddress(), port);
        }
    }

    private static int parsePort(String suffix) {
        if (suffix == null || !suffix.startsWith(":")) return 0;
        try {
            int port = Integer.parseInt(suffix.substring(1));
            return port >= 0 && port <= 65535 ? port : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String summarize(String value) {
        if (value == null) return "";
        String compact = value.replaceAll("[\\r\\n]+", " ").trim();
        return compact.length() <= 300 ? compact : compact.substring(0, 300) + "...";
    }

    private record RemoteEndpoint(InetAddress address, int port) { }

    /** Adapts the bounded response body while preserving the original metadata. */
    private record StringHttpResponse(HttpResponse<InputStream> delegate, String body)
            implements HttpResponse<String> {
        @Override public int statusCode() { return delegate.statusCode(); }
        @Override public HttpRequest request() { return delegate.request(); }
        @Override public java.util.Optional<HttpResponse<String>> previousResponse() { return java.util.Optional.empty(); }
        @Override public java.net.http.HttpHeaders headers() { return delegate.headers(); }
        @Override public java.util.Optional<javax.net.ssl.SSLSession> sslSession() { return delegate.sslSession(); }
        @Override public URI uri() { return delegate.uri(); }
        @Override public HttpClient.Version version() { return delegate.version(); }
    }
}

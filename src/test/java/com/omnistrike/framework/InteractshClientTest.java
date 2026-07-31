package com.omnistrike.framework;

import burp.api.montoya.collaborator.InteractionType;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class InteractshClientTest {

    private HttpServer server;
    private InteractshClient client;

    @AfterEach
    void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
    }

    @Test
    void registersDecryptsPollResponseAndCorrelatesInteraction() throws Exception {
        AtomicReference<PublicKey> registeredKey = new AtomicReference<>();
        AtomicReference<String> correlationId = new AtomicReference<>();
        AtomicReference<String> secretKey = new AtomicReference<>();
        AtomicReference<String> pollResponse = new AtomicReference<>(emptyPoll());
        AtomicReference<String> authorization = new AtomicReference<>();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/register", exchange -> {
            JsonObject request = readJson(exchange);
            try {
                registeredKey.set(decodePublicKey(request.get("public-key").getAsString()));
            } catch (Exception e) {
                throw new java.io.IOException("Unable to decode registered key", e);
            }
            correlationId.set(request.get("correlation-id").getAsString());
            secretKey.set(request.get("secret-key").getAsString());
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            reply(exchange, 200, "{\"message\":\"registration successful\"}");
        });
        server.createContext("/poll", exchange -> reply(exchange, 200, pollResponse.get()));
        server.createContext("/deregister", exchange -> reply(exchange, 200,
                "{\"message\":\"deregistration successful\"}"));
        server.start();

        AtomicReference<String> receivedId = new AtomicReference<>();
        AtomicReference<CustomOobInteraction> received = new AtomicReference<>();
        client = new InteractshClient(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "test-token",
                (id, interaction) -> {
                    receivedId.set(id);
                    received.set(interaction);
                },
                message -> fail("Unexpected client log: " + message));

        client.connect();
        assertTrue(client.isConnected());
        assertEquals("test-token", authorization.get());
        assertEquals(InteractshClient.CORRELATION_ID_LENGTH, correlationId.get().length());
        assertNotNull(secretKey.get());

        String payloadId = client.generatePayloadId();
        assertNotNull(payloadId);
        assertEquals(InteractshClient.CORRELATION_ID_LENGTH + InteractshClient.NONCE_LENGTH,
                payloadId.length());
        assertTrue(payloadId.startsWith(correlationId.get()));

        JsonObject interaction = new JsonObject();
        interaction.addProperty("protocol", "http");
        interaction.addProperty("unique-id", payloadId);
        interaction.addProperty("full-id", payloadId + ".example.test");
        interaction.addProperty("remote-address", "203.0.113.10:54321");
        interaction.addProperty("timestamp", "2026-08-01T10:15:30Z");
        interaction.addProperty("raw-request", "GET /proof HTTP/1.1\r\nHost: example.test\r\n\r\n");
        pollResponse.set(encryptedPoll(registeredKey.get(), interaction.toString()));

        client.pollNow();

        assertEquals(payloadId, receivedId.get());
        assertNotNull(received.get());
        assertEquals(InteractionType.HTTP, received.get().type());
        assertEquals("HTTP", received.get().getProtocol());
        assertEquals("203.0.113.10", received.get().clientIp().getHostAddress());
        assertEquals(54321, received.get().clientPort());
        assertEquals(ZonedDateTime.parse("2026-08-01T10:15:30Z"), received.get().timeStamp());
        assertTrue(received.get().customData().orElseThrow().contains("GET /proof"));
    }

    @Test
    void rejectsNonHttpServerSchemes() {
        Exception error = assertThrows(Exception.class, () -> new InteractshClient(
                "file:///tmp/oast", "", (id, interaction) -> { }, message -> { }));
        assertTrue(error.getMessage().contains("HTTP(S)"));
    }

    private static String encryptedPoll(PublicKey publicKey, String interactionJson) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey aesKey = generator.generateKey();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String encryptedKey = Base64.getEncoder().encodeToString(rsa.doFinal(aesKey.getEncoded()));

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] ciphertext = aes.doFinal(interactionJson.getBytes(StandardCharsets.UTF_8));
        byte[] message = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, message, 0, iv.length);
        System.arraycopy(ciphertext, 0, message, iv.length, ciphertext.length);

        JsonObject response = new JsonObject();
        com.google.gson.JsonArray data = new com.google.gson.JsonArray();
        data.add(Base64.getEncoder().encodeToString(message));
        response.add("data", data);
        response.add("extra", new com.google.gson.JsonArray());
        response.addProperty("aes_key", encryptedKey);
        return response.toString();
    }

    private static String emptyPoll() {
        return "{\"data\":[],\"extra\":[],\"aes_key\":\"\"}";
    }

    private static PublicKey decodePublicKey(String outerBase64) throws Exception {
        String pem = new String(Base64.getDecoder().decode(outerBase64), StandardCharsets.US_ASCII);
        String base64Der = pem
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64Der);
        return java.security.KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static JsonObject readJson(HttpExchange exchange) throws java.io.IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        return JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject();
    }

    private static void reply(HttpExchange exchange, int status, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}

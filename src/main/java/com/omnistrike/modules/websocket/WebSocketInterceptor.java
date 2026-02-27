package com.omnistrike.modules.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;
import com.omnistrike.model.WebSocketConnection;
import com.omnistrike.model.WebSocketMessage;

import java.util.function.Consumer;

/**
 * Montoya proxy WebSocket creation handler.
 * Intercepts all WebSocket connections and their messages, feeding them to the
 * connection tracker for UI display and the analyzer for passive analysis.
 */
public class WebSocketInterceptor implements ProxyWebSocketCreationHandler {

    private final MontoyaApi api;
    private final WebSocketConnectionTracker tracker;
    private final WebSocketAnalyzer analyzer;
    private volatile boolean enabled = true;
    private Consumer<String> logger;

    public WebSocketInterceptor(MontoyaApi api, WebSocketConnectionTracker tracker, WebSocketAnalyzer analyzer) {
        this.api = api;
        this.tracker = tracker;
        this.analyzer = analyzer;
    }

    public void setLogger(Consumer<String> logger) {
        this.logger = logger;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        if (!enabled) return;

        try {
            var upgradeRequest = webSocketCreation.upgradeRequest();

            // Build the upgrade URL from the request
            String upgradeUrl = buildUpgradeUrl(upgradeRequest);

            // Create and register the connection
            WebSocketConnection connection = new WebSocketConnection(upgradeUrl, upgradeRequest);
            tracker.addConnection(connection);

            log("WebSocket connection opened: " + upgradeUrl);

            // Run passive connection-level analysis
            analyzer.analyzeConnection(connection);

            // Register a message handler for this specific WebSocket
            webSocketCreation.proxyWebSocket().registerProxyMessageHandler(
                    new ConnectionMessageHandler(connection));

        } catch (Exception e) {
            logError("Error handling WebSocket creation: " + e.getMessage());
        }
    }

    /**
     * Per-connection message handler. Captures all frames and passes them to
     * the tracker and analyzer.
     */
    private class ConnectionMessageHandler implements ProxyMessageHandler {

        private final WebSocketConnection connection;

        ConnectionMessageHandler(WebSocketConnection connection) {
            this.connection = connection;
        }

        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
            if (!enabled) {
                return TextMessageReceivedAction.continueWith(interceptedTextMessage.payload());
            }
            try {
                Direction dir = interceptedTextMessage.direction();
                WebSocketMessage.Direction msgDir = dir == Direction.CLIENT_TO_SERVER
                        ? WebSocketMessage.Direction.CLIENT_TO_SERVER
                        : WebSocketMessage.Direction.SERVER_TO_CLIENT;

                WebSocketMessage msg = new WebSocketMessage(
                        connection.getId(), msgDir, interceptedTextMessage.payload());

                tracker.addMessage(connection.getId(), msg);

                // Passive analysis on every text frame
                analyzer.analyzeMessage(msg, connection);

            } catch (Exception e) {
                logError("Error handling text message: " + e.getMessage());
            }
            // Never modify — pass through unchanged
            return TextMessageReceivedAction.continueWith(interceptedTextMessage.payload());
        }

        @Override
        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
            if (!enabled) {
                return TextMessageToBeSentAction.continueWith(interceptedTextMessage.payload());
            }
            try {
                Direction dir = interceptedTextMessage.direction();
                WebSocketMessage.Direction msgDir = dir == Direction.CLIENT_TO_SERVER
                        ? WebSocketMessage.Direction.CLIENT_TO_SERVER
                        : WebSocketMessage.Direction.SERVER_TO_CLIENT;

                WebSocketMessage msg = new WebSocketMessage(
                        connection.getId(), msgDir, interceptedTextMessage.payload());

                tracker.addMessage(connection.getId(), msg);

                // Passive analysis on outgoing text frames too
                analyzer.analyzeMessage(msg, connection);

            } catch (Exception e) {
                logError("Error handling text message to be sent: " + e.getMessage());
            }
            // Never modify — pass through unchanged
            return TextMessageToBeSentAction.continueWith(interceptedTextMessage.payload());
        }

        @Override
        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
            if (!enabled) {
                return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage.payload());
            }
            try {
                Direction dir = interceptedBinaryMessage.direction();
                WebSocketMessage.Direction msgDir = dir == Direction.CLIENT_TO_SERVER
                        ? WebSocketMessage.Direction.CLIENT_TO_SERVER
                        : WebSocketMessage.Direction.SERVER_TO_CLIENT;

                byte[] bytes = interceptedBinaryMessage.payload().getBytes();
                WebSocketMessage msg = new WebSocketMessage(connection.getId(), msgDir, bytes);

                tracker.addMessage(connection.getId(), msg);

            } catch (Exception e) {
                logError("Error handling binary message: " + e.getMessage());
            }
            return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage.payload());
        }

        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
            if (!enabled) {
                return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage.payload());
            }
            try {
                Direction dir = interceptedBinaryMessage.direction();
                WebSocketMessage.Direction msgDir = dir == Direction.CLIENT_TO_SERVER
                        ? WebSocketMessage.Direction.CLIENT_TO_SERVER
                        : WebSocketMessage.Direction.SERVER_TO_CLIENT;

                byte[] bytes = interceptedBinaryMessage.payload().getBytes();
                WebSocketMessage msg = new WebSocketMessage(connection.getId(), msgDir, bytes);

                tracker.addMessage(connection.getId(), msg);

            } catch (Exception e) {
                logError("Error handling binary message to be sent: " + e.getMessage());
            }
            return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage.payload());
        }

        @Override
        public void onClose() {
            tracker.setConnectionClosed(connection.getId());
            log("WebSocket connection closed: " + connection.getUpgradeUrl());
        }
    }

    /**
     * Builds the full WebSocket upgrade URL from the HTTP request.
     */
    private String buildUpgradeUrl(burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            String url = request.url();
            if (url != null) {
                // Convert http(s):// to ws(s)://
                if (url.startsWith("https://")) {
                    return "wss://" + url.substring(8);
                } else if (url.startsWith("http://")) {
                    return "ws://" + url.substring(7);
                }
                return url;
            }
        } catch (Exception e) {
            // Fallback
        }
        return "ws://unknown";
    }

    private void log(String message) {
        Consumer<String> l = logger;
        if (l != null) {
            l.accept(message);
        }
        try {
            api.logging().logToOutput("[WS-Scanner] " + message);
        } catch (Exception ignored) {}
    }

    private void logError(String message) {
        try {
            api.logging().logToError("[WS-Scanner] " + message);
        } catch (Exception ignored) {}
    }
}

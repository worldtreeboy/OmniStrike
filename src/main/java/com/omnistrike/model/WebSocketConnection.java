package com.omnistrike.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Tracks a single WebSocket connection lifecycle: upgrade request, messages, and close.
 */
public class WebSocketConnection {

    private final String id;
    private final String upgradeUrl;
    private final HttpRequest upgradeRequest;
    private final CopyOnWriteArrayList<WebSocketMessage> messages = new CopyOnWriteArrayList<>();
    private final long createdAt;
    private volatile long closedAt;
    private volatile boolean isOpen;
    private final String originHeader;
    private final boolean cookiesPresent;
    private final List<String> protocols;

    public WebSocketConnection(String upgradeUrl, HttpRequest upgradeRequest) {
        this.id = UUID.randomUUID().toString();
        this.upgradeUrl = upgradeUrl;
        this.upgradeRequest = upgradeRequest;
        this.createdAt = System.currentTimeMillis();
        this.isOpen = true;
        this.closedAt = 0;

        // Extract metadata from upgrade request
        String origin = null;
        boolean hasCookies = false;
        List<String> protos = new ArrayList<>();

        if (upgradeRequest != null) {
            for (var header : upgradeRequest.headers()) {
                String name = header.name().toLowerCase();
                if ("origin".equals(name)) {
                    origin = header.value();
                } else if ("cookie".equals(name)) {
                    hasCookies = true;
                } else if ("sec-websocket-protocol".equals(name)) {
                    for (String p : header.value().split(",")) {
                        protos.add(p.trim());
                    }
                }
            }
        }

        this.originHeader = origin;
        this.cookiesPresent = hasCookies;
        this.protocols = List.copyOf(protos);
    }

    public String getId() { return id; }
    public String getUpgradeUrl() { return upgradeUrl; }
    public HttpRequest getUpgradeRequest() { return upgradeRequest; }
    public List<WebSocketMessage> getMessages() { return messages; }
    public long getCreatedAt() { return createdAt; }
    public long getClosedAt() { return closedAt; }
    public boolean isOpen() { return isOpen; }
    public String getOriginHeader() { return originHeader; }
    public boolean isCookiesPresent() { return cookiesPresent; }
    public List<String> getProtocols() { return protocols; }

    public void addMessage(WebSocketMessage message) {
        messages.add(message);
    }

    public void setClosed() {
        this.isOpen = false;
        this.closedAt = System.currentTimeMillis();
    }

    public int getMessageCount() {
        return messages.size();
    }

    /**
     * Returns a display label for the connection selector dropdown.
     */
    public String getDisplayLabel() {
        String status = isOpen ? "OPEN" : "CLOSED";
        String url = upgradeUrl != null ? upgradeUrl : "unknown";
        if (url.length() > 60) {
            url = url.substring(0, 60) + "...";
        }
        return "[" + status + "] " + url + " (" + messages.size() + " msgs)";
    }
}

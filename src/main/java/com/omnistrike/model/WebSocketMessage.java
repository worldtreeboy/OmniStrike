package com.omnistrike.model;

import java.util.UUID;

/**
 * Represents a single WebSocket frame (text or binary).
 */
public class WebSocketMessage {

    public enum Direction {
        CLIENT_TO_SERVER,
        SERVER_TO_CLIENT
    }

    private final String id;
    private final String connectionId;
    private final Direction direction;
    private final String payload;
    private final byte[] binary;
    private final long timestamp;
    private final boolean isText;

    public WebSocketMessage(String connectionId, Direction direction, String payload) {
        this.id = UUID.randomUUID().toString();
        this.connectionId = connectionId;
        this.direction = direction;
        this.payload = payload;
        this.binary = null;
        this.timestamp = System.currentTimeMillis();
        this.isText = true;
    }

    public WebSocketMessage(String connectionId, Direction direction, byte[] binary) {
        this.id = UUID.randomUUID().toString();
        this.connectionId = connectionId;
        this.direction = direction;
        this.payload = null;
        this.binary = binary != null ? binary.clone() : null;
        this.timestamp = System.currentTimeMillis();
        this.isText = false;
    }

    public String getId() { return id; }
    public String getConnectionId() { return connectionId; }
    public Direction getDirection() { return direction; }
    public String getPayload() { return payload; }
    public byte[] getBinary() { return binary != null ? binary.clone() : null; }
    public long getTimestamp() { return timestamp; }
    public boolean isText() { return isText; }

    /**
     * Returns a short preview of the payload for display in tables.
     */
    public String getPreview() {
        if (isText && payload != null) {
            return payload.length() > 120 ? payload.substring(0, 120) + "..." : payload;
        }
        if (binary != null) {
            return "[Binary: " + binary.length + " bytes]";
        }
        return "[empty]";
    }
}

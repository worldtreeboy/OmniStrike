package com.omnistrike.modules.websocket;

import com.omnistrike.model.WebSocketConnection;
import com.omnistrike.model.WebSocketMessage;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Thread-safe registry of all tracked WebSocket connections.
 * Retains up to MAX_CONNECTIONS entries, evicting oldest closed connections first.
 */
public class WebSocketConnectionTracker {

    private static final int MAX_CONNECTIONS = 100;

    private final ConcurrentHashMap<String, WebSocketConnection> connections = new ConcurrentHashMap<>();
    // Insertion-order tracking for LRU eviction
    private final CopyOnWriteArrayList<String> insertionOrder = new CopyOnWriteArrayList<>();

    // Listeners for UI updates
    private final CopyOnWriteArrayList<Consumer<WebSocketConnection>> connectionListeners = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<WebSocketMessage>> messageListeners = new CopyOnWriteArrayList<>();

    public void addConnection(WebSocketConnection connection) {
        evictIfNeeded();
        connections.put(connection.getId(), connection);
        insertionOrder.add(connection.getId());
        for (Consumer<WebSocketConnection> listener : connectionListeners) {
            try {
                listener.accept(connection);
            } catch (Exception ignored) {}
        }
    }

    public void addMessage(String connectionId, WebSocketMessage message) {
        WebSocketConnection conn = connections.get(connectionId);
        if (conn != null) {
            conn.addMessage(message);
            for (Consumer<WebSocketMessage> listener : messageListeners) {
                try {
                    listener.accept(message);
                } catch (Exception ignored) {}
            }
        }
    }

    public void setConnectionClosed(String connectionId) {
        WebSocketConnection conn = connections.get(connectionId);
        if (conn != null) {
            conn.setClosed();
        }
    }

    public WebSocketConnection getConnection(String id) {
        return connections.get(id);
    }

    public List<WebSocketConnection> getAllConnections() {
        // Return in insertion order
        List<WebSocketConnection> result = new ArrayList<>();
        for (String id : insertionOrder) {
            WebSocketConnection conn = connections.get(id);
            if (conn != null) {
                result.add(conn);
            }
        }
        return result;
    }

    public List<WebSocketConnection> getOpenConnections() {
        return getAllConnections().stream()
                .filter(WebSocketConnection::isOpen)
                .collect(Collectors.toList());
    }

    public int getConnectionCount() {
        return connections.size();
    }

    public void addConnectionListener(Consumer<WebSocketConnection> listener) {
        connectionListeners.add(listener);
    }

    public void addMessageListener(Consumer<WebSocketMessage> listener) {
        messageListeners.add(listener);
    }

    public void clear() {
        connections.clear();
        insertionOrder.clear();
    }

    /**
     * Evicts oldest closed connections when at capacity.
     * If no closed connections exist, evicts the oldest connection regardless.
     */
    private void evictIfNeeded() {
        while (connections.size() >= MAX_CONNECTIONS) {
            String evicted = null;
            // Prefer evicting closed connections first
            for (String id : insertionOrder) {
                WebSocketConnection conn = connections.get(id);
                if (conn != null && !conn.isOpen()) {
                    evicted = id;
                    break;
                }
            }
            // If no closed connections, evict the oldest
            if (evicted == null && !insertionOrder.isEmpty()) {
                evicted = insertionOrder.get(0);
            }
            if (evicted != null) {
                connections.remove(evicted);
                insertionOrder.remove(evicted);
            } else {
                break;
            }
        }
    }
}

package com.omnistrike.framework;

import burp.api.montoya.collaborator.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.ZonedDateTime;
import java.util.Optional;

/**
 * Custom implementation of Burp's {@link Interaction} interface for the self-hosted OOB listener.
 * Allows all 15+ scanner modules to receive OOB callbacks via {@code Consumer<Interaction>}
 * without any code changes — they already use this interface contract.
 */
public class CustomOobInteraction implements Interaction {

    private final InteractionId interactionId;
    private final InetAddress clientAddress;
    private final int clientPortNum;
    private final ZonedDateTime timestamp;
    private final String rawRequest;
    private final InteractionType interactionType;
    /** Human-readable protocol label for UI log: "HTTP", "DNS", "LDAP", etc. */
    private final String protocol;

    public CustomOobInteraction(String payloadId, InetAddress clientAddress, int clientPort,
                                String rawRequest, InteractionType type, String protocol) {
        this.interactionId  = new CustomInteractionId(payloadId);
        this.clientAddress  = clientAddress;
        this.clientPortNum  = clientPort;
        this.timestamp      = ZonedDateTime.now();
        this.rawRequest     = rawRequest;
        this.interactionType = type;
        this.protocol       = protocol;
    }

    public CustomOobInteraction(String payloadId, InetAddress clientAddress, int clientPort,
                                String rawRequest, InteractionType type) {
        this(payloadId, clientAddress, clientPort, rawRequest, type, type.name());
    }

    /** Backward-compatible constructor — defaults to HTTP. */
    public CustomOobInteraction(String payloadId, InetAddress clientAddress, int clientPort, String rawRequest) {
        this(payloadId, clientAddress, clientPort, rawRequest, InteractionType.HTTP, "HTTP");
    }

    /** Returns the true protocol ("HTTP", "DNS", "LDAP") for display in the activity log. */
    public String getProtocol() { return protocol; }

    @Override
    public InteractionId id() {
        return interactionId;
    }

    @Override
    public InteractionType type() {
        return interactionType;
    }

    @Override
    public ZonedDateTime timeStamp() {
        return timestamp;
    }

    @Override
    public InetAddress clientIp() {
        return clientAddress;
    }

    @Override
    public int clientPort() {
        return clientPortNum;
    }

    @Override
    public Optional<DnsDetails> dnsDetails() {
        return Optional.empty();
    }

    @Override
    public Optional<HttpDetails> httpDetails() {
        return Optional.empty();
    }

    @Override
    public Optional<SmtpDetails> smtpDetails() {
        return Optional.empty();
    }

    @Override
    public Optional<String> customData() {
        return Optional.ofNullable(rawRequest);
    }

    /**
     * Custom implementation of {@link InteractionId} wrapping a plain string payload ID.
     */
    private static class CustomInteractionId implements InteractionId {
        private final String id;

        CustomInteractionId(String id) {
            this.id = id;
        }

        @Override
        public String toString() {
            return id;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof InteractionId other)) return false;
            return id.equals(other.toString());
        }

        @Override
        public int hashCode() {
            return id.hashCode();
        }
    }
}

package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OobListenerTest {

    @Test
    void dnsWorkerIsLiveImmediatelyAfterStart() throws Exception {
        String payloadId = "0123456789abcdef01234567";
        int dnsPort = OobListener.randomAvailableUdpPort();
        OobListener listener = new OobListener("127.0.0.1", 0, dnsPort);
        CountDownLatch callback = new CountDownLatch(1);
        AtomicReference<String> receivedId = new AtomicReference<>();
        listener.setInteractionHandler((id, interaction) -> {
            receivedId.set(id);
            callback.countDown();
        });

        try (DatagramSocket client = new DatagramSocket()) {
            listener.startDns();
            byte[] query = dnsQuery(payloadId + ".example.test");
            client.send(new DatagramPacket(query, query.length,
                    InetAddress.getByName("127.0.0.1"), dnsPort));

            assertTrue(callback.await(2, TimeUnit.SECONDS),
                    "DNS listener accepted the port but its worker did not process the query");
            assertEquals(payloadId, receivedId.get());
        } finally {
            listener.stop();
        }
    }

    private static byte[] dnsQuery(String domain) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {
                0x12, 0x34, 0x01, 0x00,
                0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
        });
        for (String label : domain.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            out.write(bytes.length);
            out.write(bytes);
        }
        out.write(0);
        out.write(new byte[] {0x00, 0x01, 0x00, 0x01});
        return out.toByteArray();
    }
}

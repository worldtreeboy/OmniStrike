package com.omnistrike.framework;

import burp.api.montoya.collaborator.InteractionType;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Embedded HTTP + DNS server that catches OOB callbacks from target applications.
 * Uses raw {@link ServerSocket} for HTTP (not {@code com.sun.net.httpserver} which
 * is blocked by Burp Suite's classloader) and {@link DatagramSocket} for DNS.
 *
 * <ul>
 *   <li><b>HTTP</b>: Any request to {@code http://<ip>:<httpPort>/<payloadId>/...} is matched.</li>
 *   <li><b>DNS</b>: Any DNS query for {@code <payloadId>.<anything>} on the configured UDP port is matched.
 *       The first label of the queried domain is the payload ID. Responds with an A record pointing
 *       to the listener's own IP address.</li>
 * </ul>
 */
public class OobListener {

    private ServerSocket httpServerSocket;
    private ExecutorService httpExecutor;
    private Thread httpAcceptThread;
    private DatagramSocket dnsSocket;
    private Thread dnsThread;
    private ServerSocket ldapServerSocket;
    private ExecutorService ldapExecutor;
    private Thread ldapAcceptThread;

    private final String bindAddress;
    private final int httpPort;
    private volatile int dnsPort;
    private volatile int ldapPort;
    private volatile boolean httpRunning  = false;
    private volatile boolean dnsRunning   = false;
    private volatile boolean ldapRunning  = false;

    // Regex to extract our 24-char hex payload ID from raw bytes / text
    private static final java.util.regex.Pattern HEX_ID =
            java.util.regex.Pattern.compile("[0-9a-f]{24}");

    /**
     * Callback invoked for every incoming request: (payloadId, CustomOobInteraction).
     * Wired by CollaboratorManager to match against pending payloads.
     */
    private BiConsumer<String, CustomOobInteraction> interactionHandler;

    public OobListener(String bindAddress, int httpPort) {
        this.bindAddress = bindAddress;
        this.httpPort = httpPort;
        this.dnsPort = 53;
    }

    public OobListener(String bindAddress, int httpPort, int dnsPort) {
        this.bindAddress = bindAddress;
        this.httpPort = httpPort;
        this.dnsPort = dnsPort;
    }

    public OobListener(String bindAddress, int httpPort, int dnsPort, int ldapPort) {
        this.bindAddress = bindAddress;
        this.httpPort    = httpPort;
        this.dnsPort     = dnsPort;
        this.ldapPort    = ldapPort;
    }

    public void setInteractionHandler(BiConsumer<String, CustomOobInteraction> handler) {
        this.interactionHandler = handler;
    }

    // ==================== HTTP LISTENER (raw ServerSocket) ====================

    /**
     * Starts the HTTP listener using a raw ServerSocket.
     * Accepts connections on a background thread, dispatches each to a thread pool.
     */
    public void startHttp() throws IOException {
        InetAddress addr = InetAddress.getByName(bindAddress);
        httpServerSocket = new ServerSocket(httpPort, 50, addr);
        httpExecutor = createConnectionPool("OmniStrike-OOB-HTTP");
        httpRunning = true;

        httpAcceptThread = new Thread(() -> {
            while (httpRunning) {
                try {
                    Socket clientSocket = httpServerSocket.accept();
                    try {
                        httpExecutor.submit(() -> handleHttpConnection(clientSocket));
                    } catch (RejectedExecutionException rejected) {
                        try { clientSocket.close(); } catch (IOException ignored) {}
                    }
                } catch (IOException e) {
                    if (httpRunning) {
                        // Real error, not just socket closed during shutdown
                    }
                }
            }
        }, "OmniStrike-OOB-Accept");
        httpAcceptThread.setDaemon(true);
        httpAcceptThread.start();
    }

    /** Legacy start() — starts HTTP only for backward compatibility. */
    public void start() throws IOException {
        startHttp();
    }

    public void stopHttp() {
        httpRunning = false;
        if (httpServerSocket != null) {
            try { httpServerSocket.close(); } catch (IOException ignored) {}
            httpServerSocket = null;
        }
        if (httpExecutor != null) {
            httpExecutor.shutdownNow();
            httpExecutor = null;
        }
        if (httpAcceptThread != null) {
            httpAcceptThread.interrupt();
            httpAcceptThread = null;
        }
    }

    /**
     * Handles a single HTTP connection: reads the request line to extract the path,
     * extracts the payload ID, fires the callback, and sends a 200 OK response.
     */
    private void handleHttpConnection(Socket socket) {
        try {
            socket.setSoTimeout(500);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);

            // Read the request line (e.g., "GET /abc123/cmdi HTTP/1.1\r\n")
            String requestLine = readLine(in, deadlineNanos);
            if (requestLine == null || requestLine.isEmpty()) {
                socket.close();
                return;
            }

            // Read headers (we just need Host for the evidence string)
            String host = "";
            String line;
            int headerBytes = 0;
            int headerLines = 0;
            while ((line = readLine(in, deadlineNanos)) != null && !line.isEmpty()) {
                headerBytes += line.length();
                if (++headerLines > 200 || headerBytes > 65_536) {
                    throw new IOException("HTTP OOB request headers exceeded safety limit");
                }
                if (line.toLowerCase().startsWith("host:")) {
                    host = line.substring(5).trim();
                }
            }

            // Parse method and path from request line: "GET /abc123/cmdi HTTP/1.1"
            String[] parts = requestLine.split(" ");
            String method = parts.length > 0 ? parts[0] : "GET";
            String path = parts.length > 1 ? parts[1] : "/";

            // Extract payload ID from the first path segment
            String payloadId = extractPayloadId(path);

            // Build raw request string for evidence
            InetAddress remoteAddr = socket.getInetAddress();
            int remotePort = socket.getPort();
            String rawRequest = method + " " + path + " HTTP/1.1\n"
                    + "Host: " + host + "\n"
                    + "From: " + remoteAddr.getHostAddress() + ":" + remotePort;

            // Dispatch to CollaboratorManager
            if (payloadId != null && !payloadId.isEmpty() && interactionHandler != null) {
                CustomOobInteraction interaction = new CustomOobInteraction(
                        payloadId,
                        remoteAddr,
                        remotePort,
                        rawRequest
                );
                interactionHandler.accept(payloadId, interaction);
            }

            // Send 200 OK response
            String response = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/plain\r\n"
                    + "Content-Length: 2\r\n"
                    + "Connection: close\r\n"
                    + "\r\n"
                    + "OK";
            out.write(response.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (Exception e) {
            // Never crash — just close the connection
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Reads a single line from the input stream (terminated by \r\n or \n).
     */
    private String readLine(InputStream in, long deadlineNanos) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while (true) {
            if (System.nanoTime() > deadlineNanos) {
                throw new SocketTimeoutException("OOB request exceeded total read deadline");
            }
            c = in.read();
            if (c == -1) break;
            if (c == '\r') {
                int next = in.read(); // consume \n
                if (next != '\n' && next != -1) {
                    sb.append((char) c);
                    sb.append((char) next);
                    continue;
                }
                break;
            }
            if (c == '\n') break;
            sb.append((char) c);
            if (sb.length() > 8192) break; // Safety limit
        }
        return sb.toString();
    }

    // ==================== DNS LISTENER ====================

    /**
     * Starts the DNS listener on a UDP DatagramSocket.
     * Parses incoming DNS queries (RFC 1035), extracts the first label of the queried domain
     * as the payload ID, responds with an A record pointing to {@link #bindAddress},
     * and fires the interaction callback.
     */
    public void startDns() throws IOException {
        InetAddress addr = InetAddress.getByName(bindAddress);
        dnsSocket = new DatagramSocket(dnsPort, addr);
        // Publish the running state before the worker starts.  Starting the
        // thread first creates a race where it can observe false, exit, and
        // leave a bound but permanently inert DNS listener behind.
        dnsRunning = true;

        dnsThread = new Thread(() -> {
            byte[] buf = new byte[512];
            while (dnsRunning) {
                try {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    dnsSocket.receive(packet);
                    handleDnsQuery(packet);
                } catch (IOException e) {
                    if (dnsRunning) {
                        // Real error, not just socket closed
                    }
                }
            }
        }, "OmniStrike-DNS-Listener");
        dnsThread.setDaemon(true);
        dnsThread.start();
    }

    public void stopDns() {
        dnsRunning = false;
        if (dnsSocket != null) {
            dnsSocket.close();
            dnsSocket = null;
        }
        if (dnsThread != null) {
            dnsThread.interrupt();
            dnsThread = null;
        }
    }

    // ==================== LDAP LISTENER (TCP) ====================

    /**
     * Starts a minimal LDAP listener on a TCP port.
     * Scans the raw bytes of every inbound message for a 24-char hex payload ID,
     * then fires the callback. Responds with a generic BindResponse (resultCode=0)
     * so the client does not hang or retry.
     *
     * Payload ID extraction: SSRF/XXE payloads using LDAP URLs embed the hex ID in
     * the Distinguished Name (base DN). Scanning for the hex pattern is more reliable
     * than full BER/ASN.1 parsing across every LDAP client implementation.
     */
    public void startLdap() throws IOException {
        if (ldapPort <= 0) throw new IOException("LDAP port not configured");
        InetAddress addr = InetAddress.getByName(bindAddress);
        ldapServerSocket = new ServerSocket(ldapPort, 50, addr);
        ldapExecutor = createConnectionPool("OmniStrike-OOB-LDAP");
        ldapRunning = true;
        ldapAcceptThread = new Thread(() -> {
            while (ldapRunning) {
                try {
                    Socket client = ldapServerSocket.accept();
                    try {
                        ldapExecutor.submit(() -> handleLdapConnection(client));
                    } catch (RejectedExecutionException rejected) {
                        try { client.close(); } catch (IOException ignored) {}
                    }
                } catch (IOException e) {
                    if (ldapRunning) { /* real error */ }
                }
            }
        }, "OmniStrike-LDAP-Accept");
        ldapAcceptThread.setDaemon(true);
        ldapAcceptThread.start();
    }

    public void stopLdap() {
        ldapRunning = false;
        if (ldapServerSocket != null) {
            try { ldapServerSocket.close(); } catch (IOException ignored) {}
            ldapServerSocket = null;
        }
        if (ldapExecutor != null) { ldapExecutor.shutdownNow(); ldapExecutor = null; }
        if (ldapAcceptThread != null) { ldapAcceptThread.interrupt(); ldapAcceptThread = null; }
    }

    private void handleLdapConnection(Socket socket) {
        try {
            socket.setSoTimeout(500);
            InputStream in  = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);

            // Read up to 2 KB — enough to cover any LDAP bind/search request
            ByteArrayOutputStream transcript = new ByteArrayOutputStream(8192);
            byte[] buf = new byte[1024];
            String payloadId = null;
            boolean bindResponseSent = false;
            while (transcript.size() < 8192 && payloadId == null) {
                if (System.nanoTime() > deadlineNanos) break;
                int n;
                try {
                    n = in.read(buf, 0, Math.min(buf.length, 8192 - transcript.size()));
                } catch (SocketTimeoutException timeout) {
                    break;
                }
                if (n <= 0) break;
                transcript.write(buf, 0, n);
                payloadId = extractHexId(transcript.toString(StandardCharsets.ISO_8859_1));

                if (!bindResponseSent) {
                    byte[] bindResp = { 0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07,
                            0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 };
                    out.write(bindResp);
                    out.flush();
                    bindResponseSent = true;
                }
            }

            InetAddress remoteAddr = socket.getInetAddress();
            int remotePort = socket.getPort();
            String evidence = "LDAP request from " + remoteAddr.getHostAddress() + ":" + remotePort
                    + (payloadId != null ? " payloadId=" + payloadId : " (no payload ID)");

            if (payloadId != null && interactionHandler != null) {
                CustomOobInteraction interaction = new CustomOobInteraction(
                        payloadId, remoteAddr, remotePort, evidence,
                        InteractionType.HTTP, "LDAP");
                interactionHandler.accept(payloadId, interaction);
            }

            // Minimal LDAP BindResponse: resultCode=0 (success), so the client doesn't hang
            // SEQUENCE { messageID=1, [APP 1] BindResponse { resultCode=0, matchedDN="", errorMsg="" } }
        } catch (Exception ignored) {
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private ExecutorService createConnectionPool(String threadName) {
        return new ThreadPoolExecutor(4, 32, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(128), r -> {
                    Thread t = new Thread(r, threadName);
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    // ==================== COMBINED START/STOP ====================

    /** Starts both HTTP and DNS listeners. */
    public void startAll() throws IOException {
        startHttp();
        startDns();
    }

    public void stop() {
        stopHttp();
        stopDns();
        stopLdap();
    }

    public boolean isRunning() {
        return httpRunning || dnsRunning || ldapRunning;
    }

    public boolean isHttpRunning()  { return httpRunning;  }
    public boolean isDnsRunning()   { return dnsRunning;   }
    public boolean isLdapRunning()  { return ldapRunning;  }

    public int getPort() {
        return httpPort;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public int getDnsPort() {
        return dnsPort;
    }

    public int getLdapPort() {
        return ldapPort;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    /**
     * Scans text for our 24-char lowercase hex payload ID.
     * Used by LDAP (and any future protocol) where payload IDs are embedded in
     * raw protocol data rather than a clean URL path segment.
     */
    private String extractHexId(String text) {
        if (text == null) return null;
        java.util.regex.Matcher m = HEX_ID.matcher(text);
        return m.find() ? m.group() : null;
    }

    /**
     * Extracts the payload ID from the first URL path segment.
     * {@code /abc123def/cmdi} → {@code abc123def}
     * {@code /abc123def} → {@code abc123def}
     * {@code /} → {@code null}
     */
    private String extractPayloadId(String path) {
        if (path == null || path.length() <= 1) return null;
        String trimmed = path.substring(1);
        int slashIdx = trimmed.indexOf('/');
        return slashIdx > 0 ? trimmed.substring(0, slashIdx) : trimmed;
    }

    /**
     * Lists all UP, non-loopback IPv4 network interfaces for the UI dropdown.
     * Returns a list of "interfaceName - ipAddress" strings.
     */
    public static List<String[]> getNetworkInterfaces() {
        List<String[]> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        result.add(new String[]{
                                ni.getDisplayName(),
                                addr.getHostAddress()
                        });
                    }
                }
            }
        } catch (SocketException e) {
            // Fallback: at least offer localhost
        }
        result.add(new String[]{"loopback", "127.0.0.1"});
        return result;
    }

    /**
     * Finds a random available TCP port by briefly opening and closing a server socket.
     */
    public static int randomAvailablePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            return 8888 + (int) (Math.random() * 1000);
        }
    }

    /**
     * Finds a random available UDP port by briefly opening and closing a datagram socket.
     */
    public static int randomAvailableUdpPort() {
        try (DatagramSocket socket = new DatagramSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            return 5353 + (int) (Math.random() * 1000);
        }
    }

    // ==================== DNS PACKET HANDLING ====================

    /**
     * Handles an incoming DNS query packet (RFC 1035).
     */
    private void handleDnsQuery(DatagramPacket packet) {
        try {
            byte[] data = packet.getData();
            int len = packet.getLength();
            if (len < 12) return;

            int txnId = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
            int qdCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);

            if ((flags & 0x8000) != 0) return;
            if (qdCount < 1) return;

            int offset = 12;
            String domain = parseDomainName(data, offset, len);
            if (domain == null || domain.isEmpty()) return;

            String payloadId = domain.contains(".")
                    ? domain.substring(0, domain.indexOf('.'))
                    : domain;

            String rawRequest = "DNS Query: " + domain
                    + " from " + packet.getAddress().getHostAddress() + ":" + packet.getPort()
                    + " (txnId=" + txnId + ")";

            if (payloadId != null && !payloadId.isEmpty() && interactionHandler != null) {
                CustomOobInteraction interaction = new CustomOobInteraction(
                        payloadId,
                        packet.getAddress(),
                        packet.getPort(),
                        rawRequest,
                        InteractionType.DNS
                );
                interactionHandler.accept(payloadId, interaction);
            }

            byte[] response = buildDnsResponse(data, len, txnId, domain);
            if (response != null) {
                DatagramPacket responsePacket = new DatagramPacket(
                        response, response.length, packet.getAddress(), packet.getPort());
                dnsSocket.send(responsePacket);
            }
        } catch (Exception e) {
            // Never crash the DNS listener thread
        }
    }

    private String parseDomainName(byte[] data, int offset, int maxLen) {
        StringBuilder domain = new StringBuilder();
        while (offset < maxLen) {
            int labelLen = data[offset] & 0xFF;
            if (labelLen == 0) break;
            if ((labelLen & 0xC0) == 0xC0) break;
            if (offset + 1 + labelLen > maxLen) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, offset + 1, labelLen, StandardCharsets.US_ASCII));
            offset += 1 + labelLen;
        }
        return domain.toString().toLowerCase();
    }

    private byte[] buildDnsResponse(byte[] queryData, int queryLen, int txnId, String domain) {
        try {
            InetAddress responseIp = InetAddress.getByName(bindAddress);
            if (!(responseIp instanceof Inet4Address)) return null;
            byte[] ipBytes = responseIp.getAddress();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(512);

            baos.write((txnId >> 8) & 0xFF);
            baos.write(txnId & 0xFF);
            baos.write(0x85);
            baos.write(0x00);
            baos.write(0x00); baos.write(0x01); // QDCOUNT = 1
            baos.write(0x00); baos.write(0x01); // ANCOUNT = 1
            baos.write(0x00); baos.write(0x00); // NSCOUNT = 0
            baos.write(0x00); baos.write(0x00); // ARCOUNT = 0

            // queryData is a shared, reused receive buffer (see startDns): bytes past
            // queryLen are residue from previous queries, so every read must be
            // strictly bounds-checked against queryLen or we leak other clients' data.
            int offset = 12;
            while (offset < queryLen) {
                int labelLen = queryData[offset] & 0xFF;
                if (labelLen == 0) {
                    baos.write(0x00);
                    offset++;
                    break;
                }
                // Compression pointers are unsupported in the question section here
                if ((labelLen & 0xC0) != 0) return null;
                if (labelLen > 63) return null;
                if (offset + 1 + labelLen > queryLen) return null;
                baos.write(queryData, offset, 1 + labelLen);
                offset += 1 + labelLen;
            }
            if (offset + 4 <= queryLen) {
                baos.write(queryData, offset, 4);
            } else {
                // Truncated question (missing QTYPE/QCLASS) — drop the query
                return null;
            }

            baos.write(0xC0); baos.write(0x0C);
            baos.write(0x00); baos.write(0x01); // TYPE = A
            baos.write(0x00); baos.write(0x01); // CLASS = IN
            baos.write(0x00); baos.write(0x00);
            baos.write(0x00); baos.write(0x3C); // TTL = 60s
            baos.write(0x00); baos.write(0x04); // RDLENGTH = 4
            baos.write(ipBytes);

            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }
}

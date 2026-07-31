package com.omnistrike.framework;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveDataRedactorTest {

    @AfterEach
    void restorePrivacyDefaults() {
        PrivacyManager.setAiRedactionEnabled(true);
        PrivacyManager.setUiMaskingEnabled(false);
    }

    @Test
    void redactsHttpCredentialsCookiesHostsAndPrivateHeaders() {
        String input = "POST https://alice:SuperSecret@example.internal:8443/api/orders?id=42 HTTP/1.1\r\n"
                + "Host: example.internal\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123\r\n"
                + "Cookie: session=abc123; preference=dark\r\n"
                + "X-Api-Key: sk-proj-abcdefghijklmnopqrstuvwxyz123456\r\n"
                + "X-Correlation-Id: customer-trace-938475\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"email\":\"alice@example.com\",\"password\":\"p@ssword\",\"action\":\"view\"}";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertFalse(output.contains("alice:SuperSecret")),
                () -> assertFalse(output.contains("example.internal")),
                () -> assertFalse(output.contains("signature123")),
                () -> assertFalse(output.contains("abc123")),
                () -> assertFalse(output.contains("preference=dark")),
                () -> assertFalse(output.contains("abcdefghijklmnopqrstuvwxyz123456")),
                () -> assertFalse(output.contains("customer-trace-938475")),
                () -> assertFalse(output.contains("alice@example.com")),
                () -> assertFalse(output.contains("p@ssword")),
                () -> assertTrue(output.contains("Authorization: Bearer [REDACTED_AUTH_1]")),
                () -> assertTrue(output.contains("Content-Type: application/json")),
                () -> assertTrue(output.contains("\"action\":\"view\"")),
                () -> assertTrue(output.contains("/api/orders?id=[REDACTED_QUERY_VALUE_1]"))
        );
    }

    @Test
    void preservesCookieNamesAndSetCookieAttributesButRemovesValues() {
        String input = "Cookie: sid=topsecret; csrftoken=csrf-value\r\n"
                + "Set-Cookie: sid=new-secret; Path=/; Secure; HttpOnly; SameSite=Lax";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertTrue(output.contains("Cookie: sid=[REDACTED_COOKIE_1]; csrftoken=[REDACTED_COOKIE_2]")),
                () -> assertTrue(output.contains("Set-Cookie: sid=[REDACTED_SET_COOKIE_1]; Path=/; Secure; HttpOnly; SameSite=Lax")),
                () -> assertFalse(output.contains("topsecret")),
                () -> assertFalse(output.contains("csrf-value")),
                () -> assertFalse(output.contains("new-secret"))
        );
    }

    @Test
    void equivalentHostsKeepTheSamePlaceholderForOriginReasoning() {
        String input = "GET https://client.example/path HTTP/1.1\r\n"
                + "Host: client.example\r\n"
                + "Origin: https://client.example\r\n"
                + "Access-Control-Allow-Origin: https://client.example";

        String output = SensitiveDataRedactor.redact(input);

        assertFalse(output.contains("client.example"));
        assertEquals(4, countOccurrences(output, "[REDACTED_HOST_1]"));
        assertTrue(output.contains("Origin: https://[REDACTED_HOST_1]"));
        assertTrue(output.contains("Access-Control-Allow-Origin: https://[REDACTED_HOST_1]"));
    }

    @Test
    void redactsJsonFormXmlAndTemplateSensitiveValues() {
        String input = "{\"client_secret\":\"json-secret\",\"enabled\":true}\n"
                + "username=bob&password=form-secret&amount=100\n"
                + "<account><email>bob@example.org</email><item token='xml-secret'>safe</item></account>\n"
                + "{{session_token}}=template-secret";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertFalse(output.contains("json-secret")),
                () -> assertFalse(output.contains("bob@example.org")),
                () -> assertFalse(output.contains("form-secret")),
                () -> assertFalse(output.contains("amount=100")),
                () -> assertFalse(output.contains("xml-secret")),
                () -> assertFalse(output.contains("template-secret")),
                () -> assertTrue(output.contains("\"enabled\":true")),
                () -> assertTrue(output.contains("username=[REDACTED_IDENTITY_1]")),
                () -> assertTrue(output.contains("amount=[REDACTED_FORM_VALUE_1]"))
        );
    }

    @Test
    void redactsCommonPiiPaymentAndInfrastructureIdentifiers() {
        String input = "email=customer@example.com\n"
                + "card=4111 1111 1111 1111\n"
                + "ssn=123-45-6789\n"
                + "nric=S1234567D\n"
                + "phone=+6591234567\n"
                + "device=00:1A:2B:3C:4D:5E\n"
                + "requestId=550e8400-e29b-41d4-a716-446655440000\n"
                + "source=10.20.30.40";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertFalse(output.contains("customer@example.com")),
                () -> assertFalse(output.contains("4111 1111 1111 1111")),
                () -> assertFalse(output.contains("123-45-6789")),
                () -> assertFalse(output.contains("S1234567D")),
                () -> assertFalse(output.contains("+6591234567")),
                () -> assertFalse(output.contains("00:1A:2B:3C:4D:5E")),
                () -> assertFalse(output.contains("550e8400-e29b-41d4-a716-446655440000")),
                () -> assertFalse(output.contains("10.20.30.40")),
                () -> assertTrue(output.contains("[REDACTED_CARD_1]")),
                () -> assertTrue(output.contains("[REDACTED_NATIONAL_ID_1]"))
        );
    }

    @Test
    void redactsKnownKeysPrivateKeysAndUnknownHighEntropySecrets() {
        String highEntropy = "aZ9mQ2vL8pR4sT7uW1xY6kN3cB5dF0hJ";
        String input = "github_pat_abcdefghijklmnopqrstuvwxyz1234567890\n"
                + "AKIAABCDEFGHIJKLMNOP\n"
                + "AIzaSyA1234567890bcdefghijklmnopqrstuv\n"
                // Split token-shaped fixtures so repository push protection does
                // not mistake this regression input for a live credential.
                + "xoxb-" + "1234567890-ABCDEFGHIJKLMNO\n"
                + highEntropy + "\n"
                + "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertFalse(output.contains("github_pat_")),
                () -> assertFalse(output.contains("AKIAABCDEFGHIJKLMNOP")),
                () -> assertFalse(output.contains("AIzaSyA")),
                () -> assertFalse(output.contains("xoxb-")),
                () -> assertFalse(output.contains(highEntropy)),
                () -> assertFalse(output.contains("secret-material")),
                () -> assertTrue(output.contains("[REDACTED_PRIVATE_KEY_1]")),
                () -> assertTrue(output.contains("[REDACTED_HIGH_ENTROPY_1]"))
        );
    }

    @Test
    void repeatedValuesUseStablePlaceholdersAndRedactionIsIdempotent() {
        String input = "email=repeat@example.com\n{\"email\":\"repeat@example.com\"}";
        String once = SensitiveDataRedactor.redact(input);
        String twice = SensitiveDataRedactor.redact(once);

        assertEquals(2, countOccurrences(once, "[REDACTED_EMAIL_1]"));
        assertEquals(once, twice);
    }

    @Test
    void avoidsObviousFalsePositives() {
        String input = "Content-Length: 1234\nversion=1.82\n"
                + "invalid-card=4111111111111112\ninvalid-ip=999.20.30.40\n"
                + "ordinary=abcdefghijklmnopqrstuvwx";

        String output = SensitiveDataRedactor.redact(input);

        assertAll(
                () -> assertTrue(output.contains("Content-Length: 1234")),
                () -> assertTrue(output.contains("version=1.82")),
                () -> assertTrue(output.contains("4111111111111112")),
                () -> assertTrue(output.contains("999.20.30.40")),
                () -> assertTrue(output.contains("abcdefghijklmnopqrstuvwx"))
        );
    }

    @Test
    void privacyManagerDefaultsToRedactingOnlyTheOutboundCopy() {
        String original = "Cookie: session=client-secret";

        PrivacyManager.setAiRedactionEnabled(true);
        String outbound = PrivacyManager.redactAiPrompt(original);
        assertEquals("Cookie: session=client-secret", original);
        assertFalse(outbound.contains("client-secret"));

        PrivacyManager.setAiRedactionEnabled(false);
        assertSame(original, PrivacyManager.redactAiPrompt(original));
    }

    private static int countOccurrences(String value, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = value.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }
}

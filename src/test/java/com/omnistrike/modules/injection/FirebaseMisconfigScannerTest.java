package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FirebaseMisconfigScannerTest {

    @Test
    void firestoreRequiresAnActualDocument() {
        assertTrue(FirebaseMisconfigScanner.hasNonEmptyDocumentsArray(
                "{\"documents\":[{\"name\":\"projects/p/databases/d/documents/users/1\"}]}"));
        assertFalse(FirebaseMisconfigScanner.hasNonEmptyDocumentsArray(
                "{\"documents\": [\n ]}"));
        assertFalse(FirebaseMisconfigScanner.hasNonEmptyDocumentsArray("{\"documents\":null}"));
    }

    @Test
    void signInEnumerationRequiresKnownUserDifferential() {
        String missing = "{\"error\":{\"message\":\"EMAIL_NOT_FOUND\"}}";
        String wrongPassword = "{\"error\":{\"message\":\"INVALID_PASSWORD\"}}";
        String protectedError = "{\"error\":{\"message\":\"INVALID_LOGIN_CREDENTIALS\"}}";

        assertTrue(FirebaseMisconfigScanner.demonstratesSignInEnumeration(missing, wrongPassword));
        assertFalse(FirebaseMisconfigScanner.demonstratesSignInEnumeration(missing, missing));
        assertFalse(FirebaseMisconfigScanner.demonstratesSignInEnumeration(
                protectedError, protectedError));
    }

    @Test
    void extractsLegacyAndRegionalRealtimeDatabaseUrls() {
        assertEquals("https://demo.firebaseio.com",
                FirebaseMisconfigScanner.extractRealtimeDbBaseUrl(
                        "https://demo.firebaseio.com/users.json", ""));
        assertEquals("https://demo-default-rtdb.asia-southeast1.firebasedatabase.app",
                FirebaseMisconfigScanner.extractRealtimeDbBaseUrl("https://app.example/",
                        "{\"databaseURL\":\"https:\\/\\/demo-default-rtdb.asia-southeast1.firebasedatabase.app\"}"));
    }
}

package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SalesforceSOQLScannerTest {

    @Test
    void requiresActualRecordsRatherThanAnEmptyResponseShape() {
        assertTrue(SalesforceSOQLScanner.hasNonEmptyArray(
                "{\"totalSize\":1,\"records\":[{\"Id\":\"001\"}]}", "records"));
        assertFalse(SalesforceSOQLScanner.hasNonEmptyArray(
                "{\"totalSize\":0,\"records\": [\n ]}", "records"));
        assertFalse(SalesforceSOQLScanner.hasNonEmptyArray(
                "{\"records\":\"not-an-array\"}", "records"));
        assertFalse(SalesforceSOQLScanner.hasNonEmptyArray("not json", "records"));
    }

    @Test
    void soslRequiresAtLeastOneSearchRecord() {
        assertTrue(SalesforceSOQLScanner.hasNonEmptyArray(
                "{\"searchRecords\":[{\"attributes\":{}}]}", "searchRecords"));
        assertFalse(SalesforceSOQLScanner.hasNonEmptyArray(
                "{\"searchRecords\":[]}", "searchRecords"));
    }
}

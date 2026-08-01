package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ServiceNowGlideScannerTest {

    @Test
    void recognizesEncodedQueryClausesWithoutMatchingOrdinaryWords() {
        assertTrue(ServiceNowGlideScanner.containsEncodedQueryOperator("active=true^priorityIN1,2"));
        assertTrue(ServiceNowGlideScanner.containsEncodedQueryOperator("nameLIKEadmin"));
        assertTrue(ServiceNowGlideScanner.containsEncodedQueryOperator("^ORDERBYsys_created_on"));
        assertTrue(ServiceNowGlideScanner.containsEncodedQueryOperator("sys_idISNOTEMPTY"));

        assertFalse(ServiceNowGlideScanner.containsEncodedQueryOperator("admin"));
        assertFalse(ServiceNowGlideScanner.containsEncodedQueryOperator("inside information"));
        assertFalse(ServiceNowGlideScanner.containsEncodedQueryOperator("plain text"));
    }

    @Test
    void requiresRowsBeforeClaimingTableDataAccess() {
        assertTrue(ServiceNowGlideScanner.hasNonEmptyResultArray(
                "{\"result\":[{\"sys_id\":\"1\"}]}"));
        assertFalse(ServiceNowGlideScanner.hasNonEmptyResultArray("{\"result\":[]}"));
        assertFalse(ServiceNowGlideScanner.hasNonEmptyResultArray("{\"error\":{}}"));
    }

    @Test
    void sensitiveFieldsRequireActualNonRedactedData() {
        assertTrue(ServiceNowGlideScanner.hasNonTrivialFieldValue(
                "{\"result\":[{\"user_password\":\"secret\"}]}", "user_password"));
        assertTrue(ServiceNowGlideScanner.hasNonTrivialFieldValue(
                "{\"result\":[{\"active\":false}]}", "active"));
        assertFalse(ServiceNowGlideScanner.hasNonTrivialFieldValue(
                "{\"result\":[{\"user_password\":\"********\"}]}", "user_password"));
        assertFalse(ServiceNowGlideScanner.hasNonTrivialFieldValue(
                "{\"result\":[{\"user_password\":\"\"}]}", "user_password"));
        assertFalse(ServiceNowGlideScanner.hasNonTrivialFieldValue(
                "{\"result\":[{\"user_password\":null}]}", "user_password"));
    }
}

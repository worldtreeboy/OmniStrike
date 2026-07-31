package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SmartSqliDetectorTest {
    @Test
    void unionMarkerRejectsRawAndEncodedLookingReflection() {
        String marker = "xXrandommarkerXx";
        String payload = "1' UNION SELECT '" + marker + "'-- -";
        assertTrue(SmartSqliDetector.looksLikeReflectedUnionPayload(payload, payload, marker));
        assertTrue(SmartSqliDetector.looksLikeReflectedUnionPayload(
                "echo: 1&#39; UNION SELECT &#39;" + marker + "&#39;-- -", payload, marker));
        assertFalse(SmartSqliDetector.looksLikeReflectedUnionPayload(
                "<td>" + marker + "</td>", payload, marker));
    }

    @SuppressWarnings("unchecked")
    @Test
    void mysqlOobDomainsAreQuotedAndNoPayloadMutatesPersistentState() throws Exception {
        Field field = SmartSqliDetector.class.getDeclaredField("OOB_PAYLOADS");
        field.setAccessible(true);
        Map<String, String[]> payloads = (Map<String, String[]>) field.get(null);

        for (String template : payloads.get("MySQL")) {
            int at = template.indexOf("COLLAB_PLACEHOLDER");
            assertTrue(at > 0 && template.charAt(at - 1) == '\'', template);
        }

        for (String[] group : payloads.values()) {
            for (String template : group) {
                String lower = template.toLowerCase();
                assertFalse(lower.contains(" into outfile "), template);
                assertFalse(lower.contains(" into dumpfile "), template);
                assertFalse(lower.contains("sp_addlinkedserver"), template);
                assertFalse(lower.contains("create_job"), template);
                assertFalse(lower.contains("utl_file"), template);
                assertFalse(lower.contains("copy omni from program"), template);
            }
        }
    }
}

package com.omnistrike.framework.stepper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests {{placeholder}} substitution used by Stepper to patch extracted tokens
 * into outgoing requests.
 */
class StepperVariableStoreTest {

    @Test
    void substitutesKnownVariable() {
        StepperVariableStore v = new StepperVariableStore();
        v.set("id", "abc");
        assertEquals("/api/abc/x", v.substitute("/api/{{id}}/x"));
    }

    @Test
    void leavesUnknownVariableLiteral() {
        StepperVariableStore v = new StepperVariableStore();
        assertEquals("{{missing}}", v.substitute("{{missing}}"));
    }

    @Test
    void substitutesMultipleVariables() {
        StepperVariableStore v = new StepperVariableStore();
        v.set("a", "1");
        v.set("b", "2");
        assertEquals("1-2", v.substitute("{{a}}-{{b}}"));
    }

    @Test
    void inputWithoutPlaceholdersUnchanged() {
        StepperVariableStore v = new StepperVariableStore();
        v.set("a", "1");
        assertEquals("plain text", v.substitute("plain text"));
    }

    @Test
    void nullAndEmptyAreReturnedAsIs() {
        StepperVariableStore v = new StepperVariableStore();
        assertNull(v.substitute(null));
        assertEquals("", v.substitute(""));
    }

    @Test
    void valueWithRegexSpecialCharsIsInsertedLiterally() {
        // Matcher.appendReplacement treats $ and \ specially — the store must
        // quote them so a token like "$1\x" is inserted verbatim.
        StepperVariableStore v = new StepperVariableStore();
        v.set("v", "$1\\x");
        assertEquals("[$1\\x]", v.substitute("[{{v}}]"));
    }

    @Test
    void nullValueIsIgnoredOnSet() {
        StepperVariableStore v = new StepperVariableStore();
        v.set("a", null);
        assertNull(v.get("a"));
        assertEquals("{{a}}", v.substitute("{{a}}"));
    }

    @Test
    void clearRemovesAll() {
        StepperVariableStore v = new StepperVariableStore();
        v.set("a", "1");
        v.clear();
        assertNull(v.get("a"));
    }
}

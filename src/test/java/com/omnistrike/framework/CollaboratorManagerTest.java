package com.omnistrike.framework;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CollaboratorManagerTest {
    @Test
    void dnsRewriteTreatsGeneratedAddressAsLiteralReplacementText() throws Exception {
        CollaboratorManager manager = new CollaboratorManager(null);
        Method rewrite = CollaboratorManager.class.getDeclaredMethod(
                "rewriteDnsCommand", String.class, String.class, String.class, int.class);
        rewrite.setAccessible(true);

        assertEquals("nslookup id.$1\\host $1\\host",
                rewrite.invoke(manager, "nslookup COLLAB_PLACEHOLDER",
                        "id.$1\\host", "$1\\host", 53));
        assertEquals("ping -c1 id.$1\\host",
                rewrite.invoke(manager, "ping -c1 COLLAB_PLACEHOLDER",
                        "id.$1\\host", "$1\\host", 53));
    }
}

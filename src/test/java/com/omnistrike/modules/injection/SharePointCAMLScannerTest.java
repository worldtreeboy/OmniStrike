package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SharePointCAMLScannerTest {

    @Test
    void preservesSiteCollectionPrefixForRestProbes() {
        assertEquals("https://tenant.sharepoint.com/sites/team",
                SharePointCAMLScanner.extractSharePointSiteBase(
                        "https://tenant.sharepoint.com/sites/team/_api/web/lists?x=1"));
        assertEquals("https://tenant.sharepoint.com",
                SharePointCAMLScanner.extractSharePointSiteBase(
                        "https://tenant.sharepoint.com/_api/web"));
    }

    @Test
    void replacesMultilineViewFieldsInsteadOfDuplicatingThem() {
        String original = "<View><ViewFields>\n<FieldRef Name='Old'/>\n</ViewFields><Query/></View>";
        String replacement = "<ViewFields><FieldRef Name='New'/></ViewFields>";
        String result = SharePointCAMLScanner.injectViewFields(original, replacement);

        assertNotNull(result);
        assertFalse(result.contains("Name='Old'"));
        assertEquals(1, result.split("<ViewFields>", -1).length - 1);
    }
}

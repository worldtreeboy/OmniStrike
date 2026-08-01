package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SapODataScannerTest {

    @Test
    void countsV2AndV4ResultArrayElements() {
        assertEquals(3, SapODataScanner.countResultRows(
                "{\"d\":{\"results\":[{\"id\":1},{\"id\":2},{\"id\":3}]}}"));
        assertEquals(2, SapODataScanner.countResultRows(
                "{\"@odata.context\":\"x\",\"value\":[{},{}]}"));
        assertEquals(0, SapODataScanner.countResultRows("{\"d\":{\"results\":[]}}"));
    }

    @Test
    void swapsOnlyTheLastPathEntityAndPreservesQueryValues() {
        assertEquals("/sap/opu/odata/sap/OrdersService/Users?$filter=source eq 'Orders'",
                SapODataScanner.replaceLastEntitySegment(
                        "/sap/opu/odata/sap/OrdersService/Orders(42)?$filter=source eq 'Orders'",
                        "Orders", "Users"));
        assertEquals("/gateway/Orders/Users",
                SapODataScanner.replaceLastEntitySegment(
                        "/gateway/Orders/Orders", "Orders", "Users"));
    }
}

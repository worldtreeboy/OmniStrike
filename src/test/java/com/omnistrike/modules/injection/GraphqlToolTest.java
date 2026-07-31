package com.omnistrike.modules.injection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphqlToolTest {

    @Test
    void acceptsOnlyConcreteGraphqlDataAsSuccessfulProbeEvidence() {
        assertTrue(GraphqlTool.hasGraphqlDataField(
                "{\"data\":{\"__typename\":\"Query\"}}", "__typename"));
        assertFalse(GraphqlTool.hasGraphqlDataField(
                "{\"errors\":[{\"message\":\"__typename is forbidden\"}]}", "__typename"));
        assertFalse(GraphqlTool.hasGraphqlDataField(
                "<html>documentation mentions __typename</html>", "__typename"));
    }

    @Test
    void mutationErrorsAreNotReportedAsCsrfSuccess() {
        assertTrue(GraphqlTool.graphqlMutationSucceeded(
                "{\"data\":{\"updateProfile\":{\"__typename\":\"User\"}}}",
                "updateProfile"));
        assertFalse(GraphqlTool.graphqlMutationSucceeded(
                "{\"data\":{\"updateProfile\":null},\"errors\":[{\"message\":\"denied\"}]}",
                "updateProfile"));
    }
}

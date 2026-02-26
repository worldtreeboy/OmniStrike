package com.omnistrike.framework;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.Marker;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Computes request/response markers (byte-range highlights) for Burp Dashboard findings.
 * Searches for payload bytes in the request and evidence bytes in the response,
 * then attaches Marker objects so Burp highlights the relevant portions in the UI.
 */
public final class MarkerUtil {

    private MarkerUtil() {}

    /**
     * Adds request and response markers to an HttpRequestResponse based on
     * the payload string (highlighted in request) and responseEvidence string
     * (highlighted in response).
     *
     * @param reqResp           the original request/response pair
     * @param payload           the injected payload to find in the request (may be empty)
     * @param responseEvidence  the evidence string to find in the response (may be empty)
     * @return a new HttpRequestResponse with markers attached, or the original if no markers apply
     */
    public static HttpRequestResponse addMarkers(
            HttpRequestResponse reqResp, String payload, String responseEvidence) {
        if (reqResp == null) return null;

        HttpRequestResponse result = reqResp;

        // Request marker: find payload in request bytes
        if (payload != null && !payload.isEmpty() && reqResp.request() != null) {
            try {
                byte[] reqBytes = reqResp.request().toByteArray().getBytes();
                byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
                List<Marker> markers = findAllOccurrences(reqBytes, payloadBytes);
                if (!markers.isEmpty()) {
                    result = result.withRequestMarkers(markers);
                }
            } catch (Exception ignored) {
                // Don't let marker computation break the finding pipeline
            }
        }

        // Response marker: find evidence in response bytes
        if (responseEvidence != null && !responseEvidence.isEmpty()
                && reqResp.response() != null) {
            try {
                byte[] respBytes = reqResp.response().toByteArray().getBytes();
                byte[] evidenceBytes = responseEvidence.getBytes(StandardCharsets.UTF_8);
                List<Marker> markers = findAllOccurrences(respBytes, evidenceBytes);
                if (!markers.isEmpty()) {
                    result = result.withResponseMarkers(markers);
                }
            } catch (Exception ignored) {
                // Don't let marker computation break the finding pipeline
            }
        }

        return result;
    }

    /**
     * Finds all occurrences of needle in haystack and returns Markers for each.
     */
    private static List<Marker> findAllOccurrences(byte[] haystack, byte[] needle) {
        List<Marker> markers = new ArrayList<>();
        if (needle.length == 0 || haystack.length < needle.length) return markers;

        int idx = 0;
        while (idx <= haystack.length - needle.length) {
            int found = indexOf(haystack, needle, idx);
            if (found < 0) break;
            markers.add(Marker.marker(found, found + needle.length));
            idx = found + needle.length; // advance past this match
        }
        return markers;
    }

    /**
     * Simple byte array search starting from offset. Returns -1 if not found.
     */
    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        int limit = haystack.length - needle.length;
        for (int i = fromIndex; i <= limit; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }
}

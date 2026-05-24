package com.omnistrike.framework;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Builds a minimal synthetic {@link HttpRequestResponse} from a URL.
 *
 * <p>Some findings have no real HTTP exchange to attach — e.g. out-of-band TLS
 * checks, or async/Collaborator findings reported without their probe request.
 * Burp's Dashboard and Site Map are URL-keyed and won't display an issue without
 * a request to anchor it to, so such findings would silently never appear.
 * This produces a bare GET request (with an empty response) for the finding's
 * URL so the issue can still be surfaced in the Dashboard.
 */
public final class SyntheticRequest {

    private SyntheticRequest() {}

    /**
     * Returns a synthetic request/response for the given URL, or {@code null} if
     * the URL is blank or cannot be parsed into a request.
     */
    public static HttpRequestResponse fromUrl(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            String u = url.trim();
            // httpRequestFromUrl requires an absolute URL with a scheme.
            if (!u.startsWith("http://") && !u.startsWith("https://")) {
                u = "https://" + u;
            }
            HttpRequest req = HttpRequest.httpRequestFromUrl(u);
            return HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse());
        } catch (Exception e) {
            return null;
        }
    }
}

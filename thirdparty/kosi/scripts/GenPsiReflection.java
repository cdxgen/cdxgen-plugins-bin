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
 * <p><b>5. Caffeine's generated caches and nodes.</b> Caffeine picks the
 * cache implementation and its entry type by NAME from the builder's feature
 * combination ({@code LocalCacheFactory}/{@code NodeFactory}: strength,
 * expiry, weigher, stats...), then {@code Class.forName}s it and binds its
 * constructor through {@code MethodHandles.Lookup.findConstructor}; each node
 * class resolves {@code VarHandle}s on its own fields. The Analysis API builds
 * caches whose combination depends on the size of the analysed project, so an
 * agent run over small fixtures registers the few it happened to build.
 * Measured (atom-tools#95): reposilite (305 .kt), kuvasz (843) and http4k
 * (4,246) all exited 3 with {@code ClassNotFoundException:
 * com.github.benmanes.caffeine.cache.FWA} under a lazy-resolve error, while
 * the JVM jar analysed all three. Every generated class is in the jar, so
 * the whole set is derived, constructors and fields.
 *
 * <p><b>6. The platform's other by-name surfaces</b> (a bytecode audit of the
 * jar for atom-tools#95: every reflective call site, checked against the
 * metadata, with GraalVM's build-time folding measured on probe images).
 * Each is reached lazily, on a path fixtures need not take:
 * <ul>
 *   <li>extension-point types, and their ARRAYS: an extension point is
 *   registered with a class literal and reloaded by NAME on first use
 *   ({@code ExtensionPointImpl.getExtensionClass}), and
 *   {@code getExtensions()} allocates {@code X[]} reflectively. From the
 *   class literal before any {@code register*ExtensionPoint} call or
 *   {@code *ExtensionDescriptor} constructor, and from descriptor
 *   {@code <extensionPoint interface|beanClass>};</li>
 *   <li>message-bus listener interfaces: {@code syncPublisher} builds a
 *   dynamic PROXY over the topic's class ({@code Topic}, {@code Topic.create},
 *   {@code EventDispatcher.create}, {@code ReflectionUtil.proxy}, descriptor
 *   {@code <listener topic>});</li>
 *   <li>descriptor {@code <listener class>} implementations, constructed
 *   reflectively on first publish;</li>
 *   <li>{@code <stubElementTypeHolder class>}: its fields are read
 *   reflectively, and an unregistered holder yields an EMPTY field list,
 *   silently registering no stub types;</li>
 *   <li>K1 slice and diagnostic holders ({@code initSliceDebugNames},
 *   {@code Errors.Initializer}): public fields, read reflectively, silently
 *   empty when unregistered;</li>
 *   <li>fields named through an {@code UnsafeAccess} wrapper (Caffeine,
 *   OpenTelemetry's JCTools), which build-time folding cannot see through;</li>
 *   <li>lz4-java and xxhash, which assemble their implementation class
 *   names at run time and read {@code INSTANCE}.</li>
 * </ul>
 * Resources the same audit found unregistered ({@code misc/registry.properties},
 * read by the IntelliJ Registry for keys without a default) are in the
 * Makefile's {@code -H:IncludeResources}.
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
        TreeSet<String> caffeineTypes = new TreeSet<>();
        // Section 6.
        TreeSet<String> extensionTypes = new TreeSet<>();
        TreeSet<String> proxyInterfaces = new TreeSet<>();
        TreeSet<String> constructed = new TreeSet<>();
        TreeSet<String> fieldHolders = new TreeSet<>();
        TreeSet<String> publicFieldHolders = new TreeSet<>();
        java.util.TreeMap<String, TreeSet<String>> wrapperFields = new java.util.TreeMap<>();
        TreeSet<String> lz4Types = new TreeSet<>();
        TreeSet<String> namedByString = new TreeSet<>();
        try (JarFile jar = new JarFile(args[0])) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith("META-INF/") && name.endsWith(".xml")) {
                    collectServiceImplementations(jar, entry, types);
                    collectDescriptorSurfaces(jar, entry, extensionTypes, proxyInterfaces, constructed, fieldHolders);
                    continue;
                }
                if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    scanBytecode(jar, entry, extensionTypes, proxyInterfaces, publicFieldHolders, wrapperFields, namedByString);
                    if ((name.startsWith("net/jpountz/lz4/") || name.startsWith("net/jpountz/xxhash/"))
                            && (name.contains("Java") || name.contains("JNI")) && !name.contains("$")) {
                        lz4Types.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
                    }
                }
                if (name.startsWith("META-INF/services/") && !name.endsWith("/")) {
                    collectServiceLoaderProviders(jar, entry, types);
                    continue;
                }
                if (!name.endsWith(".class") || name.contains("$")) {
                    continue;
                }
                if (name.startsWith(CAFFEINE_PACKAGE)) {
                    String type = name.substring(0, name.length() - ".class".length()).replace('/', '.');
                    if (isCaffeineGenerated(type)) {
                        caffeineTypes.add(type);
                    }
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
        // A Caffeine class is also a service or PSI entry only by accident;
        // it keeps the stronger (fields too) registration below.
        types.removeAll(caffeineTypes);
        // Section 6, reduced to what THIS jar carries: a name the jar has no
        // bytecode for would fail the image build, not the run.
        java.util.function.Predicate<String> inJar = t -> {
            try (JarFile j = new JarFile(args[0])) {
                return j.getEntry(t.replace('.', '/') + ".class") != null;
            } catch (IOException e) {
                return false;
            }
        };
        for (TreeSet<String> set : List.of(extensionTypes, proxyInterfaces, constructed, fieldHolders, publicFieldHolders, lz4Types, namedByString)) {
            set.removeIf(inJar.negate());
        }
        wrapperFields.keySet().removeIf(inJar.negate());
        // One entry per type: the members each rule needs, merged.
        java.util.TreeMap<String, TreeSet<String>> platform = new java.util.TreeMap<>();
        java.util.function.BiConsumer<String, String> want = (t, member) ->
            platform.computeIfAbsent(t, k -> new TreeSet<>()).add(member);
        for (String t : extensionTypes) { want.accept(t, "type"); arrayTypes.add(t + "[]"); }
        for (String t : constructed) want.accept(t, "\"allDeclaredConstructors\": true");
        for (String t : fieldHolders) want.accept(t, "\"allDeclaredFields\": true");
        for (String t : publicFieldHolders) want.accept(t, "\"allPublicFields\": true");
        for (String t : namedByString) {
            want.accept(t, "\"allDeclaredConstructors\": true");
            want.accept(t, "\"allPublicFields\": true");
        }
        for (String t : lz4Types) {
            want.accept(t, "\"allDeclaredConstructors\": true");
            want.accept(t, "\"allPublicFields\": true");
        }
        for (var e : wrapperFields.entrySet()) {
            StringBuilder f = new StringBuilder("\"fields\": [");
            int k = 0;
            for (String field : e.getValue()) f.append(k++ == 0 ? "" : ", ").append("{ \"name\": \"").append(field).append("\" }");
            want.accept(e.getKey(), f.append("]").toString());
        }
        platform.keySet().removeAll(caffeineTypes);
        // A PSI/service type already emitted keeps its entry; the platform
        // rule's members are added to it rather than a second entry.
        TreeSet<String> constructedToo = new TreeSet<>(types);
        constructedToo.retainAll(platform.keySet());
        types.removeAll(platform.keySet());
        int total = types.size() + arrayTypes.size() + caffeineTypes.size() + platform.size() + proxyInterfaces.size();
        int i = 0;
        for (String type : types) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": \"" + type + "\", \"allDeclaredConstructors\": true }" + suffix);
        }
        for (String type : arrayTypes) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": \"" + type + "\" }" + suffix);
        }
        for (String type : caffeineTypes) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": \"" + type
                + "\", \"allDeclaredConstructors\": true, \"allDeclaredFields\": true }" + suffix);
        }
        for (var e : platform.entrySet()) {
            String suffix = ++i == total ? "" : ",";
            StringBuilder line = new StringBuilder("    { \"type\": \"" + e.getKey() + "\"");
            if (constructedToo.contains(e.getKey())) line.append(", \"allDeclaredConstructors\": true");
            for (String member : e.getValue()) {
                if (member.equals("type")) continue;
                if (constructedToo.contains(e.getKey()) && member.contains("allDeclaredConstructors")) continue;
                line.append(", ").append(member);
            }
            lines.add(line.append(" }").append(suffix).toString());
        }
        for (String iface : proxyInterfaces) {
            String suffix = ++i == total ? "" : ",";
            lines.add("    { \"type\": { \"proxy\": [\"" + iface + "\"] } }" + suffix);
        }
        lines.add("  ]");
        lines.add("}");
        Files.write(Path.of(args[1]), String.join("\n", lines).concat("\n").getBytes("UTF-8"));
        System.out.println("wrote " + types.size() + " PSI reflection entries, "
            + arrayTypes.size() + " array entries, "
            + caffeineTypes.size() + " Caffeine generated classes, "
            + platform.size() + " platform by-name types (" + extensionTypes.size() + " extension points, "
            + constructed.size() + " listeners, " + fieldHolders.size() + " stub holders, "
            + publicFieldHolders.size() + " K1 holders, " + wrapperFields.size() + " wrapper-field owners, "
            + lz4Types.size() + " lz4/xxhash) and " + proxyInterfaces.size() + " listener proxies to " + args[1]);
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
        // The SERVICE INTERFACE too: loaders check providers against it by
        // name (`DefaultErrorMessages` does `Class.forName` then
        // `Extension.class.isAssignableFrom`).
        String service = entry.getName().substring("META-INF/services/".length());
        if (jar.getEntry(service.replace('.', '/') + ".class") != null) {
            types.add(service);
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

    private static final java.util.regex.Pattern EXTENSION_POINT =
        java.util.regex.Pattern.compile("<extensionPoint\\b[^>]*>");
    private static final java.util.regex.Pattern LISTENER =
        java.util.regex.Pattern.compile("<listener\\b[^>]*>");
    private static final java.util.regex.Pattern STUB_HOLDER =
        java.util.regex.Pattern.compile("<stubElementTypeHolder\\b[^>]*>");

    private static String attribute(String element, String name) {
        var m = java.util.regex.Pattern.compile("\\b" + name + "\\s*=\\s*\"([A-Za-z_][\\w.$]*)\"").matcher(element);
        return m.find() ? m.group(1) : null;
    }

    /** Section 6 surfaces a plugin descriptor declares. */
    private static void collectDescriptorSurfaces(JarFile jar, JarEntry entry, TreeSet<String> extensionTypes,
            TreeSet<String> proxies, TreeSet<String> constructed, TreeSet<String> fieldHolders) throws IOException {
        String xml;
        try (var in = jar.getInputStream(entry)) {
            xml = new String(in.readAllBytes(), "UTF-8");
        }
        for (var m = EXTENSION_POINT.matcher(xml); m.find();) {
            for (String a : new String[] {"interface", "beanClass"}) {
                String t = attribute(m.group(), a);
                if (t != null) extensionTypes.add(t);
            }
        }
        for (var m = LISTENER.matcher(xml); m.find();) {
            String cls = attribute(m.group(), "class");
            String topic = attribute(m.group(), "topic");
            if (cls != null) constructed.add(cls);
            if (topic != null) proxies.add(topic);
        }
        for (var m = STUB_HOLDER.matcher(xml); m.find();) {
            String cls = attribute(m.group(), "class");
            if (cls != null) fieldHolders.add(cls);
        }
    }

    /** Calls whose preceding class literal is an extension point's type. */
    private static final java.util.Set<String> EXTENSION_POINT_CALLS = java.util.Set.of(
        "registerExtensionPoint", "registerApplicationExtensionPoint", "registerApplicationDynamicExtensionPoint",
        "registerDynamicExtensionPoint", "registerProjectExtensionPoint",
        // Services registered in code by class (`registerService(X.class,
        // impl)`): the container keys and reloads them by name, too.
        "registerService", "registerServiceInstance", "registerApplicationService", "registerProjectService");
    private static final java.util.Set<String> EXTENSION_DESCRIPTORS = java.util.Set.of(
        "org/jetbrains/kotlin/extensions/ProjectExtensionDescriptor", "org/jetbrains/kotlin/extensions/ApplicationExtensionDescriptor");
    /** Owners and names whose preceding class literal becomes a dynamic proxy. */
    private static final java.util.Set<String> PROXY_CALLS = java.util.Set.of(
        "com/intellij/util/messages/Topic.<init>", "com/intellij/util/messages/Topic.create",
        "com/intellij/util/messages/Topic$Companion.create", "com/intellij/util/EventDispatcher.create",
        "com/intellij/util/ReflectionUtil.proxy");
    private static final java.util.Set<String> PUBLIC_FIELD_READERS = java.util.Set.of(
        "org/jetbrains/kotlin/util/slicedMap/BasicWritableSlice.initSliceDebugNames",
        "org/jetbrains/kotlin/diagnostics/Errors$Initializer.initializeFactoryNames",
        "org/jetbrains/kotlin/diagnostics/Errors$Initializer.initializeFactoryNamesAndDefaultErrorMessages");
    /** (class literal, field name) wrappers build-time folding cannot see through. */
    private static final java.util.Set<String> FIELD_WRAPPERS = java.util.Set.of(
        "com/github/benmanes/caffeine/base/UnsafeAccess.objectFieldOffset",
        "com/github/benmanes/caffeine/cache/UnsafeAccess.objectFieldOffset",
        "io/opentelemetry/internal/shaded/jctools/util/UnsafeAccess.fieldOffset");

    /**
     * One class's call sites for the section-6 rules: the class literal (and,
     * for a field wrapper, the field-name constant) nearest before the call,
     * within a short window, the way javac and kotlinc lay the arguments out.
     */
    private static void scanBytecode(JarFile jar, JarEntry entry, TreeSet<String> extensionTypes, TreeSet<String> proxies,
            TreeSet<String> publicFieldHolders, java.util.Map<String, TreeSet<String>> wrapperFields,
            TreeSet<String> namedByString) throws IOException {
        byte[] bytes;
        try (var in = jar.getInputStream(entry)) {
            bytes = in.readAllBytes();
        }
        // Cheap pre-filter: the constant pool must name one of the targets.
        String pool = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        if (!(pool.contains("ExtensionPoint") || pool.contains("ExtensionDescriptor") || pool.contains("com/intellij/util/messages/Topic")
                || pool.contains("EventDispatcher") || pool.contains("ReflectionUtil") || pool.contains("initSliceDebugNames")
                || pool.contains("initializeFactoryNames") || pool.contains("UnsafeAccess")
                || pool.contains("forName") || pool.contains("loadClass"))) {
            return;
        }
        var node = new org.jetbrains.org.objectweb.asm.tree.ClassNode();
        try {
            new org.jetbrains.org.objectweb.asm.ClassReader(bytes).accept(node, 0);
        } catch (Throwable t) {
            return;
        }
        for (var method : node.methods) {
            if (method.instructions == null) continue;
            // A method that loads a class BY NAME: every string constant in
            // it that names a class is a candidate (`listOf("a.B", "c.D")
            // .forEach { Class.forName(it) }`, DefaultErrorMessages). Names the
            // jar has no class for are dropped by the caller.
            boolean loadsByName = false;
            java.util.List<String> strings = new java.util.ArrayList<>();
            for (var insn : method.instructions) {
                if (insn instanceof org.jetbrains.org.objectweb.asm.tree.MethodInsnNode m
                        && ((m.owner.equals("java/lang/Class") && m.name.equals("forName"))
                            || (m.name.equals("loadClass") && m.desc.startsWith("(Ljava/lang/String;")))) loadsByName = true;
                if (insn instanceof org.jetbrains.org.objectweb.asm.tree.LdcInsnNode l && l.cst instanceof String str
                        && str.matches("[A-Za-z_][\\w$]*(\\.[A-Za-z_][\\w$]*)+")) strings.add(str);
            }
            if (loadsByName) namedByString.addAll(strings);
            java.util.ArrayDeque<Object> window = new java.util.ArrayDeque<>();
            for (var insn : method.instructions) {
                if (insn instanceof org.jetbrains.org.objectweb.asm.tree.LdcInsnNode ldc) {
                    window.addLast(ldc.cst);
                    if (window.size() > 10) window.removeFirst();
                    continue;
                }
                if (!(insn instanceof org.jetbrains.org.objectweb.asm.tree.MethodInsnNode call)) continue;
                String key = call.owner + "." + call.name;
                String literal = null;
                String string = null;
                for (var it = window.descendingIterator(); it.hasNext();) {
                    Object c = it.next();
                    if (literal == null && c instanceof org.jetbrains.org.objectweb.asm.Type t
                            && t.getSort() == org.jetbrains.org.objectweb.asm.Type.OBJECT) literal = t.getClassName();
                    if (string == null && c instanceof String str) string = str;
                }
                boolean matched = true;
                if (EXTENSION_POINT_CALLS.contains(call.name)
                        || (call.name.equals("<init>") && EXTENSION_DESCRIPTORS.contains(call.owner))) {
                    if (literal != null) extensionTypes.add(literal);
                } else if (PROXY_CALLS.contains(key)) {
                    if (literal != null) proxies.add(literal);
                } else if (PUBLIC_FIELD_READERS.contains(key)) {
                    if (literal != null) publicFieldHolders.add(literal);
                } else if (FIELD_WRAPPERS.contains(key)) {
                    if (literal != null && string != null) wrapperFields.computeIfAbsent(literal, k -> new TreeSet<>()).add(string);
                } else {
                    matched = false;
                }
                // A call consumes the window only when a rule used it: the
                // arguments of an unrelated call are not the next rule's.
                if (matched) window.clear();
            }
        }
    }

    private static final String CAFFEINE_PACKAGE = "com/github/benmanes/caffeine/cache/";

    /**
     * True for a class Caffeine's factories load by name, or one whose fields
     * those classes bind: a generated (all-capitals simple name) subclass of
     * {@code BoundedLocalCache} or implementation of {@code Node}, abstract
     * parents included because they declare fields the concrete class's
     * {@code VarHandle}s name. The shape check keeps a hand-written class
     * that happens to be named in capitals out.
     */
    private static boolean isCaffeineGenerated(String type) {
        String simple = type.substring(type.lastIndexOf('.') + 1);
        if (!simple.matches("[A-Z]+")) {
            return false;
        }
        try {
            ClassLoader loader = GenPsiReflection.class.getClassLoader();
            Class<?> clazz = Class.forName(type, false, loader);
            Class<?> cache = Class.forName("com.github.benmanes.caffeine.cache.BoundedLocalCache", false, loader);
            Class<?> node = Class.forName("com.github.benmanes.caffeine.cache.Node", false, loader);
            return cache.isAssignableFrom(clazz) || node.isAssignableFrom(clazz);
        } catch (Throwable t) {
            return false;
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

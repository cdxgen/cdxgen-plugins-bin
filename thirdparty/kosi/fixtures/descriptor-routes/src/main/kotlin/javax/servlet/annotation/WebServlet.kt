// The framework's own annotation, at its real fully-qualified name.
package javax.servlet.annotation

// servlet-api by shape: `value` and `urlPatterns` are String[] aliases.
@Target(AnnotationTarget.CLASS) annotation class WebServlet(vararg val value: String = [], val urlPatterns: Array<String> = [], val name: String = "")

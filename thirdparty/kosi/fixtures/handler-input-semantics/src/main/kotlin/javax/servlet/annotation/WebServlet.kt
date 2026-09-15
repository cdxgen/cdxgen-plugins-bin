// The framework's own annotation, at its real fully-qualified name.
package javax.servlet.annotation

@Target(AnnotationTarget.CLASS) annotation class WebServlet(val value: String = "")

/** The filter's annotation — the source-level twin of `<filter-mapping>`. */
@Target(AnnotationTarget.CLASS) annotation class WebFilter(val value: String = "")

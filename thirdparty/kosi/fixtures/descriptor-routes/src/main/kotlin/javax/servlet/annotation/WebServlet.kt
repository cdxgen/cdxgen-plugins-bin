// The framework's own annotation, at its real fully-qualified name.
package javax.servlet.annotation

@Target(AnnotationTarget.CLASS) annotation class WebServlet(val value: String = "")

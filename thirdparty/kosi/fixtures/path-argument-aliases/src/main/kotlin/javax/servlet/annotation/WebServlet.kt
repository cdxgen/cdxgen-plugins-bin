// servlet-api by shape: `value` and `urlPatterns` are String[] aliases.
package javax.servlet.annotation

@Target(AnnotationTarget.CLASS) annotation class WebServlet(vararg val value: String = [], val urlPatterns: Array<String> = [], val name: String = "")

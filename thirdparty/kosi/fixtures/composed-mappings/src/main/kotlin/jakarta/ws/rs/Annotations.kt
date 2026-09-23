package jakarta.ws.rs

annotation class Path(val value: String)
annotation class GET
@Target(AnnotationTarget.ANNOTATION_CLASS) annotation class HttpMethod(val value: String)

// `@Valid` asks for VALIDATION, not injection: Spring binds a validated
// command object exactly as it binds a bare one.
package jakarta.validation

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class Valid

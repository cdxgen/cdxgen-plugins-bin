// Spring's @Bean and @Configuration at their real package, added for the
// negative half (the parameter-form binding). @Configuration is already a
// DiStereotypes entry; @Bean is the binding-method annotation.
package org.springframework.context.annotation

@Target(AnnotationTarget.CLASS)
annotation class Configuration

@Target(AnnotationTarget.FUNCTION)
annotation class Bean

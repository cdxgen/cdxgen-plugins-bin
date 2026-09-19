// Spring's @Bean and @Configuration at their real package. @Bean is the
// binding-method annotation of the Spring half; @Configuration marks the
// module class (and is itself a DiStereotypes entry).
package org.springframework.context.annotation

@Target(AnnotationTarget.CLASS)
annotation class Configuration

@Target(AnnotationTarget.FUNCTION)
annotation class Bean

// Spring's model holder at its real package: a parameter the FRAMEWORK
// supplies, which is why it is in spring-mvc's contextParameterTypes.
package org.springframework.ui

interface Model {
    fun addAttribute(value: Any): Model
}

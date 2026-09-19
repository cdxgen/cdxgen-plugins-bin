// Spring's model holder, a framework-SUPPLIED argument: one row of the
// argument table, declared here at its real package.
package org.springframework.ui

interface Model {
    fun render(): String
}

// Exposed's transaction/SQL surface at its real package (the shapes used).
package org.jetbrains.exposed.sql

class Column<T>

fun <T> Column<T>.exec(sql: String): List<T> = error("stub")

class Transaction {
    fun exec(sql: String): Int = error("stub")
}

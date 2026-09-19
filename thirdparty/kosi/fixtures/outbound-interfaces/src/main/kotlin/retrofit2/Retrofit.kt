// Retrofit's builder surface, at its real package, the shapes used.
package retrofit2

class Retrofit {
    class Builder {
        fun baseUrl(url: String): Builder = this
        fun build(): Retrofit = Retrofit()
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> create(service: Class<T>): T = null as T
}

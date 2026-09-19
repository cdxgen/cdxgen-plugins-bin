// Android's cross-component channel at its real package, the shapes used.
package android.content

class Intent {
    fun putExtra(name: String, value: String): Intent = this
    fun getStringExtra(name: String): String = ""
    fun getDataString(): String = ""
}

class Bundle {
    fun putString(name: String, value: String) {}
    fun getString(name: String): String = ""
}

abstract class ContentProvider {
    abstract fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Any?
}

class Uri

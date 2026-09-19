package android.database.sqlite

class SQLiteDatabase {
    companion object {
        fun openOrCreateDatabase(path: String, factory: Any?): SQLiteDatabase = SQLiteDatabase()
    }
    fun rawQuery(sql: String, args: Array<String>?): Unit = Unit
}

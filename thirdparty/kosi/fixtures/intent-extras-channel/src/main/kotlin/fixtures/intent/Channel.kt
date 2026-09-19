// P26 §1.4 — Android's cross-component channel.
//
// Extras OUT of one component and INTO another: the WRITE half is
// `putExtra` (a pack effect — the taint rides the intent object), the READ
// half is the existing `getStringExtra` source; between the components
// there is no call edge, which is why the read is modelled as a source.
// `getIntent()` is the inbound half of the same channel — the intent that
// STARTED this component. A ContentProvider's query() arguments are inputs
// any app on the device can supply: the provider framework entry seeds them
// like every other handler.
//
// kosi:want flow source=android-intent sink=sql-query fn=~receiverReadsExtra known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=sql-query fn=~providerQuery known-fail=syntax:1
// kosi:want-not flow source=android-intent sink=sql-query fn=~receiverReadsLiteral
// kosi:want-not diagnostic code=parse-error
package fixtures.intent

import android.app.Activity
import android.content.ContentProvider
import android.content.Intent
import android.content.Uri
import android.database.sqlite.SQLiteDatabase

class SenderActivity : Activity() {
    fun sendExtra() {
        val intent = Intent()
        // The WRITE half: the pack's effect carries the value on the intent.
        intent.putExtra("secret", readLine() ?: "")
        startActivity(intent)
    }
}

class ReceiverActivity : Activity() {
    // The READ half: a source, because the writer is another component.
    fun receiverReadsExtra(db: SQLiteDatabase) {
        val value = intent.getStringExtra("secret")
        db.rawQuery("SELECT * FROM notes WHERE body = '" + value + "'", null)
    }

    fun receiverReadsLiteral(db: SQLiteDatabase) {
        db.rawQuery("SELECT * FROM notes WHERE body = 'fixed'", null)
    }
}

class NotesProvider : ContentProvider() {
    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Any? {
        // The seeded parameters are attacker input: any app on the device
        // can call a provider's query.
        providerQuery(selection ?: "")
        return null
    }

    private fun providerQuery(selection: String) {
        val db = SQLiteDatabase.openOrCreateDatabase("/data/notes.db", null)
        db.rawQuery("SELECT * FROM notes WHERE $selection", null)
    }
}

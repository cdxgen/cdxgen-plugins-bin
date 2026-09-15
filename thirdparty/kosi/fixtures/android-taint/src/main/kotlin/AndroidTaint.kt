// The shapes that carry real Android vulnerabilities, and the one lowering
// rule that makes them visible at all.
//
// Kotlin reads a Java getter as a property: `editText.text` IS
// `editText.getText()` on the JVM, and `intent.data` is `getData()`. The
// lowering used to emit a FIELD READ for those, whose path is the local
// variable's name (`ve.text`) — carrying neither the declaring type nor the
// fact that a method runs. Model packs match callee symbols, so every
// getter-backed API was invisible to them. That is the dominant way input
// enters an Android app, which is why two intentionally-vulnerable Kotlin
// apps (AndroGoat, InsecureShop) reported ZERO findings before this.
//
// The stub jar in libs/ carries just the platform classes these shapes
// name; the real android.jar is 100MB and the fixture needs ten classes.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// Positives, one per modelled Android shape. Each is a flow a collapsing
// implementation would lose, and each is a vulnerability class shipped in a
// real app in this corpus.
// kosi:want flow source=untrusted-input sink=sql-query fn=~sqlInjectionFromTextField known-fail=syntax:1
// kosi:want flow source=android-intent sink=webview-load fn=~webViewFromIntentExtra known-fail=syntax:1
// kosi:want flow source=android-intent sink=webview-load fn=~webViewFromDeepLinkProperty known-fail=syntax:1
// kosi:want flow source=untrusted-input sink=insecure-storage fn=~secretIntoSharedPrefs known-fail=syntax:1
//
// The near-misses: the SAME sinks, reached by values that are not tainted.
// An implementation that marked every getter's result tainted, or every
// sink argument reachable, would report on these.
// kosi:want-not flow source=~ sink=~ fn=~sqlFromLiteral
// kosi:want-not flow source=~ sink=~ fn=~webViewFromLiteral
package fixtures.androidtaint

import android.app.Activity
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.webkit.WebView
import android.widget.EditText

/**
 * The property read is the source: `field.text` lowers to
 * `android.widget.EditText.getText`, which the pack names.
 */
fun sqlInjectionFromTextField(field: EditText, db: SQLiteDatabase) {
    val query = "SELECT * FROM users WHERE name = '" + field.text.toString() + "'"
    db.rawQuery(query, null)
}

/** The near-miss: the same sink, a constant query. */
fun sqlFromLiteral(db: SQLiteDatabase) {
    db.rawQuery("SELECT * FROM users WHERE name = 'fixed'", null)
}

/** IPC input through an explicit getter call. */
class IntentExtraActivity : Activity() {
    fun webViewFromIntentExtra(web: WebView) {
        web.loadUrl(intent.getStringExtra("url"))
    }

    /**
     * The deep-link shape, and the one that only works because of the
     * lowering rule: `intent.dataString` is a synthetic Java property, as
     * is `intent` itself (`getIntent()`).
     */
    fun webViewFromDeepLinkProperty(web: WebView) {
        web.loadUrl(intent.dataString)
    }

    /** The near-miss: the same sink, a constant URL. */
    fun webViewFromLiteral(web: WebView) {
        web.loadUrl("https://example.invalid/fixed")
    }
}

/** User input written into an insecure store. */
fun secretIntoSharedPrefs(field: EditText, prefs: SharedPreferences) {
    prefs.edit().putString("password", field.text.toString()).commit()
}

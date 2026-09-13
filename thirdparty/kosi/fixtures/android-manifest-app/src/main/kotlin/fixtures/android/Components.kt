// The components the manifest names, each with its lifecycle entry. The
// handler symbol must be a real node in the call graph: onCreate,
// onReceive, onStartCommand and query are the component entries.
// kosi:want endpoint framework=android path=~android.intent.action.MAIN fn=~MainActivity.onCreate mode=resolved
// kosi:want endpoint framework=android path=~android.intent.action.VIEW fn=~DeepLinkActivity.onCreate mode=resolved
// kosi:want endpoint framework=android path=~PackageReceiver fn=~PackageReceiver.onReceive mode=resolved
// kosi:want endpoint framework=android path=~SyncService fn=~SyncService.onStartCommand mode=resolved
// kosi:want endpoint framework=android path=~MetaProvider fn=~MetaProvider.query mode=resolved
// kosi:want-not endpoint framework=android path=~GhostActivity mode=resolved
// kosi:want-not endpoint framework=android fn=~UnregisteredActivity mode=resolved
package fixtures.android

class MainActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
    }
}

class DeepLinkActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
    }
}

class PackageReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: android.content.Context, intent: android.content.Intent) {}
}

class SyncService : android.app.Service() {
    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int = 0
}

class MetaProvider : android.content.ContentProvider() {
    override fun query(uri: android.net.Uri, projection: Array<String>?, selection: String?, args: Array<String>?, order: String?): android.database.Cursor? = null
    override fun onCreate(): Boolean = true
    override fun getType(uri: android.net.Uri): String? = null
    override fun insert(uri: android.net.Uri, values: android.content.ContentValues?): android.net.Uri? = null
    override fun delete(uri: android.net.Uri, selection: String?, args: Array<String>?): Int = 0
    override fun update(uri: android.net.Uri, values: android.content.ContentValues?, selection: String?, args: Array<String>?): Int = 0
}

// Declared but NOT in the manifest: no manifest entry, no endpoint.
class UnregisteredActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
    }
}

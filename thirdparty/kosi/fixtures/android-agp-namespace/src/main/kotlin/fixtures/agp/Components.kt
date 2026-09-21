// An Android module in the modern AGP layout: the manifest carries no
// `package` attribute and the package comes from the build file's
// `namespace`. Each component below is named relatively in the manifest, so
// none of them can be matched without reading that namespace.
//
// kosi:want endpoint framework=android path=~android.intent.action.MAIN fn=~HomeActivity.onCreate mode=resolved
//
// A nested component: the manifest says `Screens$DetailActivity`, the
// Kotlin declaration says `Screens.DetailActivity`. One class, two
// spellings; matching them literally leaves every nested component unmatched.
// kosi:want endpoint framework=android path=~DetailActivity fn=~DetailActivity.onCreate mode=resolved
//
// A Java component. Java declarations do not enter the KIR, so a lifecycle
// method that exists only in Java has to be found in the declaration table.
// kosi:want endpoint framework=android path=~JavaReceiver fn=~JavaReceiver.onReceive mode=resolved
//
// A class the analysed tree does not hold stays published and stays marked:
// the manifest is real, its behaviour was not read.
// kosi:want diagnostic code=endpoint-unsubstantiated mode=resolved
// kosi:want-not endpoint framework=android fn=~GhostActivity mode=resolved
package fixtures.agp

class HomeActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
    }
}

class Screens {

    class DetailActivity : android.app.Activity() {
        override fun onCreate(savedInstanceState: android.os.Bundle?) {
            super.onCreate(savedInstanceState)
        }
    }

    /**
     * Declares no lifecycle override — it inherits the framework's. The
     * class was read, so the endpoint is substantiated; there is simply no
     * handler of ours to name.
     */
    class InheritedActivity : android.app.Activity()
}

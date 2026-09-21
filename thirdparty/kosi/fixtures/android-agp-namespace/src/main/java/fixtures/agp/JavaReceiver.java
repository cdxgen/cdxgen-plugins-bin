package fixtures.agp;

/**
 * A broadcast receiver written in Java. Its lifecycle method exists only in
 * the declaration table, never in the KIR.
 */
public class JavaReceiver extends android.content.BroadcastReceiver {

    @Override
    public void onReceive(android.content.Context context, android.content.Intent intent) {
    }
}

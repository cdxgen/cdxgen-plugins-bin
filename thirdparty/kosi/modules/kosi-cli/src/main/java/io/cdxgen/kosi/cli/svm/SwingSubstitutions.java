package io.cdxgen.kosi.cli.svm;

import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;

/**
 * Keeps the native image off the AWT natives at RUN TIME.
 *
 * <p>kosi is a headless CLI, but intellij-core's {@code MockApplication}
 * schedules one runnable through Swing while extension points register
 * ({@code BinaryFileTypeDecompilers.notifyDecompilerSetChange} ->
 * {@code SwingUtilities.invokeLater} -> {@code EventQueue.invokeLater}), and
 * that touches {@code java.awt.Toolkit.<clinit>}, whose first act is
 * {@code System.loadLibrary("awt")}.
 *
 * <p>In a native image that library is NOT inside the binary: native-image
 * emits {@code libawt.dylib}/{@code libawt*.so} BESIDE the executable as
 * jdk_library artifacts, and the image's {@code java.library.path} is
 * {@code [.]}. So the binary works in its build directory and nowhere else —
 * and kosi ships exactly one file. Measured on the published darwin-arm64 and
 * linux-arm64 binaries: every component reported
 * {@code unavailable: Can't load library: awt} / {@code Could not initialize
 * class sun.awt.X11.XToolkit}, and {@code analyze} could not even parse.
 *
 * <p>The runnable is a notification with no ordering requirement, and there
 * is no event loop in a CLI to defer it to, so running it on the calling
 * thread is both correct and the only way it ever runs. With Toolkit never
 * initialised, no AWT native is loaded on any platform.
 */
@TargetClass(className = "java.awt.EventQueue")
final class Target_java_awt_EventQueue {

    @Substitute
    public static void invokeLater(Runnable runnable) {
        runnable.run();
    }

    /**
     * The Analysis API asks this on EVERY {@code analyze {}} entry
     * ({@code KaBaseAnalysisPermissionChecker.isProhibitedEdtAnalysis} ->
     * {@code MockApplication.isDispatchThread}), and the JDK answers it by
     * touching {@code Toolkit} — the same fatal load. A CLI has no event
     * dispatch thread, so the answer is false, always, and answering it
     * without AWT is what makes the RESOLVED tier work outside a build
     * directory.
     */
    @Substitute
    public static boolean isDispatchThread() {
        return false;
    }
}

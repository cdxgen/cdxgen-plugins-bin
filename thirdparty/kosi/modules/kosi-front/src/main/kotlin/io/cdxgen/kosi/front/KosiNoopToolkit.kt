package io.cdxgen.kosi.front

import java.awt.EventQueue
import java.awt.Toolkit
import java.awt.image.ColorModel
import java.awt.image.ImageObserver
import java.awt.image.ImageProducer
import java.awt.Dialog
import java.awt.Dimension
import java.awt.Font
import java.awt.FontMetrics
import java.awt.Frame
import java.awt.Image
import java.awt.datatransfer.Clipboard
import java.net.URL
import java.util.Properties

/**
 * A do-nothing AWT toolkit for native images. The IntelliJ platform's mock
 * application schedules one runnable through `SwingUtilities.invokeLater`
 * while the application environment is being created; on a JVM that is
 * harmless, but inside a GraalVM image the macOS AWT toolkit is not linked
 * (`liblwawt` natives are absent), so the first `Toolkit.getDefaultToolkit`
 * dies with `NoClassDefFoundError: java/awt/event/InputEvent`. kosi never
 * renders anything, so selecting this toolkit via the documented
 * `awt.toolkit` system property keeps the platform happy without any AWT
 * natives. Selected only when running as a native image (see
 * [AnalysisEnvironment]).
 */
@Suppress("DEPRECATION", "UNUSED_PARAMETER", "RedundantOverride")
class KosiNoopToolkit : Toolkit() {

    private val eventQueue = EventQueue()

    override fun getScreenSize(): Dimension = Dimension(1920, 1080)

    override fun getScreenResolution(): Int = 96

    override fun getColorModel(): ColorModel = ColorModel.getRGBdefault()

    @Deprecated("Deprecated in Java")
    override fun getFontList(): Array<String> = emptyArray()

    override fun getFontMetrics(font: Font): FontMetrics = object : FontMetrics(font) {
        override fun getLeading(): Int = 0
        override fun getAscent(): Int = font.size
        override fun getDescent(): Int = 0
    }

    override fun sync() = Unit

    override fun getImage(filename: String): Image? = null

    override fun getImage(url: URL): Image? = null

    override fun createImage(filename: String): Image? = null

    override fun createImage(url: URL): Image? = null

    override fun prepareImage(image: Image, width: Int, height: Int, observer: ImageObserver?): Boolean = true

    override fun checkImage(image: Image, width: Int, height: Int, observer: ImageObserver?): Int = 0

    override fun createImage(producer: ImageProducer): Image? = null

    override fun createImage(imagedata: ByteArray, imageoffset: Int, imagelength: Int): Image? = null

    override fun getPrintJob(frame: Frame, jobtitle: String, props: Properties): java.awt.PrintJob? = null

    override fun beep() = Unit

    override fun getSystemClipboard(): Clipboard = object : Clipboard("kosi-noop") {}

    override fun getSystemEventQueueImpl(): java.awt.EventQueue = eventQueue

    override fun mapInputMethodHighlight(highlight: java.awt.im.InputMethodHighlight): MutableMap<java.awt.font.TextAttribute, *>? = null

    override fun isModalityTypeSupported(type: Dialog.ModalityType): Boolean = false

    override fun isModalExclusionTypeSupported(exclusionType: Dialog.ModalExclusionType): Boolean = false


    companion object {
        const val PROPERTY: String = "awt.toolkit"
        const val CLASS_NAME: String = "io.cdxgen.kosi.front.KosiNoopToolkit"
    }
}

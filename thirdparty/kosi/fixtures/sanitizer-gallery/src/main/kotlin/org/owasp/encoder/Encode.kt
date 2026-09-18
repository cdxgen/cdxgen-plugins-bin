package org.owasp.encoder

/**
 * The real OWASP Java Encoder 1.2.x API shapes (Encode.java):
 * `public static String forHtml(String input)`,
 * `public static String forJavaScript(String input)`,
 * `public static String forUriComponent(String input)`. The fixture stubs
 * the shapes only.
 */
object Encode {
    fun forHtml(input: String?): String = input ?: ""

    fun forJavaScript(input: String?): String = input ?: ""

    fun forUriComponent(input: String?): String = input ?: ""
}

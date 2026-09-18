package org.apache.commons.lang3

/**
 * The real commons-lang3 3.x API shape (StringEscapeUtils.java):
 * `public static String escapeHtml4(String input)` — deprecated in 3.6 in
 * favour of commons-text, still present and still called by real code,
 * which is why the pack models it. The fixture stubs the shape only.
 */
object StringEscapeUtils {
    fun escapeHtml4(input: String?): String = input ?: ""
}

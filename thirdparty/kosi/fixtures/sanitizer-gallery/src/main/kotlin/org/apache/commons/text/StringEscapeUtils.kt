package org.apache.commons.text

/**
 * The real commons-text 1.x API shape (StringEscapeUtils.java):
 * `public static String escapeHtml4(String input)` — the replacement
 * project for the deprecated commons-lang3 family. The fixture stubs the
 * shape only.
 */
object StringEscapeUtils {
    fun escapeHtml4(input: String?): String = input ?: ""
}

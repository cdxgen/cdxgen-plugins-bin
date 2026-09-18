package org.springframework.web.util

/**
 * The real spring-web API shape (HtmlUtils.java):
 * `public static String htmlEscape(String input)`. The fixture stubs the
 * shape only.
 */
object HtmlUtils {
    fun htmlEscape(input: String?): String = input ?: ""
}

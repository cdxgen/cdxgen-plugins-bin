// spring-boot 3.x org.springframework.boot.web.servlet by shape:
// ServletRegistrationBean(servlet, vararg urlMappings), addUrlMappings,
// setUrlMappings(Collection); FilterRegistrationBean the same for filters.
package org.springframework.boot.web.servlet

import jakarta.servlet.Filter
import jakarta.servlet.http.HttpServlet

class ServletRegistrationBean<T : HttpServlet>(val servlet: T, vararg urlMappings: String) {
    fun addUrlMappings(vararg urlMappings: String) {}
    fun setUrlMappings(urlMappings: Collection<String>) {}
}

class FilterRegistrationBean<T : Filter>(val filter: T) {
    fun addUrlPatterns(vararg urlPatterns: String) {}
}

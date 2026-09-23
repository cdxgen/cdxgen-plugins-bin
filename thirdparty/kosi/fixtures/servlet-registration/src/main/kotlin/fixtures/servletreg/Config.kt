// Servlets registered in code, not in web.xml (docs.spring.io spring-boot
// "Registering Servlets, Filters, and Listeners as Spring Beans": "use the
// ServletRegistrationBean, FilterRegistrationBean ... classes"). The
// mapping is the bean's url mappings; the handlers are the servlet's own
// doGet/doPost overrides.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=servlet path=/reports/* method=GET fn=~ReportServlet.doGet mode=resolved
// kosi:want endpoint framework=servlet path=/reports/* method=POST fn=~ReportServlet.doPost mode=resolved
// kosi:want endpoint framework=servlet path=/legacy/reports method=GET fn=~ReportServlet.doGet mode=resolved
// kosi:want endpoint framework=servlet path=/admin/purge method=DELETE fn=~AdminServlet.doDelete mode=resolved
// kosi:want endpoint framework=servlet path=/admin/wipe method=DELETE fn=~AdminServlet.doDelete mode=resolved
// kosi:want endpoint framework=servlet path=/admin/apply method=DELETE fn=~AdminServlet.doDelete mode=resolved
// kosi:want endpoint framework=servlet path=/api/* anymethod=true fn=~AuditFilter.doFilter mode=resolved
//
// Negative half: a servlet only serves the verbs it overrides; one nothing
// registers serves nothing; a bean's patterns never leak to another bean.
// kosi:want-not endpoint framework=servlet path=/reports/* method=DELETE
// kosi:want-not endpoint framework=servlet fn=~IdleServlet
// kosi:want-not endpoint framework=servlet path=/admin/purge fn=~ReportServlet
// kosi:want-not endpoint framework=servlet path=/reports/* fn=~AdminServlet
package fixtures.servletreg

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServlet
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.boot.web.servlet.ServletRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

class ReportServlet : HttpServlet() {
    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {}
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {}
}

class AdminServlet : HttpServlet() {
    override fun doDelete(req: HttpServletRequest, resp: HttpServletResponse) {}
}

class AuditFilter : Filter {
    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {}
}

// Declared, never registered: serves nothing.
class IdleServlet : HttpServlet() {
    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {}
}

@Configuration
class ServletConfig {
    @Bean
    fun reports(): ServletRegistrationBean<ReportServlet> = ServletRegistrationBean(ReportServlet(), "/reports/*", "/legacy/reports")

    @Bean
    fun admin(): ServletRegistrationBean<AdminServlet> {
        val bean = ServletRegistrationBean(AdminServlet())
        bean.addUrlMappings("/admin/purge")
        bean.setUrlMappings(listOf("/admin/wipe"))
        return bean
    }

    @Bean
    fun adminApply(): ServletRegistrationBean<AdminServlet> =
        ServletRegistrationBean(AdminServlet()).apply { addUrlMappings("/admin/apply") }

    @Bean
    fun audit(): FilterRegistrationBean<AuditFilter> {
        val bean = FilterRegistrationBean(AuditFilter())
        bean.addUrlPatterns("/api/*")
        return bean
    }
}

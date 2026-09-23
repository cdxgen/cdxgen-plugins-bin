// jakarta.servlet-api 6.x by shape.
package jakarta.servlet.http

interface HttpServletRequest
interface HttpServletResponse

abstract class HttpServlet {
    protected open fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {}
    protected open fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {}
    protected open fun doDelete(req: HttpServletRequest, resp: HttpServletResponse) {}
}

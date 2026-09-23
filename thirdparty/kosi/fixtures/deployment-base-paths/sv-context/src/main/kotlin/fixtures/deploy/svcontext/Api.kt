package fixtures.deploy.svcontext

import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@WebServlet("/s")
class Svc {
    fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        response.sendRedirect(request.getParameter("to"))
    }
}

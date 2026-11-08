package jakarta.servlet.http

import jakarta.servlet.ServletRequest

interface HttpServletRequest : ServletRequest {
    fun getRequestURL(): StringBuffer
}

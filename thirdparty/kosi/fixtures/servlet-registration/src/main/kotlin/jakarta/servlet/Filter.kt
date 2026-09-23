package jakarta.servlet

interface ServletRequest
interface ServletResponse
interface FilterChain
interface Filter {
    fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain)
}

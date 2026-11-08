package org.springframework.web.servlet.support

class ServletUriComponentsBuilder {
    companion object {
        fun fromCurrentContextPath(): ServletUriComponentsBuilder = ServletUriComponentsBuilder()
        fun fromCurrentRequest(): ServletUriComponentsBuilder = ServletUriComponentsBuilder()
        fun fromCurrentRequestUri(): ServletUriComponentsBuilder = ServletUriComponentsBuilder()
        fun fromCurrentServletPath(): ServletUriComponentsBuilder = ServletUriComponentsBuilder()
    }
}

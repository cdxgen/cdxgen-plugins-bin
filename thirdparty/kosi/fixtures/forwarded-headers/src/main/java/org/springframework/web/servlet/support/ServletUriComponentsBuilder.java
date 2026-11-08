// Java, as Spring declares it: the factories are static methods of the class,
// so the callee FQN is ServletUriComponentsBuilder.fromCurrentRequest, not a
// Kotlin companion's.
package org.springframework.web.servlet.support;

import org.springframework.web.util.UriComponentsBuilder;

public class ServletUriComponentsBuilder extends UriComponentsBuilder {
    public static ServletUriComponentsBuilder fromCurrentContextPath() { return new ServletUriComponentsBuilder(); }
    public static ServletUriComponentsBuilder fromCurrentRequest() { return new ServletUriComponentsBuilder(); }
    public static ServletUriComponentsBuilder fromCurrentRequestUri() { return new ServletUriComponentsBuilder(); }
    public static ServletUriComponentsBuilder fromCurrentServletPath() { return new ServletUriComponentsBuilder(); }
}

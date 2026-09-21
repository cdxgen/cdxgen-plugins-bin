// dropwizard.io/en/stable/manual/auth.html: "annotate the parameter
// representing your principal with @Auth". The value is the AUTHENTICATED
// PRINCIPAL the framework injects after the authenticator ran — it is not
// request data, and treating it as such invents a source on every secured
// Dropwizard resource.
package io.dropwizard.auth

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class Auth

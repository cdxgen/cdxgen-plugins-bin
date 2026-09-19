// P27 §2 — Spring MVC's ARGUMENT BINDING rule, one handler per row of the
// framework's own table.
//
// The rule, verbatim from Spring's reference documentation
// (web/webmvc/mvc-controller/ann-methods/arguments.html):
//
//   "If a method argument is not matched to any of the earlier values in this
//    table and it is a simple type (as determined by BeanUtils#isSimpleProperty),
//    it is resolved as a @RequestParam. Otherwise, it is resolved as a
//    @ModelAttribute."
//
// So an UNANNOTATED parameter is always request data. Seeding only ANNOTATED
// parameters read 3 of spring-petclinic's 11 real flows (R174).
//
// The cost of over-correcting is this file. Every type in that table's
// framework-supplied rows must stay UNSEEDED, or every controller in the
// corpus grows a false finding through its Model or its BindingResult. Each
// want-not is one row: delete the matching `contextParameterTypes` entry and
// its handler reports.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_context_request_WebRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_context_request_NativeWebRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_ServletRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_ServletResponse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpServletRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpServletResponse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpSession
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_PushBuilder
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_ServletRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_ServletResponse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpServletRequest
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpServletResponse
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_jakarta_servlet_http_HttpSession
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_security_Principal
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_http_HttpMethod
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_util_Locale
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_util_TimeZone
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_time_ZoneId
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_io_InputStream
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_io_Reader
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_io_OutputStream
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_io_Writer
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_util_Map
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_kotlin_collections_Map
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_kotlin_collections_MutableMap
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_ui_Model
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_ui_ModelMap
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_servlet_mvc_support_RedirectAttributes
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_validation_Errors
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_validation_BindingResult
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_bind_support_SessionStatus
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_util_UriComponentsBuilder
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_web_bind_WebDataBinder
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_security_core_annotation_AuthenticationPrincipal
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_security_core_annotation_CurrentSecurityContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_web_bind_annotation_SessionAttribute
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_web_bind_annotation_RequestAttribute
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_beans_factory_annotation_Autowired
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_beans_factory_annotation_Value
// kosi:want flow source=untrusted-input sink=process-exec fn=~simpleTypeIsQueryParam mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~simpleTypeArrayIsQueryParam mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~complexTypeIsCommandObject mode=endpoint
package fixtures.springargs

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

/** A command object: not a simple type, so Spring binds it field by field. */
class SearchForm {
    var term: String = ""
}

@RestController
class ArgumentApi {

    @GetMapping("/ctx_org_springframework_web_context_request_WebRequest")
    fun ctx_org_springframework_web_context_request_WebRequest(arg: org.springframework.web.context.request.WebRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_web_context_request_NativeWebRequest")
    fun ctx_org_springframework_web_context_request_NativeWebRequest(arg: org.springframework.web.context.request.NativeWebRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_ServletRequest")
    fun ctx_jakarta_servlet_ServletRequest(arg: jakarta.servlet.ServletRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_ServletResponse")
    fun ctx_jakarta_servlet_ServletResponse(arg: jakarta.servlet.ServletResponse): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpServletRequest")
    fun ctx_jakarta_servlet_http_HttpServletRequest(arg: jakarta.servlet.http.HttpServletRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpServletResponse")
    fun ctx_jakarta_servlet_http_HttpServletResponse(arg: jakarta.servlet.http.HttpServletResponse): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpSession")
    fun ctx_jakarta_servlet_http_HttpSession(arg: jakarta.servlet.http.HttpSession): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_PushBuilder")
    fun ctx_jakarta_servlet_http_PushBuilder(arg: jakarta.servlet.http.PushBuilder): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_ServletRequest")
    fun ctx_jakarta_servlet_ServletRequest(arg: javax.servlet.ServletRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_ServletResponse")
    fun ctx_jakarta_servlet_ServletResponse(arg: javax.servlet.ServletResponse): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpServletRequest")
    fun ctx_jakarta_servlet_http_HttpServletRequest(arg: javax.servlet.http.HttpServletRequest): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpServletResponse")
    fun ctx_jakarta_servlet_http_HttpServletResponse(arg: javax.servlet.http.HttpServletResponse): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_jakarta_servlet_http_HttpSession")
    fun ctx_jakarta_servlet_http_HttpSession(arg: javax.servlet.http.HttpSession): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_security_Principal")
    fun ctx_java_security_Principal(arg: java.security.Principal): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_http_HttpMethod")
    fun ctx_org_springframework_http_HttpMethod(arg: org.springframework.http.HttpMethod): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_util_Locale")
    fun ctx_java_util_Locale(arg: java.util.Locale): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_util_TimeZone")
    fun ctx_java_util_TimeZone(arg: java.util.TimeZone): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_time_ZoneId")
    fun ctx_java_time_ZoneId(arg: java.time.ZoneId): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_io_InputStream")
    fun ctx_java_io_InputStream(arg: java.io.InputStream): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_io_Reader")
    fun ctx_java_io_Reader(arg: java.io.Reader): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_io_OutputStream")
    fun ctx_java_io_OutputStream(arg: java.io.OutputStream): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_io_Writer")
    fun ctx_java_io_Writer(arg: java.io.Writer): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_java_util_Map")
    fun ctx_java_util_Map(arg: java.util.Map<String, Any>): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_kotlin_collections_Map")
    fun ctx_kotlin_collections_Map(arg: kotlin.collections.Map<String, Any>): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_kotlin_collections_MutableMap")
    fun ctx_kotlin_collections_MutableMap(arg: kotlin.collections.MutableMap<String, Any>): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_ui_Model")
    fun ctx_org_springframework_ui_Model(arg: org.springframework.ui.Model): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_ui_ModelMap")
    fun ctx_org_springframework_ui_ModelMap(arg: org.springframework.ui.ModelMap): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_web_servlet_mvc_support_RedirectAttributes")
    fun ctx_org_springframework_web_servlet_mvc_support_RedirectAttributes(arg: org.springframework.web.servlet.mvc.support.RedirectAttributes): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_validation_Errors")
    fun ctx_org_springframework_validation_Errors(arg: org.springframework.validation.Errors): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_validation_BindingResult")
    fun ctx_org_springframework_validation_BindingResult(arg: org.springframework.validation.BindingResult): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_web_bind_support_SessionStatus")
    fun ctx_org_springframework_web_bind_support_SessionStatus(arg: org.springframework.web.bind.support.SessionStatus): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_web_util_UriComponentsBuilder")
    fun ctx_org_springframework_web_util_UriComponentsBuilder(arg: org.springframework.web.util.UriComponentsBuilder): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ctx_org_springframework_web_bind_WebDataBinder")
    fun ctx_org_springframework_web_bind_WebDataBinder(arg: org.springframework.web.bind.WebDataBinder): Process =
        ProcessBuilder(arg.toString()).start()

    @GetMapping("/ann_AuthenticationPrincipal")
    fun ann_org_springframework_security_core_annotation_AuthenticationPrincipal(@org.springframework.security.core.annotation.AuthenticationPrincipal arg: String): Process = ProcessBuilder(arg).start()

    @GetMapping("/ann_CurrentSecurityContext")
    fun ann_org_springframework_security_core_annotation_CurrentSecurityContext(@org.springframework.security.core.annotation.CurrentSecurityContext arg: String): Process = ProcessBuilder(arg).start()

    @GetMapping("/ann_SessionAttribute")
    fun ann_org_springframework_web_bind_annotation_SessionAttribute(@org.springframework.web.bind.annotation.SessionAttribute arg: String): Process = ProcessBuilder(arg).start()

    @GetMapping("/ann_RequestAttribute")
    fun ann_org_springframework_web_bind_annotation_RequestAttribute(@org.springframework.web.bind.annotation.RequestAttribute arg: String): Process = ProcessBuilder(arg).start()

    @GetMapping("/ann_Autowired")
    fun ann_org_springframework_beans_factory_annotation_Autowired(@org.springframework.beans.factory.annotation.Autowired arg: String): Process = ProcessBuilder(arg).start()

    @GetMapping("/ann_Value")
    fun ann_org_springframework_beans_factory_annotation_Value(@org.springframework.beans.factory.annotation.Value arg: String): Process = ProcessBuilder(arg).start()

    /** A simple type, unannotated: Spring resolves it as a @RequestParam. */
    @GetMapping("/simple")
    fun simpleTypeIsQueryParam(term: String): Process = ProcessBuilder(term).start()

    /** `isSimpleProperty` is "a simple value type OR AN ARRAY of one". */
    @GetMapping("/simple-array")
    fun simpleTypeArrayIsQueryParam(terms: Array<String>): Process =
        ProcessBuilder(terms[0]).start()

    /**
     * A complex type, unannotated: a @ModelAttribute command object. Its
     * data is on its FIELDS, so the seed must be field-bearing — a bare
     * fact derives nothing on `form.term`, which is how
     * `processFindForm(owner)` reaching `findByLastName(owner.lastName)`
     * went unreported in spring-petclinic.
     */
    @PostMapping("/command")
    fun complexTypeIsCommandObject(form: SearchForm): Process =
        ProcessBuilder(form.term).start()
}

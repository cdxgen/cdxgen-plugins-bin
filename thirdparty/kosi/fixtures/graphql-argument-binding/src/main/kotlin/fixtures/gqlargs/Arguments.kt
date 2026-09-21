// — graphql's ARGUMENT BINDING rule, one handler per framework-supplied type.
//
// From docs.spring.io/spring-graphql/reference/controllers.html, verbatim:
//
//   "By default, if the method parameter name is available, for example with the -parameters compiler flag in Java 8+ or with debugging info from the compiler, it is used to look up the argument."
//
// kosi had this framework as handlerInput=annotated, which seeds NOTHING for
// a handler that binds without annotations. Each want-not below is one
// framework-supplied type: drop its pack entry and that handler reports.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_graphql_schema_DataFetchingEnvironment
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_graphql_GraphQLContext
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_graphql_schema_DataFetchingFieldSelectionSet
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_dataloader_DataLoader
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_util_Locale
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_security_Principal
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_data_domain_Sort
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_graphql_data_query_ScrollSubrange
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_data_domain_Subrange
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_security_core_annotation_AuthenticationPrincipal
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_graphql_data_method_annotation_ContextValue
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ann_org_springframework_graphql_data_method_annotation_LocalContextValue
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedIsBound mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedSimpleIsBound mode=endpoint
package fixtures.gqlargs

/** What the framework binds from the request. */
class Command {
    var value: String = ""
}

@org.springframework.stereotype.Controller
class ArgumentApi {

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_graphql_schema_DataFetchingEnvironment(arg: graphql.schema.DataFetchingEnvironment): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_graphql_GraphQLContext(arg: graphql.GraphQLContext): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_graphql_schema_DataFetchingFieldSelectionSet(arg: graphql.schema.DataFetchingFieldSelectionSet): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_org_dataloader_DataLoader(arg: org.dataloader.DataLoader<String, String>): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_java_util_Locale(arg: java.util.Locale): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_java_security_Principal(arg: java.security.Principal): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_org_springframework_data_domain_Sort(arg: org.springframework.data.domain.Sort): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_org_springframework_graphql_data_query_ScrollSubrange(arg: org.springframework.graphql.data.query.ScrollSubrange): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ctx_org_springframework_data_domain_Subrange(arg: org.springframework.data.domain.Subrange<String>): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ann_org_springframework_security_core_annotation_AuthenticationPrincipal(@org.springframework.security.core.annotation.AuthenticationPrincipal arg: String): Process = ProcessBuilder(arg).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ann_org_springframework_graphql_data_method_annotation_ContextValue(@org.springframework.graphql.data.method.annotation.ContextValue arg: String): Process = ProcessBuilder(arg).start()

    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun ann_org_springframework_graphql_data_method_annotation_LocalContextValue(@org.springframework.graphql.data.method.annotation.LocalContextValue arg: String): Process = ProcessBuilder(arg).start()

    /**
     * The rule this fixture exists for: an unannotated parameter is bound
     * from the request, so it carries attacker input.
     */
    @org.springframework.graphql.data.method.annotation.MutationMapping
    fun unannotatedIsBound(payload: Command): Process = ProcessBuilder(payload.value).start()

    /** A simple type binds as a scalar, and is input just the same. */
    @org.springframework.graphql.data.method.annotation.QueryMapping
    fun unannotatedSimpleIsBound(term: String): Process = ProcessBuilder(term).start()
}

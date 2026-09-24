package fixtures.javasig;

// Annotation members whose type names a Kotlin declaration.
@interface Bound {
    Class<? extends Service> wildcard() default Service.class;
    Class<Model> exact() default Model.class;
}

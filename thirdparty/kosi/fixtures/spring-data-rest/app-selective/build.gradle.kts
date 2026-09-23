plugins { kotlin("jvm") }

// Spring Data REST without the Boot starter: the webmvc artifact itself.
dependencies { implementation("org.springframework.data:spring-data-rest-webmvc:3.6.4") }

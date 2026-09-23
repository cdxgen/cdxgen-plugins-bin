plugins { kotlin("jvm") }

// Spring Data REST is declared but its jar is NOT on the analysed classpath.
dependencies { implementation("org.springframework.boot:spring-boot-starter-data-rest") }

plugins { kotlin("jvm") }

// Spring Data REST is what exports repositories as HTTP resources.
dependencies { implementation("org.springframework.boot:spring-boot-starter-data-rest") }

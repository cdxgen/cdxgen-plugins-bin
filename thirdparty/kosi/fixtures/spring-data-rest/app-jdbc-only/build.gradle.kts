plugins { kotlin("jvm") }

// A data-jdbc app: its repositories are persistence, not HTTP.
dependencies { implementation("org.springframework.boot:spring-boot-starter-data-jdbc") }

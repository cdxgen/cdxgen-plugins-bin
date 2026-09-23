package org.springframework.data.rest.webmvc.config

import org.springframework.data.rest.core.config.RepositoryRestConfiguration

interface RepositoryRestConfigurer {
    fun configureRepositoryRestConfiguration(config: RepositoryRestConfiguration) {}
}
